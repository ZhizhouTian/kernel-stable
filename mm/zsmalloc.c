/*
 * zsmalloc memory allocator
 *
 * Copyright (C) 2011  Nitin Gupta
 * Copyright (C) 2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the license that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 */

/*
 * Following is how we use various fields and flags of underlying
 * struct page(s) to form a zspage.
 *
 * Usage of struct page fields:
 *	page->private: points to the first component (0-order) page
 *	page->index (union with page->freelist): override by struct zs_meta
 *
 *	For _first_ page only:
 *
 *	page->private: refers to the component page after the first page
 *		If the page is first_page for huge object, it stores handle.
 *		Look at size_class->huge.
 *	page->lru: links together first pages of various zspages.
 *		Basically forming list of zspages in a fullness group.
 *	page->freelist: override by struct zs_meta
 *
 * Usage of struct page flags:
 *	PG_private: identifies the first component page
 *	PG_private2: identifies the last component page
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/vmalloc.h>
#include <linux/preempt.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/zsmalloc.h>
#include <linux/zpool.h>
#include <linux/mount.h>
#include <linux/migrate.h>

/*
 * This must be power of 2 and greater than of equal to sizeof(link_free).
 * These two conditions ensure that any 'struct link_free' itself doesn't
 * span more than 1 page which avoids complex case of mapping 2 pages simply
 * to restore link_free pointer values.
 */
#define ZS_ALIGN		8

/*
 * A single 'zspage' is composed of up to 2^N discontiguous 0-order (single)
 * pages. ZS_MAX_ZSPAGE_ORDER defines upper limit on N.
 */
#define ZS_MAX_ZSPAGE_ORDER 2
#define ZS_MAX_PAGES_PER_ZSPAGE (_AC(1, UL) << ZS_MAX_ZSPAGE_ORDER)

#define ZS_HANDLE_SIZE (sizeof(unsigned long))

/*
 * Object location (<PFN>, <obj_idx>) is encoded as
 * as single (unsigned long) handle value.
 *
 * Note that object index <obj_idx> is relative to system
 * page <PFN> it is stored in, so for each sub-page belonging
 * to a zspage, obj_idx starts with 0.
 *
 * This is made more complicated by various memory models and PAE.
 */

#ifndef MAX_PHYSMEM_BITS
#ifdef CONFIG_HIGHMEM64G
#define MAX_PHYSMEM_BITS 36
#else /* !CONFIG_HIGHMEM64G */
/*
 * If this definition of MAX_PHYSMEM_BITS is used, OBJ_INDEX_BITS will just
 * be PAGE_SHIFT
 */
#define MAX_PHYSMEM_BITS BITS_PER_LONG
#endif
#endif
#define _PFN_BITS		(MAX_PHYSMEM_BITS - PAGE_SHIFT)

/*
 * Memory for allocating for handle keeps object position by
 * encoding <page, obj_idx> and the encoded value has a room
 * in least bit(ie, look at obj_to_location).
 * We use the bit to synchronize between object access by
 * user and migration.
 */
#define HANDLE_PIN_BIT	0

/*
 * Head in allocated object should have OBJ_ALLOCATED_TAG
 * to identify the object was allocated or not.
 * It's okay to add the status bit in the least bit because
 * header keeps handle which is 4byte-aligned address so we
 * have room for two bit at least.
 */
#define OBJ_ALLOCATED_TAG 1
#define OBJ_TAG_BITS 1
#define OBJ_INDEX_BITS	(BITS_PER_LONG - _PFN_BITS - OBJ_TAG_BITS)
#define OBJ_INDEX_MASK	((_AC(1, UL) << OBJ_INDEX_BITS) - 1)

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
/* ZS_MIN_ALLOC_SIZE must be multiple of ZS_ALIGN */
#define ZS_MIN_ALLOC_SIZE \
	MAX(32, (ZS_MAX_PAGES_PER_ZSPAGE << PAGE_SHIFT >> OBJ_INDEX_BITS))
/* each chunk includes extra space to keep handle */
#define ZS_MAX_ALLOC_SIZE	PAGE_SIZE

#define FREEOBJ_BITS 11
#define CLASS_BITS	8
#define CLASS_MASK	((1 << CLASS_BITS) - 1)
#define FULLNESS_BITS	2
#define FULLNESS_MASK	((1 << FULLNESS_BITS) - 1)
#define INUSE_BITS	11
#define INUSE_MASK	((1 << INUSE_BITS) - 1)

/*
 * On systems with 4K page size, this gives 255 size classes! There is a
 * trader-off here:
 *  - Large number of size classes is potentially wasteful as free page are
 *    spread across these classes
 *  - Small number of size classes causes large internal fragmentation
 *  - Probably its better to use specific size classes (empirically
 *    determined). NOTE: all those class sizes must be set as multiple of
 *    ZS_ALIGN to make sure link_free itself never has to span 2 pages.
 *
 *  ZS_MIN_ALLOC_SIZE and ZS_SIZE_CLASS_DELTA must be multiple of ZS_ALIGN
 *  (reason above)
 */
#define ZS_SIZE_CLASS_DELTA	(PAGE_SIZE >> CLASS_BITS)

/*
 * We do not maintain any list for completely empty or full pages
 */
enum fullness_group {
	ZS_ALMOST_FULL,
	ZS_ALMOST_EMPTY,
	_ZS_NR_FULLNESS_GROUPS,

	ZS_EMPTY = _ZS_NR_FULLNESS_GROUPS,
	ZS_FULL
};

enum zs_stat_type {
	OBJ_ALLOCATED,
	OBJ_USED,
	CLASS_ALMOST_FULL,
	CLASS_ALMOST_EMPTY,
};

#ifdef CONFIG_ZSMALLOC_STAT
#define NR_ZS_STAT_TYPE	(CLASS_ALMOST_EMPTY + 1)
#else
#define NR_ZS_STAT_TYPE	(OBJ_USED + 1)
#endif

struct zs_size_stat {
	unsigned long objs[NR_ZS_STAT_TYPE];
};

#ifdef CONFIG_ZSMALLOC_STAT
static struct dentry *zs_stat_root;
#endif

static struct vfsmount *zsmalloc_mnt;

/*
 * number of size_classes
 */
static int zs_size_classes;

/*
 * We assign a page to ZS_ALMOST_EMPTY fullness group when:
 *	n <= N / f, where
 * n = number of allocated objects
 * N = total number of objects zspage can store
 * f = fullness_threshold_frac
 *
 * Similarly, we assign zspage to:
 *	ZS_ALMOST_FULL	when n > N / f
 *	ZS_EMPTY	when n == 0
 *	ZS_FULL		when n == N
 *
 * (see: fix_fullness_group())
 */
static const int fullness_threshold_frac = 4;

struct size_class {
	spinlock_t lock;
	struct page *fullness_list[_ZS_NR_FULLNESS_GROUPS];
	/*
	 * Size of objects stored in this class. Must be multiple
	 * of ZS_ALIGN.
	 */
	int size;
	int objs_per_zspage;
	unsigned int index;

	struct zs_size_stat stats;

	/* Number of PAGE_SIZE sized pages to combine to form a 'zspage' */
	int pages_per_zspage;
	/* huge object: pages_per_zspage == 1 && maxobj_per_zspage == 1 */
	bool huge;
};

/*
 * Placed within free objects to form a singly linked list.
 * For every zspage, first_page->freeobj gives head of this list.
 *
 * This must be power of 2 and less than or equal to ZS_ALIGN
 */
struct link_free {
	union {
		/*
		 * free object list
		 * It's valid for non-allocated object
		 */
		unsigned long next;
		/*
		 * Handle of allocated object.
		 */
		unsigned long handle;
	};
};

struct zs_pool {
	const char *name;

	struct size_class **size_class;
	struct kmem_cache *handle_cachep;

	gfp_t flags;	/* allocation flags used when growing pool */
	atomic_long_t pages_allocated;

	struct zs_pool_stats stats;

	/* Compact classes */
	struct shrinker shrinker;
	/*
	 * To signify that register_shrinker() was successful
	 * and unregister_shrinker() will not Oops.
	 */
	bool shrinker_enabled;
#ifdef CONFIG_ZSMALLOC_STAT
	struct dentry *stat_dentry;
#endif
	struct inode *inode;
};

struct zs_meta {
	union {
		/* first page */
		struct {
			unsigned long freeobj:FREEOBJ_BITS;
			unsigned long class:CLASS_BITS;
			unsigned long fullness:FULLNESS_BITS;
			unsigned long inuse:INUSE_BITS;
		};
		/* tail pages */
		struct {
			struct page *next;
		};
	};
};

struct mapping_area {
#ifdef CONFIG_PGTABLE_MAPPING
	struct vm_struct *vm; /* vm area for mapping object that span pages */
#else
	char *vm_buf; /* copy buffer for objects that span pages */
#endif
	char *vm_addr; /* address of kmap_atomic()'ed pages */
	enum zs_mapmode vm_mm; /* mapping mode */
};

static int create_handle_cache(struct zs_pool *pool)
{
	pool->handle_cachep = kmem_cache_create("zs_handle", ZS_HANDLE_SIZE,
					0, 0, NULL);
	return pool->handle_cachep ? 0 : 1;
}

static void destroy_handle_cache(struct zs_pool *pool)
{
	kmem_cache_destroy(pool->handle_cachep);
}

static unsigned long alloc_handle(struct zs_pool *pool)
{
	return (unsigned long)kmem_cache_alloc(pool->handle_cachep,
		pool->flags & ~__GFP_HIGHMEM);
}

static void free_handle(struct zs_pool *pool, unsigned long handle)
{
	kmem_cache_free(pool->handle_cachep, (void *)handle);
}

static void record_obj(unsigned long handle, unsigned long obj)
{
	/*
	 * lsb of @obj represents handle lock while other bits
	 * represent object value the handle is pointing so
	 * updating shouldn't do store tearing.
	 */
	WRITE_ONCE(*(unsigned long *)handle, obj);
}

/* zpool driver */

#ifdef CONFIG_ZPOOL

static void *zs_zpool_create(const char *name, gfp_t gfp,
			     const struct zpool_ops *zpool_ops,
			     struct zpool *zpool)
{
	return zs_create_pool(name, gfp);
}

static void zs_zpool_destroy(void *pool)
{
	zs_destroy_pool(pool);
}

static int zs_zpool_malloc(void *pool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	*handle = zs_malloc(pool, size);
	return *handle ? 0 : -1;
}
static void zs_zpool_free(void *pool, unsigned long handle)
{
	zs_free(pool, handle);
}

static int zs_zpool_shrink(void *pool, unsigned int pages,
			unsigned int *reclaimed)
{
	return -EINVAL;
}

static void *zs_zpool_map(void *pool, unsigned long handle,
			enum zpool_mapmode mm)
{
	enum zs_mapmode zs_mm;

	switch (mm) {
	case ZPOOL_MM_RO:
		zs_mm = ZS_MM_RO;
		break;
	case ZPOOL_MM_WO:
		zs_mm = ZS_MM_WO;
		break;
	case ZPOOL_MM_RW: /* fallthru */
	default:
		zs_mm = ZS_MM_RW;
		break;
	}

	return zs_map_object(pool, handle, zs_mm);
}
static void zs_zpool_unmap(void *pool, unsigned long handle)
{
	zs_unmap_object(pool, handle);
}

static u64 zs_zpool_total_size(void *pool)
{
	return zs_get_total_pages(pool) << PAGE_SHIFT;
}

static struct zpool_driver zs_zpool_driver = {
	.type =		"zsmalloc",
	.owner =	THIS_MODULE,
	.create =	zs_zpool_create,
	.destroy =	zs_zpool_destroy,
	.malloc =	zs_zpool_malloc,
	.free =		zs_zpool_free,
	.shrink =	zs_zpool_shrink,
	.map =		zs_zpool_map,
	.unmap =	zs_zpool_unmap,
	.total_size =	zs_zpool_total_size,
};

MODULE_ALIAS("zpool-zsmalloc");
#endif /* CONFIG_ZPOOL */

static unsigned int get_maxobj_per_zspage(int size, int pages_per_zspage)
{
	return pages_per_zspage * PAGE_SIZE / size;
}

/* per-cpu VM mapping areas for zspage accesses that cross page boundaries */
static DEFINE_PER_CPU(struct mapping_area, zs_map_area);

static int is_first_page(struct page *page)
{
	return PagePrivate(page);
}

static int is_last_page(struct page *page)
{
	return PagePrivate2(page);
}

/*
 * Indicate that whether zspage is isolated for page migration.
 * Protected by size_class lock
 */
static void SetZsPageIsolate(struct page *first_page)
{
	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);
	SetPageUptodate(first_page);
}

static int ZsPageIsolate(struct page *first_page)
{
	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	return PageUptodate(first_page);
}

static void ClearZsPageIsolate(struct page *first_page)
{
	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);
	ClearPageUptodate(first_page);
}

static int get_zspage_inuse(struct page *first_page)
{
	struct zs_meta *m;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	m = (struct zs_meta *)&first_page->freelist;

	return m->inuse;
}

static void set_zspage_inuse(struct page *first_page, int val)
{
	struct zs_meta *m;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	m = (struct zs_meta *)&first_page->freelist;
	m->inuse = val;
}

static void mod_zspage_inuse(struct page *first_page, int val)
{
	struct zs_meta *m;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	m = (struct zs_meta *)&first_page->freelist;
	m->inuse += val;
}

static void set_freeobj(struct page *first_page, int idx)
{
	struct zs_meta *m;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	m = (struct zs_meta *)&first_page->freelist;
	m->freeobj = idx;
}

static unsigned long get_freeobj(struct page *first_page)
{
	struct zs_meta *m;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	m = (struct zs_meta *)&first_page->freelist;
	return m->freeobj;
}

static void set_next_page(struct page *page, struct page *next)
{
	struct zs_meta *m;

	VM_BUG_ON_PAGE(is_first_page(page), page);

	m = (struct zs_meta *)&page->index;
	m->next = next;
}

static struct page *get_next_page(struct page *page)
{
	struct page *next;

	if (is_last_page(page))
		next = NULL;
	else if (is_first_page(page))
		next = (struct page *)page_private(page);
	else {
		struct zs_meta *m = (struct zs_meta *)&page->index;

		VM_BUG_ON(!m->next);
		next = m->next;
	}

	return next;
}

static void get_zspage_mapping(struct page *first_page,
				unsigned int *class_idx,
				enum fullness_group *fullness)
{
	struct zs_meta *m;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	m = (struct zs_meta *)&first_page->freelist;
	*fullness = m->fullness;
	*class_idx = m->class;
}

static void set_zspage_mapping(struct page *first_page,
				unsigned int class_idx,
				enum fullness_group fullness)
{
	struct zs_meta *m;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	m = (struct zs_meta *)&first_page->freelist;
	m->fullness = fullness;
	m->class = class_idx;
}

/*
 * zsmalloc divides the pool into various size classes where each
 * class maintains a list of zspages where each zspage is divided
 * into equal sized chunks. Each allocation falls into one of these
 * classes depending on its size. This function returns index of the
 * size class which has chunk size big enough to hold the give size.
 */
static int get_size_class_index(int size)
{
	int idx = 0;

	if (likely(size > ZS_MIN_ALLOC_SIZE))
		idx = DIV_ROUND_UP(size - ZS_MIN_ALLOC_SIZE,
				ZS_SIZE_CLASS_DELTA);

	return min(zs_size_classes - 1, idx);
}

static inline void zs_stat_inc(struct size_class *class,
				enum zs_stat_type type, unsigned long cnt)
{
	if (type < NR_ZS_STAT_TYPE)
		class->stats.objs[type] += cnt;
}

static inline void zs_stat_dec(struct size_class *class,
				enum zs_stat_type type, unsigned long cnt)
{
	if (type < NR_ZS_STAT_TYPE)
		class->stats.objs[type] -= cnt;
}

static inline unsigned long zs_stat_get(struct size_class *class,
				enum zs_stat_type type)
{
	if (type < NR_ZS_STAT_TYPE)
		return class->stats.objs[type];
	return 0;
}

#ifdef CONFIG_ZSMALLOC_STAT

static int __init zs_stat_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	zs_stat_root = debugfs_create_dir("zsmalloc", NULL);
	if (!zs_stat_root)
		return -ENOMEM;

	return 0;
}

static void __exit zs_stat_exit(void)
{
	debugfs_remove_recursive(zs_stat_root);
}

static unsigned long zs_can_compact(struct size_class *class);

static int zs_stats_size_show(struct seq_file *s, void *v)
{
	int i;
	struct zs_pool *pool = s->private;
	struct size_class *class;
	int objs_per_zspage;
	unsigned long class_almost_full, class_almost_empty;
	unsigned long obj_allocated, obj_used, pages_used, freeable;
	unsigned long total_class_almost_full = 0, total_class_almost_empty = 0;
	unsigned long total_objs = 0, total_used_objs = 0, total_pages = 0;
	unsigned long total_freeable = 0;

	seq_printf(s, " %5s %5s %11s %12s %13s %10s %10s %16s %8s\n",
			"class", "size", "almost_full", "almost_empty",
			"obj_allocated", "obj_used", "pages_used",
			"pages_per_zspage", "freeable");

	for (i = 0; i < zs_size_classes; i++) {
		class = pool->size_class[i];

		if (class->index != i)
			continue;

		spin_lock(&class->lock);
		class_almost_full = zs_stat_get(class, CLASS_ALMOST_FULL);
		class_almost_empty = zs_stat_get(class, CLASS_ALMOST_EMPTY);
		obj_allocated = zs_stat_get(class, OBJ_ALLOCATED);
		obj_used = zs_stat_get(class, OBJ_USED);
		freeable = zs_can_compact(class);
		spin_unlock(&class->lock);

		objs_per_zspage = get_maxobj_per_zspage(class->size,
				class->pages_per_zspage);
		pages_used = obj_allocated / objs_per_zspage *
				class->pages_per_zspage;

		seq_printf(s, " %5u %5u %11lu %12lu %13lu"
				" %10lu %10lu %16d %8lu\n",
			i, class->size, class_almost_full, class_almost_empty,
			obj_allocated, obj_used, pages_used,
			class->pages_per_zspage, freeable);

		total_class_almost_full += class_almost_full;
		total_class_almost_empty += class_almost_empty;
		total_objs += obj_allocated;
		total_used_objs += obj_used;
		total_pages += pages_used;
		total_freeable += freeable;
	}

	seq_puts(s, "\n");
	seq_printf(s, " %5s %5s %11lu %12lu %13lu %10lu %10lu %16s %8lu\n",
			"Total", "", total_class_almost_full,
			total_class_almost_empty, total_objs,
			total_used_objs, total_pages, "", total_freeable);

	return 0;
}

static int zs_stats_size_open(struct inode *inode, struct file *file)
{
	return single_open(file, zs_stats_size_show, inode->i_private);
}

static const struct file_operations zs_stat_size_ops = {
	.open           = zs_stats_size_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int zs_pool_stat_create(struct zs_pool *pool, const char *name)
{
	struct dentry *entry;

	if (!zs_stat_root)
		return -ENODEV;

	entry = debugfs_create_dir(name, zs_stat_root);
	if (!entry) {
		pr_warn("debugfs dir <%s> creation failed\n", name);
		return -ENOMEM;
	}
	pool->stat_dentry = entry;

	entry = debugfs_create_file("classes", S_IFREG | S_IRUGO,
			pool->stat_dentry, pool, &zs_stat_size_ops);
	if (!entry) {
		pr_warn("%s: debugfs file entry <%s> creation failed\n",
				name, "classes");
		return -ENOMEM;
	}

	return 0;
}

static void zs_pool_stat_destroy(struct zs_pool *pool)
{
	debugfs_remove_recursive(pool->stat_dentry);
}

#else /* CONFIG_ZSMALLOC_STAT */
static int __init zs_stat_init(void)
{
	return 0;
}

static void __exit zs_stat_exit(void)
{
}

static inline int zs_pool_stat_create(struct zs_pool *pool, const char *name)
{
	return 0;
}

static inline void zs_pool_stat_destroy(struct zs_pool *pool)
{
}
#endif


/*
 * For each size class, zspages are divided into different groups
 * depending on how "full" they are. This was done so that we could
 * easily find empty or nearly empty zspages when we try to shrink
 * the pool (not yet implemented). This function returns fullness
 * status of the given page.
 */
static enum fullness_group get_fullness_group(struct size_class *class,
						struct page *first_page)
{
	int inuse, objs_per_zspage;
	enum fullness_group fg;

	inuse = get_zspage_inuse(first_page);
	objs_per_zspage = class->objs_per_zspage;

	if (inuse == 0)
		fg = ZS_EMPTY;
	else if (inuse == objs_per_zspage)
		fg = ZS_FULL;
	else if (inuse <= 3 * objs_per_zspage / fullness_threshold_frac)
		fg = ZS_ALMOST_EMPTY;
	else
		fg = ZS_ALMOST_FULL;

	return fg;
}

/*
 * Each size class maintains various freelists and zspages are assigned
 * to one of these freelists based on the number of live objects they
 * have. This functions inserts the given zspage into the freelist
 * identified by <class, fullness_group>.
 */
static void insert_zspage(struct size_class *class,
				enum fullness_group fullness,
				struct page *first_page)
{
	struct page **head;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	if (fullness >= _ZS_NR_FULLNESS_GROUPS)
		return;

	zs_stat_inc(class, fullness == ZS_ALMOST_EMPTY ?
			CLASS_ALMOST_EMPTY : CLASS_ALMOST_FULL, 1);

	head = &class->fullness_list[fullness];
	if (!*head) {
		*head = first_page;
		return;
	}

	/*
	 * We want to see more ZS_FULL pages and less almost
	 * empty/full. Put pages with higher inuse first.
	 */
	list_add_tail(&first_page->lru, &(*head)->lru);
	if (get_zspage_inuse(first_page) >= get_zspage_inuse(*head))
		*head = first_page;
}

/*
 * This function removes the given zspage from the freelist identified
 * by <class, fullness_group>.
 */
static void remove_zspage(struct size_class *class,
				enum fullness_group fullness,
				struct page *first_page)
{
	struct page **head;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);

	if (fullness >= _ZS_NR_FULLNESS_GROUPS)
		return;

	head = &class->fullness_list[fullness];
	VM_BUG_ON_PAGE(!*head, first_page);
	if (list_empty(&(*head)->lru))
		*head = NULL;
	else if (*head == first_page)
		*head = (struct page *)list_entry((*head)->lru.next,
					struct page, lru);

	list_del_init(&first_page->lru);
	zs_stat_dec(class, fullness == ZS_ALMOST_EMPTY ?
			CLASS_ALMOST_EMPTY : CLASS_ALMOST_FULL, 1);
}

/*
 * Each size class maintains zspages in different fullness groups depending
 * on the number of live objects they contain. When allocating or freeing
 * objects, the fullness status of the page can change, say, from ALMOST_FULL
 * to ALMOST_EMPTY when freeing an object. This function checks if such
 * a status change has occurred for the given page and accordingly moves the
 * page from the freelist of the old fullness group to that of the new
 * fullness group.
 */
static enum fullness_group fix_fullness_group(struct size_class *class,
						struct page *first_page)
{
	int class_idx;
	enum fullness_group currfg, newfg;

	get_zspage_mapping(first_page, &class_idx, &currfg);
	newfg = get_fullness_group(class, first_page);
	if (newfg == currfg)
		goto out;

	/* Later, putback will insert page to right list */
	if (!ZsPageIsolate(first_page)) {
		remove_zspage(class, currfg, first_page);
		insert_zspage(class, newfg, first_page);
	}
	set_zspage_mapping(first_page, class_idx, newfg);

out:
	return newfg;
}

/*
 * We have to decide on how many pages to link together
 * to form a zspage for each size class. This is important
 * to reduce wastage due to unusable space left at end of
 * each zspage which is given as:
 *     wastage = Zp % class_size
 *     usage = Zp - wastage
 * where Zp = zspage size = k * PAGE_SIZE where k = 1, 2, ...
 *
 * For example, for size class of 3/8 * PAGE_SIZE, we should
 * link together 3 PAGE_SIZE sized pages to form a zspage
 * since then we can perfectly fit in 8 such objects.
 */
static int get_pages_per_zspage(int class_size)
{
	int i, max_usedpc = 0;
	/* zspage order which gives maximum used size per KB */
	int max_usedpc_order = 1;

	for (i = 1; i <= ZS_MAX_PAGES_PER_ZSPAGE; i++) {
		int zspage_size;
		int waste, usedpc;

		zspage_size = i * PAGE_SIZE;
		waste = zspage_size % class_size;
		usedpc = (zspage_size - waste) * 100 / zspage_size;

		if (usedpc > max_usedpc) {
			max_usedpc = usedpc;
			max_usedpc_order = i;
		}
	}

	return max_usedpc_order;
}

/*
 * A single 'zspage' is composed of many system pages which are
 * linked together using fields in struct page. This function finds
 * the first/head page, given any component page of a zspage.
 */
static struct page *get_first_page(struct page *page)
{
	if (is_first_page(page))
		return page;
	else
		return (struct page *)page_private(page);
}

int get_first_obj_ofs(struct size_class *class, struct page *first_page,
			struct page *page)
{
	int pos, bound;
	int page_idx = 0;
	int ofs = 0;
	struct page *cursor = first_page;

	if (first_page == page)
		goto out;

	while (page != cursor) {
		page_idx++;
		cursor = get_next_page(cursor);
	}

	bound = PAGE_SIZE * page_idx;
	pos = (((class->objs_per_zspage * class->size) *
		page_idx / class->pages_per_zspage) / class->size
		) * class->size;

	ofs = (pos + class->size) % PAGE_SIZE;
out:
	return ofs;
}

static void objidx_to_page_and_offset(struct size_class *class,
				struct page *first_page,
				unsigned long obj_idx,
				struct page **obj_page,
				unsigned long *offset_in_page)
{
	int i;
	unsigned long offset;
	struct page *cursor;
	int nr_page;

	offset = obj_idx * class->size;
	cursor = first_page;
	nr_page = offset >> PAGE_SHIFT;

	*offset_in_page = offset & ~PAGE_MASK;

	for (i = 0; i < nr_page; i++)
		cursor = get_next_page(cursor);

	*obj_page = cursor;
}

/**
 * obj_to_location - get (<page>, <obj_idx>) from encoded object value
 * @page: page object resides in zspage
 * @obj_idx: object index
 */
static void obj_to_location(unsigned long obj, struct page **page,
				unsigned long *obj_idx)
{
	obj >>= OBJ_TAG_BITS;
	*page = pfn_to_page(obj >> OBJ_INDEX_BITS);
	*obj_idx = (obj & OBJ_INDEX_MASK);
}

/**
 * location_to_obj - get obj value encoded from (<page>, <obj_idx>)
 * @page: page object resides in zspage
 * @obj_idx: object index
 */
static unsigned long location_to_obj(struct page *page,
				unsigned long obj_idx)
{
	unsigned long obj;

	obj = page_to_pfn(page) << OBJ_INDEX_BITS;
	obj |= obj_idx & OBJ_INDEX_MASK;
	obj <<= OBJ_TAG_BITS;

	return obj;
}

static unsigned long handle_to_obj(unsigned long handle)
{
	return *(unsigned long *)handle;
}

static unsigned long obj_to_head(struct size_class *class, struct page *page,
			void *obj)
{
	if (class->huge) {
		VM_BUG_ON_PAGE(!is_first_page(page), page);
		return page_private(page);
	} else
		return *(unsigned long *)obj;
}

static inline int testpin_tag(unsigned long handle)
{
	unsigned long *ptr = (unsigned long *)handle;

	return test_bit(HANDLE_PIN_BIT, ptr);
}

static inline int trypin_tag(unsigned long handle)
{
	unsigned long *ptr = (unsigned long *)handle;

	return !test_and_set_bit_lock(HANDLE_PIN_BIT, ptr);
}

static void pin_tag(unsigned long handle)
{
	while (!trypin_tag(handle));
}

static void unpin_tag(unsigned long handle)
{
	unsigned long *ptr = (unsigned long *)handle;

	clear_bit_unlock(HANDLE_PIN_BIT, ptr);
}

static void reset_page(struct page *page)
{
	__ClearPageMovable(page);
	clear_bit(PG_private, &page->flags);
	clear_bit(PG_private_2, &page->flags);
	set_page_private(page, 0);
	page->freelist = NULL;
	page->mapping = NULL;
	page_mapcount_reset(page);
}

/**
 * lock_zspage - lock all pages in the zspage
 * @first_page: head page of the zspage
 *
 * To prevent destroy during migration, zspage freeing should
 * hold locks of all pages in a zspage
 */
void lock_zspage(struct page *first_page)
{
	struct page *cursor = first_page;

	do {
		while (!trylock_page(cursor));
	} while ((cursor = get_next_page(cursor)) != NULL);
}

static void free_zspage(struct zs_pool *pool, struct page *first_page)
{
	struct page *nextp, *tmp;

	VM_BUG_ON_PAGE(!is_first_page(first_page), first_page);
	VM_BUG_ON_PAGE(get_zspage_inuse(first_page), first_page);

	lock_zspage(first_page);
	nextp = (struct page *)page_private(first_page);

	/* zspage with only 1 system page */
	if (!nextp)
		goto out;

	do {
		tmp = nextp;
		nextp = get_next_page(nextp);
		reset_page(tmp);
		unlock_page(tmp);
		__free_page(tmp);
	} while (nextp);
out:
	reset_page(first_page);
	unlock_page(first_page);
	__free_page(first_page);
}

/* Initialize a newly allocated zspage */
static void init_zspage(struct size_class *class, struct page *first_page,
			struct address_space *mapping)
{
	int freeobj = 1;
	unsigned long off = 0;
	struct page *page = first_page;

	first_page->freelist = NULL;
	INIT_LIST_HEAD(&first_page->lru);
	set_zspage_inuse(first_page, 0);
	BUG_ON(!trylock_page(first_page));
	first_page->mapping = mapping;
	__SetPageMovable(first_page);
	unlock_page(first_page);

	while (page) {
		struct page *next_page;
		struct link_free *link;
		void *vaddr;

		vaddr = kmap_atomic(page);
		link = (struct link_free *)vaddr + off / sizeof(*link);

		while ((off += class->size) < PAGE_SIZE) {
			link->next = freeobj++ << OBJ_ALLOCATED_TAG;
			link += class->size / sizeof(*link);
		}

		/*
		 * We now come to the last (full or partial) object on this
		 * page, which must point to the first object on the next
		 * page (if present)
		 */
		next_page = get_next_page(page);
		if (next_page) {
			link->next = freeobj++ << OBJ_ALLOCATED_TAG;
		} else {
			/*
			 * Reset OBJ_ALLOCATED_TAG bit to last link for
			 * migration to know it is allocated object or not.
			 */
			link->next = -1 << OBJ_ALLOCATED_TAG;
		}
		kunmap_atomic(vaddr);
		page = next_page;
		off %= PAGE_SIZE;
	}

	set_freeobj(first_page, 0);
}

static void create_page_chain(struct page *pages[], int nr_pages)
{
	int i;
	struct page *page;
	struct page *prev_page = NULL;
	struct page *first_page = NULL;

	for (i = 0; i < nr_pages; i++) {
		page = pages[i];

		if (i == 0) {
			SetPagePrivate(page);
			set_page_private(page, 0);
			first_page = page;
		}

		if (i == 1)
			set_page_private(first_page, (unsigned long)page);
		if (i >= 1) {
			set_next_page(page, NULL);
			set_page_private(page, (unsigned long)first_page);
		}
		if (i >= 2)
			set_next_page(prev_page, page);
		if (i == nr_pages - 1)
			SetPagePrivate2(page);

		prev_page = page;
	}
}

static void replace_sub_page(struct size_class *class, struct page *first_page,
		struct page *newpage, struct page *oldpage)
{
	struct page *page;
	struct page *pages[ZS_MAX_PAGES_PER_ZSPAGE] = {NULL,};
	int idx = 0;

	page = first_page;
	do {
		if (page == oldpage)
			pages[idx] = newpage;
		else
			pages[idx] = page;
		idx++;
	} while ((page = get_next_page(page)) != NULL);

	create_page_chain(pages, class->pages_per_zspage);

	if (is_first_page(oldpage)) {
		enum fullness_group fg;
		int class_idx;

		SetZsPageIsolate(newpage);
		get_zspage_mapping(oldpage, &class_idx, &fg);
		set_zspage_mapping(newpage, class_idx, fg);
		set_freeobj(newpage, get_freeobj(oldpage));
		set_zspage_inuse(newpage, get_zspage_inuse(oldpage));
		if (class->huge)
			set_page_private(newpage,  page_private(oldpage));
	}

	newpage->mapping = oldpage->mapping;
	__SetPageMovable(newpage);
}

/*
 * Allocate a zspage for the given size class
 */
static struct page *alloc_zspage(struct zs_pool *pool,
				struct size_class *class)
{
	int i;
	struct page *first_page = NULL;
	struct page *pages[ZS_MAX_PAGES_PER_ZSPAGE];

	/*
	 * Allocate individual pages and link them together as:
	 * 1. first page->private = first sub-page
	 * 2. all sub-pages are linked together using page->lru
	 * 3. each sub-page is linked to the first page using page->private
	 *
	 * For each size class, First/Head pages are linked together using
	 * page->lru. Also, we set PG_private to identify the first page
	 * (i.e. no other sub-page has this flag set) and PG_private_2 to
	 * identify the last page.
	 */
	for (i = 0; i < class->pages_per_zspage; i++) {
		struct page *page;

		page = alloc_page(pool->flags);
		if (!page) {
			while (--i >= 0)
				__free_page(pages[i]);
			return NULL;
		}

		pages[i] = page;
	}

	create_page_chain(pages, class->pages_per_zspage);
	first_page = pages[0];
	init_zspage(class, first_page, pool->inode->i_mapping);

	return first_page;
}

static struct page *find_get_zspage(struct size_class *class)
{
	int i;
	struct page *page;

	for (i = 0; i < _ZS_NR_FULLNESS_GROUPS; i++) {
		page = class->fullness_list[i];
		if (page)
			break;
	}

	return page;
}

#ifdef CONFIG_PGTABLE_MAPPING
static inline int __zs_cpu_up(struct mapping_area *area)
{
	/*
	 * Make sure we don't leak memory if a cpu UP notification
	 * and zs_init() race and both call zs_cpu_up() on the same cpu
	 */
	if (area->vm)
		return 0;
	area->vm = alloc_vm_area(PAGE_SIZE * 2, NULL);
	if (!area->vm)
		return -ENOMEM;
	return 0;
}

static inline void __zs_cpu_down(struct mapping_area *area)
{
	if (area->vm)
		free_vm_area(area->vm);
	area->vm = NULL;
}

static inline void *__zs_map_object(struct mapping_area *area,
				struct page *pages[2], int off, int size)
{
	BUG_ON(map_vm_area(area->vm, PAGE_KERNEL, pages));
	area->vm_addr = area->vm->addr;
	return area->vm_addr + off;
}

static inline void __zs_unmap_object(struct mapping_area *area,
				struct page *pages[2], int off, int size)
{
	unsigned long addr = (unsigned long)area->vm_addr;

	unmap_kernel_range(addr, PAGE_SIZE * 2);
}

#else /* CONFIG_PGTABLE_MAPPING */

static inline int __zs_cpu_up(struct mapping_area *area)
{
	/*
	 * Make sure we don't leak memory if a cpu UP notification
	 * and zs_init() race and both call zs_cpu_up() on the same cpu
	 */
	if (area->vm_buf)
		return 0;
	area->vm_buf = kmalloc(ZS_MAX_ALLOC_SIZE, GFP_KERNEL);
	if (!area->vm_buf)
		return -ENOMEM;
	return 0;
}

static inline void __zs_cpu_down(struct mapping_area *area)
{
	kfree(area->vm_buf);
	area->vm_buf = NULL;
}

static void *__zs_map_object(struct mapping_area *area,
			struct page *pages[2], int off, int size)
{
	int sizes[2];
	void *addr;
	char *buf = area->vm_buf;

	/* disable page faults to match kmap_atomic() return conditions */
	pagefault_disable();

	/* no read fastpath */
	if (area->vm_mm == ZS_MM_WO)
		goto out;

	sizes[0] = PAGE_SIZE - off;
	sizes[1] = size - sizes[0];

	/* copy object to per-cpu buffer */
	addr = kmap_atomic(pages[0]);
	memcpy(buf, addr + off, sizes[0]);
	kunmap_atomic(addr);
	addr = kmap_atomic(pages[1]);
	memcpy(buf + sizes[0], addr, sizes[1]);
	kunmap_atomic(addr);
out:
	return area->vm_buf;
}

static void __zs_unmap_object(struct mapping_area *area,
			struct page *pages[2], int off, int size)
{
	int sizes[2];
	void *addr;
	char *buf;

	/* no write fastpath */
	if (area->vm_mm == ZS_MM_RO)
		goto out;

	buf = area->vm_buf;
	buf = buf + ZS_HANDLE_SIZE;
	size -= ZS_HANDLE_SIZE;
	off += ZS_HANDLE_SIZE;

	sizes[0] = PAGE_SIZE - off;
	sizes[1] = size - sizes[0];

	/* copy per-cpu buffer to object */
	addr = kmap_atomic(pages[0]);
	memcpy(addr + off, buf, sizes[0]);
	kunmap_atomic(addr);
	addr = kmap_atomic(pages[1]);
	memcpy(addr, buf + sizes[0], sizes[1]);
	kunmap_atomic(addr);

out:
	/* enable page faults to match kunmap_atomic() return conditions */
	pagefault_enable();
}

#endif /* CONFIG_PGTABLE_MAPPING */

static int zs_cpu_notifier(struct notifier_block *nb, unsigned long action,
				void *pcpu)
{
	int ret, cpu = (long)pcpu;
	struct mapping_area *area;

	switch (action) {
	case CPU_UP_PREPARE:
		area = &per_cpu(zs_map_area, cpu);
		ret = __zs_cpu_up(area);
		if (ret)
			return notifier_from_errno(ret);
		break;
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		area = &per_cpu(zs_map_area, cpu);
		__zs_cpu_down(area);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block zs_cpu_nb = {
	.notifier_call = zs_cpu_notifier
};

static int zs_register_cpu_notifier(void)
{
	int cpu, uninitialized_var(ret);

	cpu_notifier_register_begin();

	__register_cpu_notifier(&zs_cpu_nb);
	for_each_online_cpu(cpu) {
		ret = zs_cpu_notifier(NULL, CPU_UP_PREPARE, (void *)(long)cpu);
		if (notifier_to_errno(ret))
			break;
	}

	cpu_notifier_register_done();
	return notifier_to_errno(ret);
}

static void zs_unregister_cpu_notifier(void)
{
	int cpu;

	cpu_notifier_register_begin();

	for_each_online_cpu(cpu)
		zs_cpu_notifier(NULL, CPU_DEAD, (void *)(long)cpu);
	__unregister_cpu_notifier(&zs_cpu_nb);

	cpu_notifier_register_done();
}

static void init_zs_size_classes(void)
{
	int nr;

	nr = (ZS_MAX_ALLOC_SIZE - ZS_MIN_ALLOC_SIZE) / ZS_SIZE_CLASS_DELTA + 1;
	if ((ZS_MAX_ALLOC_SIZE - ZS_MIN_ALLOC_SIZE) % ZS_SIZE_CLASS_DELTA)
		nr += 1;

	zs_size_classes = nr;
}

static bool can_merge(struct size_class *prev, int size, int pages_per_zspage)
{
	if (prev->pages_per_zspage != pages_per_zspage)
		return false;

	if (get_maxobj_per_zspage(prev->size, prev->pages_per_zspage)
		!= get_maxobj_per_zspage(size, pages_per_zspage))
		return false;

	return true;
}

static bool zspage_full(struct size_class *class, struct page *first_page)
{
	return get_zspage_inuse(first_page) == class->objs_per_zspage;
}

static bool zspage_empty(struct size_class *class, struct page *first_page)
{
	return get_zspage_inuse(first_page) == 0;
}

unsigned long zs_get_total_pages(struct zs_pool *pool)
{
	return atomic_long_read(&pool->pages_allocated);
}
EXPORT_SYMBOL_GPL(zs_get_total_pages);

/**
 * zs_map_object - get address of allocated object from handle.
 * @pool: pool from which the object was allocated
 * @handle: handle returned from zs_malloc
 *
 * Before using an object allocated from zs_malloc, it must be mapped using
 * this function. When done with the object, it must be unmapped using
 * zs_unmap_object.
 *
 * Only one object can be mapped per cpu at a time. There is no protection
 * against nested mappings.
 *
 * This function returns with preemption and page faults disabled.
 */
void *zs_map_object(struct zs_pool *pool, unsigned long handle,
			enum zs_mapmode mm)
{
	struct page *page;
	unsigned long obj, obj_idx, off;

	unsigned int class_idx;
	enum fullness_group fg;
	struct size_class *class;
	struct mapping_area *area;
	struct page *pages[2];
	void *ret;

	/*
	 * Because we use per-cpu mapping areas shared among the
	 * pools/users, we can't allow mapping in interrupt context
	 * because it can corrupt another users mappings.
	 */
	WARN_ON_ONCE(in_interrupt());

	/* From now on, migration cannot move the object */
	pin_tag(handle);

	obj = handle_to_obj(handle);
	obj_to_location(obj, &page, &obj_idx);
	get_zspage_mapping(get_first_page(page), &class_idx, &fg);
	class = pool->size_class[class_idx];
	off = (class->size * obj_idx) & ~PAGE_MASK;

	area = &get_cpu_var(zs_map_area);
	area->vm_mm = mm;
	if (off + class->size <= PAGE_SIZE) {
		/* this object is contained entirely within a page */
		area->vm_addr = kmap_atomic(page);
		ret = area->vm_addr + off;
		goto out;
	}

	/* this object spans two pages */
	pages[0] = page;
	pages[1] = get_next_page(page);
	BUG_ON(!pages[1]);

	ret = __zs_map_object(area, pages, off, class->size);
out:
	if (!class->huge)
		ret += ZS_HANDLE_SIZE;

	return ret;
}
EXPORT_SYMBOL_GPL(zs_map_object);

void zs_unmap_object(struct zs_pool *pool, unsigned long handle)
{
	struct page *page;
	unsigned long obj, obj_idx, off;

	unsigned int class_idx;
	enum fullness_group fg;
	struct size_class *class;
	struct mapping_area *area;

	obj = handle_to_obj(handle);
	obj_to_location(obj, &page, &obj_idx);
	get_zspage_mapping(get_first_page(page), &class_idx, &fg);
	class = pool->size_class[class_idx];
	off = (class->size * obj_idx) & ~PAGE_MASK;

	area = this_cpu_ptr(&zs_map_area);
	if (off + class->size <= PAGE_SIZE)
		kunmap_atomic(area->vm_addr);
	else {
		struct page *pages[2];

		pages[0] = page;
		pages[1] = get_next_page(page);
		BUG_ON(!pages[1]);

		__zs_unmap_object(area, pages, off, class->size);
	}
	put_cpu_var(zs_map_area);
	unpin_tag(handle);
}
EXPORT_SYMBOL_GPL(zs_unmap_object);

static unsigned long obj_malloc(struct size_class *class,
				struct page *first_page, unsigned long handle)
{
	unsigned long obj;
	struct link_free *link;

	struct page *m_page;
	unsigned long m_offset;
	void *vaddr;

	obj = get_freeobj(first_page);
	objidx_to_page_and_offset(class, first_page, obj,
				&m_page, &m_offset);

	vaddr = kmap_atomic(m_page);
	link = (struct link_free *)vaddr + m_offset / sizeof(*link);
	set_freeobj(first_page, link->next >> OBJ_ALLOCATED_TAG);
	if (!class->huge)
		/* record handle in the header of allocated chunk */
		link->handle = handle | OBJ_ALLOCATED_TAG;
	else
		/* record handle in first_page->private */
		set_page_private(first_page, handle | OBJ_ALLOCATED_TAG);
	kunmap_atomic(vaddr);
	mod_zspage_inuse(first_page, 1);

	obj = location_to_obj(m_page, obj);

	return obj;
}


/**
 * zs_malloc - Allocate block of given size from pool.
 * @pool: pool to allocate from
 * @size: size of block to allocate
 *
 * On success, handle to the allocated object is returned,
 * otherwise 0.
 * Allocation requests with size > ZS_MAX_ALLOC_SIZE will fail.
 */
unsigned long zs_malloc(struct zs_pool *pool, size_t size)
{
	unsigned long handle, obj;
	struct size_class *class;
	struct page *first_page;

	if (unlikely(!size || size > ZS_MAX_ALLOC_SIZE))
		return 0;

	handle = alloc_handle(pool);
	if (!handle)
		return 0;

	/* extra space in chunk to keep the handle */
	size += ZS_HANDLE_SIZE;
	class = pool->size_class[get_size_class_index(size)];

	spin_lock(&class->lock);
	first_page = find_get_zspage(class);

	if (!first_page) {
		spin_unlock(&class->lock);
		first_page = alloc_zspage(pool, class);
		if (unlikely(!first_page)) {
			free_handle(pool, handle);
			return 0;
		}

		set_zspage_mapping(first_page, class->index, ZS_EMPTY);
		atomic_long_add(class->pages_per_zspage,
					&pool->pages_allocated);

		spin_lock(&class->lock);
		zs_stat_inc(class, OBJ_ALLOCATED, get_maxobj_per_zspage(
				class->size, class->pages_per_zspage));
	}

	obj = obj_malloc(class, first_page, handle);
	zs_stat_inc(class, OBJ_USED, 1);
	/* Now move the zspage to another fullness group, if required */
	fix_fullness_group(class, first_page);
	record_obj(handle, obj);
	spin_unlock(&class->lock);

	return handle;
}
EXPORT_SYMBOL_GPL(zs_malloc);

static void obj_free(struct size_class *class, unsigned long obj)
{
	struct link_free *link;
	struct page *first_page, *f_page;
	unsigned long f_objidx, f_offset;
	void *vaddr;

	obj &= ~OBJ_ALLOCATED_TAG;
	obj_to_location(obj, &f_page, &f_objidx);
	f_offset = (class->size * f_objidx) & ~PAGE_MASK;
	first_page = get_first_page(f_page);
	vaddr = kmap_atomic(f_page);

	/* Insert this object in containing zspage's freelist */
	link = (struct link_free *)(vaddr + f_offset);
	link->next = get_freeobj(first_page) << OBJ_ALLOCATED_TAG;
	if (class->huge)
		set_page_private(first_page, 0);
	kunmap_atomic(vaddr);
	set_freeobj(first_page, f_objidx);
	mod_zspage_inuse(first_page, -1);
}

void zs_free(struct zs_pool *pool, unsigned long handle)
{
	struct page *first_page, *f_page;
	unsigned long obj, f_objidx;
	int class_idx;
	struct size_class *class;
	enum fullness_group fullness;

	if (unlikely(!handle))
		return;

	/* Once handle is pinned, page|object migration cannot work */
	pin_tag(handle);
	obj = handle_to_obj(handle);
	obj_to_location(obj, &f_page, &f_objidx);
	first_page = get_first_page(f_page);

	get_zspage_mapping(first_page, &class_idx, &fullness);
	class = pool->size_class[class_idx];

	spin_lock(&class->lock);
	obj_free(class, obj);
	zs_stat_dec(class, OBJ_USED, 1);
	fullness = fix_fullness_group(class, first_page);
	if (fullness == ZS_EMPTY) {
		zs_stat_dec(class, OBJ_ALLOCATED, get_maxobj_per_zspage(
				class->size, class->pages_per_zspage));
		spin_unlock(&class->lock);
		atomic_long_sub(class->pages_per_zspage,
					&pool->pages_allocated);
		free_zspage(pool, first_page);
		goto out;
	}
	spin_unlock(&class->lock);
out:
	unpin_tag(handle);

	free_handle(pool, handle);
}
EXPORT_SYMBOL_GPL(zs_free);

static void zs_object_copy(struct size_class *class, unsigned long dst,
				unsigned long src)
{
	struct page *s_page, *d_page;
	unsigned long s_objidx, d_objidx;
	unsigned long s_off, d_off;
	void *s_addr, *d_addr;
	int s_size, d_size, size;
	int written = 0;

	s_size = d_size = class->size;

	obj_to_location(src, &s_page, &s_objidx);
	obj_to_location(dst, &d_page, &d_objidx);

	s_off = (class->size * s_objidx) & ~PAGE_MASK;
	d_off = (class->size * d_objidx) & ~PAGE_MASK;

	if (s_off + class->size > PAGE_SIZE)
		s_size = PAGE_SIZE - s_off;

	if (d_off + class->size > PAGE_SIZE)
		d_size = PAGE_SIZE - d_off;

	s_addr = kmap_atomic(s_page);
	d_addr = kmap_atomic(d_page);

	while (1) {
		size = min(s_size, d_size);
		memcpy(d_addr + d_off, s_addr + s_off, size);
		written += size;

		if (written == class->size)
			break;

		s_off += size;
		s_size -= size;
		d_off += size;
		d_size -= size;

		if (s_off >= PAGE_SIZE) {
			kunmap_atomic(d_addr);
			kunmap_atomic(s_addr);
			s_page = get_next_page(s_page);
			s_addr = kmap_atomic(s_page);
			d_addr = kmap_atomic(d_page);
			s_size = class->size - written;
			s_off = 0;
		}

		if (d_off >= PAGE_SIZE) {
			kunmap_atomic(d_addr);
			d_page = get_next_page(d_page);
			d_addr = kmap_atomic(d_page);
			d_size = class->size - written;
			d_off = 0;
		}
	}

	kunmap_atomic(d_addr);
	kunmap_atomic(s_addr);
}

static unsigned long handle_from_obj(struct size_class *class,
				struct page *first_page, int obj_idx)
{
	struct page *page;
	unsigned long offset_in_page;
	void *addr;
	unsigned long head, handle = 0;

	objidx_to_page_and_offset(class, first_page, obj_idx,
			&page, &offset_in_page);

	addr = kmap_atomic(page);
	head = obj_to_head(class, page, addr + offset_in_page);
	if (head & OBJ_ALLOCATED_TAG)
		handle = head & ~OBJ_ALLOCATED_TAG;
	kunmap_atomic(addr);

	return handle;
}

static int migrate_zspage(struct size_class *class, struct page *dst_page,
				struct page *src_page)
{
	unsigned long handle;
	unsigned long old_obj, new_obj;
	int i;
	int nr_migrated = 0;

	for (i = 0; i < class->objs_per_zspage; i++) {
		handle = handle_from_obj(class, src_page, i);
		if (!handle)
			continue;
		if (zspage_full(class, dst_page))
			break;
		old_obj = handle_to_obj(handle);
		new_obj = obj_malloc(class, dst_page, handle);
		zs_object_copy(class, new_obj, old_obj);
		nr_migrated++;
		/*
		 * record_obj updates handle's value to free_obj and it will
		 * invalidate lock bit(ie, HANDLE_PIN_BIT) of handle, which
		 * breaks synchronization using pin_tag(e,g, zs_free) so
		 * let's keep the lock bit.
		 */
		new_obj |= BIT(HANDLE_PIN_BIT);
		record_obj(handle, new_obj);
		obj_free(class, old_obj);
	}
	return nr_migrated;
}

/*
 * putback_zspage - add @first_page into right class's fullness list
 * @class: destination class
 * @first_page: target page
 *
 * Return @first_page's updated fullness_group
 */
static enum fullness_group putback_zspage(struct size_class *class,
					struct page *first_page)
{
	enum fullness_group fullness;

	VM_BUG_ON_PAGE(!list_empty(&first_page->lru), first_page);
	VM_BUG_ON_PAGE(ZsPageIsolate(first_page), first_page);

	fullness = get_fullness_group(class, first_page);
	insert_zspage(class, fullness, first_page);
	set_zspage_mapping(first_page, class->index, fullness);

	return fullness;
}

/*
 * freeze_zspage - freeze all objects in a zspage
 * @class: size class of the page
 * @first_page: first page of zspage
 *
 * Freeze all allocated objects in a zspage so objects couldn't be
 * freed until unfreeze objects. It should be called under class->lock.
 *
 * RETURNS:
 * the number of pinned objects
 */
static int freeze_zspage(struct size_class *class, struct page *first_page)
{
	unsigned long obj_idx;
	struct page *obj_page;
	unsigned long offset;
	void *addr;
	int nr_freeze = 0;

	for (obj_idx = 0; obj_idx < class->objs_per_zspage; obj_idx++) {
		unsigned long head;

		objidx_to_page_and_offset(class, first_page, obj_idx,
					&obj_page, &offset);
		addr = kmap_atomic(obj_page);
		head = obj_to_head(class, obj_page, addr + offset);
		if (head & OBJ_ALLOCATED_TAG) {
			unsigned long handle = head & ~OBJ_ALLOCATED_TAG;

			if (!trypin_tag(handle)) {
				kunmap_atomic(addr);
				break;
			}
			nr_freeze++;
		}
		kunmap_atomic(addr);
	}

	return nr_freeze;
}

/*
 * unfreeze_page - unfreeze objects freezed by freeze_zspage in a zspage
 * @class: size class of the page
 * @first_page: freezed zspage to unfreeze
 * @nr_obj: the number of objects to unfreeze
 *
 * unfreeze objects in a zspage.
 */
static void unfreeze_zspage(struct size_class *class, struct page *first_page,
			int nr_obj)
{
	unsigned long obj_idx;
	struct page *obj_page;
	unsigned long offset;
	void *addr;
	int nr_unfreeze = 0;

	for (obj_idx = 0; obj_idx < class->objs_per_zspage &&
			nr_unfreeze < nr_obj; obj_idx++) {
		unsigned long head;

		objidx_to_page_and_offset(class, first_page, obj_idx,
					&obj_page, &offset);
		addr = kmap_atomic(obj_page);
		head = obj_to_head(class, obj_page, addr + offset);
		if (head & OBJ_ALLOCATED_TAG) {
			unsigned long handle = head & ~OBJ_ALLOCATED_TAG;

			VM_BUG_ON(!testpin_tag(handle));
			unpin_tag(handle);
			nr_unfreeze++;
		}
		kunmap_atomic(addr);
	}
}

/*
 * isolate_source_page - isolate a zspage for migration source
 * @class: size class of zspage for isolation
 *
 * Returns a zspage which are isolated from list so anyone can
 * allocate a object from that page. As well, freeze all objects
 * allocated in the zspage so anyone cannot access that objects
 * (e.g., zs_map_object, zs_free).
 */
static struct page *isolate_source_page(struct size_class *class)
{
	int i;
	struct page *page = NULL;

	for (i = ZS_ALMOST_EMPTY; i >= ZS_ALMOST_FULL; i--) {
		int inuse, freezed;

		page = class->fullness_list[i];
		if (!page)
			continue;

		remove_zspage(class, i, page);

		inuse = get_zspage_inuse(page);
		freezed = freeze_zspage(class, page);

		if (inuse != freezed) {
			unfreeze_zspage(class, page, freezed);
			putback_zspage(class, page);
			page = NULL;
			continue;
		}

		break;
	}

	return page;
}

/*
 * isolate_target_page - isolate a zspage for migration target
 * @class: size class of zspage for isolation
 *
 * Returns a zspage which are isolated from list so anyone can
 * allocate a object from that page. As well, freeze all objects
 * allocated in the zspage so anyone cannot access that objects
 * (e.g., zs_map_object, zs_free).
 */
static struct page *isolate_target_page(struct size_class *class)
{
	int i;
	struct page *page;

	for (i = 0; i < _ZS_NR_FULLNESS_GROUPS; i++) {
		int inuse, freezed;

		page = class->fullness_list[i];
		if (!page)
			continue;

		remove_zspage(class, i, page);

		inuse = get_zspage_inuse(page);
		freezed = freeze_zspage(class, page);

		if (inuse != freezed) {
			unfreeze_zspage(class, page, freezed);
			putback_zspage(class, page);
			page = NULL;
			continue;
		}

		break;
	}

	return page;
}

/*
 *
 * Based on the number of unused allocated objects calculate
 * and return the number of pages that we can free.
 */
static unsigned long zs_can_compact(struct size_class *class)
{
	unsigned long obj_wasted;
	unsigned long obj_allocated, obj_used;

	obj_allocated = zs_stat_get(class, OBJ_ALLOCATED);
	obj_used = zs_stat_get(class, OBJ_USED);
	obj_wasted = obj_allocated - obj_used;

	obj_wasted /= get_maxobj_per_zspage(class->size,
			class->pages_per_zspage);

	return obj_wasted * class->pages_per_zspage;
}

static void __zs_compact(struct zs_pool *pool, struct size_class *class)
{
	struct page *src_page = NULL;
	struct page *dst_page = NULL;

	while (1) {
		int nr_migrated;

		spin_lock(&class->lock);
		if (!zs_can_compact(class)) {
			spin_unlock(&class->lock);
			break;
		}

		/*
		 * Isolate source page and freeze all objects in a zspage
		 * to prevent zspage destroying.
		 */
		if (!src_page) {
			src_page = isolate_source_page(class);
			if (!src_page) {
				spin_unlock(&class->lock);
				break;
			}
		}

		/* Isolate target page and freeze all objects in the zspage */
		if (!dst_page) {
			dst_page = isolate_target_page(class);
			if (!dst_page) {
				spin_unlock(&class->lock);
				break;
			}
		}
		spin_unlock(&class->lock);

		nr_migrated = migrate_zspage(class, dst_page, src_page);

		if (zspage_full(class, dst_page)) {
			spin_lock(&class->lock);
			putback_zspage(class, dst_page);
			unfreeze_zspage(class, dst_page,
				class->objs_per_zspage);
			spin_unlock(&class->lock);
			dst_page = NULL;
		}

		if (zspage_empty(class, src_page)) {
			free_zspage(pool, src_page);
			spin_lock(&class->lock);
			zs_stat_dec(class, OBJ_ALLOCATED,
				get_maxobj_per_zspage(
				class->size, class->pages_per_zspage));
			atomic_long_sub(class->pages_per_zspage,
					&pool->pages_allocated);

			pool->stats.pages_compacted += class->pages_per_zspage;
			spin_unlock(&class->lock);
			src_page = NULL;
		}
	}

	if (!src_page && !dst_page)
		return;

	spin_lock(&class->lock);
	if (src_page) {
		putback_zspage(class, src_page);
		unfreeze_zspage(class, src_page,
				class->objs_per_zspage);
	}

	if (dst_page) {
		putback_zspage(class, dst_page);
		unfreeze_zspage(class, dst_page,
				class->objs_per_zspage);
	}

	spin_unlock(&class->lock);
}

unsigned long zs_compact(struct zs_pool *pool)
{
	int i;
	struct size_class *class;

	for (i = zs_size_classes - 1; i >= 0; i--) {
		class = pool->size_class[i];
		if (!class)
			continue;
		if (class->index != i)
			continue;
		__zs_compact(pool, class);
	}

	return pool->stats.pages_compacted;
}
EXPORT_SYMBOL_GPL(zs_compact);

void zs_pool_stats(struct zs_pool *pool, struct zs_pool_stats *stats)
{
	memcpy(stats, &pool->stats, sizeof(struct zs_pool_stats));
}
EXPORT_SYMBOL_GPL(zs_pool_stats);

static unsigned long zs_shrinker_scan(struct shrinker *shrinker,
		struct shrink_control *sc)
{
	unsigned long pages_freed;
	struct zs_pool *pool = container_of(shrinker, struct zs_pool,
			shrinker);

	pages_freed = pool->stats.pages_compacted;
	/*
	 * Compact classes and calculate compaction delta.
	 * Can run concurrently with a manually triggered
	 * (by user) compaction.
	 */
	pages_freed = zs_compact(pool) - pages_freed;

	return pages_freed ? pages_freed : SHRINK_STOP;
}

static unsigned long zs_shrinker_count(struct shrinker *shrinker,
		struct shrink_control *sc)
{
	int i;
	struct size_class *class;
	unsigned long pages_to_free = 0;
	struct zs_pool *pool = container_of(shrinker, struct zs_pool,
			shrinker);

	for (i = zs_size_classes - 1; i >= 0; i--) {
		class = pool->size_class[i];
		if (!class)
			continue;
		if (class->index != i)
			continue;

		pages_to_free += zs_can_compact(class);
	}

	return pages_to_free;
}

static void zs_unregister_shrinker(struct zs_pool *pool)
{
	if (pool->shrinker_enabled) {
		unregister_shrinker(&pool->shrinker);
		pool->shrinker_enabled = false;
	}
}

static int zs_register_shrinker(struct zs_pool *pool)
{
	pool->shrinker.scan_objects = zs_shrinker_scan;
	pool->shrinker.count_objects = zs_shrinker_count;
	pool->shrinker.batch = 0;
	pool->shrinker.seeks = DEFAULT_SEEKS;

	return register_shrinker(&pool->shrinker);
}

bool zs_page_isolate(struct page *page, isolate_mode_t mode)
{
	struct zs_pool *pool;
	struct size_class *class;
	int class_idx;
	enum fullness_group fullness;
	struct page *first_page;

	/*
	 * The page is locked so it couldn't be destroyed.
	 * For detail, look at lock_zspage in free_zspage.
	 */
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageIsolated(page), page);
	/*
	 * In this implementation, it allows only first page migration.
	 */
	VM_BUG_ON_PAGE(!is_first_page(page), page);
	first_page = page;

	/*
	 * Without class lock, fullness is meaningless while constant
	 * class_idx is okay. We will get it under class lock at below,
	 * again.
	 */
	get_zspage_mapping(first_page, &class_idx, &fullness);
	pool = page->mapping->private_data;
	class = pool->size_class[class_idx];

	if (!spin_trylock(&class->lock))
		return false;

	get_zspage_mapping(first_page, &class_idx, &fullness);
	remove_zspage(class, fullness, first_page);
	SetZsPageIsolate(first_page);
	SetPageIsolated(page);
	spin_unlock(&class->lock);

	return true;
}

int zs_page_migrate(struct address_space *mapping, struct page *newpage,
		struct page *page, enum migrate_mode mode)
{
	struct zs_pool *pool;
	struct size_class *class;
	int class_idx;
	enum fullness_group fullness;
	struct page *first_page;
	void *s_addr, *d_addr, *addr;
	int ret = -EBUSY;
	int offset = 0;
	int freezed = 0;

	VM_BUG_ON_PAGE(!PageMovable(page), page);
	VM_BUG_ON_PAGE(!PageIsolated(page), page);

	first_page = page;
	get_zspage_mapping(first_page, &class_idx, &fullness);
	pool = page->mapping->private_data;
	class = pool->size_class[class_idx];

	/*
	 * Get stable fullness under class->lock
	 */
	if (!spin_trylock(&class->lock))
		return ret;

	get_zspage_mapping(first_page, &class_idx, &fullness);
	if (get_zspage_inuse(first_page) == 0)
		goto out_class_unlock;

	freezed = freeze_zspage(class, first_page);
	if (freezed != get_zspage_inuse(first_page))
		goto out_unfreeze;

	/* copy contents from page to newpage */
	s_addr = kmap_atomic(page);
	d_addr = kmap_atomic(newpage);
	memcpy(d_addr, s_addr, PAGE_SIZE);
	kunmap_atomic(d_addr);
	kunmap_atomic(s_addr);

	offset = get_first_obj_ofs(class, first_page, page);

	addr = kmap_atomic(page);
	do {
		unsigned long handle;
		unsigned long head;
		unsigned long new_obj, old_obj;
		unsigned long obj_idx;
		struct page *dummy;

		head = obj_to_head(class, page, addr + offset);
		if (head & OBJ_ALLOCATED_TAG) {
			handle = head & ~OBJ_ALLOCATED_TAG;
			if (!testpin_tag(handle))
				BUG();

			old_obj = handle_to_obj(handle);
			obj_to_location(old_obj, &dummy, &obj_idx);
			new_obj = location_to_obj(newpage, obj_idx);
			new_obj |= BIT(HANDLE_PIN_BIT);
			record_obj(handle, new_obj);
		}
		offset += class->size;
	} while (offset < PAGE_SIZE);
	kunmap_atomic(addr);

	replace_sub_page(class, first_page, newpage, page);
	first_page = newpage;
	get_page(newpage);
	VM_BUG_ON_PAGE(get_fullness_group(class, first_page) ==
			ZS_EMPTY, first_page);
	ClearZsPageIsolate(first_page);
	putback_zspage(class, first_page);

	/* Migration complete. Free old page */
	reset_page(page);
	ClearPageIsolated(page);
	put_page(page);
	ret = MIGRATEPAGE_SUCCESS;

out_unfreeze:
	unfreeze_zspage(class, first_page, freezed);
out_class_unlock:
	spin_unlock(&class->lock);

	return ret;
}

void zs_page_putback(struct page *page)
{
	struct zs_pool *pool;
	struct size_class *class;
	int class_idx;
	enum fullness_group fullness;
	struct page *first_page;

	VM_BUG_ON_PAGE(!PageMovable(page), page);
	VM_BUG_ON_PAGE(!PageIsolated(page), page);

	first_page = page;
	get_zspage_mapping(first_page, &class_idx, &fullness);
	pool = page->mapping->private_data;
	class = pool->size_class[class_idx];

	/*
	 * If there is race betwwen zs_free and here, free_zspage
	 * in zs_free will wait the page lock of @page without
	 * destroying of zspage.
	 */
	INIT_LIST_HEAD(&first_page->lru);
	spin_lock(&class->lock);
	ClearPageIsolated(page);
	ClearZsPageIsolate(first_page);
	putback_zspage(class, first_page);
	spin_unlock(&class->lock);
}

const struct address_space_operations zsmalloc_aops = {
	.isolate_page = zs_page_isolate,
	.migratepage = zs_page_migrate,
	.putback_page = zs_page_putback,
};

/**
 * zs_create_pool - Creates an allocation pool to work from.
 * @flags: allocation flags used to allocate pool metadata
 *
 * This function must be called before anything when using
 * the zsmalloc allocator.
 *
 * On success, a pointer to the newly created pool is returned,
 * otherwise NULL.
 */
struct zs_pool *zs_create_pool(const char *name, gfp_t flags)
{
	int i;
	struct zs_pool *pool;
	struct size_class *prev_class = NULL;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;

	pool->size_class = kcalloc(zs_size_classes, sizeof(struct size_class *),
			GFP_KERNEL);
	if (!pool->size_class) {
		kfree(pool);
		return NULL;
	}

	pool->name = kstrdup(name, GFP_KERNEL);
	if (!pool->name)
		goto err;

	if (create_handle_cache(pool))
		goto err;

	/*
	 * Iterate reversly, because, size of size_class that we want to use
	 * for merging should be larger or equal to current size.
	 */
	for (i = zs_size_classes - 1; i >= 0; i--) {
		int size;
		int pages_per_zspage;
		struct size_class *class;

		size = ZS_MIN_ALLOC_SIZE + i * ZS_SIZE_CLASS_DELTA;
		if (size > ZS_MAX_ALLOC_SIZE)
			size = ZS_MAX_ALLOC_SIZE;
		pages_per_zspage = get_pages_per_zspage(size);

		/*
		 * size_class is used for normal zsmalloc operation such
		 * as alloc/free for that size. Although it is natural that we
		 * have one size_class for each size, there is a chance that we
		 * can get more memory utilization if we use one size_class for
		 * many different sizes whose size_class have same
		 * characteristics. So, we makes size_class point to
		 * previous size_class if possible.
		 */
		if (prev_class) {
			if (can_merge(prev_class, size, pages_per_zspage)) {
				pool->size_class[i] = prev_class;
				continue;
			}
		}

		class = kzalloc(sizeof(struct size_class), GFP_KERNEL);
		if (!class)
			goto err;

		class->size = size;
		class->index = i;
		class->pages_per_zspage = pages_per_zspage;
		class->objs_per_zspage = class->pages_per_zspage *
						PAGE_SIZE / class->size;
		if (pages_per_zspage == 1 && class->objs_per_zspage == 1)
			class->huge = true;
		spin_lock_init(&class->lock);
		pool->size_class[i] = class;

		prev_class = class;
	}

	pool->flags = flags;

	if (zs_pool_stat_create(pool, name))
		goto err;

	pool->inode = alloc_anon_inode(zsmalloc_mnt->mnt_sb);
	if (IS_ERR(pool->inode)) {
		pool->inode = NULL;
		goto err;
	}

	pool->inode->i_mapping->a_ops = &zsmalloc_aops;
	pool->inode->i_mapping->private_data = pool;

	/*
	 * Not critical, we still can use the pool
	 * and user can trigger compaction manually.
	 */
	if (zs_register_shrinker(pool) == 0)
		pool->shrinker_enabled = true;
	return pool;

err:
	zs_destroy_pool(pool);
	return NULL;
}
EXPORT_SYMBOL_GPL(zs_create_pool);

void zs_destroy_pool(struct zs_pool *pool)
{
	int i;

	zs_unregister_shrinker(pool);
	if (pool->inode)
		iput(pool->inode);
	zs_pool_stat_destroy(pool);

	for (i = 0; i < zs_size_classes; i++) {
		int fg;
		struct size_class *class = pool->size_class[i];

		if (!class)
			continue;

		if (class->index != i)
			continue;

		for (fg = 0; fg < _ZS_NR_FULLNESS_GROUPS; fg++) {
			if (class->fullness_list[fg]) {
				pr_info("Freeing non-empty class with size %db, fullness group %d\n",
					class->size, fg);
			}
		}
		kfree(class);
	}

	destroy_handle_cache(pool);
	kfree(pool->size_class);
	kfree(pool->name);
	kfree(pool);
}
EXPORT_SYMBOL_GPL(zs_destroy_pool);

static struct dentry *zs_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name, void *data)
{
	static const struct dentry_operations ops = {
		.d_dname = simple_dname,
	};

	return mount_pseudo(fs_type, "zsmalloc:", NULL, &ops, ZSMALLOC_MAGIC);
}

static struct file_system_type zsmalloc_fs = {
	.name		= "zsmalloc",
	.mount		= zs_mount,
	.kill_sb	= kill_anon_super,
};

static int __init zs_init(void)
{
	int ret;

	zsmalloc_mnt = kern_mount(&zsmalloc_fs);
	if (IS_ERR(zsmalloc_mnt)) {
		ret = PTR_ERR(zsmalloc_mnt);
		goto out;
	}

	ret = zs_register_cpu_notifier();
	if (ret)
		goto notifier_fail;

	/*
	 * A zspage's a free object index, class index, fullness group,
	 * inuse object count are encoded in its (first)page->freelist
	 * so sizeof(struct zs_meta) should be less than
	 * sizeof(page->freelist(i.e., void *)).
	 */
	BUILD_BUG_ON(sizeof(struct zs_meta) > sizeof(unsigned long));

	init_zs_size_classes();

#ifdef CONFIG_ZPOOL
	zpool_register_driver(&zs_zpool_driver);
#endif

	ret = zs_stat_init();
	if (ret) {
		pr_err("zs stat initialization failed\n");
		goto stat_fail;
	}

	return 0;

stat_fail:
#ifdef CONFIG_ZPOOL
	zpool_unregister_driver(&zs_zpool_driver);
#endif
notifier_fail:
	zs_unregister_cpu_notifier();
	kern_unmount(zsmalloc_mnt);
out:
	return ret;
}

static void __exit zs_exit(void)
{
#ifdef CONFIG_ZPOOL
	zpool_unregister_driver(&zs_zpool_driver);
#endif
	zs_unregister_cpu_notifier();

	kern_unmount(zsmalloc_mnt);

	zs_stat_exit();
}

module_init(zs_init);
module_exit(zs_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
