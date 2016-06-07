/*
 * zsmalloc memory allocator
 *
 * Copyright (C) 2011  Nitin Gupta
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the license that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 */


/*
 * This allocator is designed for use with zcache and zram. Thus, the
 * allocator is supposed to work well under low memory conditions. In
 * particular, it never attempts higher order page allocation which is
 * very likely to fail under memory pressure. On the other hand, if we
 * just use single (0-order) pages, it would suffer from very high
 * fragmentation -- any object of size PAGE_SIZE/2 or larger would occupy
 * an entire page. This was one of the major issues with its predecessor
 * (xvmalloc).
 *
 * To overcome these issues, zsmalloc allocates a bunch of 0-order pages
 * and links them together using various 'struct page' fields. These linked
 * pages act as a single higher-order page i.e. an object can span 0-order
 * page boundaries. The code refers to these linked pages as a single entity
 * called zspage.
 *
 * Following is how we use various fields and flags of underlying
 * struct page(s) to form a zspage.
 *
 * Usage of struct page fields:
 *	page->first_page: points to the first component (0-order) page
 *	page->index (union with page->freelist): offset of the first object
 *		starting in this page. For the first page, this is
 *		always 0, so we use this field (aka freelist) to point
 *		to the first free object in zspage.
 *	page->lru: links together all component pages (except the first page)
 *		of a zspage
 *
 *	For _first_ page only:
 *
 *	page->private (union with page->first_page): refers to the
 *		component page after the first page
 *	page->freelist: points to the first free object in zspage.
 *		Free objects are linked together using in-place
 *		metadata.
 *	page->objects: maximum number of objects we can store in this
 *		zspage (class->zspage_order * PAGE_SIZE / class->size)
 *	page->lru: links together first pages of various zspages.
 *		Basically forming list of zspages in a fullness group.
 *	page->mapping: class index and fullness group of the zspage
 *
 * Usage of struct page flags:
 *	PG_private: identifies the first component page
 *	PG_private2: identifies the last component page
 *
 */

#ifdef CONFIG_ZSMALLOC_DEBUG
#define DEBUG
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/vmalloc.h>
#include <linux/hardirq.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/pagemap.h>
#include <linux/migrate.h>
#include <linux/page-flags.h>

#include "zsmalloc.h"

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
 * as single (void *) handle value.
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
#define HANDLE_PIN_BIT  0

/*
 * Head in allocated object should have OBJ_ALLOCATED_TAG
 * to identify the object was allocated or not.
 * It's okay to add the status bit in the least bit because
 * header keeps handle which is 4byte-aligned address so we
 * have room for two bit at least.
 */
#define OBJ_ALLOCATED_TAG 1
#define OBJ_TAG_BITS 1
#define OBJ_INDEX_BITS	(BITS_PER_LONG - _PFN_BITS - OBJ_ALLOCATED_TAG)
#define OBJ_INDEX_MASK	((_AC(1, UL) << OBJ_INDEX_BITS) - 1)

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
/* ZS_MIN_ALLOC_SIZE must be multiple of ZS_ALIGN */
#define ZS_MIN_ALLOC_SIZE \
	MAX(32, (ZS_MAX_PAGES_PER_ZSPAGE << PAGE_SHIFT >> OBJ_INDEX_BITS))
#define ZS_MAX_ALLOC_SIZE	PAGE_SIZE

#define FREEOBJ_BITS 11
#define CLASS_BITS      8
#define CLASS_MASK      ((1 << CLASS_BITS) - 1)
#define FULLNESS_BITS   2
#define FULLNESS_MASK   ((1 << FULLNESS_BITS) - 1)
#define INUSE_BITS      11
#define INUSE_MASK      ((1 << INUSE_BITS) - 1)

/*
 * On systems with 4K page size, this gives 254 size classes! There is a
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
#define ZS_SIZE_CLASS_DELTA	(PAGE_SIZE >> 8)
#define ZS_SIZE_CLASSES		((ZS_MAX_ALLOC_SIZE - ZS_MIN_ALLOC_SIZE) / \
					ZS_SIZE_CLASS_DELTA + 1)

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

/*
 * We assign a page to ZS_ALMOST_EMPTY fullness group when:
 *	n <= N / f, where
 * n = number of allocated objects
 * N = total number of objects zspage can store
 * f = 1/fullness_threshold_frac
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

	/* Number of PAGE_SIZE sized pages to combine to form a 'zspage' */
	int pages_per_zspage;


	/* stats */
	u64 pages_allocated;

};

/*
 * Placed within free objects to form a singly linked list.
 * For every zspage, first_page->freelist gives head of this list.
 *
 * This must be power of 2 and less than or equal to ZS_ALIGN
 */
struct link_free {
	/* Handle of next free chunk (encodes <PFN, obj_idx>) */
	unsigned long next;
};

struct zs_pool {
	struct size_class size_class[ZS_SIZE_CLASSES];
	struct kmem_cache *handle_cachep;

	gfp_t flags;	/* allocation flags used when growing pool */
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

/*
 * A zspage's class index and fullness group
 * are encoded in its (first)page->mapping
 */
#define CLASS_IDX_BITS	28
#define CLASS_IDX_MASK	((1 << CLASS_IDX_BITS) - 1)

/*
 * By default, zsmalloc uses a copy-based object mapping method to access
 * allocations that span two pages. However, if a particular architecture
 * performs VM mapping faster than copying, then it should be added here
 * so that USE_PGTABLE_MAPPING is defined. This causes zsmalloc to use
 * page table mapping rather than copying for object mapping.
*/
#if defined(CONFIG_ARM) && !defined(MODULE)
#define USE_PGTABLE_MAPPING
#endif

struct mapping_area {
#ifdef USE_PGTABLE_MAPPING
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
			pool->flags & ~(__GFP_HIGHMEM|__GFP_MOVABLE));
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
	 *                                       */
	*(unsigned long *)handle = obj;
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
	BUG_ON(!is_first_page(first_page));
	SetPageUptodate(first_page);
}

static int ZsPageIsolate(struct page *first_page)
{
	BUG_ON(!is_first_page(first_page));

	return PageUptodate(first_page);
}

static void ClearZsPageIsolate(struct page *first_page)
{
	BUG_ON(!is_first_page(first_page));
	ClearPageUptodate(first_page);
}

static int get_zspage_inuse(struct page *first_page)
{
	struct zs_meta *m;

	BUG_ON(!is_first_page(first_page));

	m = (struct zs_meta *)&first_page->freelist;

	return m->inuse;
}

static void set_zspage_inuse(struct page *first_page, int val)
{
	struct zs_meta *m;

	BUG_ON(!is_first_page(first_page));

	m = (struct zs_meta *)&first_page->freelist;
	m->inuse = val;
}

static void mod_zspage_inuse(struct page *first_page, int val)
{
	struct zs_meta *m;

	BUG_ON(!is_first_page(first_page));

	m = (struct zs_meta *)&first_page->freelist;
	m->inuse += val;
}

static __attribute__((optimize("O0"))) void set_freeobj(struct page *first_page, int idx)
{
	struct zs_meta *m;

	BUG_ON(!is_first_page(first_page));

	m = (struct zs_meta *)&first_page->freelist;
	m->freeobj = idx;
}

static __attribute__((optimize("O0"))) unsigned long get_freeobj(struct page *first_page)
{
	struct zs_meta *m;

	BUG_ON(!is_first_page(first_page));

	m = (struct zs_meta *)&first_page->freelist;
	return m->freeobj;
}

/*
 * A single 'zspage' is composed of many system pages which are
 * linked together using fields in struct page. This function finds
 * the first/head page, given any component page of a zspage.
 */
static __attribute__((optimize("O0"))) struct page *get_first_page(struct page *page)
{
	if (is_first_page(page))
		return page;
	else
		return (struct page *)page_private(page);
}

static void set_next_page(struct page *page, struct page *next)
{
	struct zs_meta *m;

	BUG_ON(is_first_page(page));

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

		BUG_ON(!m->next);
		next = m->next;
	}

	return next;
}

static __attribute__((optimize("O0"))) void get_zspage_mapping(struct page *page, unsigned int *class_idx,
				enum fullness_group *fullness)
{
	struct zs_meta *m;
	BUG_ON(!is_first_page(page));

	m = (struct zs_meta *)&page->freelist;
	*fullness = m->fullness;
	*class_idx = m->class;
}

static __attribute__((optimize("O0"))) void set_zspage_mapping(struct page *page, unsigned int class_idx,
				enum fullness_group fullness)
{
	struct zs_meta *m;
	BUG_ON(!is_first_page(page));

	m = (struct zs_meta *)&page->freelist;
	m->fullness = fullness;
	m->class = class_idx;
}

static __attribute__((optimize("O0"))) int get_size_class_index(int size)
{
	int idx = 0;

	if (likely(size > ZS_MIN_ALLOC_SIZE))
		idx = DIV_ROUND_UP(size - ZS_MIN_ALLOC_SIZE,
				ZS_SIZE_CLASS_DELTA);

	return idx;
}

static __attribute__((optimize("O0"))) enum fullness_group get_fullness_group(struct size_class *class, struct page *page)
{
	int inuse, max_objects;
	enum fullness_group fg;
	BUG_ON(!is_first_page(page));

	inuse = get_zspage_inuse(page);
	max_objects = class->objs_per_zspage;

	if (inuse == 0)
		fg = ZS_EMPTY;
	else if (inuse == max_objects)
		fg = ZS_FULL;
	else if (inuse <= max_objects / fullness_threshold_frac)
		fg = ZS_ALMOST_EMPTY;
	else
		fg = ZS_ALMOST_FULL;

	return fg;
}

static __attribute__((optimize("O0"))) void insert_zspage(struct page *page, struct size_class *class,
				enum fullness_group fullness)
{
	struct page **head;

	BUG_ON(!is_first_page(page));

	if (fullness >= _ZS_NR_FULLNESS_GROUPS)
		return;

	head = &class->fullness_list[fullness];
	if (*head)
		list_add_tail(&page->lru, &(*head)->lru);

	*head = page;
}

static __attribute__((optimize("O0"))) void remove_zspage(struct page *page, struct size_class *class,
				enum fullness_group fullness)
{
	struct page **head;

	BUG_ON(!is_first_page(page));

	if (fullness >= _ZS_NR_FULLNESS_GROUPS)
		return;

	head = &class->fullness_list[fullness];
	BUG_ON(!*head);
	if (list_empty(&(*head)->lru))
		*head = NULL;
	else if (*head == page)
		*head = (struct page *)list_entry((*head)->lru.next,
					struct page, lru);

	list_del_init(&page->lru);
}

static __attribute__((optimize("O0"))) enum fullness_group fix_fullness_group(struct zs_pool *pool,
						struct page *page)
{
	int class_idx;
	struct size_class *class;
	enum fullness_group currfg, newfg;

	BUG_ON(!is_first_page(page));

	get_zspage_mapping(page, &class_idx, &currfg);
	class = &pool->size_class[class_idx];
	newfg = get_fullness_group(class, page);
	if (newfg == currfg)
		goto out;

	remove_zspage(page, class, currfg);
	insert_zspage(page, class, newfg);
	set_zspage_mapping(page, class_idx, newfg);

out:
	return newfg;
}

/*
 * We have to decide on how many pages to link together
 * to form a zspage for each size class. This is important
 * to reduce wastage due to unusable space left at end of
 * each zspage which is given as:
 *	wastage = Zp - Zp % size_class
 * where Zp = zspage size = k * PAGE_SIZE where k = 1, 2, ...
 *
 * For example, for size class of 3/8 * PAGE_SIZE, we should
 * link together 3 PAGE_SIZE sized pages to form a zspage
 * since then we can perfectly fit in 8 such objects.
 */
static __attribute__((optimize("O0"))) int get_pages_per_zspage(int class_size)
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

static bool check_isolated_page(struct page *first_page)
{
	struct page *cursor;

	for (cursor = first_page; cursor != NULL; cursor =
			get_next_page(cursor)) {
		if (PageIsolated(cursor))
			return true;
	}

	return false;
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
	pos = (((class->objs_per_zspage* class->size) *
		page_idx / class->pages_per_zspage) / class->size
		) * class->size;

	ofs = (pos + class->size) % PAGE_SIZE;
out:
	return ofs;
}

static __attribute__((optimize("O0"))) void objidx_to_page_and_offset(struct size_class *class,
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

/*
 * Encode <page, obj_idx> as a single handle value.
 * On hardware platforms with physical memory starting at 0x0 the pfn
 * could be 0 so we ensure that the handle will never be 0 by adjusting the
 * encoded obj_idx value before encoding.
 */
static __attribute__((optimize("O0"))) unsigned long obj_location_to_handle(struct page *page,
				unsigned long obj_idx)
{
	unsigned long obj_head;

	obj_head = page_to_pfn(page) << OBJ_INDEX_BITS;
	obj_head |= (obj_idx & OBJ_INDEX_MASK);
	obj_head <<= OBJ_TAG_BITS;

	return obj_head;
}

/*
 * Decode <page, obj_idx> pair from the given object handle. We adjust the
 * decoded obj_idx back to its original value since it was adjusted in
 * obj_location_to_handle().
 */
static __attribute__((optimize("O0"))) void obj_handle_to_location(unsigned long obj_head, struct page **page,
				unsigned long *obj_idx)
{
	obj_head >>= OBJ_TAG_BITS;
	*page = pfn_to_page(obj_head >> OBJ_INDEX_BITS);
	*obj_idx = obj_head & OBJ_INDEX_MASK;
}

static unsigned long handle_to_obj(unsigned long handle)
{
	return *(unsigned long *)handle;
}

static unsigned long obj_to_head(void* obj)
{
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
	clear_bit(PG_private, &page->flags);
	clear_bit(PG_private_2, &page->flags);
	set_page_private(page, 0);
	page->mapping = NULL;
	page->freelist = NULL;
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

int trylock_zspage(struct page *first_page, struct page *locked_page)
{
	struct page *cursor, *fail;

	BUG_ON(!is_first_page(first_page));

	for (cursor = first_page; cursor != NULL; cursor =
			get_next_page(cursor)) {
		if (cursor != locked_page) {
			if (!trylock_page(cursor)) {
				fail = cursor;
				goto unlock;
			}
		}
	}

	return 1;
unlock:
	for (cursor = first_page; cursor != fail; cursor =
			get_next_page(cursor)) {
		if (cursor != locked_page)
			unlock_page(cursor);
	}

	return 0;
}

void unlock_zspage(struct page *first_page, struct page *locked_page)
{
	struct page *cursor = first_page;

	for (; cursor != NULL; cursor = get_next_page(cursor)) {
		BUG_ON(!PageLocked(cursor));
		if (cursor != locked_page)
			unlock_page(cursor);
	};
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

	BUG_ON(!list_empty(&first_page->lru));
	BUG_ON(ZsPageIsolate(first_page));
	BUG_ON(check_isolated_page(first_page));

	fullness = get_fullness_group(class, first_page);
	insert_zspage(first_page, class, fullness);
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
		head = obj_to_head(addr + offset);
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
		head = obj_to_head(addr + offset);
		if (head & OBJ_ALLOCATED_TAG) {
			unsigned long handle = head & ~OBJ_ALLOCATED_TAG;

			VM_BUG_ON(!testpin_tag(handle));
			unpin_tag(handle);
			nr_unfreeze++;
		}
		kunmap_atomic(addr);
	}
}

static void free_zspage(struct page *first_page)
{
	struct page *nextp, *tmp;

	BUG_ON(!is_first_page(first_page));
	BUG_ON(get_zspage_inuse(first_page));

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

static __attribute__((optimize("O0"))) void create_page_chain(struct page *pages[], int nr_pages)
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
	}

	newpage->mapping = oldpage->mapping;
	__SetPageMovable(newpage);
}

bool zs_page_isolate(struct page *page)
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
	BUG_ON(!PageLocked(page));
	BUG_ON(PageIsolated(page));
	/*
	 * first_page will not be destroyed by PG_lock of @page but it could
	 * be migrated out. For prohibiting it, zs_page_migrate calls
	 * trylock_zspage so it closes the race.
	 */
	first_page = get_first_page(page);

	/*
	 * Without class lock, fullness is meaningless while constant
	 * class_idx is okay. We will get it under class lock at below,
	 * again.
	 */
	get_zspage_mapping(first_page, &class_idx, &fullness);
	pool = page->mapping->private_data;
	class = &pool->size_class[class_idx];

	if (!spin_trylock(&class->lock))
		return false;

	if (check_isolated_page(first_page))
		goto skip_isolate;

	/*
	 * If this is first time isolation for zspage, isolate zspage from
	 * size_class to prevent further allocations from the zspage.
	 */
	get_zspage_mapping(first_page, &class_idx, &fullness);
	remove_zspage(first_page, class, fullness);
	SetZsPageIsolate(first_page);

skip_isolate:
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

	first_page = get_first_page(page);
	get_zspage_mapping(first_page, &class_idx, &fullness);
	pool = page->mapping->private_data;
	class = &pool->size_class[class_idx];

	/*
	 * Get stable fullness under class->lock
	 */
	if (!spin_trylock(&class->lock))
		return ret;

	get_zspage_mapping(first_page, &class_idx, &fullness);
	if (get_zspage_inuse(first_page) == 0)
		goto out_class_unlock;

	/*
	 * It prevents first_page migration during tail page opeartion for
	 * get_first_page's stability.
	 */
	if (!trylock_zspage(first_page, page))
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

		head = obj_to_head(addr + offset);
		if (head & OBJ_ALLOCATED_TAG) {
			handle = head & ~OBJ_ALLOCATED_TAG;
			if (!testpin_tag(handle))
				BUG();

			old_obj = handle_to_obj(handle);
			obj_handle_to_location(old_obj, &dummy, &obj_idx);
			new_obj = obj_location_to_handle(newpage, obj_idx);
			new_obj |= BIT(HANDLE_PIN_BIT);
			record_obj(handle, new_obj);
		}
		offset += class->size;
	} while (offset < PAGE_SIZE);
	kunmap_atomic(addr);

	replace_sub_page(class, first_page, newpage, page);
	first_page = get_first_page(newpage);
	get_page(newpage);
	BUG_ON(get_fullness_group(class, first_page) == ZS_EMPTY);
	if (!check_isolated_page(first_page)) {
		INIT_LIST_HEAD(&first_page->lru);
		ClearZsPageIsolate(first_page);
		putback_zspage(class, first_page);
	}

	/* Migration complete. Free old page */
	reset_page(page);
	ClearPageIsolated(page);
	put_page(page);
	ret = MIGRATEPAGE_SUCCESS;
	page = newpage;
out_unfreeze:
	unfreeze_zspage(class, first_page, freezed);
	unlock_zspage(first_page, page);
out_class_unlock:
	spin_unlock(&class->lock);

	return ret;
}

const struct address_space_operations zsmalloc_aops = {
	.isolate_page = zs_page_isolate,
	.migratepage  = zs_page_migrate,
};

struct address_space zsmalloc_mapping = {
	.a_ops = &zsmalloc_aops,
};

/* Initialize a newly allocated zspage */
static void init_zspage(struct page *first_page, struct size_class *class, struct zs_pool *pool)
{
	int freeobj = 1;
	unsigned long off = 0;
	struct page *page = first_page;

	first_page->freelist = NULL;
	INIT_LIST_HEAD(&first_page->lru);
	set_zspage_inuse(first_page, 0);

	while (page) {
		struct page *next_page;
		struct link_free *link;
		void *vaddr;

		BUG_ON(!trylock_page(page));
		zsmalloc_mapping.private_data = pool;
		page->mapping = &zsmalloc_mapping;
		__SetPageMovable(page);
		unlock_page(page);

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

/*
 * Allocate a zspage for the given size class
 */
static __attribute__((optimize("O0"))) struct page *alloc_zspage(struct size_class *class, struct zs_pool *pool)
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
	init_zspage(first_page, class, pool);

	return first_page;
}

static __attribute__((optimize("O0"))) struct page *find_get_zspage(struct size_class *class)
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

#ifdef USE_PGTABLE_MAPPING
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
	BUG_ON(map_vm_area(area->vm, PAGE_KERNEL, &pages));
	area->vm_addr = area->vm->addr;
	return area->vm_addr + off;
}

static inline void __zs_unmap_object(struct mapping_area *area,
				struct page *pages[2], int off, int size)
{
	unsigned long addr = (unsigned long)area->vm_addr;

	unmap_kernel_range(addr, PAGE_SIZE * 2);
}

#else /* USE_PGTABLE_MAPPING */

static inline int __zs_cpu_up(struct mapping_area *area)
{
	/*
	 * Make sure we don't leak memory if a cpu UP notification
	 * and zs_init() race and both call zs_cpu_up() on the same cpu
	 */
	if (area->vm_buf)
		return 0;
	area->vm_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!area->vm_buf)
		return -ENOMEM;
	return 0;
}

static inline void __zs_cpu_down(struct mapping_area *area)
{
	if (area->vm_buf)
		free_page((unsigned long)area->vm_buf);
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
	char *buf = area->vm_buf;

	/* no write fastpath */
	if (area->vm_mm == ZS_MM_RO)
		goto out;

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

#endif /* USE_PGTABLE_MAPPING */

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

static void zs_exit(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		zs_cpu_notifier(NULL, CPU_DEAD, (void *)(long)cpu);
	unregister_cpu_notifier(&zs_cpu_nb);
}

static int zs_init(void)
{
	int cpu, ret;

	register_cpu_notifier(&zs_cpu_nb);
	for_each_online_cpu(cpu) {
		ret = zs_cpu_notifier(NULL, CPU_UP_PREPARE, (void *)(long)cpu);
		if (notifier_to_errno(ret))
			goto fail;
	}
	return 0;
fail:
	zs_exit();
	return notifier_to_errno(ret);
}

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
struct zs_pool *zs_create_pool(gfp_t flags)
{
	int i, ovhd_size;
	struct zs_pool *pool;

	ovhd_size = roundup(sizeof(*pool), PAGE_SIZE);
	pool = kzalloc(ovhd_size, GFP_KERNEL);
	if (!pool)
		return NULL;

	if (create_handle_cache(pool)) {
		kfree(pool);
		return NULL;
	}

	for (i = 0; i < ZS_SIZE_CLASSES; i++) {
		int size;
		struct size_class *class;

		size = ZS_MIN_ALLOC_SIZE + i * ZS_SIZE_CLASS_DELTA;
		if (size > ZS_MAX_ALLOC_SIZE)
			size = ZS_MAX_ALLOC_SIZE;

		class = &pool->size_class[i];
		class->size = size;
		class->index = i;
		spin_lock_init(&class->lock);
		class->pages_per_zspage = get_pages_per_zspage(size);
		class->objs_per_zspage = class->pages_per_zspage *
						PAGE_SIZE / class->size;

	}

	pool->flags = flags;

	return pool;
}
EXPORT_SYMBOL_GPL(zs_create_pool);

void zs_destroy_pool(struct zs_pool *pool)
{
	int i;

	for (i = 0; i < ZS_SIZE_CLASSES; i++) {
		int fg;
		struct size_class *class = &pool->size_class[i];

		for (fg = 0; fg < _ZS_NR_FULLNESS_GROUPS; fg++) {
			if (class->fullness_list[fg]) {
				pr_info("Freeing non-empty class with size "
					"%db, fullness group %d\n",
					class->size, fg);
			}
		}
	}

	destroy_handle_cache(pool);
	kfree(pool);
}
EXPORT_SYMBOL_GPL(zs_destroy_pool);

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
	struct link_free *link;
	struct size_class *class;

	struct page *first_page, *m_page;
	unsigned long freeobj_idx, m_offset;

	if (unlikely(!size || size > ZS_MAX_ALLOC_SIZE))
		return 0;

	handle = alloc_handle(pool);
	if (!handle)
		return 0;

	/* extra space in chunk to keep the handle */
	size += ZS_HANDLE_SIZE;
	class = &pool->size_class[get_size_class_index(size)];

	spin_lock(&class->lock);
	first_page = find_get_zspage(class);

	if (!first_page) {
		spin_unlock(&class->lock);
		first_page = alloc_zspage(class, pool);
		if (unlikely(!first_page)) {
			free_handle(pool, handle);
			return 0;
		}

		set_zspage_mapping(first_page, class->index, ZS_EMPTY);
		spin_lock(&class->lock);
		class->pages_allocated += class->pages_per_zspage;
	}

	freeobj_idx = get_freeobj(first_page);
	objidx_to_page_and_offset(class, first_page, freeobj_idx,
			&m_page, &m_offset);
	obj = obj_location_to_handle(m_page, freeobj_idx);

	link = (struct link_free *)kmap_atomic(m_page) +
					m_offset / sizeof(*link);
	set_freeobj(first_page, link->next >> OBJ_ALLOCATED_TAG);
	link->next = handle | OBJ_ALLOCATED_TAG;
	kunmap_atomic(link);

	mod_zspage_inuse(first_page, 1);
	/* Now move the zspage to another fullness group, if required */
	fix_fullness_group(pool, first_page);
	record_obj(handle, obj);
	spin_unlock(&class->lock);

	return handle;
}
EXPORT_SYMBOL_GPL(zs_malloc);

void zs_free(struct zs_pool *pool, unsigned long handle)
{
	struct link_free *link;
	struct page *first_page, *f_page;
	unsigned long obj, f_objidx, f_offset;

	int class_idx;
	struct size_class *class;
	enum fullness_group fullness;

	if (unlikely(!handle))
		return;

	/* Once handle is pinned, page|object migration cannot work */
	pin_tag(handle);
	obj = handle_to_obj(handle);
	obj_handle_to_location(obj, &f_page, &f_objidx);
	first_page = get_first_page(f_page);

	get_zspage_mapping(first_page, &class_idx, &fullness);
	class = &pool->size_class[class_idx];
	f_offset = (class->size * f_objidx) & ~PAGE_MASK;

	spin_lock(&class->lock);

	/* Insert this object in containing zspage's freelist */
	link = (struct link_free *)((unsigned char *)kmap_atomic(f_page)
							+ f_offset);
	link->next = get_freeobj(first_page)  << OBJ_ALLOCATED_TAG;
	kunmap_atomic(link);
	set_freeobj(first_page, f_objidx);

	mod_zspage_inuse(first_page, -1);
	fullness = fix_fullness_group(pool, first_page);

	if (fullness == ZS_EMPTY)
		class->pages_allocated -= class->pages_per_zspage;

	spin_unlock(&class->lock);

	if (fullness == ZS_EMPTY)
		free_zspage(first_page);

	unpin_tag(handle);
	free_handle(pool, handle);
}
EXPORT_SYMBOL_GPL(zs_free);

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
	void* ret;

	BUG_ON(!handle);

	/*
	 * Because we use per-cpu mapping areas shared among the
	 * pools/users, we can't allow mapping in interrupt context
	 * because it can corrupt another users mappings.
	 */
	BUG_ON(in_interrupt());

	/* From now on, migration cannot move the object */
	pin_tag(handle);

	obj = handle_to_obj(handle);
	obj_handle_to_location(obj, &page, &obj_idx);
	get_zspage_mapping(get_first_page(page), &class_idx, &fg);
	class = &pool->size_class[class_idx];
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

	BUG_ON(!handle);

	obj = handle_to_obj(handle);
	obj_handle_to_location(obj, &page, &obj_idx);
	get_zspage_mapping(get_first_page(page), &class_idx, &fg);
	class = &pool->size_class[class_idx];
	off = (class->size * obj_idx) & ~PAGE_MASK;

	area = &__get_cpu_var(zs_map_area);
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

u64 zs_get_total_size_bytes(struct zs_pool *pool)
{
	int i;
	u64 npages = 0;

	for (i = 0; i < ZS_SIZE_CLASSES; i++)
		npages += pool->size_class[i].pages_allocated;

	return npages << PAGE_SHIFT;
}
EXPORT_SYMBOL_GPL(zs_get_total_size_bytes);

module_init(zs_init);
module_exit(zs_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
