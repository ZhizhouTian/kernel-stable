#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/semaphore.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/wait.h>
#include <linux/highmem.h>

#include <asm/uaccess.h>

#define DEVICE_NAME "scullpipe"
#define CLASS_NAME "scullpipe_class"

static int nr_major;
static int nr_minor;

//#define USE_PAGE


struct scullpipe_dev {
#ifdef USE_PAGE
	struct page *ringpage;
#else
	char *ringbuf;
#endif
	unsigned int cap;
	unsigned int ridx;
	unsigned int widx;
	wait_queue_head_t rwq;
	wait_queue_head_t wwq;
	struct semaphore sem;
	struct cdev cdev;
};

#ifndef USE_PAGE
static int readspdpage(struct scullpipe_dev *spd, char __user *buf,
		unsigned int count)
{
	if (copy_to_user(buf, spd->ringbuf+spd->ridx, count))
		return -EFAULT;
	return 0;
}
#else
static int readspdpage(struct scullpipe_dev *spd, char __user *buf,
		unsigned int count)
{
	char *addr = NULL;

	addr = kmap_atomic(spd->ringpage);
	if (copy_to_user(buf, addr+spd->ridx, count))
		return -EFAULT;
	kunmap_atomic(addr);

	return 0;
}
#endif

static __attribute__((optimize("O0")))  ssize_t scullpipe_read(struct file *filp,
		char __user *buf, size_t count, loff_t *offset)
{
	int retval = 0;
	struct scullpipe_dev *spd = filp->private_data;
	int cnt = 0;

	if (down_interruptible(&spd->sem))
		return -ERESTARTSYS;

	while (spd->ridx == spd->widx) {
		up(&spd->sem);

		if (wait_event_interruptible(spd->rwq, spd->ridx != spd->widx))
			return -ERESTARTSYS;

		if (down_interruptible(&spd->sem))
			return -ERESTARTSYS;
	}

	if (spd->ridx > spd->widx) {
		cnt = spd->cap - spd->ridx;
	} else {
		cnt = spd->widx - spd->ridx;
	}

	if (count > cnt)
		count = cnt;

	if (readspdpage(spd, buf, count))
		return -EFAULT;

	*offset += count;
	spd->ridx = (spd->ridx + count) % spd->cap;
	retval = count;

	up(&spd->sem);
	return retval;
}

static unsigned int space_free(struct scullpipe_dev *spd)
{
	if (spd->ridx == spd->widx)
		return spd->cap - 1;
	return ((spd->cap - spd->widx + spd->ridx) % spd->cap) - 1;
}

#ifndef USE_PAGE
static int writespdpage(struct scullpipe_dev *spd, const char __user *buf,
		unsigned int count)
{
	if (copy_from_user(spd->ringbuf+spd->widx, buf, count))
		return -EFAULT;
	return 0;
}
#else
static int writespdpage(struct scullpipe_dev *spd, const char __user *buf,
		unsigned int count)
{
	char *addr = NULL;

	addr = kmap_atomic(spd->ringpage);
	if (copy_from_user(addr+spd->widx, buf, count))
		return -EFAULT;
	kunmap_atomic(addr);

	return 0;
}
#endif

static __attribute__((optimize("O0"))) ssize_t scullpipe_write(struct file *filp,
		const char __user *buf, size_t count, loff_t *offset)
{
	int retval = -ENOMEM;
	struct scullpipe_dev *spd = filp->private_data;
	int cnt = 0;

	if (down_interruptible(&spd->sem))
		return -ERESTARTSYS;

	while (space_free(spd) == 0) {
		up(&spd->sem);

		if (wait_event_interruptible(spd->wwq, space_free(spd) != 0))
			return -ERESTARTSYS;

		if(down_interruptible(&spd->sem))
			return -ERESTARTSYS;
	}

	if (spd->widx >= spd->ridx) {
		if (spd->ridx == 0) {
			cnt = spd->cap - spd->widx - 1;
		} else {
			cnt = spd->cap - spd->widx;
		}
	} else {
		cnt = spd->ridx - spd->widx - 1;
	}

	if (count > cnt)
		count = cnt;

	if (writespdpage(spd, buf, count))
		return -EFAULT;

	*offset += count;
	spd->widx = (spd->widx + count) % spd->cap;
	retval = count;

	up(&spd->sem);
	return retval;
}

static int scullpipe_open(struct inode *inode, struct file *filp)
{
	struct scullpipe_dev *spd = NULL;

	spd = container_of(inode->i_cdev, struct scullpipe_dev, cdev);
	filp->private_data = spd;
	return 0;
}

static int scullpipe_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static struct file_operations scullpipe_fops = {
	.open = scullpipe_open,
	.read = scullpipe_read,
	.write = scullpipe_write,
	.release = scullpipe_close,
};

static void scullpipe_setup_cdev(struct scullpipe_dev *spd, int index)
{
	int err = 0;
	int devno = 0;

	if (nr_major) {
		devno = MKDEV(nr_major, nr_minor + index);
		err = register_chrdev_region(devno, 1, DEVICE_NAME);
	} else {
		err = alloc_chrdev_region(&devno, 0, 1, DEVICE_NAME);
		nr_major = MAJOR(devno);
	}

	if (err < 0) {
		pr_info("register-chrdev failed: %d\n", err);
	}

	cdev_init(&spd->cdev, &scullpipe_fops);
	spd->cdev.owner = THIS_MODULE;
	err = cdev_add(&spd->cdev, devno, 1);
	if (err) {
		pr_info("fail to add cdev %s.\n", DEVICE_NAME);
	}
}

static void scullpipe_setup(struct scullpipe_dev *spd)
{
#ifndef USE_PAGE
	spd->ringbuf = kmalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
#else
	spd->ringpage = alloc_page(GFP_KERNEL);
#endif
	spd->cap = PAGE_SIZE; // 可以缩小这个值以便调试
	spd->ridx = 0;
	spd->widx = 0;
	init_waitqueue_head(&spd->rwq);
	init_waitqueue_head(&spd->wwq);
	sema_init(&spd->sem, 1);
	scullpipe_setup_cdev(spd, 0);
}

static void scullpipe_cleanup(struct scullpipe_dev *spd)
{
	if (spd == NULL)
		return;
#ifndef USE_PAGE
	if (spd->ringbuf != NULL)
		kfree(spd->ringbuf);
#else
	if (spd->ringpage != NULL)
		__free_page(spd->ringpage);
#endif
	cdev_del(&spd->cdev);
	unregister_chrdev_region(MKDEV(nr_major, nr_minor), 1);
}

static struct scullpipe_dev *scullpipedev;
static struct class *clz;
static struct device *dev;

static int __init scullpipe_init(void)
{
	scullpipedev = kmalloc(sizeof(struct scullpipe_dev), GFP_KERNEL);
	if (scullpipedev == NULL) {
		pr_info("alloc dev %s fail", DEVICE_NAME);
		return -ENOMEM;
	}

	scullpipe_setup(scullpipedev);

	clz = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(clz)) {
		unregister_chrdev(nr_major, DEVICE_NAME);
		pr_info("registe class failed.\n");
		return PTR_ERR(clz);
	}

	dev = device_create(clz, NULL, MKDEV(nr_major, 0), NULL, DEVICE_NAME);
	if (IS_ERR(dev)) {
		class_destroy(clz);
		unregister_chrdev(nr_major, DEVICE_NAME);
		return PTR_ERR(dev);
	}

	pr_info("Create device : %s success.\n", DEVICE_NAME);
	return 0;
}

static void __exit scullpipe_exit(void)
{
	device_destroy(clz, MKDEV(nr_major, 0));
	class_destroy(clz);
	scullpipe_cleanup(scullpipedev);

	if (scullpipedev != NULL)
		kfree(scullpipedev);
	pr_info("Destory device : %s success.\n", DEVICE_NAME);
}

module_init(scullpipe_init);
module_exit(scullpipe_exit);
MODULE_LICENSE("GPL");
