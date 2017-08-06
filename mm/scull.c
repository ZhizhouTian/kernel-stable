#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/semaphore.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/kernel.h>

#include <asm/uaccess.h>

#define DEVICE_NAME "scull"
#define CLASS_NAME "scull_class"

static int nr_major;
static int nr_minor;
int default_nr_quantum = 2;
int default_quantum_size = 4000;

struct scull_qset {
	char **data;
	struct list_head list;
};

struct scull_dev {
	struct list_head head;
	unsigned long total_used;
	int nr_quantum;
	int quantum_size;
	struct semaphore sem;
	struct cdev cdev;
};

static __attribute__((optimize("O0"))) ssize_t scull_read(struct file *filp,
		char __user *buf, size_t count, loff_t *offset)
{
	int i = 0;
	struct scull_dev *sd = filp->private_data;
	int total_qset = 0;
	struct scull_qset *pos = NULL;
	int which_qset_idx = 0;
	struct scull_qset *which_qset = NULL;
	int offset_in_quantum = 0;
	int offset_in_qset = 0;
	int which_quantum = 0;
	int retval = 0;

	if (down_interruptible(&sd->sem))
		return -ERESTARTSYS;

	if (*offset >= sd->total_used) {
		goto end;
	}

	if (*offset + count >= sd->total_used) {
		count = sd->total_used - *offset;
	}

	which_qset_idx = *offset / (sd->nr_quantum * sd->quantum_size);
	offset_in_qset = *offset % (sd->nr_quantum * sd->quantum_size);

	total_qset = 0;
	list_for_each_entry(pos, &sd->head, list) {
		total_qset++;
	}

	if (which_qset_idx >= total_qset) {
		pr_info("read exceed last qset!\n");
		retval = -EINVAL;
		goto end;
	}

	list_for_each_entry(which_qset, &sd->head, list) {
		if (i >= which_qset_idx)
			break;
		i++;
	}

	which_quantum = offset_in_qset / sd->quantum_size;
	offset_in_quantum = offset_in_qset % sd->quantum_size;
	BUG_ON(which_quantum >= sd->nr_quantum);

	if (offset_in_quantum + count > sd->quantum_size)
		count = sd->quantum_size - offset_in_quantum;

	if (copy_to_user(buf, which_qset->data[which_quantum]+offset_in_quantum, count)) {
		retval = -EFAULT;
		goto end;
	}

	*offset += count;
	retval = count;

end:
	up(&sd->sem);
	return retval;
}

static struct scull_qset* scull_qset_malloc(struct scull_dev *sd)
{
	int i = 0;
	struct scull_qset *ret = NULL;
	ret = kmalloc(sizeof(struct scull_qset), GFP_KERNEL);
	if (ret == NULL)
		goto alloc_qset_fail;

	ret->data = kmalloc(sizeof(char*) * sd->nr_quantum, GFP_KERNEL);
	if (ret->data == NULL)
		goto alloc_quantum_fail;

	for (i=0; i<sd->nr_quantum; i++) {
		ret->data[i] = kmalloc(sizeof(char) * sd->quantum_size, GFP_KERNEL);
		if (ret->data[i] == NULL)
			goto alloc_data_fail;
	}

	INIT_LIST_HEAD(&ret->list);
	return ret;

alloc_quantum_fail:
	for (i--; i>=0; i--) {
		kfree(ret->data[i]);
	}
alloc_data_fail:
	kfree(ret->data);
alloc_qset_fail:
	return NULL;
}

static __attribute__((optimize("O0"))) ssize_t scull_write(struct file *filp,
		const char __user *buf, size_t count, loff_t *offset)
{
	int i = 0;
	struct scull_dev *sd = filp->private_data;
	int which_qset_idx = 0;
	int total_qset = 0;
	struct scull_qset *pos = NULL;
	struct scull_qset *which_qset = NULL;
	int offset_in_qset = 0;
	int which_quantum = 0;
	int offset_in_quantum = 0;
	int retval = -ENOMEM;

	if (down_interruptible(&sd->sem))
		return -ERESTARTSYS;

	which_qset_idx = (*offset) / (sd->nr_quantum * sd->quantum_size);
	offset_in_qset = (*offset) % (sd->nr_quantum * sd->quantum_size);

	list_for_each_entry(pos, &sd->head, list) {
		total_qset++;
	}

	if (which_qset_idx > total_qset) {
		pr_info("exceed last qset. will get a hole if do this.\n");
		retval = -EINVAL;
		goto end;
	}

	if (which_qset_idx == total_qset) {
		which_qset = scull_qset_malloc(sd);
		if (which_qset == NULL) {
			goto end;
		}
		list_add_tail(&which_qset->list, &sd->head);
	} else {
		list_for_each_entry(which_qset, &sd->head, list) {
			if (i >= which_qset_idx)
				break;
			i++;
		}
	}

	which_quantum = offset_in_qset / sd->quantum_size;
	offset_in_quantum = offset_in_qset % sd->quantum_size;
	BUG_ON(which_quantum >= sd->nr_quantum);

	if (count > sd->quantum_size - offset_in_quantum)
		count = sd->quantum_size - offset_in_quantum;
	if (copy_from_user(which_qset->data[which_quantum]+offset_in_quantum, buf, count)) {
		retval = -EFAULT;
		goto end;
	}
	*offset += count;

	if (sd->total_used < *offset)
		sd->total_used = *offset;

end:
	up(&sd->sem);
	return count;
}

static __attribute__((optimize("O0"))) void scull_dev_trim(struct scull_dev *sdev)
{
	struct scull_qset *pos = NULL;
	struct scull_qset *n = NULL;
	int i = 0;

	list_for_each_entry_safe(pos, n, &sdev->head, list) {
		if (pos->data != NULL) {
			for (i=0; i<sdev->nr_quantum; i++) {
				kfree(pos->data[i]);
			}
			kfree(pos->data);
		}
		list_del(&pos->list);
		kfree(pos);
	}

	sdev->nr_quantum = default_nr_quantum;
	sdev->quantum_size = default_quantum_size;
	sdev->total_used = 0;
}

static int scull_open(struct inode *inode, struct file *filp)
{
	struct scull_dev *sdev = NULL;

	sdev = container_of(inode->i_cdev, struct scull_dev, cdev);
	filp->private_data = sdev;

	if ((filp->f_flags & O_ACCMODE) == O_WRONLY) {
		scull_dev_trim(sdev);
	}
	return 0;
}

static int scull_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static struct file_operations scull_fops = {
	.open = scull_open,
	.read = scull_read,
	.write = scull_write,
	.release = scull_close,
};

static void scull_setup_cdev(struct scull_dev *sd, int index)
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

	cdev_init(&sd->cdev, &scull_fops);
	sd->cdev.owner = THIS_MODULE;
	err = cdev_add(&sd->cdev, devno, 1);
	if (err) {
		pr_info("fail to add cdev %s.\n", DEVICE_NAME);
	}
}

static void scull_setup(struct scull_dev *sd)
{
	INIT_LIST_HEAD(&sd->head);
	sd->nr_quantum = default_nr_quantum;
	sd->quantum_size = default_quantum_size;
	sd->total_used = 0;
	sema_init(&sd->sem, 1);
	scull_setup_cdev(sd, 0);
}

static void scull_cleanup(struct scull_dev *sd)
{
	if (sd == NULL)
		return;
	scull_dev_trim(sd);
	cdev_del(&sd->cdev);
	unregister_chrdev_region(MKDEV(nr_major, nr_minor), 1);
}

static struct scull_dev *sculldev;
static struct class *clz;
static struct device *dev;

static int __init scull_init(void)
{
	sculldev = kmalloc(sizeof(struct scull_dev), GFP_KERNEL);
	if (sculldev == NULL) {
		pr_info("alloc dev %s fail", DEVICE_NAME);
		return -ENOMEM;
	}

	scull_setup(sculldev);

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

static void __exit scull_exit(void)
{
	device_destroy(clz, MKDEV(nr_major, 0));
	class_destroy(clz);
	scull_cleanup(sculldev);

	if (sculldev != NULL)
		kfree(sculldev);
	pr_info("Destory device : %s success.\n", DEVICE_NAME);
}

module_init(scull_init);
module_exit(scull_exit);
MODULE_LICENSE("GPL");
