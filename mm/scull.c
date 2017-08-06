#include <linux/init.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/gfp.h>

struct scull_dev {
	//struct scull_qset *data;
	int quantum;
	int qset;
	unsigned long size;
	unsigned int access_key;
	struct semaphore sem;
	struct cdev cdev;
};

static int scull_major = 0;
static int scull_minor = 0;
static int scull_nr_devs = 1;

static void scull_setup_cdev(struct scull_dev *dev, int index)
{
	int err, devno = MKDEV(scull_major, scull_minor + index);
	cdev_init(&dev->cdev, &scull_fops);
	dev->cdev.owner = THIS_MODULE;
	err = cdev_add(&dev->cdev, devno, 1);
	if (err) {
		pr_info("error %d adding scull %d\n", err, index);
	}
}

static int __init scull_init(void)
{
	int result = 1;
	dev_t dev = 0;

	if (scull_major) {
		dev = MKDEV(scull_major, scull_minor);
		result = register_chrdev_region(dev, scull_nr_devs, "scull");
	} else {
		result = alloc_chrdev_region(&dev, scull_minor, scull_nr_devs, "scull");
		scull_major = MAJOR(dev);
	}

	if (result < 0) {
		pr_info("scull: can not get major :%d\n", scull_major);
		return result;
	}

	scull_devices = kmalloc(scull_nr_devs * sizeof(struct scull_dev), GFP_KERNEL);
	if (!scull_devices) {
		result = -ENOMEM;
	}
	return 0;
}

static void __exit scull_exit(void)
{
	pr_info("goodbye\n");
}

module_init(scull_init);
module_exit(scull_exit);
MODULE_LICENSE("GPL");
