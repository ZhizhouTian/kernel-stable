#include <linux/init.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/cdev.h>

struct scull_dev {
	//struct scull_qset *data;
	int quantum;
	int qset;
	unsigned long size;
	unsigned int access_key;
	struct semaphore sem;
	struct cdev cdev;
};

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
	pr_info("scull linux\n");
	return 0;
}

static void __exit scull_exit(void)
{
	pr_info("goodbye\n");
}

module_init(scull_init);
module_exit(scull_exit);
MODULE_LICENSE("GPL");
