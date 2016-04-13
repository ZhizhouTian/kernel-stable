#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

unsigned long pagemem;
unsigned char *kmallocmem;
unsigned char *vmallocmem;

static int __init mem_module_init(void)
{
	pagemem = __get_free_pages(GFP_KERNEL, 0);
	if (pagemem == 0) {
		pr_err("<1> __get_free_pages failed.\n");
		return -ENOMEM;
	}
	pr_info("<1>pagemem addr=%lx.\n", pagemem);

	kmallocmem = (unsigned char*)kmalloc(sizeof(char) * 1024, GFP_KERNEL);
	if (kmallocmem == NULL) {
		pr_err("<1> kmalloc failed.\n");
		return -ENOMEM;
	}
	pr_info("<1>kmallocmem addr=%p.\n", kmallocmem);

	vmallocmem = (unsigned char*)vmalloc(sizeof(char) * 1024);
	if (vmallocmem == NULL) {
		pr_err("<1> vmalloc failed.\n");
		return -ENOMEM;
	}
	pr_info("<1>vmallocmem addr=%p.\n", vmallocmem);
	return 0;
}

static void __exit mem_module_exit(void)
{
	free_page(pagemem);
	kfree(kmallocmem);
	vfree(vmallocmem);
}

module_init(mem_module_init);
module_exit(mem_module_exit);
MODULE_LICENSE("GPL v2");
