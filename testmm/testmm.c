#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

unsigned long pagemem;
unsigned char *kmallocmem;
unsigned char *vmallocmem;

int __init mem_module_init(void)
{
	//最好每次内存申请都检查申请是否成功
	//下面这段仅仅作为演示的代码没有检查
	pagemem = __get_free_pages(GFP_KERNEL, 0);
	pr_info("<1>pagemem addr=%lx.\n", pagemem);

	kmallocmem = (unsigned char*)kmalloc(100, 0);
	pr_info("<1>kmallocmem addr=%p.\n", kmallocmem);

	vmallocmem = (unsigned char*)vmalloc(1000000);
	pr_info("<1>vmallocmem addr=%p.\n", vmallocmem);

	return 0;
}

void __exit mem_module_exit(void)
{
	free_page(pagemem);
	kfree(kmallocmem);
	vfree(vmallocmem);
}

module_init(mem_module_init);
module_exit(mem_module_exit);
MODULE_LICENSE("GPL");
