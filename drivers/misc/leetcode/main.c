#include "list_node.h"

#define PROC_NAME "main_proc"

static int main_proc_show(struct seq_file *m, void *v)
{
	test_odd_even_list(m);
	return 0;
}

static int main_proc_open(struct inode *inode, struct  file *file) {
	return single_open(file, main_proc_show, NULL);
}

static const struct file_operations main_proc_fops = {
	.owner = THIS_MODULE,
	.open = main_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init main_proc_init(void) {
	proc_create(PROC_NAME, 0, NULL, &main_proc_fops);
	return 0;
}

static void __exit main_proc_exit(void) {
	remove_proc_entry(PROC_NAME, NULL);
}

MODULE_LICENSE("GPL");
module_init(main_proc_init);
module_exit(main_proc_exit);
