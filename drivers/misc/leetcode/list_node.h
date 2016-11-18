#ifndef __LISTNODE_H
#define __LISTNODE_H
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/list.h>
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <asm/uaccess.h>	/* for copy_from_user */
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/list_sort.h>

struct list_node {
	int val;
	struct list_head list;
};

void alloc_list_nodes(struct list_head* head, int *values, int size);
void free_list_nodes(struct list_head* nodes);
void show_list_nodes(struct list_head* nodes, struct seq_file* m);
void sort_list_nodes(struct list_head* head);
void rm_list_nodes(struct list_head* nodes, int val);
void swap_list_nodes_in_pairs(struct list_head* head);

#endif
