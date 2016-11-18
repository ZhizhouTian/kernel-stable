#include "list_node.h"

void alloc_list_nodes(struct list_head* head, int *values, int size)
{
	int i;

	for (i=0; i<size; i++) {
		struct list_node* tmp = kmalloc(sizeof(struct list_node), GFP_KERNEL);
		tmp->val = values[i];
		list_add_tail(&tmp->list, head);
	}
}

void free_list_nodes(struct list_head* nodes)
{
	struct list_node* np, *tp;

	list_for_each_entry_safe(np, tp, nodes, list) {
		list_del(&np->list);
		kfree(np);
	}
}

void show_list_nodes(struct list_head* nodes, struct seq_file* m)
{
	struct list_node* np, *tp;

	list_for_each_entry_safe(np, tp, nodes, list)
		seq_printf(m, "%d ", np->val);
	seq_printf(m, "\n");
}

void rm_list_nodes(struct list_head* nodes, int val)
{
	struct list_node* np, *tp;

	list_for_each_entry_safe(np, tp, nodes, list) {
		if (np->val == val) {
			list_del(&np->list);
			kfree(np);
		}
	}
}

static int list_node_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct list_node *node_a, *node_b;

	node_a = list_entry(a, struct list_node, list);
	node_b = list_entry(b, struct list_node, list);

	/* long to int */
	if (node_a->val < node_b->val)
		return -1;

	else if (node_a->val > node_b->val)
		return 1;

	return 0;
}


void sort_list_nodes(struct list_head* head)
{
	list_sort(NULL, head, list_node_cmp);
}

/* 24. Swap Nodes in Pairs */
void swap_list_nodes_in_pairs(struct list_head* head)
{
	struct list_head* pos = NULL;
	struct list_head* n0;
	struct list_head* n1;
	struct list_head* n2;
	struct list_head* n3;
	int i = 0;

	list_for_each(pos, head) {
		if ((i % 2) == 0) {
			n0 = pos->prev;
			n1 = pos;
		} else if ((i % 2) == 1) {
			n2 = pos;
			n3 = pos->next;

			n0->next = n2;

			n1->prev = n2;
			n1->next = n3;

			n2->prev = n0;
			n2->next = n1;

			n3->prev = n1;

			pos = n1;
		}

		i++;
	}
}

/* 21. Merge Two Sorted Lists, 还未验证 */
void merge_list_node(struct list_head* new, struct list_head* l1, struct list_head* l2)
{
	struct list_node* node1, *next1;
	struct list_node* node2, *next2;
	struct list_head* pos, *n;

	node1 = list_first_entry(l1, typeof(*node1), list);
	next1 = list_next_entry(node1, list);

	node2 = list_first_entry(l2, typeof(*node2), list);
	next2 = list_next_entry(node2, list);

	while (&node1->list != l1 && &node2->list != l2) {
		if (node1->val < node2->val) {
			list_move_tail(&node1->list, new);
			node1 = next1;
			next1 = list_next_entry(next1, list);
		} else {
			list_move_tail(&node2->list, new);
			node2 = next2;
			next2 = list_next_entry(next2, list);
		}
	}

	list_for_each_safe(pos, n, l1) {
		list_move_tail(pos, new);
	}

	list_for_each_safe(pos, n, l2) {
		list_move_tail(pos, new);
	}
}
