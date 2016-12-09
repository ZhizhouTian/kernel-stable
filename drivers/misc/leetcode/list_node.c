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

/* 21. Merge Two Sorted Lists */
void merge_list_node(struct list_head* new, struct list_head* l1,
			struct list_head* l2)
{
	struct list_node *pos1, *pos2, *n1, *n2;

	pos1 = list_first_entry(l1, struct list_node, list);
	pos2 = list_first_entry(l2, struct list_node, list);
	n1 = list_next_entry(pos1, list);
	n2 = list_next_entry(pos2, list);

	while (&pos1->list != l1 && &pos2->list != l2) {
		if (pos1->val < pos2->val) {
			list_move_tail(&pos1->list, new);
			pos1 = n1;
			n1 = list_next_entry(n1, list);
		} else {
			list_move_tail(&pos2->list, new);
			pos2 = n2;
			n2 = list_next_entry(n2, list);
		}
	}

	while (&pos1->list != l1) {
		list_move_tail(&pos1->list, new);
		pos1 = n1;
		n1 = list_next_entry(n1, list);
	}

	while (&pos2->list != l2) {
		list_move_tail(&pos2->list, new);
		pos2 = n2;
		n2 = list_next_entry(n2, list);
	}
}

/* 160-IntersectionofTwoLinkedLists.c */
struct list_head* get_intersection_node(struct list_head* heada, struct list_head* headb)
{
	struct list_node *pos1, *pos2;

	pos1 = list_last_entry(heada, struct list_node, list);
	pos2 = list_last_entry(headb, struct list_node, list);

	while ((&pos1->list != heada) && (&pos2->list != headb) && (pos1->val == pos2->val)) {
		pos1 = list_prev_entry(pos1, list);
		pos2 = list_prev_entry(pos2, list);
	}

	return &pos1->list;
}

/* 083 Remove Duplicates from Sorted List */
void delete_duplicates(struct list_head* head)
{
	struct list_node* pos, *n;

	/*
	for (pos = list_first_entry(head, struct list_ndoe, list),
			n = list_next_entry(pos, list);
		&pos->list != head;
		pos = n, n = list_next_entry(n, list))*/

	for (pos = list_first_entry(head, typeof(*pos), list),
		n = list_next_entry(pos, list);
		&pos->list != head;
		pos = n, n = list_next_entry(n, list)) {
		if (pos->val == n->val) {
			list_del(&pos->list);
			kfree(pos);
		}
	}
}

void test_delete_duplicates(struct seq_file* m)
{
	int values[] = {1, 1, 2, 3, 4, 5};
	LIST_HEAD(head);
	alloc_list_nodes(&head, values, sizeof(values)/sizeof(*values));
	show_list_nodes(&head, m);
	delete_duplicates(&head);
	show_list_nodes(&head, m);
}

/* 24. Swap Nodes in Pairs */
void swap_pairs(struct list_head* head)
{
	struct list_node* prev, *pos, *n;
	unsigned int length = 0;
	int tmp;

	for(pos=list_first_entry(head, typeof(*pos), list),
		n=list_next_entry(pos, list);
		&pos->list != head;
		prev=pos, pos=n, n=list_next_entry(n, list)) {
		if (length++ % 2 != 1)
			continue;
		tmp = prev->val;
		prev->val = pos->val;
		pos->val = tmp;
	}
}

void test_swap_pairs(struct seq_file* m)
{
	int values[] = {1, 2, 3, 4, 5, 6, 7};
	struct list_head* head = kmalloc(sizeof(struct list_head), GFP_KERNEL);
	INIT_LIST_HEAD(head);

	alloc_list_nodes(head, values, sizeof(values)/sizeof(*values));
	show_list_nodes(head, m);
	swap_pairs(head);
	show_list_nodes(head, m);
	kfree(head);
}

/* 445. Add Two Numbers II */
void add_two_numbers(struct list_head* l1, struct list_head* l2,
		struct list_head* ret)
{
	struct list_node* pos1, *n1, *pos2, *n2, *temp;
	int carry = 0;

	pos1 = list_last_entry(l1, typeof(*pos1), list);
	pos2 = list_last_entry(l2, typeof(*pos2), list);
	n1 = list_prev_entry(pos1, list);
	n2 = list_prev_entry(pos2, list);

	while (&pos1->list != l1 || &pos2->list != l2 || carry != 0) {
		int num1=0, num2=0;

		temp = kmalloc(sizeof(struct list_node), GFP_KERNEL);
		if (&pos1->list != l1) {
			num1 = pos1->val;
			pos1 = n1;
			n1 = list_prev_entry(n1, list);
		}
		if (&pos2->list != l2) {
			num2 = pos2->val;
			pos2 = n2;
			n2 = list_prev_entry(n2, list);
		}
		temp->val = (num1 + num2 + carry) % 10;
		carry = !!((num1 + num2 + carry) / 10);

		list_add(&temp->list, ret);
	}
}

void test_add_two_numbers(struct seq_file* m)
{
	int nums1[] = {7, 2, 4, 3};
	int nums2[] = {5, 6, 4};

	LIST_HEAD(l1);
	LIST_HEAD(l2);
	LIST_HEAD(ret);

	alloc_list_nodes(&l1, nums1, sizeof(nums1)/sizeof(*nums1));
	alloc_list_nodes(&l2, nums2, sizeof(nums2)/sizeof(*nums2));
	show_list_nodes(&l1, m);
	show_list_nodes(&l2, m);
	add_two_numbers(&l1, &l2, &ret);
	show_list_nodes(&ret, m);
}

/* 328. Odd Even Linked List */
void odd_even_list(struct list_head* head)
{
	struct list_head* pos, *n;
	unsigned int index = 0;

	LIST_HEAD(odd);
	list_for_each_safe(pos, n, head) {
		if (index % 2 == 0) {
			list_move(pos, &odd);
		}
		index++;
	}
	list_for_each_safe(pos, n, &odd)
		list_move(pos, head);
}

void test_odd_even_list(struct seq_file* m)
{
	LIST_HEAD(head);
	int values[] = {1,2,3,4,5,6,7};
	alloc_list_nodes(&head, values, sizeof(values)/sizeof(*values));
	show_list_nodes(&head, m);
	odd_even_list(&head);
	show_list_nodes(&head, m);
}
