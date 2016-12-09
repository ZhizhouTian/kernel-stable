#include "utils.h"

unsigned long readlong(const unsigned char* mem)
{
	if (sizeof(unsigned long) == 4)
		return read32(mem);
	else
		return read64(mem);
}

void test_read32(struct seq_file* m)
{
	char x[] = {1, 0, 0, 0};
	int v = read32(x);
	seq_printf(m, "%d.\n", v);
}

int is_little_endian(void)
{
	const union {int i; char x[4];} one = {1};
	return one.x[0];
}

void test_is_little_endian(struct seq_file* m)
{
	seq_printf(m, "is little endian? %s.\n",
			is_little_endian()?"yes":"no");
}
