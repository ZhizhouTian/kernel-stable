#include "utils.h"

ssize_t readlong(const u8 *mem)
{
#if BITS_PER_LONG == 32
	return read32(mem);
#else
	return read64(mem);
#endif
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

void zstd_wildcopy(void *dst, void *src, size_t length)
{
	u8 *ip = src;
	u8 *op = dst;
	u8* oend = op + length;

	do {
		memcpy (op, ip, 8);
		ip += 8;
		op += 8;
	} while (op < oend);
}

