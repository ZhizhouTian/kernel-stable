#ifdef STATIC
#define PREBOOT
#endif

#include <linux/zstd.h>

#ifdef PREBOOT
STATIC int __decompress(unsigned char *buf, long in_len,
			      long (*fill)(void*, unsigned long),
			      long (*flush)(void*, unsigned long),
			      unsigned char *output, long out_len,
			      long *posp,
			      void (*error)(char *x)
	)
{
	unsigned long long out_size;
	size_t decompress_size;

	out_size = ZSTD_getDecompressedSize(buf, in_len);
	if (out_size == 0)
		return -1;

	decompress_size = ZSTD_decompress(buf, in_len, output, out_size);
	if (decompress_size != out_size)
		return out_size;

	return 0;
}
#endif
