#ifndef __ZSTD_H
#define __ZSTD_H

#include <linux/types.h>

struct zstd_frame_param {
	unsigned long long frame_content_size;
	unsigned int window_size;
	unsigned int dict_id;
	unsigned int checksum_flag;
};

#define MAX_LL 35
#define MAX_ML  52
#define MAX_OFF 28
#define MAX_SEQ MAX_LL

#define LL_FSELOG 9
#define OFF_FSELOG 8
#define ML_FSELOG 9
#define HUF_LOG 12
#define FSE_DTABLE_SIZE_U32(log) (1 + (1 << log))

/* number of repcodes */
#define ZSTD_REP_NUM      3
/* number of repcodes to check by the optimal parser */
#define ZSTD_REP_CHECK    (ZSTD_REP_NUM)
#define ZSTD_REP_MOVE     (ZSTD_REP_NUM-1)
#define ZSTD_REP_MOVE_OPT (ZSTD_REP_NUM)
static const unsigned int rep_start_value[ZSTD_REP_NUM] = { 1, 4, 8 };

#define WILDCOPY_OVERLENGTH 8
#define ZSTD_BLOCKSIZE_ABSOLUTEMAX (128 * 1024)
#define ZSTD_FRAMEHEADERSIZE_MAX 18

#define ZSTD_BLOCK_HEADER_SIZE 3

enum block_type { bt_raw, bt_rle, bt_compressed, bt_reserved };
enum zstd_stage {
	ZSTDds_getFrameHeaderSize,
	ZSTDds_decodeFrameHeader,
	ZSTDds_decodeBlockHeader,
	ZSTDds_decompressBlock,
	ZSTDds_decompressLastBlock,
	ZSTDds_checkChecksum,
	ZSTDds_decodeSkippableHeader,
	ZSTDds_skipFrame
};

enum symbol_encoding_type {
	set_basic,
	set_rle,
	set_compressed,
	set_repeat
};

struct xxh64_state {
	unsigned long long total_len;
	unsigned long long v1;
	unsigned long long v2;
	unsigned long long v3;
	unsigned long long v4;
	unsigned long long mem64[4];   /* buffer defined as U64 for alignment */
	unsigned memsize;
	unsigned reserved[2];
};

struct zstd_decompress_context {
	unsigned int *llt_ptr;
	unsigned int *mlt_ptr;
	unsigned int *oft_ptr;
	unsigned int *huf_ptr;

	unsigned int ll_table[FSE_DTABLE_SIZE_U32(LL_FSELOG)];
	unsigned int of_table[FSE_DTABLE_SIZE_U32(OFF_FSELOG)];
	unsigned int ml_table[FSE_DTABLE_SIZE_U32(ML_FSELOG)];
	unsigned int huf_table[FSE_DTABLE_SIZE_U32(HUF_LOG)];

	void *prev_dst_end;
	void *base;
	void *vbase;
	void *dict_end;
	size_t expected;
	u32 rep[ZSTD_REP_NUM];
	struct zstd_frame_param param;
	enum block_type type;
	enum zstd_stage stage;
	u32 lit_entropy;
	u32 fse_entropy;
	struct xxh64_state xxh_state;
	ssize_t header_size;
	u32 dict_id;
	u8 *lit_ptr;
	ssize_t lit_buf_size;
	ssize_t lit_size;
	ssize_t rle_size;
	u8 lit_buf[ZSTD_BLOCKSIZE_ABSOLUTEMAX + WILDCOPY_OVERLENGTH];
	u8 header_buf[ZSTD_FRAMEHEADERSIZE_MAX];
};

struct block_properties {
	enum block_type type;
	unsigned int last_block;
	unsigned int origin_size;
};

int zstd_get_frame_param(void* src_buf, ssize_t size,
			 struct zstd_frame_param* param);

#define malloc(size) kmalloc(size, GFP_KERNEL)
#define calloc(size) kmalloc(size, GFP_KERNEL | __GFP_ZERO)
#define free(p) kfree(p)
#endif
