#ifndef __ZSTD_H
#define __ZSTD_H

struct zstd_frame_param {
	unsigned long long frame_content_size;
	unsigned int window_size;
	unsigned int dict_id;
	unsigned int checksum_flag;
};

#define LLFSELOG 9
#define OffFSELog 8
#define MLFSELog 9
#define HufLog 12
#define FSE_DTABLE_SIZE_U32(log) (1+(1<<log))

#define ZSTD_REP_NUM      3                 /* number of repcodes */
#define ZSTD_REP_CHECK    (ZSTD_REP_NUM)    /* number of repcodes to check by the optimal parser */
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

enum symbol_encoding_type { set_basic, set_rle, set_compressed, set_repeat };

struct xxh64_state {
	unsigned long long total_len;
	unsigned long long v1;
	unsigned long long v2;
	unsigned long long v3;
	unsigned long long v4;
	unsigned long long mem64[4];   /* buffer defined as U64 for alignment */
	unsigned memsize;
	unsigned reserved[2];          /* never read nor write, will be removed in a future version */
};

struct zstd_decompress_context {
	const unsigned int* llt_ptr;
	const unsigned int* mlt_ptr;
	const unsigned int* oft_ptr;
	const unsigned int* huf_ptr;

	unsigned int ll_table[FSE_DTABLE_SIZE_U32(LLFSELOG)];
	unsigned int of_table[FSE_DTABLE_SIZE_U32(OffFSELog)];
	unsigned int ml_table[FSE_DTABLE_SIZE_U32(MLFSELog)];
	unsigned int huf_table[FSE_DTABLE_SIZE_U32(HufLog)];

	const void* prev_dst_end;
	const void* base;
	const void* vbase;
	const void* dict_end;
	unsigned int expected;
	unsigned int rep[ZSTD_REP_NUM];
	struct zstd_frame_param param;
	enum block_type type;
	enum zstd_stage stage;
	unsigned int lit_entropy;
	unsigned int fse_entropy;
	struct xxh64_state xxh_state;
	unsigned int header_size;
	unsigned dict_id;
	const char* lit_ptr;
	unsigned int lit_buf_size;
	unsigned int lit_size;
	unsigned int rle_size;
	char* lit_buf;
	char header_buf[ZSTD_FRAMEHEADERSIZE_MAX];
};

struct block_properties {
	enum block_type type;
	unsigned int last_block;
	unsigned int origin_size;
};

int zstd_get_frame_param(const void* src_buf, unsigned int size,
			 struct zstd_frame_param* param);

#define malloc(size) kmalloc(size, GFP_KERNEL)
#endif
