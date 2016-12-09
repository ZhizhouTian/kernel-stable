#include "utils.h"
#include "zstd.h"

static const unsigned char zstd_fcs_field_sizes[] = {0, 2, 4, 8};
static const unsigned char zstd_dictid_field_sizes[] = {0, 1, 2, 4};

#define ZSTD_MAGICNUMBER 0xFD2FB528
#define ZSTD_FRAME_HEADER_MIN_SIZE 5

#define ZSTD_WINDOWLOG_ABSOLUTEMIN 10

static inline unsigned int
zstd_get_frame_header_size(const unsigned char* src, unsigned int size)
{
	const unsigned char fhd = src[4];
	const unsigned char dict_id_flag = fhd & 3;
	const unsigned char single_segement_flag = (fhd >> 5) & 1;
	const unsigned char fcs_flag = (fhd >> 6) & 3;

	return ZSTD_FRAME_HEADER_MIN_SIZE + !single_segement_flag
		+ zstd_dictid_field_sizes[dict_id_flag]
		+ zstd_fcs_field_sizes[fcs_flag]
		+ (single_segement_flag && !fcs_flag);
}

static inline unsigned int zstd_get_window_size(unsigned char desc)
{
	unsigned int exponent = desc >> 3;
	unsigned int mantissa = desc & 7;

	unsigned int window_base = 1 << (ZSTD_WINDOWLOG_ABSOLUTEMIN + exponent);
	unsigned int window_add = (window_base >> 3) * mantissa;

	return window_base + window_add;
}

static void _zstd_get_frame_param(const unsigned char* src,
			  unsigned int size, struct zstd_frame_param* param)
{
	const unsigned char fhd = src[4];
	const unsigned char dict_id_flag = fhd & 3;
	const unsigned char checksum_flag = (fhd >> 2) & 1;
	const unsigned char single_segement_flag = (fhd >> 5) & 1;
	const unsigned char fcs_flag = (fhd >> 6) & 3;
	unsigned int pos = 5;

	if (!single_segement_flag)
		param->window_size = zstd_get_window_size(src[pos++]);

	if (dict_id_flag == 1) {
		param->dict_id = src[pos];
		pos++;
	} else if (dict_id_flag == 2) {
		param->dict_id = read16(src+pos);
		pos += 2;
	}else if (dict_id_flag == 3) {
		param->dict_id = read32(src+pos);
		pos += 4;
	}

	if (fcs_flag == 0) {
		if (single_segement_flag) {
			param->frame_content_size = src[pos];
			pos++;
		}
	} else if (fcs_flag == 1) {
		param->frame_content_size = read16(src+pos);
		pos += 2;
	} else if (fcs_flag == 2) {
		param->frame_content_size = read32(src+pos);
		pos += 4;
	} else if (fcs_flag == 3) {
		param->frame_content_size = read64(src+pos);
		pos += 8;
	}

	if (single_segement_flag)
		param->window_size = param->frame_content_size;
	param->dict_id = dict_id_flag;
	param->checksum_flag = checksum_flag;
}

int zstd_get_frame_param(const void* src_buf, unsigned int size,
			 struct zstd_frame_param* param)
{
	const char* src = src_buf;
	unsigned int frame_header_size = 0;
	int ret = 0;

	if (size < ZSTD_FRAME_HEADER_MIN_SIZE) {
		ret = -ZSTD_FRAME_HEADER_MIN_SIZE;
		goto error;
	}

	if (read32(src) != ZSTD_MAGICNUMBER) {
		ret = -1;
		goto error;
	}

	frame_header_size = zstd_get_frame_header_size(src, size);
	if (size < frame_header_size) {
		ret = -frame_header_size;
		goto error;
	}

	_zstd_get_frame_param(src, size, param);
error:
	return ret;
}

static void
init_zstd_decompress_context(struct zstd_decompress_context* context,
				  const void* dst)
{
	context->expected = ZSTD_FRAME_HEADER_MIN_SIZE;
	context->stage = ZSTDds_getFrameHeaderSize;
	context->prev_dst_end = dst;
	context->base = dst;
	context->vbase = dst;
	context->dict_end = NULL;
	context->huf_table[0] = HufLog * 0x1000001;
	context->lit_entropy = 0;
	context->fse_entropy = 0;
	context->dict_id = 0;
	memcpy (context->rep, rep_start_value, sizeof(rep_start_value));
	context->llt_ptr = context->ll_table;
	context->mlt_ptr = context->ml_table;
	context->oft_ptr = context->of_table;
	context->huf_ptr = context->huf_table;
}

static unsigned int
zstd_get_block_size(const void* src, unsigned int src_size,
		    struct block_properties* prop)
{
	unsigned int block_header = read24(src);
	unsigned int size = block_header >> 3;
	prop->last_block = block_header & 1;
	prop->type = (enum block_type)((block_header >> 1) & 3);
	prop->origin_size = size;
	if (prop->type == bt_rle)
		return 1;
	if (prop->type == bt_reserved)
		return -1;
	return size;
}

struct algo_time {
	unsigned int tabletime;
	unsigned int decode256time;
};

static struct algo_time algotimes[16][3] =
{
	/* single, double, quad */
	{{0,0}, {1,1}, {2,2}},  /* Q==0 : impossible */
	{{0,0}, {1,1}, {2,2}},  /* Q==1 : impossible */
	{{  38,130}, {1313, 74}, {2151, 38}},   /* Q == 2 : 12-18% */
	{{ 448,128}, {1353, 74}, {2238, 41}},   /* Q == 3 : 18-25% */
	{{ 556,128}, {1353, 74}, {2238, 47}},   /* Q == 4 : 25-32% */
	{{ 714,128}, {1418, 74}, {2436, 53}},   /* Q == 5 : 32-38% */
	{{ 883,128}, {1437, 74}, {2464, 61}},   /* Q == 6 : 38-44% */
	{{ 897,128}, {1515, 75}, {2622, 68}},   /* Q == 7 : 44-50% */
	{{ 926,128}, {1613, 75}, {2730, 75}},   /* Q == 8 : 50-56% */
	{{ 947,128}, {1729, 77}, {3359, 77}},   /* Q == 9 : 56-62% */
	{{1107,128}, {2083, 81}, {4006, 84}},   /* Q ==10 : 62-69% */
	{{1177,128}, {2379, 87}, {4785, 88}},   /* Q ==11 : 69-75% */
	{{1242,128}, {2415, 93}, {5155, 84}},   /* Q ==12 : 75-81% */
	{{1349,128}, {2644,106}, {5260,106}},   /* Q ==13 : 81-87% */
	{{1455,128}, {2422,124}, {4174,124}},   /* Q ==14 : 87-93% */
	{{ 722,128}, {1891,145}, {1936,146}},   /* Q ==15 : 93-99% */
};


unsigned int huf_select_decoder(unsigned int dst_size, unsigned int src_size)
{
	unsigned int q = (unsigned int) (src_size * 16 / dst_size);
	unsigned int d256 = (unsigned int) (dst_size >> 8);
	unsigned int dtime0 = algotimes[q][0].tabletime +
			      (algotimes[q][0].decode256time * d256);
	unsigned int dtime1 = algotimes[q][1].tabletime +
			      (algotimes[q][1].decode256time * d256);
	dtime1 += dtime1 >> 3;
	return dtime1 < dtime0;
}

struct huf_deltx2 {
	unsigned char byte;
	unsigned char nbbits;
};

struct bit_dstream {
	unsigned long bit_container;
	unsigned int bit_consumed;
	const unsigned char* ptr;
	const unsigned char* start;
};

struct dtable_desc {
	unsigned char max_table_log;
	unsigned char table_type;
	unsigned char table_log;
	unsigned char reserved;
};

static struct dtable_desc huf_get_dtable_desc(const unsigned int* huf_table)
{
	struct dtable_desc dtd;
	memcpy(&dtd, huf_table, sizeof(dtd));
	return dtd;
}

unsigned int bit_highbit32(unsigned int val)
{
	return 31 - __builtin_clz(val);
}

static unsigned long bit_init_dstream(struct bit_dstream* bitd,
			const void* src, unsigned long src_size)
{
	unsigned char lastbyte;

	if (src_size >= sizeof(bitd->bit_container)) {
		bitd->start = (const unsigned char*) src;
		bitd->ptr = (const unsigned char*) src
			+ src_size - sizeof(bitd->bit_container);
		bitd->bit_container = readlong(bitd->ptr);
		lastbyte = ((unsigned char*) src)[src_size - 1];
		bitd->bit_consumed = lastbyte?8-bit_highbit32(lastbyte):0;
		if (lastbyte == 0)
			return (unsigned long)-1;
	}

	return src_size;
}

enum bit_dstream_status {
	BIT_DStream_unfinished,
	BIT_DStream_endOfBuffer,
	BIT_DStream_completed,
	BIT_DStream_overflow
};

enum bit_dstream_status bit_reload_dstream(bit_dstream* bitd)
{
	if (bitd->bit_consumed > sizeof(bitd->bit_container) * 8)
		return BIT_DStream_overflow;

	if (bitd->ptr >= bitd->start + sizeof(bitd->bit_container)) {
		bitd->ptr -= bitd->bit_container >> 3;
		bitd->bit_consumed &= 7;
		bitd->bit_container = readlong(bitd->ptr);
		return BIT_DStream_unfinished;
	}
}

static unsigned int huf_decompress4x2_using_dtable(void* dst,
			unsigned int dst_size, void* src, unsigned int src_size,
			const unsigned int *huf_table)
{
	const unsigned char* istart = (const unsigned char*) src;
	unsigned char* ostart = (unsigned char*) dst;
	unsigned char* oend = ostart + dst_size;
	const void* dtptr = huf_table + 1;
	const struct huf_deltx2* dt = (const struct huf_deltx2*) dtptr;

	/* Init */
	struct bit_dstream bitd1;
	struct bit_dstream bitd2;
	struct bit_dstream bitd3;
	struct bit_dstream bitd4;

	unsigned int len1 = read16(istart);
	unsigned int len2 = read16(istart+2);
	unsigned int len3 = read16(istart+4);
	unsigned int len4 = src_size - (len1+len1+len2+len3+6);
	unsigned char* istart1 = istart + 6;
	unsigned char* istart2 = istart1 + len1;
	unsigned char* istart3 = istart2 + len2;
	unsigned char* istart4 = istart3 + len3;

	unsigned int segment_size = (dst_size+3)/4;
	unsigned char* opstart2 = ostart + segment_size;
	unsigned char* opstart3 = opstart2 + segment_size;
	unsigned char* opstart4 = opstart3 + segment_size;
	unsigned char* op1 = ostart;
	unsigned char* op2 = opstart2;
	unsigned char* op3 = opstart3;
	unsigned char* op4 = opstart4;
	unsigned int end_signal;

	struct dtable_desc dtd = huf_get_dtable_desc(huf_table);
	unsigned int dtlog = dtd.table_log;

	if (len4 > src_size)
		return -1;

	bit_init_dstream(&bitd1, istart1, len1);
	bit_init_dstream(&bitd2, istart2, len2);
	bit_init_dstream(&bitd3, istart3, len3);
	bit_init_dstream(&bitd4, istart4, len4);

	end_signal = bit_reload_dstream(&bitd1) | bit_reload_dstream(&bitd2) |
		     bit_reload_dstream(&bitd3) | bit_reload_dstream(&bitd4);

	while (end_signal==BIT_DStream_unfinished && (op4<(oend-7))) {
		huf_decode_symbolx2_2(op1, &bitd1);
		huf_decode_symbolx2_2(op1, &bitd2);
	}
}

static unsigned int huf_decompress4x2(unsigned int* huf_table, void *dst,
			unsigned int dst_size, const void* src,
			unsigned int src_size)
{
	const unsigned char* ip = (const unsigned char*) src;

	unsigned int hsize = huf_readtablex2(huf_table, src, src_size);
	if (hsize >= src_size)
		return -1;
	ip += hsize;
	src_size -= hsize;

	return huf_decompress4x2_using_dtable(dst, dst_size, ip, src_size,
			huf_table);
}

static unsigned int
huf_decompress4x_hufonly(unsigned int* huf_table, void* dst,
			unsigned int dst_size, const void* src,
			unsigned int src_size)
{
	unsigned int algonb = 0;

	if (src_size >= dst_size || src_size <= 1)
		return -1;
	algonb = huf_select_decoder(dst_size, src_size);
	/*
	if (algonb == 1)
		return huf_decompress4x4(huf_table, dst, dst_size, src,
					src_size);
	*/
	return huf_decompress4x2(huf_table, dst, dst_size, src, src_size);
}

static unsigned int
zstd_decompress_literals(struct zstd_decompress_context* context,
			const void* src, unsigned int src_size)
{
	const unsigned char* istart = (const unsigned char*) src;
	enum symbol_encoding_type type =
		(enum symbol_encoding_type)(istart[0] & 3);
	unsigned int lhsize, litsize, litcsize;
	unsigned int single_stream = 0;
	unsigned int lhlcode = (istart[0] >> 2) & 3;
	unsigned int lhc = read32(istart);

	switch (type) {
	case set_compressed:
		if (src_size < 5)
			return -1;
		switch(lhlcode) {
		case 0: case 1: default:
			single_stream = !lhlcode;
			lhsize = 3;
			litsize = (lhc >> 4) & 0x3FF;
			litcsize = (lhc >> 4) & 0x3FF;
			break;
		case 2:
			break;
		case 3:
			break;
		}

		if (litsize > ZSTD_BLOCKSIZE_ABSOLUTEMAX)
			return -1;
		if (litcsize + lhsize > src_size)
			return -1;
		if (type != set_repeat && single_stream) {
			huf_decompress4x_hufonly(context->huf_table,
				context->lit_buf, litsize,
				istart+lhsize, litcsize);
		}
		break;
	case set_repeat:
	case set_basic:
	case set_rle:
	default:
		return -1;
	}

	return 0;
}

static unsigned int
zstd_decompress_block(struct zstd_decompress_context* context,
			void* dst, unsigned int dst_size,
			const void* src, unsigned int src_size)
{
	const unsigned char* ip = (const unsigned char*) src;
	unsigned int lit_size = 0;

	if (src_size >= ZSTD_BLOCKSIZE_ABSOLUTEMAX)
		return -1;

	lit_size = zstd_decompress_literals(context, src, src_size);

	return 0;
}

static unsigned int
zstd_decompress_frame(struct zstd_decompress_context* context,
			void* dst, unsigned int dst_size,
			const void* src, unsigned int src_size)
{
	const unsigned char* ip = (const unsigned char*) src;
	unsigned char* ostart = (unsigned char*)dst;
	unsigned char* oend = ostart + sizeof(unsigned char)*dst_size;
	unsigned char* op = ostart;
	unsigned int remain = src_size;
	unsigned int decode_size;
	struct zstd_frame_param param;
	unsigned int frame_header_size;
	struct block_properties properties;
	unsigned int compress_block_size = 0;

	if (src_size < 9)
		return -1;

	frame_header_size = zstd_get_frame_header_size(src, src_size);

	ip += frame_header_size;
	remain = frame_header_size;

	while (1) {
		compress_block_size = zstd_get_block_size(ip,
				remain, &properties);
		if (compress_block_size < 0)
			return compress_block_size;
		ip += ZSTD_BLOCK_HEADER_SIZE;
		remain -= ZSTD_BLOCK_HEADER_SIZE;
		if (compress_block_size > remain)
			return -1;

		switch (properties.type) {
		case bt_compressed:
			decode_size = zstd_decompress_block(context,
					op, oend-op, ip, compress_block_size);
			break;
		case bt_raw:
		case bt_rle:
		case bt_reserved:
		default:
			return -1;
		}
	}

	return 0;
}

int zstd_decompress(void* dst, unsigned int dst_size,
		    const void* src, unsigned int src_size)
{
	struct zstd_decompress_context *context
		= malloc(sizeof(struct zstd_decompress_context));
	context->lit_buf = malloc(ZSTD_BLOCKSIZE_ABSOLUTEMAX
			+ ZSTD_FRAMEHEADERSIZE_MAX);
	init_zstd_decompress_context(context, dst);
	zstd_decompress_frame(context, dst, dst_size, src, src_size);

	return 0;
}
