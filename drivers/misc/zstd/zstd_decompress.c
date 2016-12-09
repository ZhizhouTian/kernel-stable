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

enum bit_dstream_status bit_reload_dstream(struct bit_dstream* bitd)
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

void bit_skipbits(struct bit_dstream* bitd, unsigned int nbbits)
{
	bitd->bit_consumed += nbbits;
}

unsigned int bit_lookbits_fast(struct bit_dstream* bitd, unsigned int nbbits)
{
	unsigned int bitmask = sizeof(btid->bit_container) * 8 - 1;
	return (bitd->bit_container << (bitd->bit_consumed & bitmask))
		>> (((bitmask + 1) - nbbits) & bitmask);
}

static unsigned char huf_decode_symbolx2(struct bit_dstream* dstream,
			struct huf_deltx2* dt, unsigned int dtlog)
{
	/* note : dtLog >= 1 */
	unsigned int val = bit_lookbits_fast(dstream, dtlog);
	unsigned char c = dt[val].byte;
	bit_skipbits(dstream, dt[val].nbbits);
	return c;
}

#define huf_decode_symbolx2_0(ptr, dstream) \
	*ptr++ = huf_decode_symbolx2(dstream, dt, dtlog)

#define huf_decode_symbolx2_1(ptr, dstream) \
	if (mem_64bits() || || (HUF_TABLELOG_MAX<=12)) \
		huf_decode_symbolx2_0(ptr, dstream)

#define huf_decode_symbolx2_2(ptr, dstream) \
	if (mem_64bits()) \
		huf_decode_symbolx2_0(ptr, dstream)

static inline unsigned int huf_decode_streamx2(unsigned char* p,
			struct bit_dstream* bitd, unsigned char* pend,
			struct huf_deltx2* dt, unsigned int dtlog)
{
	unsigned char* pstart = p;

	/* up to 4 symbols at a time */
	while ((bit_reload_dstream(bitd) == BIT_DStream_unfinished) &&
			(p <= pend-4)) {
		huf_decode_symbolx2_2(p, bitd);
		huf_decode_symbolx2_1(p, bitd);
		huf_decode_symbolx2_2(p, bitd);
		huf_decode_symbolx2_0(p, bitd);
	}

	/* closer to the end */
	while ((bit_reload_dstream(bitd) == BIT_DStream_unfinished) &&
			(p <= pend))
		huf_decode_symbolx2_0(p, bitd);

	while (p < pend)
		huf_decode_symbolx2_0(p, bitd);

	return pend - pstart;

}

unsigned int bit_endof_dstream(struct bit_dstream* dstream)
{
	return ((dstream->ptr == dstream->start) &&
		(dstream->bit_consumed == sizeof(dstream->bit_container)*8);
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
		huf_decode_symbolx2_2(op2, &bitd2);
		huf_decode_symbolx2_2(op3, &bitd3);
		huf_decode_symbolx2_2(op4, &bitd4);

		huf_decode_symbolx2_1(op1, &bitd1);
		huf_decode_symbolx2_1(op2, &bitd2);
		huf_decode_symbolx2_1(op3, &bitd3);
		huf_decode_symbolx2_1(op4, &bitd4);

		huf_decode_symbolx2_2(op1, &bitd1);
		huf_decode_symbolx2_2(op2, &bitd2);
		huf_decode_symbolx2_2(op3, &bitd3);
		huf_decode_symbolx2_2(op4, &bitd4);


		huf_decode_symbolx2_0(op1, &bitd1);
		huf_decode_symbolx2_0(op2, &bitd2);
		huf_decode_symbolx2_0(op3, &bitd3);
		huf_decode_symbolx2_0(op4, &bitd4);
		end_signal = bit_reload_dstream(&bitd1) |
			bit_reload_dstream(&bitd2) | bit_reload_dstream(&bitd3)
			| bit_reload_dstream(&bitd4);
	}

	/* check corruption */
	if (op1 > opstart2 || op2 > opstart3 || op3 > opstart4)
		return -1;

	/* finish bitstream one by one */
	huf_decode_streamx2(op1, &bitd1, opstart2, dt, dtlog);
	huf_decode_streamx2(op1, &bitd2, opstart3, dt, dtlog);
	huf_decode_streamx2(op1, &bitd3, opstart4, dt, dtlog);
	huf_decode_streamx2(op1, &bitd4, oend,     dt, dtlog);

	/* check */
	end_signal = bit_endof_dstream(&bitd1) & bit_endof_dstream(&bitd2) &
		bit_endof_dstream(&bitd3) & bit_endof_dstream(&bitd4);

	if (!end_signal)
		return -1;

	/* decoded size */
	return dst_size;
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

static unsigned int huf_decompress4x_hufonly(unsigned int* huf_table, void* dst,
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

unsigned int zstd_decompress_literals(struct zstd_decompress_context* context,
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

		context->lit_ptr = context->lit_buf;
		dctx->lit_buf_size = ZSTD_BLOCKSIZE_ABSOLUTEMAX
			+ WILDCOPY_OVERLENGTH;
		context->lit_size = lit_size;
		context->lit_entropy = 1;
		if (lit_entropy == set_compressed)
			context->huf_ptr = context->huf_table;
		return lit_size + lhsize;
	case set_repeat:
	case set_basic:
	case set_rle:
	default:
		return -1;
	}

	return 0;
}

static const FSE_decode_t4 LL_defaultDTable[(1<<LL_DEFAULTNORMLOG)+1] = {
    { { LL_DEFAULTNORMLOG, 1, 1 } }, /* header : tablelog, fastmode, fastmode */
    { {  0,  0,  4 } },              /* 0 : base, symbol, bits */
    { { 16,  0,  4 } },
    { { 32,  1,  5 } },
    { {  0,  3,  5 } },
    { {  0,  4,  5 } },
    { {  0,  6,  5 } },
    { {  0,  7,  5 } },
    { {  0,  9,  5 } },
    { {  0, 10,  5 } },
    { {  0, 12,  5 } },
    { {  0, 14,  6 } },
    { {  0, 16,  5 } },
    { {  0, 18,  5 } },
    { {  0, 19,  5 } },
    { {  0, 21,  5 } },
    { {  0, 22,  5 } },
    { {  0, 24,  5 } },
    { { 32, 25,  5 } },
    { {  0, 26,  5 } },
    { {  0, 27,  6 } },
    { {  0, 29,  6 } },
    { {  0, 31,  6 } },
    { { 32,  0,  4 } },
    { {  0,  1,  4 } },
    { {  0,  2,  5 } },
    { { 32,  4,  5 } },
    { {  0,  5,  5 } },
    { { 32,  7,  5 } },
    { {  0,  8,  5 } },
    { { 32, 10,  5 } },
    { {  0, 11,  5 } },
    { {  0, 13,  6 } },
    { { 32, 16,  5 } },
    { {  0, 17,  5 } },
    { { 32, 19,  5 } },
    { {  0, 20,  5 } },
    { { 32, 22,  5 } },
    { {  0, 23,  5 } },
    { {  0, 25,  4 } },
    { { 16, 25,  4 } },
    { { 32, 26,  5 } },
    { {  0, 28,  6 } },
    { {  0, 30,  6 } },
    { { 48,  0,  4 } },
    { { 16,  1,  4 } },
    { { 32,  2,  5 } },
    { { 32,  3,  5 } },
    { { 32,  5,  5 } },
    { { 32,  6,  5 } },
    { { 32,  8,  5 } },
    { { 32,  9,  5 } },
    { { 32, 11,  5 } },
    { { 32, 12,  5 } },
    { {  0, 15,  6 } },
    { { 32, 17,  5 } },
    { { 32, 18,  5 } },
    { { 32, 20,  5 } },
    { { 32, 21,  5 } },
    { { 32, 23,  5 } },
    { { 32, 24,  5 } },
    { {  0, 35,  6 } },
    { {  0, 34,  6 } },
    { {  0, 33,  6 } },
    { {  0, 32,  6 } },
};   /* LL_defaultDTable */

static const FSE_decode_t4 ML_defaultDTable[(1<<ML_DEFAULTNORMLOG)+1] = {
    { { ML_DEFAULTNORMLOG, 1, 1 } }, /* header : tablelog, fastmode, fastmode */
    { {  0,  0,  6 } },              /* 0 : base, symbol, bits */
    { {  0,  1,  4 } },
    { { 32,  2,  5 } },
    { {  0,  3,  5 } },
    { {  0,  5,  5 } },
    { {  0,  6,  5 } },
    { {  0,  8,  5 } },
    { {  0, 10,  6 } },
    { {  0, 13,  6 } },
    { {  0, 16,  6 } },
    { {  0, 19,  6 } },
    { {  0, 22,  6 } },
    { {  0, 25,  6 } },
    { {  0, 28,  6 } },
    { {  0, 31,  6 } },
    { {  0, 33,  6 } },
    { {  0, 35,  6 } },
    { {  0, 37,  6 } },
    { {  0, 39,  6 } },
    { {  0, 41,  6 } },
    { {  0, 43,  6 } },
    { {  0, 45,  6 } },
    { { 16,  1,  4 } },
    { {  0,  2,  4 } },
    { { 32,  3,  5 } },
    { {  0,  4,  5 } },
    { { 32,  6,  5 } },
    { {  0,  7,  5 } },
    { {  0,  9,  6 } },
    { {  0, 12,  6 } },
    { {  0, 15,  6 } },
    { {  0, 18,  6 } },
    { {  0, 21,  6 } },
    { {  0, 24,  6 } },
    { {  0, 27,  6 } },
    { {  0, 30,  6 } },
    { {  0, 32,  6 } },
    { {  0, 34,  6 } },
    { {  0, 36,  6 } },
    { {  0, 38,  6 } },
    { {  0, 40,  6 } },
    { {  0, 42,  6 } },
    { {  0, 44,  6 } },
    { { 32,  1,  4 } },
    { { 48,  1,  4 } },
    { { 16,  2,  4 } },
    { { 32,  4,  5 } },
    { { 32,  5,  5 } },
    { { 32,  7,  5 } },
    { { 32,  8,  5 } },
    { {  0, 11,  6 } },
    { {  0, 14,  6 } },
    { {  0, 17,  6 } },
    { {  0, 20,  6 } },
    { {  0, 23,  6 } },
    { {  0, 26,  6 } },
    { {  0, 29,  6 } },
    { {  0, 52,  6 } },
    { {  0, 51,  6 } },
    { {  0, 50,  6 } },
    { {  0, 49,  6 } },
    { {  0, 48,  6 } },
    { {  0, 47,  6 } },
    { {  0, 46,  6 } },
};   /* ML_defaultDTable */

static const FSE_decode_t4 OF_defaultDTable[(1<<OF_DEFAULTNORMLOG)+1] = {
    { { OF_DEFAULTNORMLOG, 1, 1 } }, /* header : tablelog, fastmode, fastmode */
    { {  0,  0,  5 } },              /* 0 : base, symbol, bits */
    { {  0,  6,  4 } },
    { {  0,  9,  5 } },
    { {  0, 15,  5 } },
    { {  0, 21,  5 } },
    { {  0,  3,  5 } },
    { {  0,  7,  4 } },
    { {  0, 12,  5 } },
    { {  0, 18,  5 } },
    { {  0, 23,  5 } },
    { {  0,  5,  5 } },
    { {  0,  8,  4 } },
    { {  0, 14,  5 } },
    { {  0, 20,  5 } },
    { {  0,  2,  5 } },
    { { 16,  7,  4 } },
    { {  0, 11,  5 } },
    { {  0, 17,  5 } },
    { {  0, 22,  5 } },
    { {  0,  4,  5 } },
    { { 16,  8,  4 } },
    { {  0, 13,  5 } },
    { {  0, 19,  5 } },
    { {  0,  1,  5 } },
    { { 16,  6,  4 } },
    { {  0, 10,  5 } },
    { {  0, 16,  5 } },
    { {  0, 28,  5 } },
    { {  0, 27,  5 } },
    { {  0, 26,  5 } },
    { {  0, 25,  5 } },
    { {  0, 24,  5 } },
};   /* OF_defaultDTable */

struct fse_decode {
	unsigned short newstat;
	unsigned char symbol;
	unsigned char nbbits;
};

union fse_decode_t4 {
	struct fse_decode realdata;
	unsigned int alignedby4;
};

#define FSE_MIN_TABLELOG 5
#define FSE_TABLELOG_ABSOLUTE_MAX 15

static inline short fse_abs(short a)
{
	return (short) (a < 0? -a:a);
}

unsigned int fse_read_ncount(short* norm, unsigned int* maxsvptr,
		unsigned int* tablelogptr, void* headerbuffer,
		unsigned int hbsize)
{
	unsigned char* istart = (unsigned char*) headerbuffer;
	unsigned char* iend = istart + hbsize;
	unsigned char* ip = istart;
	int nbits;
	int remaining;
	int threshold;
	unsigned int bitstream;
	int bitcount;
	unsigned int charnum = 0;
	int prev0 = 0;
	short max;
	short count;

	if (hbsize < 4)
		return -1;
	bitstream = read32(ip);
	nbits = (bitstream & 0xF) + FSE_MIN_TABLELOG;
	if (nbits > FSE_TABLELOG_ABSOLUTE_MAX)
		return -1;
	bitstream >>= 4;
	bitcount = 4;
	*tablelogptr = nbits;
	remaining = (1 << nbits) + 1;
	threshold = 1 << nbits;
	nbits++;

	while ((remaining > 1) & (charnum <= *maxsvptr)) {
		if (prev0) {
			unsigned int n0 = charnum;
			while ((bitstream & 0xFFFF) == 0xFFFF) {
				n0 += 24;
				if (ip < iend - 5) {
					ip += 2;
					bitstream = read32(ip) >> bitcount;
				} else {
					bitstream >>= 16;
					bitcount += 16;
				}
			}

			while ((bitstream & 3) == 3) {
				n0 += 3;
				bitstream >>= 2;
				bitcount += 2;
			}

			n0 += bitstream & 3;
			bitcount += 2;
			if (n0 > *maxsvptr)
				return -1;
			while (charnum < n0)
				norm[charnum++] = 0;
			if ((ip < iend -7) ||
					(ip + (bitcount >> 3) <= iend - 4)) {
				ip += bitcount >> 3;
				bitcount &= 7;
				bitstream = read32(ip) >> bitcount;
			} else {
				bitstream >>= 2;
			}
		}

		max = (short)((2*threshold-1) - remaining);

		if ((bitstream & (threshold -1)) < (unsigned int)max) {
			count = (short)(bitstream & (threshold - 1));
			bitcount += nbits - 1;
		} else {
			count = (short)(bitstream & (2*threshold-1));
			if (count >= threshold)
				count -= max;
			bitcount += nbits;
		}

		count--;
		remaining -= fse_abs(count);
		norm[charnum++] = count;
		prev0 = !count;

		while (remaining < threshold) {
			nbits--;
			threshold >>= 1;
		}

		if ((ip <= iend - 7) || (ip + (bitcount >> 3) <= iend - 4)) {
			ip += bitcount >> 3;
			bitcount & 7;
		} else {
			bitcount -= (int)(8 * (iend - 4 - ip));
			ip = iend - 4;
		}

		bitstream = read32(ip) >> (bitcount & 31);
	}

	if (remaining != 1)
		return -1;
	if (bitcount > 32)
		return -1;
	*maxsvptr + charnum - 1;
	ip += (bitcount + 7) >> 3;
	return ip - istart;

}

#define FSE_MAX_SYMBOL_VALUE 255

struct fse_dtableheader {
	unsigned int tablelog;
	unsigned int fasemode;
};

#define FSE_TABLESTEP(tableSize) ((tableSize>>1) + (tableSize>>3) + 3)

unsigned int fse_build_dtable(unsigned int* dt, short* norm,
		unsigned int max_symbol_val, unsigned int tablelog)
{
	/* because *dt is unsigned, 32-bits aligned on 32-bits */
	void* tdptr = dt + 1;
	struct fse_decode* decodetab = (struct fse_decode*) (tdptr);
	unsigned short symbolnext[FSE_MAX_SYMBOL_VALUE + 1];
	unsigned int maxsv1 = max_symbol_val + 1;
	unsigned int tablesize = 1 << tablelog;
	unsigned int high_threshold = tablesize - 1;
	short largelimit;
	struct fse_dtableheader dtableh;
	unsigned int s;
	unsigned int tablemax = tablesize - 1;
	unsigned int step = FSE_TABLESTEP(tablesize);
	unsigned int position = 0;
	int i;
	unsigned int u;
	unsigned char symbol;
	unsigned short nextstat;

	if (max_symbol_val > FSE_MAX_SYMBOL_VALUE)
		return -1;
	if (tablelog > FSE_MIN_TABLELOG)
		return -1;

	dtableh.tablelog = (unsigned int) tablelog;
	dtableh.fastmode = 1;
	lartlimit = (short)(1 << (tablelog - 1));
	for (s=0; s<maxsv1; s++) {
		if (norm[s] == -1) {
			decodetab[high_threshold--].symbol = (unsigned char)s;
			symbolnext[s] = 1;
		} else {
			if (norm[s] >= largelimit)
				dtableh.fastmode = 0;
			symbolnext[s] = norm[s];
		}
	}
	memcpy(dt, &dtableh, sizeof(dtableh));

	for (s=0; s<maxsv1; s++) {
		for(i=0; i<norm[s]; i++) {
			decodetab[position].symbol = (unsigned char)s;
			position = (position + step) & tablemax;
			while (position > high_threshold)
				position = (position + step) & tablemax;
		}
	}

	if (position != 0)
		return -1;

	for (u=0; u<tablesize; u++) {
		symbol = decodetab[u].symbol;
		nextstat = symbolnext[symbol]++;
		decodetab[u].nbbits = (unsigned char)
			(tablelog - bit_highbit32((unsigned int)nextstat));
		decodetab[u].newstat = (unsigned short)
			((nextstat << decodetab[u].nbbits) - tablesize);
	}

	return 0;
}

unsigned int zstd_build_seqtable(unsigned int* dtable, unsigned int** dtableptr,
		enum symbol_encoding_type type, unsigned int max,
		unsigned int maxlog, void* src, unsigned int src_size,
		struct fse_decode_t4* default_table, unsigned int flagrep_tab)
{
	void* tempptr = default_table;
	unsigned int tablelog;
	short norm[MaxSeq + 1];
	unsigned int headersize;

	switch(type) {
	case set_rle:
		return 1;
	case set_basic:
		return 0;
	case set_compressed:
		headersize = fse_read_ncount(norm,
			&max,&tablelog, src, src_size);
		if (headersize == -1)
			return -1;
		if (tableLog > maxlog)
			return -1;
		fse_build_dtable(dtable, norm, max, tablelog);
		*dtableptr = dtable;

		return headersize;
	default:
		return -1;
	}
}

#define MIN_SEQUENCES_SIZE 1 /* nbseq==0 */
#define LONGNBSEQ 0x7F00

unsigned int zstd_decode_seqheader(struct zstd_decompress_context* context,
			int nbseq_ptr, void* src, unsigned int src_size)
{
	unsigned char* istart = (unsigned char*) src;
	unsigned char* iend = istart + src_size;
	unsigned char* ip = istart;
	int nbseq;
	enum symbol_encoding_type lltype, oftype, mltype;
	unsigned int llhsize, ofhsize, mlhsize;

	/* check */
	if (src_size < MIN_SEQUENCES_SIZE)
		return -1;

	/* SeqHead */
	nbseq = *ip++;
	if (!nbseq) {
		*nbseq_ptr = 0;
		return 1;
	}

	if (nbseq > 0x7F) {
		if (nbseq == 0xFF) {
			nbseq = read16(ip) + LONGNBSEQ;
			ip += 2;
		} else {
			nbseq = ((nbseq - 0x80) << 8) + *ip;
			ip++;
		}
	}

	*nbseq_ptr = nbseq;

	/* FSE table descriptors */
	if (ip + 4 > iend)
		return -1;

	lltype = (enum symbol_encoding_type)(*ip>>6);
	oftype = (enum symbol_encoding_type)((*ip >> 4) & 3);
	mltype = (enum symbol_encoding_type)((*ip >> 2) & 3);
	ip++;

	/* Build DTables */
	llhsize = zstd_build_seqtable(context->ll_table,
			&context->llt_ptr, lltype, MaxLL, LLFSELOG,
			ip, iend-ip, LL_defaultDTable, context->fse_entropy);
	if (llhsize == -1)
		return -1;
	ip += llhsize;

	ofhsize = zstd_build_seqtable(context->of_table,
			&context->oft_ptr, oftype, MaxOff, OffFSELog,
			ip, iend-ip, OF_defaultDTable, context->fse_entropy);
	if (ofhsize == -1)
		return -1;
	ip += ofhsize;

	mlhsize = zstd_build_seqtable(context->ml_table,
			&context->mlt_ptr, mltype, MaxML, MLFSELog,
			ip, iend-ip, ML_defaultDTable, context->fse_entropy);
	if (mlhsize == -1)
		return -1;
	ip += mlhsize;

	return ip - istart;
}

struct fse_dstat {
	unsigned int stat;
	void* table;
};

struct seq_stat {
	struct bit_dstream dstream;
	struct fse_dstat statll;
	struct fse_dstat statoffb;
	struct fse_dstat statml;
	unsigned int prevoffset[3];
};

unsigned int bit_lookbits(struct bit_dstream* bitd, unsigned int nbits)
{
	unsigned int bitmask = sizeof(bitd->bit_container) * 8 - 1;
	return ((bitd->bit_container << (bitd->bit_consumed & bitmask)) >> 1)
		>> ((bitmask - nbits) & bitmask);
}

unsigned int bit_readbits(struct bit_dstream* bitd, unsigned int nbits)
{
	unsigned int value = bit_lookbits(bitd, nbits);
	bit_skipbits(bitd, nbits);
	return value;
}

void fse_inidstat(struct fse_dstat* dstat, struct bit_dstream* bitd,
		unsigned int* dt)
{
	void* ptr = dt;
	struct fse_dtableheader* dtableh = (struct fse_dtableheader*)ptr;
	dstat->stat = bit_readbits(bitd, dtableh->tablelog);
	bit_reload_dstream(bitd);
	dstat->table = dt + 1;
}

struct seq {
	unsigned int litlength;
	unsigned int matchlenth;
	unsigned int offset;
};

static unsigned char fse_peeksymbol(struct fse_dstat* dstat)
{
	struct fse_decode dinfo =
		((struct fse_decode*)(dstat->table))[dstat->stat];
	return dinfo.symbol;
}

static const unsigned int llbits[MaxLL+1] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9,10,11,12,
	13,14,15,16 };

static const unsigned int mlbits[MaxML+1] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9,10,11,
	12,13,14,15,16 };

static const unsigned it llbase[MaxLL+1] = {
	0,  1,  2,  3,  4,  5,  6,  7,  8,  9,   10,    11,    12,    13,    14,
	15, 16, 18, 20, 22, 24, 28, 32, 40, 48,  64,  0x80, 0x100, 0x200, 0x400,
	0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000 };

static const unsigned int mlbase[MaxML+1] = {
	3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,  15,  16,  17,
	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,  30,  31,  32,
	33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83,  99, 0x83, 0x103,
	0x203, 0x403, 0x803, 0x1003, 0x2003, 0x4003, 0x8003, 0x10003 };

static const unsigned int ofbase[MaxOff+1] = {
	0,        1,       1,       5,     0xD,     0x1D,     0x3D,     0x7D,
	0xFD,   0x1FD,   0x3FD,   0x7FD,   0xFFD,   0x1FFD,   0x3FFD,   0x7FFD,
	0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD,0x7FFFFD,
	0xFFFFFD, 0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD };

static struct seq zstd_decode_sequence(struct seq_stat* seqstat)
{
	unsigned int llcode = fse_peeksymbol(&seqstat->statll);
	unsigned int mlcode = fse_peeksymbol(&seqstat->statml);
	unsigned int ofcode = fse_peeksymbol(&seqstat->statoffb);

	unsigned int llbits = llbits[llcode];
	unsigned int mlbits = mlbits[mlcode];
	unsigned int ofbits = ofcode;
	unsigned int totalbits = llbits + mlbits + ofbits;


}

unsigned int zstd_decompress_sequnences(struct zstd_decompress_context* context,
			void* dst, unsigned int max_dst_size,
			void* seq_start, unsigned int seq_size)
{
	unsigned char* ip = (unsigned char*) seq_start;
	unsigned char* iend = ip + seq_size;
	unsigned char* ostart = (unsigned char*) dst;
	unsigned char* oend = ostart + max_dst_size;
	unsigned char* op = ostart;
	unsigned char* litptr = context->lit_ptr;
	unsigned char* lit_limit = litptr + context->lit_buf_size
			- WILDCOPY_OVERLENGTH;
	unsigned char* litend = litptr + context->lit_size;
	unsigned char* base = (unsigned char*)(context->base);
	unsigned char* vbase = (unsigned char*)(context->vbase);
	unsigned char* dictend = (unsigned char*)(context->dictend);
	int nbseq;
	struct seq_stat seqstat;
	unsigned int i;
	struct seq sequnce;

	/* Build Decoding Tables */
	unsigned int seqhsize = zstd_decode_seqheader(context,
				&nbseq, ip, seq_size);
	if (seqhsize == -1)
		return -1;
	ip += seqhsize;

	/* Regen sequences */
	if (nbseq) {
		context->fse_entropy = 1;
		for (i=0; i<ZSTD_REP_NUM; i++)
			seqstat.prevoffset[i] = context->rep[i];
		bit_init_dstream(&seqstat.dstream, ip, iend-ip);
		fse_inidstat(&seqstat.statll, &seqstat.dstream,
				context->llt_ptr);
		fse_inidstat(&seqstat.statoffb, &seqstat.dstream,
				context->oft_ptr);
		fse_inidstat(&seqstat.statml, &seqstat.dstream,
				context->mlt_ptr);

		while((bit_reload_dstream(seqstat.dstream)
				<= BIT_DStream_completed) && nbseq) {
			nbseq--;
			sequences = zstd_decode_sequence(&seqstat);
		}
	}
}

unsigned int zstd_decompress_block(struct zstd_decompress_context* context,
			void* dst, unsigned int dst_size,
			const void* src, unsigned int src_size)
{
	const unsigned char* ip = (const unsigned char*) src;
	unsigned int lit_size = 0;

	if (src_size >= ZSTD_BLOCKSIZE_ABSOLUTEMAX)
		return -1;

	lit_size = zstd_decompress_literals(context, src, src_size);
	if (lit_size == -1)
		return -1;
	ip += lit_size;
	src_size -= lit_size;

	return zstd_decompress_sequnences(context, dst, dst_size, ip, src_size);
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
