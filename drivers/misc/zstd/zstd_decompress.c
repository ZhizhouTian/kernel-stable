#include "utils.h"
#include "zstd.h"

static unsigned char zstd_fcs_field_sizes[] = {0, 2, 4, 8};
static unsigned char zstd_dictid_field_sizes[] = {0, 1, 2, 4};

#define ZSTD_MAGICNUMBER 0xFD2FB528
#define ZSTD_FRAME_HEADER_MIN_SIZE 5

#define ZSTD_WINDOWLOG_ABSOLUTEMIN 10

#define HUF_SYMBOLVALUE_MAX 255
#define HUF_TABLELOG_ABSOLUTEMAX  16
#define HUF_TABLELOG_MAX  12

static ssize_t zstd_get_frame_header_size(u8 *src, ssize_t size)
{
	u8 fhd = src[4];
	u8 dict_id_flag = fhd & 3;
	u8 single_segement_flag = (fhd >> 5) & 1;
	u8 fcs_flag = (fhd >> 6) & 3;

	return ZSTD_FRAME_HEADER_MIN_SIZE + !single_segement_flag
		+ zstd_dictid_field_sizes[dict_id_flag]
		+ zstd_fcs_field_sizes[fcs_flag]
		+ (single_segement_flag && !fcs_flag);
}

static ssize_t zstd_get_window_size(u8 desc)
{
	ssize_t exponent = desc >> 3;
	ssize_t mantissa = desc & 7;

	ssize_t window_base = 1 << (ZSTD_WINDOWLOG_ABSOLUTEMIN + exponent);
	ssize_t window_add = (window_base >> 3) * mantissa;

	return window_base + window_add;
}

static void _zstd_get_frame_param(u8 *src, ssize_t size,
		struct zstd_frame_param* param)
{
	u8 fhd = src[4];
	u8 dict_id_flag = fhd & 3;
	u8 checksum_flag = (fhd >> 2) & 1;
	u8 single_segement_flag = (fhd >> 5) & 1;
	u8 fcs_flag = (fhd >> 6) & 3;
	ssize_t pos = 5;

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

int zstd_get_frame_param(void* src_buf, ssize_t size,
			 struct zstd_frame_param* param)
{
	u8 *src = src_buf;
	ssize_t frame_header_size = 0;
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

static void init_zstd_decompress_context(struct zstd_decompress_context* ctx,
			void* dst)
{
	ctx->expected = ZSTD_FRAME_HEADER_MIN_SIZE;
	ctx->stage = ZSTDds_getFrameHeaderSize;
	ctx->prev_dst_end = dst;
	ctx->base = dst;
	ctx->vbase = dst;
	ctx->dict_end = NULL;
	ctx->huf_table[0] = HUF_LOG * 0x1000001;
	ctx->lit_entropy = 0;
	ctx->fse_entropy = 0;
	ctx->dict_id = 0;
	memcpy (ctx->rep, rep_start_value, sizeof(rep_start_value));
	ctx->llt_ptr = ctx->ll_table;
	ctx->mlt_ptr = ctx->ml_table;
	ctx->oft_ptr = ctx->of_table;
	ctx->huf_ptr = ctx->huf_table;
	ctx->lit_buf_size =
		ZSTD_BLOCKSIZE_ABSOLUTEMAX + ZSTD_FRAMEHEADERSIZE_MAX;
}

static ssize_t zstd_get_block_size(void* src, size_t src_size,
		    struct block_properties* prop)
{
	u32 block_header = read24(src);
	u32 size = block_header >> 3;

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
	u32 tabletime;
	u32 decode256time;
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


static u32 huf_select_decoder(ssize_t dst_size, ssize_t src_size)
{
	u32 q = (u32) (src_size * 16 / dst_size);
	u32 d256 = (u32) (dst_size >> 8);
	u32 dtime0 = algotimes[q][0].tabletime +
			      (algotimes[q][0].decode256time * d256);
	u32 dtime1 = algotimes[q][1].tabletime +
			      (algotimes[q][1].decode256time * d256);
	dtime1 += dtime1 >> 3;
	return dtime1 < dtime0;
}

struct huf_deltx2 {
	unsigned char byte;
	unsigned char nbits;
};

struct bit_dstream {
	size_t bit_container;
	u32 bit_consumed;
	u8 *ptr;
	u8 *start;
};

struct dtable_desc {
	u8 max_table_log;
	u8 table_type;
	u8 table_log;
	u8 reserved;
};

static struct dtable_desc huf_get_dtable_desc(unsigned int* huf_table)
{
	struct dtable_desc dtd;
	memcpy(&dtd, huf_table, sizeof(dtd));
	return dtd;
}

unsigned int bit_highbit32(unsigned int val)
{
	return 31 - __builtin_clz(val);
}

static ssize_t bit_init_dstream(struct bit_dstream* bitd, u8* src,
			ssize_t src_size)
{
	u8 lastbyte;

	if (src_size < 1) {
		memset(bitd, 0, sizeof(*bitd));
		return -1;
	}

	if (src_size >= sizeof(bitd->bit_container)) {
		bitd->start = (u8*) src;
		bitd->ptr = (u8*) src + src_size - sizeof(bitd->bit_container);
		bitd->bit_container = readlong(bitd->ptr);
		lastbyte = ((u8*) src)[src_size - 1];
		bitd->bit_consumed = lastbyte ? 8 - bit_highbit32(lastbyte):0;
		if (lastbyte == 0)
			return -1;
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
	u32 nbytes;
	enum bit_dstream_status result;

	if (bitd->bit_consumed > sizeof(bitd->bit_container) * 8)
		return BIT_DStream_overflow;

	if (bitd->ptr >= bitd->start + sizeof(bitd->bit_container)) {
		bitd->ptr -= bitd->bit_consumed >> 3;
		bitd->bit_consumed &= 7;
		bitd->bit_container = readlong(bitd->ptr);
		return BIT_DStream_unfinished;
	}

	if (bitd->ptr == bitd->start) {
		if (bitd->bit_consumed < sizeof(bitd->bit_container) * 8)
			return BIT_DStream_endOfBuffer;
		return BIT_DStream_completed;
	}

	nbytes = bitd->bit_consumed >> 3;
	result = BIT_DStream_unfinished;
	if (bitd->ptr - nbytes < bitd->start) {
		nbytes = (u32) (bitd->ptr - bitd->start);
		result = BIT_DStream_endOfBuffer;
	}
	bitd->ptr -= nbytes;
	bitd->bit_consumed -= nbytes * 8;
	bitd->bit_container = readlong(bitd->ptr);

	return result;
}

void bit_skipbits(struct bit_dstream* bitd, unsigned int nbits)
{
	bitd->bit_consumed += nbits;
}

static ssize_t bit_lookbits_fast(struct bit_dstream* bitd, unsigned int nbits)
{
	u32 bitmask = sizeof(bitd->bit_container) * 8 - 1;
	return (bitd->bit_container << (bitd->bit_consumed & bitmask))
		>> (((bitmask + 1) - nbits) & bitmask);
}

static unsigned char huf_decode_symbolx2(struct bit_dstream* dstream,
			struct huf_deltx2* dt, unsigned int dtlog)
{
	/* note : dtLog >= 1 */
	unsigned int val = bit_lookbits_fast(dstream, dtlog);
	unsigned char c = dt[val].byte;
	bit_skipbits(dstream, dt[val].nbits);
	return c;
}

#define huf_decode_symbolx2_0(ptr, dstream) \
	*ptr++ = huf_decode_symbolx2(dstream, dt, dtlog)

#if BITS_PER_LONG == 64
#define huf_decode_symbolx2_1(ptr, dstream) \
	if ((HUF_TABLELOG_MAX <= 12)) \
		huf_decode_symbolx2_0(ptr, dstream)
#else
#define huf_decode_symbolx2_1(ptr, dstream)
#endif

#if BITS_PER_LONG == 64
#define huf_decode_symbolx2_2(ptr, dstream) huf_decode_symbolx2_0(ptr, dstream)
#else
#define huf_decode_symbolx2_2(ptr, dstream)
#endif

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
	return (dstream->ptr == dstream->start) &&
		(dstream->bit_consumed == sizeof(dstream->bit_container) * 8);
}

static ssize_t huf_decompress4x2_using_dtable(u8 *dst, ssize_t dst_size,
			u8 *src, ssize_t src_size, u32 *huf_table)
{
	u8 *istart = src;
	u8 *ostart = dst;
	u8 *oend = ostart + dst_size;
	void *dtptr = huf_table + 1;
	struct huf_deltx2 *dt = (struct huf_deltx2*) dtptr;

	/* Init */
	struct bit_dstream bitd1;
	struct bit_dstream bitd2;
	struct bit_dstream bitd3;
	struct bit_dstream bitd4;

	ssize_t len1 = read16(istart);
	ssize_t len2 = read16(istart+2);
	ssize_t len3 = read16(istart+4);
	ssize_t len4 = src_size - (len1 + len1 + len2 + len3 + 6);

	u8 *istart1 = istart + 6;
	u8 *istart2 = istart1 + len1;
	u8 *istart3 = istart2 + len2;
	u8 *istart4 = istart3 + len3;

	ssize_t segment_size = (dst_size + 3) / 4;
	u8 *opstart2 = ostart + segment_size;
	u8 *opstart3 = opstart2 + segment_size;
	u8 *opstart4 = opstart3 + segment_size;
	u8 *op1 = ostart;
	u8 *op2 = opstart2;
	u8 *op3 = opstart3;
	u8 *op4 = opstart4;
	u32 end_signal;

	struct dtable_desc dtd = huf_get_dtable_desc(huf_table);
	u32 dtlog = dtd.table_log;

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

struct fse_dstat {
	ssize_t stat;
	void* table;
};

struct fse_decode {
	u16 newstat;
	u8 symbol;
	u8 nbits;
};

struct fse_dtableheader {
	u16 tablelog;
	u16 fastmode;
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

static void fse_init_dstate(struct fse_dstat *dstat, struct bit_dstream *bitd,
			u32 *dt)
{
	void *ptr = dt;
	struct fse_dtableheader *dtable_header = (struct fse_dtableheader*) ptr;
	dstat->stat = bit_readbits(bitd, dtable_header->tablelog);
	bit_reload_dstream(bitd);
	dstat->table = dt + 1;
}

static ssize_t bit_readbits_fast(struct bit_dstream *bitd, u32 nbits)
{
	ssize_t value = bit_lookbits_fast(bitd, nbits);
	bit_skipbits(bitd, nbits);

	return value;
}

static u8 fse_decode_symbol_fast(struct fse_dstat *dstat,
			struct bit_dstream *bitd)
{
	struct fse_decode dinfo =
		((struct fse_decode*)(dstat->table))[dstat->stat];
	u32 nbits = dinfo.nbits;
	u8 symbol = dinfo.symbol;
	ssize_t lowbits = bit_readbits_fast(bitd, nbits);

	dstat->stat = dinfo.newstat + lowbits;
	return symbol;
}

#define FSE_MAX_MEMORY_USAGE 14
#define FSE_MAX_TABLELOG  (FSE_MAX_MEMORY_USAGE-2)

static ssize_t fse_decompress_using_dtable_generic(u8 *dst, ssize_t dst_size,
			u8 *src, ssize_t src_size, u32 *dt, u32 fast)
{
	u8 *ostart = dst;
	u8 *op = ostart;
	u8 *omax = op + dst_size;
	u8 *olimit = omax - 3;

	struct bit_dstream bitd;
	struct fse_dstat stat1;
	struct fse_dstat stat2;

	if (bit_init_dstream(&bitd, src, src_size) < 0)
		return -1;

	fse_init_dstate(&stat1, &bitd, dt);
	fse_init_dstate(&stat2, &bitd, dt);

	for ( ; bit_reload_dstream(&bitd) == BIT_DStream_unfinished
			&& op < olimit; op += 4) {
		op[0] = fse_decode_symbol_fast(&stat1, &bitd);

		if (FSE_MAX_TABLELOG * 2 + 7 > sizeof(bitd.bit_container) * 8)
			bit_reload_dstream(&bitd);

		op[1] = fse_decode_symbol_fast(&stat2, &bitd);
		if (FSE_MAX_TABLELOG * 4 + 7 > sizeof(bitd.bit_container) * 8) {
			if (bit_reload_dstream(&bitd) >
					BIT_DStream_unfinished) {
				op += 2;
				break;
			}
		}

		op[2] = fse_decode_symbol_fast(&stat1, &bitd);
		if (FSE_MAX_TABLELOG * 2 + 7 > sizeof(bitd.bit_container) * 8)
			bit_reload_dstream(&bitd);

		op[3] = fse_decode_symbol_fast(&stat2, &bitd);
	}

	while (1) {
		if (op > (omax - 2))
			return -1;
		*op++ = fse_decode_symbol_fast(&stat1, &bitd);
		if (bit_reload_dstream(&bitd) == BIT_DStream_overflow) {
			*op++ = fse_decode_symbol_fast(&stat2, &bitd);
			break;
		}

		if (op > (omax - 2))
			return -1;

		*op++ = fse_decode_symbol_fast(&stat2, &bitd);
		if (bit_reload_dstream(&bitd) == BIT_DStream_overflow) {
			*op++ = fse_decode_symbol_fast(&stat1, &bitd);
			break;
		}
	}

	return op - ostart;
}

static ssize_t fse_decompress_using_dtable(u8 *dst, ssize_t origin_size,
			u8 *src, ssize_t src_size, u32 *dt)
{
	void *ptr = dt;
	struct fse_dtableheader *dtable_header = (struct fse_dtableheader*) ptr;
	u32 fastmode = dtable_header->fastmode;

	/* do nothing with non-fastmode now */
	if (!fastmode)
		return -1;

	/* select fast mode (static) */
	return fse_decompress_using_dtable_generic(dst,
			origin_size, src, src_size, dt, 1);
}

#define FSE_MAX_SYMBOL_VALUE 255

static ssize_t fse_read_ncount(short *norm, u32 *maxsvptr, u32 *tablelogptr,
		u8 *headerbuffer, ssize_t hbsize);

static int fse_build_dtable(u32 *dt, short* norm, u32 max_symbol_val,
			u32 tablelog);

static ssize_t fse_decompress(u8 *dst, ssize_t max_dst_size,
			u8 *src, ssize_t src_size)
{
	u8 *istart = src;
	u8 *ip = istart;
	short counting[FSE_MAX_SYMBOL_VALUE + 1];
	/* Static analyzer seems unable to understand this table
	 * will be properly initialized later */
	u32 dt[4097];
	u32 tablelog;
	u32 max_symbol_val = FSE_MAX_SYMBOL_VALUE;
	ssize_t ncount_length;
	int ret;

	if (src_size < 2)
		return -1;

	ncount_length = fse_read_ncount(counting, &max_symbol_val, &tablelog,
			istart, src_size);
	if (ncount_length >= src_size)
		return -1;

	ip += ncount_length;
	src_size -= ncount_length;

	ret = fse_build_dtable(dt, counting, max_symbol_val, tablelog);
	if (ret < 0)
		return -1;

	return fse_decompress_using_dtable(dst, max_dst_size, ip, src_size, dt);
}

static ssize_t huf_readstats(u8 *huf_weight, ssize_t hwsize, u32 *rank_stats,
			u32 *nbsymbols_ptr, u32 *tablelog_ptr,
			u8 *src, ssize_t src_size)
{
	u32 weight_total;
	u8 *ip = src;
	ssize_t isize = ip[0];
	ssize_t osize;
	u32 i;
	u32 tablelog;
	u32 total;
	u32 rest;
	u32 verify;
	u32 lastweight;

	if (isize >= 128) {
		osize = isize - 127;
		isize = ((osize + 1) / 2);
		if (isize + 1 > src_size)
			return -1;
		if (osize >= hwsize)
			return -1;
		ip += 1;
		for (i = 0; i < osize; i += 2) {
			huf_weight[i] = ip[i / 2] >> 4;
			huf_weight[i + 1] = ip[i / 2] & 15;
		}
	} else {
		if (isize + 1 > src_size)
			return -1;
		osize = fse_decompress(huf_weight, hwsize - 1, ip + 1, isize);
		if (osize < 0)
			return osize;
	}

	memset(rank_stats, 0, (HUF_TABLELOG_ABSOLUTEMAX + 1) * sizeof(u32));
	weight_total = 0;
	for (i = 0; i < osize; i++) {
		if (huf_weight[i] >= HUF_TABLELOG_ABSOLUTEMAX)
			return -1;
		rank_stats[huf_weight[i]]++;
		weight_total += (1 << huf_weight[i]) >> 1;
	}

	tablelog = bit_highbit32(weight_total) + 1;
	if (tablelog > HUF_TABLELOG_ABSOLUTEMAX)
		return -1;
	*tablelog_ptr = tablelog;

	total = 1 << tablelog;
	rest = total - weight_total;
	verify = 1 << bit_highbit32(rest);
	lastweight = bit_highbit32(rest) + 1;
	if (verify != rest)
		return -1;
	huf_weight[osize] = (u8)lastweight;
	rank_stats[lastweight]++;

	if (rank_stats[1] < 2 || (rank_stats[1] & 1))
		return -1;

	*nbsymbols_ptr = (u32)(osize + 1);

	return isize + 1;
}

static ssize_t huf_readtablex2(unsigned int* huf_table, u8 *src,
			ssize_t src_size)
{
	u8 huf_weight[HUF_SYMBOLVALUE_MAX + 1];
	u32 rank_val[HUF_TABLELOG_MAX + 1];
	u32 tablelog = 0;
	u32 nbsymbols = 0;
	ssize_t isize;
	void* dtptr = huf_table + 1;
	struct huf_deltx2* dt = (struct huf_deltx2*) dtptr;
	struct dtable_desc dtd;
	u32 n;
	u32 next_rank_start = 0;
	u32 curr_rank;
	u32 w;
	u32 length;
	u32 i;
	struct huf_deltx2 d;

	isize = huf_readstats(huf_weight, HUF_SYMBOLVALUE_MAX + 1, rank_val,
			&nbsymbols, &tablelog, src, src_size);
	if (isize < 0)
		return isize;

	dtd = huf_get_dtable_desc(huf_table);
	if (tablelog > (u32)(dtd.max_table_log + 1))
		return -1;
	dtd.table_type = 0;
	dtd.table_log = (u8)tablelog;
	memcpy (huf_table, &dtd, sizeof(dtd));

	for (n = 1; n < tablelog + 1; n++) {
		curr_rank = next_rank_start;
		next_rank_start += (rank_val[n] << (n - 1));
		rank_val[n]= curr_rank;
	}

	for (n = 0; n < nbsymbols; n++) {
		w = huf_weight[n];
		length = (1 << w) >> 1;
		d.byte = (u8)n;
		d.nbits = (u8) (tablelog + 1 - w);
		for (i = rank_val[w]; i < rank_val[w] + length; i++)
			dt[i] = d;
		rank_val[w] += length;
	}

	return isize;
}

static ssize_t huf_decompress4x2(unsigned int* huf_table, u8 *dst, ssize_t dst_size,
			u8* src, ssize_t src_size)
{
	u8 *ip = src;

	ssize_t hsize = huf_readtablex2(huf_table, src, src_size);
	if (hsize >= src_size)
		return -1;
	ip += hsize;
	src_size -= hsize;

	return huf_decompress4x2_using_dtable(dst, dst_size, ip, src_size,
			huf_table);
}

static ssize_t huf_decompress4x_hufonly(unsigned int* huf_table, u8 *dst,
			ssize_t dst_size, u8 *src, ssize_t src_size)
{
	u32 algonb = 0;

	if (dst_size == 0 || src_size >= dst_size || src_size <= 1)
		return -1;
	algonb = huf_select_decoder(dst_size, src_size);
	/*
	if (algonb == 1)
		return huf_decompress4x4(huf_table, dst, dst_size, src,
					src_size);
	*/
	return huf_decompress4x2(huf_table, dst, dst_size, src, src_size);
}

static ssize_t zstd_decompress_literals(struct zstd_decompress_context* context,
			void* src, ssize_t src_size)
{
	ssize_t ret = 0;
	u8 *istart = src;
	enum symbol_encoding_type type =
		(enum symbol_encoding_type)(istart[0] & 3);
	ssize_t lhsize;
	ssize_t litsize;
	ssize_t litcsize;
	u32 single_stream = 0;
	u32 lhlcode = (istart[0] >> 2) & 3;
	u32 lhc = read32(istart);

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
		case 3:
			break;
		}

		if (litsize > ZSTD_BLOCKSIZE_ABSOLUTEMAX)
			return -1;
		if (litcsize + lhsize > src_size)
			return -1;

		if (type != set_repeat && single_stream) {
			ret = huf_decompress4x_hufonly(context->huf_table,
				context->lit_buf, litsize,
				istart+lhsize, litcsize);
			if (ret < 0)
				return -1;
		}

		context->lit_ptr = context->lit_buf;
		context->lit_buf_size = ZSTD_BLOCKSIZE_ABSOLUTEMAX
			+ WILDCOPY_OVERLENGTH;
		context->lit_size = litsize;
		context->lit_entropy = 1;
		if (type == set_compressed)
			context->huf_ptr = context->huf_table;
		return litsize + lhsize;
	case set_repeat:
	case set_basic:
	case set_rle:
	default:
		return -1;
	}

	return 0;
}

union fse_decode_t4 {
	struct fse_decode realdata;
	unsigned int alignedby4;
};

#define LL_DEFAULTNORMLOG 6  /* for static allocation */
#define ML_DEFAULTNORMLOG 6  /* for static allocation */
#define OF_DEFAULTNORMLOG 5  /* for static allocation */

static union fse_decode_t4 LL_defaultDTable[(1 << LL_DEFAULTNORMLOG) + 1] = {
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

static union fse_decode_t4 ML_defaultDTable[(1<<ML_DEFAULTNORMLOG)+1] = {
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

static union fse_decode_t4 OF_defaultDTable[(1<<OF_DEFAULTNORMLOG)+1] = {
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

#define FSE_MIN_TABLELOG 5
#define FSE_TABLELOG_ABSOLUTE_MAX 15

static short fse_abs(short a)
{
	return (short) (a < 0? -a:a);
}

static ssize_t fse_read_ncount(short *norm, u32 *maxsvptr, u32 *tablelogptr,
		u8 *headerbuffer, ssize_t hbsize)
{
	u8* istart = headerbuffer;
	u8* iend = istart + hbsize;
	u8* ip = istart;
	int nbits;
	int remaining;
	int threshold;
	u32 bitstream;
	int bitcount;
	u32 charnum = 0;
	int prev0 = 0;
	short max;
	short count;
	u32 n0;

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
			n0 = charnum;

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
			if ((ip <= iend -7) ||
					(ip + (bitcount >> 3) <= iend - 4)) {
				ip += bitcount >> 3;
				bitcount &= 7;
				bitstream = read32(ip) >> bitcount;
			} else {
				bitstream >>= 2;
			}
		}

		max = (short)((2 * threshold - 1) - remaining);

		if ((bitstream & (threshold - 1)) < (u32)max) {
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
			bitcount &= 7;
		} else {
			bitcount -= (int)(8 * (iend - 4 - ip));
			ip = iend - 4;
		}

		bitstream = read32(ip) >> (bitcount & 31);
	}

	if (remaining != 1 || bitcount > 32)
		return -1;

	*maxsvptr = charnum - 1;
	ip += (bitcount + 7) >> 3;
	return ip - istart;
}

#define FSE_TABLESTEP(tableSize) ((tableSize>>1) + (tableSize>>3) + 3)

static int fse_build_dtable(u32 *dt, short* norm, u32 max_symbol_val,
			u32 tablelog)
{
	/* because *dt is unsigned, 32-bits aligned on 32-bits */
	void* tdptr = dt + 1;
	struct fse_decode* decodetab = (struct fse_decode*) (tdptr);
	u16 symbolnext[FSE_MAX_SYMBOL_VALUE + 1];
	u32 maxsv1 = max_symbol_val + 1;
	u32 tablesize = 1 << tablelog;
	u32 high_threshold = tablesize - 1;

	short largelimit;
	struct fse_dtableheader dtableh;
	u32 s;
	u32 tablemask = tablesize - 1;
	u32 step = FSE_TABLESTEP(tablesize);
	u32 position = 0;
	int i;
	u32 u;
	u8 symbol;
	u16 nextstat;

	if (max_symbol_val > FSE_MAX_SYMBOL_VALUE)
		return -1;
	if (tablelog > FSE_MIN_TABLELOG)
		return -1;

	dtableh.tablelog = (unsigned int) tablelog;
	dtableh.fastmode = 1;
	largelimit = (short)(1 << (tablelog - 1));

	for (s = 0; s < maxsv1; s++) {
		if (norm[s] == -1) {
			decodetab[high_threshold--].symbol = (u8)s;
			symbolnext[s] = 1;
		} else {
			if (norm[s] >= largelimit)
				dtableh.fastmode = 0;
			symbolnext[s] = norm[s];
		}
	}
	memcpy(dt, &dtableh, sizeof(dtableh));

	for (s = 0; s < maxsv1; s++) {
		for(i = 0; i < norm[s]; i++) {
			decodetab[position].symbol = (u8)s;
			position = (position + step) & tablemask;
			while (position > high_threshold)
				position = (position + step) & tablemask;
		}
	}

	if (position != 0)
		return -1;

	for (u = 0; u < tablesize; u++) {
		symbol = (u8)(decodetab[u].symbol);
		nextstat = symbolnext[symbol]++;
		decodetab[u].nbits = (u8)(tablelog - bit_highbit32(nextstat));
		decodetab[u].newstat =
			(u16) ((nextstat << decodetab[u].nbits) - tablesize);
	}

	return 0;
}

unsigned int zstd_build_seqtable(unsigned int* dtable, unsigned int** dtableptr,
		enum symbol_encoding_type type, unsigned int max,
		unsigned int maxlog, void* src, unsigned int src_size,
		union fse_decode_t4* default_table, unsigned int flagrep_tab)
{
	short norm[MAX_SEQ + 1];
	unsigned int headersize;
	u32 tablelog;

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
		if (tablelog > maxlog)
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
			int *nbseq_ptr, void* src, unsigned int src_size)
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
			&context->llt_ptr, lltype, MAX_LL, LL_FSELOG,
			ip, iend-ip, LL_defaultDTable, context->fse_entropy);
	if (llhsize == -1)
		return -1;
	ip += llhsize;

	ofhsize = zstd_build_seqtable(context->of_table,
			&context->oft_ptr, oftype, MAX_OFF, OFF_FSELOG,
			ip, iend-ip, OF_defaultDTable, context->fse_entropy);
	if (ofhsize == -1)
		return -1;
	ip += ofhsize;

	mlhsize = zstd_build_seqtable(context->ml_table,
			&context->mlt_ptr, mltype, MAX_ML, ML_FSELOG,
			ip, iend-ip, ML_defaultDTable, context->fse_entropy);
	if (mlhsize == -1)
		return -1;
	ip += mlhsize;

	return ip - istart;
}

struct seq_stat {
	struct bit_dstream dstream;
	struct fse_dstat statll;
	struct fse_dstat statoffb;
	struct fse_dstat statml;
	unsigned int prevoffset[3];
};

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

static u32 llbits[MAX_LL+1] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9,10,11,12,
	13,14,15,16 };

static u32 mlbits[MAX_ML+1] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9,10,11,
	12,13,14,15,16 };

static u32 llbase[MAX_LL+1] = {
	0,  1,  2,  3,  4,  5,  6,  7,  8,  9,   10,    11,    12,    13,    14,
	15, 16, 18, 20, 22, 24, 28, 32, 40, 48,  64,  0x80, 0x100, 0x200, 0x400,
	0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000 };

static u32 mlbase[MAX_ML+1] = {
	3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,  15,  16,  17,
	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,  30,  31,  32,
	33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83,  99, 0x83, 0x103,
	0x203, 0x403, 0x803, 0x1003, 0x2003, 0x4003, 0x8003, 0x10003 };

static u32 ofbase[MAX_OFF+1] = {
	0,        1,       1,       5,     0xD,     0x1D,     0x3D,     0x7D,
	0xFD,   0x1FD,   0x3FD,   0x7FD,   0xFFD,   0x1FFD,   0x3FFD,   0x7FFD,
	0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD,0x7FFFFD,
	0xFFFFFD, 0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD };

static void fse_update_state(struct fse_dstat *dstate, struct bit_dstream *bit)
{
	struct fse_decode dinfo =
		((struct fse_decode*)(dstate->table))[dstate->stat];
	u32 nbits = dinfo.nbits;
	size_t lowbits = bit_readbits(bit, nbits);
	dstate->stat = dinfo.newstat + lowbits;
}

static struct seq zstd_decode_sequence(struct seq_stat* seqstat)
{
	u32 llcode = fse_peeksymbol(&seqstat->statll);
	u32 mlcode = fse_peeksymbol(&seqstat->statml);
	u32 ofcode = fse_peeksymbol(&seqstat->statoffb);

	u32 llbit = llbits[llcode];
	u32 mlbit = mlbits[mlcode];
	u32 ofbit = ofcode;
#if BITS_PER_LONG == 64
	u32 totalbits = llbit + mlbit + ofbit;
#endif

	size_t offset;
	size_t tmp;
	struct seq seq;

	if (!ofcode) {
		offset = 0;
	} else {
		offset = ofbase[ofcode]
			+ bit_readbits(&seqstat->dstream, ofbit);
#if BITS_PER_LONG == 32
		bit_reload_dstream(&seqstat->dstream);
#endif
	}

	if (ofcode <= 1) {
		offset += (llcode == 0);

		if (offset) {
			tmp = (offset == 3)? seqstat->prevoffset[0] - 1
				:seqstat->prevoffset[offset];
			tmp += !tmp;
			if (offset != 1)
				seqstat->prevoffset[2] = seqstat->prevoffset[1];
			seqstat->prevoffset[1] = seqstat->prevoffset[0];
			seqstat->prevoffset[0] = offset = tmp;
		} else {
			offset = seqstat->prevoffset[0];
		}
	} else {
		seqstat->prevoffset[2] = seqstat->prevoffset[1];
		seqstat->prevoffset[1] = seqstat->prevoffset[0];
		seqstat->prevoffset[0] = offset;
	}

	seq.offset = offset;
	seq.matchlenth = mlbase[mlcode]
		+ ((mlcode > 32) ? bit_readbits(&seqstat->dstream, mlbit) : 0);
#if BITS_PER_LONG == 32
	if (mlbits + llbits > 24)
		bit_reload_dstream(&seqstat->dstream);
#endif
	seq.litlength = llbase[llcode]
		+ ((llcode > 32) ? bit_readbits(&seqstat->dstream, llbit) : 0);
#if BITS_PER_LONG == 32
	bit_reload_dstream(&seqstat->dstream);
#else
	if (totalbits > 64 - 7 - (LL_FSELOG + ML_FSELOG + OFF_FSELOG))
		bit_reload_dstream(&seqstat->dstream);
#endif
	/* ANS state update */
	fse_update_state(&seqstat->statll, &seqstat->dstream);
	fse_update_state(&seqstat->statml, &seqstat->dstream);
#if BITS_PER_LONG == 32
	bit_reload_dstream(&seqstat->dstream);
#endif
	fse_update_state(&seqstat->statoffb, &seqstat->dstream);

	return seq;
}

#define MINMATCH 3

static ssize_t zstd_exec_sequence(u8 *op, u8 *oend, struct seq sequence,
			u8 **litptr, u8 *lit_limit, u8 *base, u8 *vbase,
			u8 *dict_end)
{
	u8 *olit_end = op + sequence.litlength;
	size_t sequence_len = sequence.litlength + sequence.matchlenth;
	u8 *omatch_end = op + sequence_len;
	u8 *oend_w = oend - WILDCOPY_OVERLENGTH;
	u8 *ilitend = *litptr + sequence.litlength;
	u8 *match = olit_end - sequence.offset;
	size_t len;
	u32 dec32table[] = { 0, 1, 2, 1, 4, 4, 4, 4 };
	int dec64table[] = { 8, 8, 8, 7, 8, 9,10,11 };
	int sub2;

	if (olit_end > oend_w || omatch_end > oend)
		return -1;

	if (ilitend > lit_limit)
		return -1;

	memcpy(op, *litptr, 8);
	if (sequence.litlength > 8)
		zstd_wildcopy(op + 8, (*litptr) + 8, sequence.litlength - 8);
	op = olit_end;
	*litptr = ilitend;

	if (sequence.offset > (olit_end - base)) {
		if (sequence.offset > (olit_end - vbase))
			return -1;
		match = dict_end - (base - match);
		if (match + sequence.matchlenth <= dict_end) {
			memmove(olit_end, match, sequence.matchlenth);
			return sequence_len;
		}

		len = dict_end - match;
		memmove(olit_end, match, len);
		op = olit_end + len;
		sequence.matchlenth -= len;
		match = base;
		if (op > oend_w) {
			while (op < omatch_end)
				*op++ = *match--;
			return sequence_len;
		}
	}

	if (sequence.offset < 8) {
		sub2 = dec64table[sequence.offset];
		op[0] = match[0];
		op[1] = match[1];
		op[2] = match[2];
		op[3] = match[3];
		match += dec32table[sequence.offset];
		memcpy(op + 4, match, 4);
		match -= sub2;
	} else {
		memcpy(op, match, 8);
	}

	op += 8;
	match += 8;

	if (omatch_end > oend - (16 - MINMATCH)) {
		if (op < oend_w) {
			zstd_wildcopy(op, match, oend_w - op);
			match += oend_w - op;
			op = oend_w;
		}
		while (op < omatch_end)
			*op++ = *match++;
	} else {
		zstd_wildcopy(op, match, sequence.matchlenth - 8);
	}

	return sequence_len;
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
	unsigned char* dictend = (unsigned char*)(context->dict_end);
	int nbseq;
	struct seq_stat seqstat;
	unsigned int i;
	struct seq sequence;
	ssize_t one_seq_size;
	size_t last_llsize;

	/* Build Decoding Tables */
	unsigned int seqhsize = zstd_decode_seqheader(context,
				&nbseq, ip, seq_size);
	if (seqhsize == -1)
		return -1;
	ip += seqhsize;

	/* Regen sequence */
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

		while((bit_reload_dstream(&seqstat.dstream)
				<= BIT_DStream_completed) && nbseq) {
			nbseq--;
			sequence = zstd_decode_sequence(&seqstat);
			one_seq_size = zstd_exec_sequence(op, oend, sequence,
				&litptr, lit_limit, base, vbase, dictend);
			if (one_seq_size == -1)
				return -1;
			op += one_seq_size;
		}

		if (nbseq)
			return -1;
		for (i = 0; i < ZSTD_REP_NUM; i++)
			context->rep[i] = (u32)(seqstat.prevoffset[i]);
	}

	last_llsize = litend - litptr;
	if (last_llsize > (oend - op))
		return -1;
	memcpy (op, litptr, last_llsize);
	return op - ostart;
}

static ssize_t zstd_decompress_block(struct zstd_decompress_context* context,
			void* dst, ssize_t dst_size,
			void* src, ssize_t src_size)
{
	u8 *ip = src;
	ssize_t lit_size = 0;

	if (src_size >= ZSTD_BLOCKSIZE_ABSOLUTEMAX)
		return -1;

	lit_size = zstd_decompress_literals(context, src, src_size);
	if (lit_size == -1)
		return -1;
	ip += lit_size;
	src_size -= lit_size;

	return zstd_decompress_sequnences(context, dst, dst_size, ip, src_size);
}

u64 PRIME64_1 = 11400714785074694791ULL;
u64 PRIME64_2 = 14029467366897019727ULL;
u64 PRIME64_3 =  1609587929392839161ULL;
u64 PRIME64_4 =  9650029242287828579ULL;
u64 PRIME64_5 =  2870177450012600261ULL;

#define xxh_rotl64(x,r) ((x << r) | (x >> (64 - r)))

static u64 xxh64_round(u64 acc, u64 input)
{
	acc += input * PRIME64_2;
	acc = xxh_rotl64(acc, 31);
	acc *= PRIME64_1;

	return acc;
}

static int xxh64_update(struct xxh64_state* state, void* input, size_t len)
{
	u8 *p = input;
	u8 *bend = p + len;
	u8 *limit;
	u64 v1, v2, v3, v4;

	state->total_len += len;

	if (state->memsize + len < 32) {
		memcpy (((u8*)state->mem64) + state->memsize, input, len);
		state->memsize += (u32)len;
		return 0;
	}

	if (state->memsize) {
		memcpy (((u8*)state->mem64) + state->memsize,
				input, 32 - state->memsize);
		state->v1 = xxh64_round(state->v1, read64(state->mem64 + 0));
		state->v2 = xxh64_round(state->v1, read64(state->mem64 + 1));
		state->v3 = xxh64_round(state->v1, read64(state->mem64 + 2));
		state->v4 = xxh64_round(state->v1, read64(state->mem64 + 3));

		p += 32 - state->memsize;
		state->memsize = 0;
	}

	if (p + 32 <= bend) {
		limit = bend - 32;

		do {
			v1 = xxh64_round(v1, read64(p));
			p += 8;
			v2 = xxh64_round(v2, read64(p));
			p += 8;
			v3 = xxh64_round(v3, read64(p));
			p += 8;
			v4 = xxh64_round(v4, read64(p));
			p += 8;
		} while (p <= limit);

		state->v1 = v1;
		state->v2 = v2;
		state->v3 = v3;
		state->v4 = v4;
	}

	if (p < bend) {
		memcpy (state->mem64, p, (size_t)(bend - p));
		state->memsize = (unsigned int)(bend - p);
	}

	return 0;
}

static u64 xxh64_merge_round(u64 acc, u64 val)
{
	val = xxh64_round(0, val);
	acc ^= val;
	acc = acc * PRIME64_1 + PRIME64_4;

	return acc;
}

static u64 xxh64_digest(struct xxh64_state *state)
{
	u8 *p = (u8*)state->mem64;
	u8 *bend = (u8*)state->mem64 + state->memsize;
	u64 h64;
	u64 v1;
	u64 v2;
	u64 v3;
	u64 v4;
	u64 k1;

	if (state->total_len >= 32) {
		v1 = state->v1;
		v2 = state->v2;
		v3 = state->v3;
		v4 = state->v4;

		h64 = xxh_rotl64(v1, 1) + xxh_rotl64(v2, 7)
			+ xxh_rotl64(v3, 12) + xxh_rotl64(v4, 18);
		h64 = xxh64_merge_round(h64, v1);
		h64 = xxh64_merge_round(h64, v2);
		h64 = xxh64_merge_round(h64, v3);
		h64 = xxh64_merge_round(h64, v4);
	} else {
		h64 = state->v3 + PRIME64_5;
	}

	h64 += (u64) state->total_len;

	while (p + 8 <= bend) {
		k1 = xxh64_round(0, read64(p));
		h64 ^= k1;
		h64 = xxh_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
		p += 8;
	}

	if (p + 4 <= bend) {
		h64 ^= (u64) (read32(p) * PRIME64_1);
		h64 = xxh_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
		p += 4;
	}

	while (p < bend) {
		h64 ^= (*p) * PRIME64_5;
		h64 = xxh_rotl64(h64, 11) * PRIME64_1;
		p++;
	}

	h64 ^= h64 >> 33;
	h64 *= PRIME64_2;
	h64 ^= h64 >> 29;
	h64 *= PRIME64_3;
	h64 ^= h64 >> 32;

	return h64;
}

static ssize_t zstd_decompress_frame(struct zstd_decompress_context* context,
			void* dst, ssize_t dst_size,
			void* src, ssize_t src_size)
{
	u8 *ip = src;
	u8 *ostart = dst;
	u8 *oend = ostart + dst_size;
	u8 *op = ostart;

	ssize_t remain = src_size;
	ssize_t frame_header_size;
	ssize_t decode_size;
	ssize_t block_size = 0;
	struct block_properties properties;
	u32 check_calc;
	u32 check_read;

	if (src_size < 9)
		return -1;

	frame_header_size = zstd_get_frame_header_size(src, src_size);

	ip += frame_header_size;
	remain -= frame_header_size;

	while (1) {
		block_size = zstd_get_block_size(ip, remain, &properties);
		if (block_size < 0)
			return block_size;

		ip += ZSTD_BLOCK_HEADER_SIZE;
		remain -= ZSTD_BLOCK_HEADER_SIZE;
		if (block_size > remain)
			return -1;

		switch (properties.type) {
		case bt_compressed:
			decode_size = zstd_decompress_block(context,
					op, oend-op, ip, block_size);
			break;
		case bt_raw:
		case bt_rle:
		case bt_reserved:
		default:
			return -1;
		}

		if (decode_size == -1)
			return -1;

		if (context->param.checksum_flag)
			xxh64_update(&context->xxh_state, op, decode_size);

		op += decode_size;
		ip += block_size;
		remain -= block_size;
		if (properties.last_block)
			break;
	}

	if (context->param.checksum_flag) {
		check_calc = (u32) xxh64_digest(&context->xxh_state);
		check_read = read32(ip);
		if (check_calc != check_calc)
			return -1;
		remain -= 4;
	}

	if (remain)
		return -1;

	return op - ostart;
}

ssize_t zstd_decompress(void* dst, ssize_t dst_size,
		    void* src, ssize_t src_size)
{
	struct zstd_decompress_context *ctx;
	ssize_t ret;

	ctx = calloc(sizeof(struct zstd_decompress_context));
	if (ctx == NULL)
		return -ENOMEM;

	init_zstd_decompress_context(ctx, dst);
	ret = zstd_decompress_frame(ctx, dst, dst_size, src, src_size);

	free(ctx);

	return ret;
}
