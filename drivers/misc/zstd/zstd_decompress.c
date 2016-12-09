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

static unsigned int
huf_decompress4x_hufonly(unsigned int* huf_table, void* dst,
			unsigned int dst_size, const void* src,
			unsigned int src_size)
{
	unsigned int algonb = 0;

	if (src_size >= dst_size || src_size <= 1)
		return -1;
	/*
	algonb = huf_select_decoder(dst_size, src_size);
	if (algonb == 1)
		return huf_decompress4x4(huf_table, dst, dst_size, src,
					src_size);
	return huf_decompress4x2(huf_table, dst, dst_size, src, src_size);
	*/
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
