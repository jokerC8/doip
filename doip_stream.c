#include "doip_stream.h"
#include <string.h>

void doip_stream_init(doip_stream_t *doip_stream, unsigned char *data, unsigned int len)
{
	doip_stream->len = 0;
	doip_stream->cap = len;
	doip_stream->curr = data;
	doip_stream->start = data;
}

void doip_stream_reset(doip_stream_t *doip_stream)
{
	if (doip_stream) {
		doip_stream->curr = doip_stream->start;
		doip_stream->len = 0;
	}
}

unsigned int doip_stream_left_len(doip_stream_t *doip_stream)
{
	if (doip_stream->cap >= doip_stream->len) {
		return doip_stream->cap - doip_stream->len;
	}
	return 0;
}

unsigned int doip_stream_len(doip_stream_t *doip_stream)
{
	return doip_stream->len;
}

unsigned int doip_stream_cap(doip_stream_t *doip_stream)
{
	return doip_stream->cap;
}

unsigned char *doip_stream_ptr(doip_stream_t *doip_stream)
{
	return doip_stream->curr;
}

uint8_t *doip_stream_start_ptr(doip_stream_t *doip_stream)
{
	return doip_stream->start;
}

uint32_t doip_stream_forward(doip_stream_t *doip_stream, uint32_t step)
{
	uint32_t offset = (doip_stream->cap - doip_stream->len >= step) ? step : doip_stream->cap - doip_stream->len;

	doip_stream->curr += offset;
	doip_stream->len += offset;

	return offset;
}

uint32_t doip_stream_move_backward(doip_stream_t *doip_stream, uint32_t step)
{
	uint32_t offset = (doip_stream->len >= step) ? step : doip_stream->len;

	doip_stream->curr -= offset;
	doip_stream->len -= offset;

	return offset;
}

uint32_t doip_stream_write_byte(doip_stream_t *doip_stream, uint8_t val)
{
	if (doip_stream_left_len(doip_stream) >= 1) {
		*doip_stream->curr++ = val;
		++doip_stream->len;
		return 1;
	}
	return 0;
}

uint32_t doip_stream_write_be16(doip_stream_t *doip_stream, uint16_t val)
{
	uint32_t cnt = 0;

	cnt += doip_stream_write_byte(doip_stream, (uint8_t)(val >> 8));
	cnt += doip_stream_write_byte(doip_stream, (uint8_t)val);
	return cnt;
}

uint32_t doip_stream_write_be32(doip_stream_t *doip_stream, uint32_t val)
{
	uint32_t cnt = 0;

	cnt += doip_stream_write_be16(doip_stream, (uint16_t)(val >> 16));
	cnt += doip_stream_write_be16(doip_stream, (uint16_t)val);
	return cnt;
}

uint32_t doip_stream_write_be64(doip_stream_t *doip_stream, uint64_t val)
{
	uint32_t cnt = 0;

	cnt += doip_stream_write_be32(doip_stream, (uint32_t)(val >> 32));
	cnt += doip_stream_write_be32(doip_stream, (uint32_t)val);
	return cnt;
}

uint32_t doip_stream_write_le16(doip_stream_t *doip_stream, uint16_t val)
{
	uint32_t cnt = 0;

	cnt += doip_stream_write_byte(doip_stream, (uint8_t)val);
	cnt += doip_stream_write_byte(doip_stream, (uint8_t)(val >> 8));
	return cnt;
}

uint32_t doip_stream_write_le32(doip_stream_t *doip_stream, uint32_t val)
{
	uint32_t cnt = 0;

	cnt += doip_stream_write_le16(doip_stream, (uint16_t)(val));
	cnt += doip_stream_write_le16(doip_stream, (uint16_t)(val >> 16));
	return cnt;
}

uint32_t doip_stream_write_le64(doip_stream_t *doip_stream, uint64_t val)
{
	uint32_t cnt = 0;

	cnt += doip_stream_write_le32(doip_stream, (uint32_t)(val));
	cnt += doip_stream_write_le32(doip_stream, (uint32_t)(val >> 32));
	return cnt;
}

uint32_t doip_stream_write_data(doip_stream_t *doip_stream, uint8_t *data, uint32_t len)
{
	uint32_t cnt = 0;

	for (uint32_t i = 0; i < len; ++i) {
		if (doip_stream_left_len(doip_stream) > 0) {
			cnt += doip_stream_write_byte(doip_stream, data[i]);
		}
		else {
			break;
		}
	}
	return cnt;
}

uint32_t doip_stream_write_string(doip_stream_t *doip_stream, const char *str)
{
	return doip_stream_write_data(doip_stream, (uint8_t *)str, strlen(str));
}

uint8_t doip_stream_read_byte(doip_stream_t *doip_stream)
{
	uint8_t val = 0;

	if (doip_stream->cap - doip_stream->len >= 1) {
		val = *doip_stream->curr++;
		++doip_stream->len;
	}
	return val;
}

uint16_t doip_stream_read_be16(doip_stream_t *doip_stream)
{
	uint16_t val = 0;

	if (doip_stream->cap - doip_stream->len >= 2) {
		uint16_t hi = doip_stream_read_byte(doip_stream);
		uint16_t lo = doip_stream_read_byte(doip_stream);
		val = hi << 8 | lo;
	}
	return val;
}

uint32_t doip_stream_read_be32(doip_stream_t *doip_stream)
{
	uint32_t val = 0;

	if (doip_stream->cap - doip_stream->len >= 4) {
		uint32_t hi = doip_stream_read_be16(doip_stream);
		uint32_t lo = doip_stream_read_be16(doip_stream);
		val = hi << 16 | lo;
	}
	return val;
}

uint64_t doip_stream_read_be64(doip_stream_t *doip_stream)
{
	uint64_t val = 0;

	if (doip_stream->cap - doip_stream->len >= 1) {
		uint64_t hi = doip_stream_read_be32(doip_stream);
		uint64_t lo = doip_stream_read_be32(doip_stream);
		val = hi << 32 | lo;
	}
	return val;
}

uint16_t doip_stream_read_le16(doip_stream_t *doip_stream)
{
	uint16_t val = 0;

	if (doip_stream->cap - doip_stream->len >= 2) {
		uint16_t lo = doip_stream_read_byte(doip_stream);
		uint16_t hi = doip_stream_read_byte(doip_stream);
		val = hi << 8 | lo;
	}
	return val;
}

uint32_t doip_stream_read_le32(doip_stream_t *doip_stream)
{
	uint32_t val = 0;

	if (doip_stream->cap - doip_stream->len >= 4) {
		uint32_t lo = doip_stream_read_le16(doip_stream);
		uint32_t hi = doip_stream_read_le16(doip_stream);
		val = hi << 16 | lo;
	}
	return val;
}

uint64_t doip_stream_read_le64(doip_stream_t *doip_stream)
{
	uint64_t val = 0;

	if (doip_stream->cap - doip_stream->len >= 8) {
		uint64_t lo = doip_stream_read_le32(doip_stream);
		uint64_t hi = doip_stream_read_le32(doip_stream);
		val = hi << 32 | lo;
	}
	return val;
}

uint32_t doip_stream_read_data(doip_stream_t *doip_stream, uint8_t *buffer, uint32_t len)
{
	uint32_t i = 0;

	for (; i < len; ++i) {
		if (doip_stream_left_len(doip_stream) > 0) {
			buffer[i] = doip_stream_read_byte(doip_stream);
		}
		else {
			break;
		}
	}
	return i;
}
