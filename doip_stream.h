#ifndef __DOIP_STREAM_H__
#define __DOIP_STREAM_H__

#include <stdint.h>

struct doip_stream {
	uint32_t cap;
	uint32_t len;
	uint8_t *curr;
	uint8_t *start;
};

typedef struct doip_stream doip_stream_t;

void doip_stream_init(doip_stream_t *doip_stream, unsigned char *data, unsigned int len);

void doip_stream_reset(doip_stream_t *doip_stream);

uint32_t doip_stream_left_len(doip_stream_t *doip_stream);

uint32_t doip_stream_len(doip_stream_t *doip_stream);

uint32_t doip_stream_cap(doip_stream_t *doip_stream);

uint8_t *doip_stream_ptr(doip_stream_t *doip_stream);

uint8_t *doip_stream_start_ptr(doip_stream_t *doip_stream);

uint32_t doip_stream_forward(doip_stream_t *doip_stream, uint32_t step);

uint32_t doip_stream_backward(doip_stream_t *doip_stream, uint32_t step);

uint32_t doip_stream_write_byte(doip_stream_t *doip_stream, uint8_t val);

uint32_t doip_stream_write_be16(doip_stream_t *doip_stream, uint16_t val);

uint32_t doip_stream_write_be32(doip_stream_t *doip_stream, uint32_t val);

uint32_t doip_stream_write_be64(doip_stream_t *doip_stream, uint64_t val);

uint32_t doip_stream_write_le16(doip_stream_t *doip_stream, uint16_t val);

uint32_t doip_stream_write_le32(doip_stream_t *doip_stream, uint32_t val);

uint32_t doip_stream_write_le64(doip_stream_t *doip_stream, uint64_t val);

uint32_t doip_stream_write_data(doip_stream_t *doip_stream, uint8_t *data, uint32_t len);

uint32_t doip_stream_write_string(doip_stream_t *doip_stream, const char *str);

uint8_t doip_stream_read_byte(doip_stream_t *doip_stream);

uint16_t doip_stream_read_be16(doip_stream_t *doip_stream);

uint32_t doip_stream_read_be32(doip_stream_t *doip_stream);

uint64_t doip_stream_read_be64(doip_stream_t *doip_stream);

uint16_t doip_stream_read_le16(doip_stream_t *doip_stream);

uint32_t doip_stream_read_le32(doip_stream_t *doip_stream);

uint64_t doip_stream_read_le64(doip_stream_t *doip_stream);

uint32_t doip_stream_read_data(doip_stream_t *doip_stream, uint8_t *buffer, uint32_t len);

#endif
