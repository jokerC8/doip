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

uint32_t doip_stream_left_len(doip_stream_t *doip_stream);

uint32_t doip_stream_len(doip_stream_t *doip_stream);

uint32_t doip_stream_cap(doip_stream_t *doip_stream);

uint8_t *doip_stream_current_ptr(doip_stream_t *doip_stream);

uint8_t *doip_stream_start_ptr(doip_stream_t *doip_stream);

uint32_t doip_stream_move_forward(doip_stream_t *doip_stream, uint32_t step);

uint32_t doip_stream_move_backward(doip_stream_t *doip_stream, uint32_t step);

uint32_t doip_stream_write_byte(doip_stream_t *doip_stream, uint8_t val);

uint32_t doip_stream_write_hword(doip_stream_t *doip_stream, uint16_t val);

uint32_t doip_stream_write_word(doip_stream_t *doip_stream, uint32_t val);

uint32_t doip_stream_write_double_word(doip_stream_t *doip_stream, uint64_t val);

uint32_t doip_stream_write_le_hword(doip_stream_t *doip_stream, uint16_t val);

uint32_t doip_stream_write_le_word(doip_stream_t *doip_stream, uint32_t val);

uint32_t doip_stream_write_le_double_word(doip_stream_t *doip_stream, uint64_t val);

uint32_t doip_stream_write_data(doip_stream_t *doip_stream, uint8_t *data, uint32_t len);

uint32_t doip_stream_write_string(doip_stream_t *doip_stream, const char *str);

uint8_t doip_stream_read_byte(doip_stream_t *doip_stream);

uint16_t doip_stream_read_hword(doip_stream_t *doip_stream);

uint32_t doip_stream_read_word(doip_stream_t *doip_stream);

uint64_t doip_stream_read_double_word(doip_stream_t *doip_stream);

uint16_t doip_stream_read_le_hword(doip_stream_t *doip_stream);

uint32_t doip_stream_read_le_word(doip_stream_t *doip_stream);

uint64_t doip_stream_read_le_double_word(doip_stream_t *doip_stream);

uint32_t doip_stream_read_data(doip_stream_t *doip_stream, uint8_t *buffer, uint32_t len);

#endif
