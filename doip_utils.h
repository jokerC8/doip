#ifndef __DOIP_UTILS_H__
#define __DOIP_UTILS_H__

#include <stdio.h>
#include <time.h>
#include <assert.h>

void *doip_malloc(unsigned long size);

void *doip_calloc(unsigned long nmemb, unsigned long size);

void doip_free(void *ptr);

#define DOIP_DEBUG_ENABLE

#ifndef ARRAYSIZE
#define ARRAYSIZE(arr) (sizeof(arr)/sizeof(arr[0]))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#define doip_assert(expr, format, args...) do {\
	if (!!!(expr)) { \
		loge(format, ##args); \
		assert(!!(expr)); \
	} \
} while (0)

#ifdef DOIP_DEBUG_ENABLE

#define logd(format, args...) do {\
	int offset = 0; \
	char __buffer__[1024] = {0}; \
	time_t cur; \
	struct tm tm; \
	time(&cur); \
	localtime_r(&cur, &tm); \
	offset += strftime(__buffer__ + offset, sizeof(__buffer__) - offset, "\033[32m%Y-%m-%d %H:%M:%S ", &tm); \
	offset += snprintf(__buffer__ + offset, sizeof(__buffer__) - offset, "[func:%s, line:%d] " format "\033[0m", __FUNCTION__, __LINE__, ##args); \
	fprintf(stdout, "%s", __buffer__); \
} while (0)

#define loge(format, args...) do {\
	int offset = 0; \
	char __buffer__[1024] = {0}; \
	time_t cur; \
	struct tm tm; \
	time(&cur); \
	localtime_r(&cur, &tm); \
	offset += strftime(__buffer__ + offset, sizeof(__buffer__) - offset, "\033[31m%Y-%m-%d %H:%M:%S ", &tm); \
	offset += snprintf(__buffer__ + offset, sizeof(__buffer__) - offset, "[func:%s, line:%d] " format "\033[0m", __FUNCTION__, __LINE__, ##args); \
	fprintf(stderr, "%s", __buffer__); \
} while (0)

#define doip_hexdump(data, len) do { \
	int offset = 0; \
	char __buffer__[4096] = {0}; \
	time_t cur; \
	struct tm tm; \
	time(&cur); \
	localtime_r(&cur, &tm); \
	offset += strftime(__buffer__ + offset, sizeof(__buffer__) - offset, "\033[32m%Y-%m-%d %H:%M:%S ", &tm); \
	offset += snprintf(__buffer__ + offset, sizeof(__buffer__) - offset, "[line:%d, func:%s] ", __LINE__, __FUNCTION__); \
	for (uint32_t i = 0; i < len; ++i) { \
		offset += snprintf(__buffer__ + offset, sizeof(__buffer__) - offset, "%02x ", (data)[i]); \
	} \
	offset += snprintf(__buffer__ + offset, sizeof(__buffer__) - offset, "\033[0m"); \
	fprintf(stdout, "%s\n", __buffer__); \
} while (0)

#else

#define logd(format, args...)
#define loge(format, args...)
#define doip_hexdump(data, len)

#endif

#endif
