#ifndef __DOIP_UTILS_H__
#define __DOIP_UTILS_H__

#include <stdio.h>
#include <time.h>

void *doip_malloc(unsigned long size);

void *doip_calloc(unsigned long nmemb, unsigned long size);

void doip_free(void *ptr);

#define logd(format, args...) do {\
	int offset = 0; \
	char buffer[1024] = {0}; \
	time_t cur; \
	struct tm tm; \
	time(&cur); \
	localtime_r(&cur, &tm); \
	offset += strftime(buffer + offset, sizeof(buffer) - offset, "\033[32m%Y-%m-%d %H:%M:%S ", &tm); \
	offset += snprintf(buffer + offset, sizeof(buffer) - offset, "[line:%d, func:%s] " format "\033[0m", __LINE__, __FUNCTION__, ##args); \
	fprintf(stdout, "%s", buffer); \
} while (0)

#define loge(format, args...) do {\
	int offset = 0; \
	char buffer[1024] = {0}; \
	time_t cur; \
	struct tm tm; \
	time(&cur); \
	localtime_r(&cur, &tm); \
	offset += strftime(buffer + offset, sizeof(buffer) - offset, "\033[31m%Y-%m-%d %H:%M:%S ", &tm); \
	offset += snprintf(buffer + offset, sizeof(buffer) - offset, "[line:%d, func:%s] " format "\033[0m", __LINE__, __FUNCTION__, ##args); \
	fprintf(stderr, "%s", buffer); \
} while (0)

#define doip_assert(expr, format, args...) do {\
	if (!!!expr) { \
		loge(format, ##args); \
		assert(!!expr); \
	} \
} while (0)

#define doip_hexdump(data, len) do { \
	int offset = 0; \
	char buffer[4096] = {0}; \
	time_t cur; \
	struct tm tm; \
	time(&cur); \
	localtime_r(&cur, &tm); \
	offset += strftime(buffer + offset, sizeof(buffer) - offset, "\033[32m%Y-%m-%d %H:%M:%S ", &tm); \
	offset += snprintf(buffer + offset, sizeof(buffer) - offset, "[line:%d, func:%s] ", __LINE__, __FUNCTION__); \
	for (uint32_t i = 0; i < len; ++i) { \
		offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%02x ", data[i]); \
	} \
	offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\033[0m"); \
	fprintf(stdout, "%s\n", buffer); \
} while (0)

#endif
