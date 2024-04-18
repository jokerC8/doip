#ifndef __DOIP_UTILS_H__
#define __DOIP_UTILS_H__

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

#define loge(format, ...) do {\
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

#endif
