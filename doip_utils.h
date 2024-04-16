#ifndef __DOIP_UTILS_H__
#define __DOIP_UTILS_H__

void *doip_malloc(unsigned long size);

void *doip_calloc(unsigned long nmemb, unsigned long size);

void doip_free(void *ptr);

#define logd(format, args...) do {\
	char buffer[1024] = {0}; \
	snprintf(buffer, sizeof(buffer), "\033[32m[line:%d, func:%s]" format "\033[0m", __LINE__, __FUNCTION__, ##args); \
	fprintf(stdout, "%s", buffer); \
} while (0)

#define loge(format, ...) do {\
	char buffer[1024] = {0}; \
	snprintf(buffer, sizeof(buffer), "\033[31m[line:%d, func:%s]" format "\033[0m", __LINE__, __FUNCTION__, ##args); \
	fprintf(stderr, "%s", buffer); \
} while (0)

#endif
