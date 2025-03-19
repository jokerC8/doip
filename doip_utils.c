#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "doip_entity.h"

void *doip_malloc(unsigned long size)
{
	return calloc(1, size);
}

void *doip_calloc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

void doip_free(void *ptr)
{
	if (ptr) {
		free(ptr);
	}
}
