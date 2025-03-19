#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "doip_entity.h"

#define VIN "0123456789abcdefg"
#define EID "\x1a\x2b\x3c\x4d\x5e\x6f"

#define ARRAYSIZE(arr) (sizeof(arr)/sizeof(arr[0]))

int main()
{
	uint16_t *white_list = malloc(100 * sizeof(uint16_t));

	for (int i = 0; i < 100; i++) {
		white_list[i] = 0x00fc + i;
	}

	doip_entity_t *doip_entity = doip_entity_alloc(0x00fb, 0xe400, "127.0.0.1", 13400, "127.0.0.1", 13400);

	/* 设置doip entity vin */
	doip_entity_set_vin(doip_entity, VIN, sizeof(VIN) - 1);

	/* 设置允许路由激活的ECU逻辑地址白名单 */
	doip_entity_set_white_list(doip_entity, white_list, 100);

	/* 启动doip entity */
	doip_entity_start(doip_entity);

	return 0;
}
