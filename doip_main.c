#include <stdint.h>
#include <stdlib.h>
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

	doip_entity_t *doip_entity = doip_entity_alloc();

	doip_entity_set_eid(doip_entity, (unsigned char *)EID);

	doip_entity_set_vin(doip_entity, VIN, sizeof(VIN) - 1);

	doip_entity_set_max_tcp_clients(doip_entity, 100);

	doip_entity_set_tcp_server(doip_entity, "127.0.0.1", 13400);

	doip_entity_set_udp_server(doip_entity, "127.0.0.1", 13400);

	doip_entity_set_logic_addr(doip_entity, 0x00fb);

	doip_entity_set_func_addr(doip_entity, 0xf400);

	doip_entity_set_white_list(doip_entity, white_list, 100);

	doip_entity_start(doip_entity);

	return 0;
}
