#include "doip_entity.h"
#include "list.h"

#include <ev.h>
#include <assert.h>
#include <stdint.h>

typedef struct doip_client {
	uint8_t status;
	int handler;
	char client[32];
	uint16_t port;
	ev_io *watcher;
	ev_timer *initial_activity_timer;
	ev_timer *general_activity_timer;
	struct list_head list;
	doip_entity_t *doip_entity;
} doip_client_t;

typedef struct doip_server {
	uint8_t status;
	int handler;
	char addr[32];
	uint16_t port;
	ev_io *watcher;
	struct list_head head;
	doip_entity_t *doip_entity;
} doip_server_t;

struct doip_entity {
	void *userdata;
	uint16_t logic_addr;
	uint16_t func_addr;
	uint16_t *white_list;
	uint16_t white_list_count;
	int initial_activity_time;
	int general_activity_time;
	int announce_wait_time;
	int announce_count;
	int announce_internal;
	doip_server_t tcp_server;
	doip_server_t udp_server;
	ev_prepare *prepare_w;
#ifdef EV_MULTIPLICITY
	struct ev_loop *loop;
#else
	int loop;
#endif
};

static void doip_assert(uint8_t expr, const char *comment)
{
	if (!expr) {
		printf("%s\n", comment);
		assert(expr);
	}
}

doip_entity_t *doip_entity_alloc()
{
	doip_entity_t *doip_entity = malloc(sizeof(*doip_entity));

	if (!doip_entity) {
		return NULL;
	}

	bzero(doip_entity, sizeof(*doip_entity));
	doip_entity->loop = ev_default_loop(0);
	doip_entity->prepare_w = malloc(sizeof(ev_prepare));
	doip_entity->tcp_server.watcher = malloc(sizeof(ev_io));
	doip_entity->udp_server.watcher = malloc(sizeof(ev_io));

	doip_entity->tcp_server.doip_entity = doip_entity;
	doip_entity->udp_server.doip_entity = doip_entity;

	doip_assert(doip_entity->loop && \
			doip_entity->prepare_w && \
			doip_entity->tcp_server.watcher && \
			doip_entity->udp_server.watcher, "malloc failed");

	doip_entity->initial_activity_time = 1;
	doip_entity->general_activity_time = 1;
	doip_entity->announce_count = 3;
	doip_entity->announce_internal = 1;
	doip_entity->announce_wait_time = 300;

	return doip_entity;
}

void doip_entity_set_userdata(doip_entity_t *doip_entity, void *userdata)
{
	if (doip_entity) {
		doip_entity->userdata = userdata;
	}
}

void *doip_entity_userdata(doip_entity_t *doip_entity)
{
	if (doip_entity) {
		return doip_entity->userdata;
	}
	return NULL;
}

void doip_entity_set_initial_activity_time(doip_entity_t *doip_entity, int time)
{
	if (doip_entity) {
		doip_entity->initial_activity_time = time;
	}
}

void doip_entity_set_general_activity_time(doip_entity_t *doip_entity, int time)
{
	if (doip_entity) {
		doip_entity->general_activity_time = time;
	}
}

void doip_entity_set_announce_wait_time(doip_entity_t *doip_entity, int time)
{
	if (doip_entity) {
		doip_entity->announce_wait_time = time;
	}
}

void doip_entity_set_announce_count(doip_entity_t *doip_entity, int count)
{
	if (doip_entity) {
		doip_entity->announce_count = count;
	}
}

void doip_entity_set_announce_internal(doip_entity_t *doip_entity, int internal)
{
	if (doip_entity) {
		doip_entity->announce_internal = internal;
	}
}

void doip_entity_set_tcp_server(doip_entity_t *doip_entity, const char *addr, unsigned short port)
{
	if (!(doip_entity && addr)) {
		return;
	}

	doip_entity->tcp_server.port = port;
	memcpy(doip_entity->tcp_server.addr, addr, sizeof(doip_entity->tcp_server.addr));
}

void doip_entity_set_udp_server(doip_entity_t *doip_entity, const char *addr, unsigned short port)
{
	if (!(doip_entity && addr)) {
		return;
	}

	doip_entity->udp_server.port = port;
	memcpy(doip_entity->udp_server.addr, addr, sizeof(doip_entity->udp_server.addr));
}

void doip_entity_set_logic_addr(doip_entity_t *doip_entity, unsigned short addr)
{
	if (doip_entity) {
		doip_entity->logic_addr = addr;
	}
}

void doip_entity_set_func_addr(doip_entity_t *doip_entity, unsigned short addr)
{
	if (doip_entity) {
		doip_entity->func_addr = addr;
	}
}

void doip_entity_set_white_list(doip_entity_t *doip_entity, unsigned short *addr, int count)
{
	if (doip_entity) {
		doip_entity->white_list_count = count;
		doip_entity->white_list = malloc(count * sizeof(uint16_t));
		memcpy(doip_entity->white_list, addr, count);
	}
}

int doip_entity_start(doip_entity_t *doip_entity)
{
	if (!doip_entity) {
		return -1;
	}

	ev_run(doip_entity->loop, 0);

	return 0;
}
