#include "doip_entity.h"
#include "doip_stream.h"
#include "doip_utils.h"
#include "list.h"

#include <ev.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifndef EV_MULTIPLICITY
#error "libev must build with EV_MULTIPLICITY"
#endif

#define MIN(x,y) ((x)>(y) ? (y) : (x))

enum {
	UNINITIALIZED,
	INITIALIZED,
	ROUTINGACTIVATED,
	FINALIZATION,
};

typedef struct doip_pdu_t {
	uint8_t protocol;
	uint8_t inverse;
	uint16_t payload_type;
	uint32_t payload_len;
	uint32_t payload_cap;
	uint32_t data_len;
	uint8_t *payload;
} doip_pdu_t;

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
	uint16_t client_nums;
#define MAX_DOIP_PDU_SIZE  (0x10000)
	doip_pdu_t doip_pdu;
	struct sockaddr_in broadcast; /* for udp server */
	struct sockaddr_in target;
	struct list_head head;
	doip_entity_t *doip_entity;
} doip_server_t;

struct doip_entity {
	char vin[20];
	uint8_t eid[6];
	uint8_t gid[6];
	void *userdata;
	uint16_t logic_addr;
	uint16_t func_addr;
	uint16_t *white_list;
	uint16_t white_list_count;
	double initial_activity_time;
	double general_activity_time;
	int announce_wait_time;
	int announce_count;
	double announce_internal;
	doip_server_t tcp_server;
	doip_server_t udp_server;
	ev_prepare *prepare_w;
	ev_check *check_w;
	struct ev_loop *loop;
};

static void doip_assert(uint8_t expr, const char *comment)
{
	if (!expr) {
		logd("%s\n", comment);
		assert(expr);
	}
}

static const char *show_message_info(uint16_t type)
{
	switch (type) {
		case Generic_Doip_Header_Negative_Ack:
			return "generic doip header negative ack";
		case Vehicle_Identify_Request_Message:
			return "vehicle identify request message";
		case Vehicle_Identify_Request_Message_With_EID:
			return "vehicle identify request message with EID";
		case Vehicle_Identify_Request_Message_With_VIN:
			return "vehicle identify request message with vin";
		case Routing_Activation_Request:
			return "routine activation request";
		case Alive_Check_Request:
			return "alive check request";
		case Diagnostic_Message:
			return "diagnostic message";
		case Doip_Entity_Status_Request:
			return "doip entity status request";
		case Diagnotic_Powermode_Information_Request:
			return "diagnostic power mode information request";
		default:
			return "unknow message type";
	}
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

void doip_entity_set_vin(doip_entity_t *doip_entity, const char *vin, int len)
{
	if (doip_entity) {
		bzero(doip_entity->vin, sizeof(doip_entity->vin));
		memcpy(doip_entity->vin, vin, sizeof(doip_entity->vin));
	}
}

void doip_entity_set_eid(doip_entity_t *doip_entity, unsigned char eid[6])
{
	if (doip_entity) {
		bzero(doip_entity->eid, sizeof(doip_entity->eid));
		memcpy(doip_entity->eid, eid, sizeof(doip_entity->eid));
	}
}

void doip_entity_set_gid(doip_entity_t *doip_entity, unsigned char gid[6])
{
	if (doip_entity) {
		bzero(doip_entity->gid, sizeof(doip_entity->gid));
		memcpy(doip_entity->gid, gid, sizeof(doip_entity->gid));
	}
}

static void update_doip_header_len(uint8_t *data, int len, uint32_t payload_len)
{
	STREAM_T strm;

	if (len > 8) {
		YX_InitStrm(&strm, data, len);
		YX_MovStrmPtr(&strm, 4);
		YX_WriteLONG_Strm(&strm, payload_len);
	}
}

static int assemble_doip_header(uint8_t *data, int len, uint16_t payload_type, uint32_t payload_len)
{
	STREAM_T strm;

	YX_InitStrm(&strm, data, len);
	YX_WriteBYTE_Strm(&strm, 0x02);
	YX_WriteBYTE_Strm(&strm, 0xfd);
	YX_WriteHWORD_Strm(&strm, payload_type);
	YX_WriteLONG_Strm(&strm, payload_len);
	return YX_GetStrmLen(&strm);
}

static ssize_t udp_server_send(doip_entity_t *doip_entity, uint8_t *data, int len)
{
	if (!(doip_entity && doip_entity->udp_server.status == INITIALIZED && doip_entity->udp_server.handler > 0)) {
		return 0;
	}

	return send(doip_entity->udp_server.handler, data, len, 0);
}

static ssize_t doip_entity_tcp_send(doip_client_t *client, uint8_t *data, int len)
{
	ssize_t count = 0, total = 0;

	if (!(client && data && client->handler > 0 && len > 0)) {
		return 0;
	}

	while ((count = send(client->handler, data + total, len - total, 0)) > 0) {
		total += count;
		if (total == count) {
			break;
		}
	}

	return total;
}

static ssize_t tcp_send_generic_header_nack(doip_client_t *doip_client, int nack)
{
	STREAM_T strm;
	uint8_t buffer[16] = {0};

	YX_InitStrm(&strm, buffer, sizeof(buffer));
	YX_MovStrmPtr(&strm, assemble_doip_header(YX_GetStrmPtr(&strm), YX_GetStrmLeftLen(&strm), Generic_Doip_Header_Negative_Ack, 0));
	YX_WriteBYTE_Strm(&strm, nack);
	update_doip_header_len(YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm), YX_GetStrmLen(&strm) - 8);

	return doip_entity_tcp_send(doip_client, YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm));
}

static ssize_t udp_send_generic_header_nack(doip_entity_t *doip_entity, int nack)
{
	STREAM_T strm;
	uint8_t buffer[16] = {0};

	YX_InitStrm(&strm, buffer, sizeof(buffer));
	YX_MovStrmPtr(&strm, assemble_doip_header(YX_GetStrmPtr(&strm), YX_GetStrmLeftLen(&strm), Generic_Doip_Header_Negative_Ack, 0));
	YX_WriteBYTE_Strm(&strm, nack);
	update_doip_header_len(YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm), YX_GetStrmLen(&strm) - 8);

	return udp_server_send(doip_entity, YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm));
}

static int tcp_doip_header_verify(doip_pdu_t *doip_pdu, int *errcode)
{
	if (!((doip_pdu->protocol == 0x00 && doip_pdu->inverse == 0xff) || \
		(doip_pdu->protocol == 0x01 && doip_pdu->inverse == 0xfe) || \
		(doip_pdu->protocol == 0x02 && doip_pdu->inverse == 0xfd))) {
		*errcode = Header_NACK_Incorrect_Pattern_Format;
		return -1;
	}

	if (!((doip_pdu->payload_type == Routing_Activation_Request) || \
		(doip_pdu->payload_type == Alive_Check_Request) || \
		(doip_pdu->payload_type == Diagnostic_Message))) {
		*errcode = Header_NACK_Unknow_Payload_type;
		return -1;
	}

	/* just for testing */
	if (doip_pdu->data_len > MAX_DOIP_PDU_SIZE/2) {
		*errcode = Header_NACK_Message_Too_Large;
		return -1;
	}

	/* just for testing */
	if (doip_pdu->data_len > MAX_DOIP_PDU_SIZE * 2/3) {
		*errcode = Header_NACK_Out_Of_Memory;
		return -1;
	}

	/* fixed length, min length, max length */
	if (!((doip_pdu->payload_type == Routing_Activation_Request && doip_pdu->data_len == 0x11) || \
		(doip_pdu->payload_type == Alive_Check_Request && doip_pdu->data_len == 8) || \
		(doip_pdu->payload_type == Diagnostic_Message && doip_pdu->data_len > 8))) {
		*errcode = Header_NACK_Invalid_Payload_Len;
		return -1;
	}

	return 0;
}

static int udp_doip_header_verify(doip_pdu_t *doip_pdu, int *errcode)
{
	if (!((doip_pdu->protocol == 0x00 && doip_pdu->inverse == 0xff) || \
		(doip_pdu->protocol == 0x01 && doip_pdu->inverse == 0xfe) || \
		(doip_pdu->protocol == 0x02 && doip_pdu->inverse == 0xfd))) {
		*errcode = Header_NACK_Incorrect_Pattern_Format;
		return -1;
	}

	if (!((doip_pdu->payload_type == Generic_Doip_Header_Negative_Ack) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message_With_EID) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message_With_VIN) || \
		(doip_pdu->payload_type == Doip_Entity_Status_Request) || \
		(doip_pdu->payload_type == Diagnotic_Powermode_Information_Request))) {
		*errcode = Header_NACK_Unknow_Payload_type;
		return -1;
	}

	/* just for testing */
	if (doip_pdu->data_len > MAX_DOIP_PDU_SIZE/2) {
		*errcode = Header_NACK_Message_Too_Large;
		return -1;
	}

	/* just for testing */
	if (doip_pdu->data_len > MAX_DOIP_PDU_SIZE * 2/3) {
		*errcode = Header_NACK_Out_Of_Memory;
		return -1;
	}

	/* fixed length, min length, max length */
	if (!((doip_pdu->payload_type == Generic_Doip_Header_Negative_Ack && doip_pdu->data_len == 9) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message && doip_pdu->data_len == 8) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message_With_EID && doip_pdu->data_len == 14) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message_With_VIN && doip_pdu->data_len == 25) || \
		(doip_pdu->payload_type == Doip_Entity_Status_Request && doip_pdu->data_len == 8) || \
		(doip_pdu->payload_type == Diagnotic_Powermode_Information_Request && doip_pdu->data_len == 8))) {
		*errcode = Header_NACK_Invalid_Payload_Len;
		return -1;
	}

	return 0;
}

static int disassemble_doip_header(uint8_t *data, uint32_t len, doip_pdu_t *doip_pdu)
{
	STREAM_T strm;

	if (len < 8) {
		return -1;
	}

	YX_InitStrm(&strm, data, len);
	doip_pdu->protocol = YX_ReadBYTE_Strm(&strm);
	doip_pdu->inverse = YX_ReadBYTE_Strm(&strm);
	doip_pdu->payload_type = YX_ReadHWORD_Strm(&strm);
	doip_pdu->payload_len = YX_ReadLONG_Strm(&strm);
	doip_pdu->data_len = len;

	logd("protocol:0x%02x\n", doip_pdu->protocol);
	logd("inverse:0x%02x\n", doip_pdu->inverse);
	logd("payload_type:0x%04x\n", doip_pdu->payload_type);
	logd("payload_len:0x%x\n\n", doip_pdu->payload_len);

	return YX_GetStrmLen(&strm);
}

static int vehicle_identify_announce(doip_entity_t *doip_entity)
{
	STREAM_T strm;
	uint8_t buffer[64] = {0};
	doip_server_t *udp_server = &doip_entity->udp_server;

	YX_InitStrm(&strm, buffer, sizeof(buffer));
	YX_MovStrmPtr(&strm, assemble_doip_header(YX_GetStrmPtr(&strm), YX_GetStrmLeftLen(&strm), Vehicle_Announcememt_Message, 0));
	YX_WriteDATA_Strm(&strm, (uint8_t *)doip_entity->vin, 17);
	YX_WriteHWORD_Strm(&strm, doip_entity->logic_addr);
	YX_WriteDATA_Strm(&strm, doip_entity->eid, sizeof(doip_entity->eid));
	YX_WriteDATA_Strm(&strm, doip_entity->gid, sizeof(doip_entity->gid));
	YX_WriteBYTE_Strm(&strm, 0x00);
	YX_WriteBYTE_Strm(&strm, 0x00);

	update_doip_header_len(YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm), YX_GetStrmLen(&strm) - 8);

	return sendto(udp_server->handler, YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm), 0, (struct sockaddr *)&doip_entity->udp_server.broadcast, sizeof(doip_entity->udp_server.broadcast));
}

static int vehicle_identify_respon(doip_entity_t *doip_entity)
{
	STREAM_T strm;
	uint8_t buffer[64] = {0};
	doip_server_t *udp_server = &doip_entity->udp_server;

	YX_InitStrm(&strm, buffer, sizeof(buffer));
	YX_MovStrmPtr(&strm, assemble_doip_header(YX_GetStrmPtr(&strm), YX_GetStrmLeftLen(&strm), Vehicle_Announcememt_Message, 0));
	YX_WriteDATA_Strm(&strm, (uint8_t *)doip_entity->vin, 17);
	YX_WriteHWORD_Strm(&strm, doip_entity->logic_addr);
	YX_WriteDATA_Strm(&strm, doip_entity->eid, sizeof(doip_entity->eid));
	YX_WriteDATA_Strm(&strm, doip_entity->gid, sizeof(doip_entity->gid));
	YX_WriteBYTE_Strm(&strm, 0x00);
	YX_WriteBYTE_Strm(&strm, 0x00);

	update_doip_header_len(YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm), YX_GetStrmLen(&strm) - 8);

	int n = sendto(udp_server->handler, YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm), 0, (struct sockaddr *)&udp_server->target, sizeof(udp_server->target));
	return n;
}

static int vehicle_identify_respon_with_eid(doip_entity_t *doip_entity)
{
	if (memcmp(doip_entity->eid, &doip_entity->udp_server.doip_pdu.payload[8], 6) == 0) {
		return vehicle_identify_respon(doip_entity);
	}

	return 0;
}

static int vehicle_identify_respon_with_vin(doip_entity_t *doip_entity)
{
	if (memcmp(doip_entity->vin, &doip_entity->udp_server.doip_pdu.payload[8], 17) == 0) {
		return vehicle_identify_respon(doip_entity);
	}

	return 0;
}

static int doip_entity_status_respon(doip_entity_t *doip_entity)
{
	STREAM_T strm;
	uint8_t buffer[16] = {0};

	YX_InitStrm(&strm, buffer, sizeof(buffer));
	YX_MovStrmPtr(&strm, assemble_doip_header(YX_GetStrmStartPtr(&strm), YX_GetStrmLeftLen(&strm), Doip_Entity_Status_Response, 0));
	YX_WriteBYTE_Strm(&strm, 0x01);
	YX_WriteBYTE_Strm(&strm, 2);
	YX_WriteBYTE_Strm(&strm, doip_entity->tcp_server.client_nums);
	YX_WriteLONG_Strm(&strm, doip_entity->tcp_server.doip_pdu.payload_cap);

	update_doip_header_len(YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm), YX_GetStrmLen(&strm) - 8);

	return udp_server_send(doip_entity, YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm));
}

static int diagnostic_powermode_information_respon(doip_entity_t *doip_entity)
{
	STREAM_T strm;
	uint8_t buffer[16] = {0};

	YX_InitStrm(&strm, buffer, sizeof(buffer));
	YX_MovStrmPtr(&strm, assemble_doip_header(YX_GetStrmStartPtr(&strm), YX_GetStrmLeftLen(&strm), Diagnotic_Powermode_Information_Response, 0));
	YX_WriteBYTE_Strm(&strm, 0x01);

	update_doip_header_len(YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm), YX_GetStrmLen(&strm) - 8);

	return udp_server_send(doip_entity, YX_GetStrmStartPtr(&strm), YX_GetStrmLen(&strm));
}

static void routing_activation_request(doip_client_t *doip_client)
{
}

static void alive_check_request(doip_client_t *doip_client)
{

}

static void disgnostic_message_handler(doip_client_t *doip_client)
{

}

static void tcp_read_cb(struct ev_loop *loop, ev_io *w, int e)
{
	int errcode = 0;
	ssize_t count = 0, total = 0;
	doip_entity_t *doip_entity = ev_userdata(loop);
	doip_server_t *tcp_server = &doip_entity->tcp_server;
	doip_client_t *doip_client = w->data;

	while ((count = recv(w->fd, tcp_server->doip_pdu.payload + total, 8 - total, 0)) > 0) {
		total += count;
		if (total == 0x08) {
			break;
		}
	}

	if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		return; /* no data avaliable */
	}

	if (count < 8) {
		doip_client->status = FINALIZATION;
		return; /* error or peer disconnected */
	}

	disassemble_doip_header(tcp_server->doip_pdu.payload, total, &tcp_server->doip_pdu);

	logd("payload_type:0x%04x (%s)\n", tcp_server->doip_pdu.payload_type, show_message_info(tcp_server->doip_pdu.payload_type));

	if (!tcp_doip_header_verify(&tcp_server->doip_pdu, &errcode)) {
		tcp_send_generic_header_nack(doip_client, errcode);
		doip_client->status = FINALIZATION;
		return;
	}

	total = 0;
	while ((count = recv(w->fd, tcp_server->doip_pdu.payload + 8, tcp_server->doip_pdu.payload_len, 0)) > 0) {
		total += count;
		if (total == tcp_server->doip_pdu.payload_len) {
			break;
		}
	}

	switch (doip_entity->tcp_server.doip_pdu.payload_type) {
		case Routing_Activation_Request:
			routing_activation_request(doip_client);
			return;
		case Alive_Check_Request:
			alive_check_request(doip_client);
			return;
		case Diagnostic_Message:
			disgnostic_message_handler(doip_client);
			return;
		default:
			logd("unknow payload_type\n");
			return;
	}
}

static void general_activity_timer_callback(struct ev_loop *loop, ev_timer *w, int e)
{
	doip_client_t *doip_client = w->data;

	if (doip_client->status != ROUTINGACTIVATED) {
		doip_client->status = FINALIZATION;
	}
}

static void initial_activity_timer_callback(struct ev_loop *loop, ev_timer *w, int e)
{
	doip_client_t *doip_client = w->data;

	if (doip_client->status != ROUTINGACTIVATED) {
		doip_client->status = FINALIZATION;
	}
}

static void accept_cb(struct ev_loop *loop, ev_io *w, int e)
{
	socklen_t socklen;
	struct sockaddr_in client;
	doip_client_t *doip_client = NULL;
	doip_entity_t *doip_entity = ev_userdata(loop);

	socklen = sizeof(client);
	int connfd = accept(w->fd, (struct sockaddr *)&client, &socklen);
	if ((connfd < 0) && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		/* no new connection */
		return;
	}

	doip_client = malloc(sizeof(*doip_client));
	doip_assert(!!doip_client, "malloc failed");

	doip_client->watcher = malloc(sizeof(ev_io));
	doip_client->general_activity_timer = malloc(sizeof(ev_timer));
	doip_client->initial_activity_timer = malloc(sizeof(ev_timer));
	INIT_LIST_HEAD(&doip_client->list);
	doip_client->handler = connfd;
	doip_client->status = INITIALIZED;
	doip_client->doip_entity = doip_entity;
	doip_client->port = be16toh(client.sin_port);
	inet_ntop(AF_INET, &client.sin_addr, doip_client->client, sizeof(doip_client->client));
	doip_client->status = INITIALIZED;
	doip_assert(doip_client->watcher && doip_client->general_activity_timer && doip_client->initial_activity_timer, "malloc failed");

	doip_client->watcher->data = doip_client;

	ev_io_init(doip_client->watcher, tcp_read_cb, doip_client->handler, EV_READ);
	ev_io_start(loop, doip_client->watcher);

	ev_timer_init(doip_client->general_activity_timer, general_activity_timer_callback, 0, doip_entity->general_activity_time/1000);
	// ev_timer_start(loop, doip_client->general_activity_timer);

	ev_timer_init(doip_client->initial_activity_timer, initial_activity_timer_callback, 0, doip_entity->initial_activity_time/1000);
	ev_timer_start(loop, doip_client->initial_activity_timer);

	/* add client to list */
	list_add(&doip_client->list, &doip_entity->tcp_server.head);
}

static int tcp_server_init(doip_entity_t *doip_entity)
{
	int fd;
	struct sockaddr_in server;

	if (!doip_entity) {
		return -1;
	}

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return -1;
	}

	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	/* set nonblock */
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	bzero((uint8_t *)&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htobe16(doip_entity->tcp_server.port);
	inet_pton(AF_INET, doip_entity->tcp_server.addr, &server.sin_addr);

	if (bind(fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		goto finish;
	}

	if (listen(fd, 10) < 0) {
		goto finish;
	}

	doip_entity->tcp_server.handler = fd;
	doip_entity->tcp_server.status = INITIALIZED;

	return fd;

finish:
	if (fd > 0) {
		close(fd);
		fd = 0;
	}
	return -1;
}

static int udp_server_init(doip_entity_t *doip_entity)
{
	int fd;
	int broadcast = 1;
	struct sockaddr_in server;

	if (!doip_entity) {
		return -1;
	}

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		return -1;
	}

	logd("fd:%d\n", fd);

	/* set nonblock */
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	/* enable broadcast */
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (uint8_t *)&broadcast, sizeof(broadcast));

	bzero((uint8_t *)&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htobe16(doip_entity->udp_server.port);
	inet_pton(AF_INET, doip_entity->udp_server.addr, &server.sin_addr);

	if (bind(fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		goto finish;
	}

	doip_entity->udp_server.handler = fd;
	doip_entity->udp_server.status = INITIALIZED;

	/* init broadcast target */
	bzero(&doip_entity->udp_server.broadcast, sizeof(doip_entity->udp_server.broadcast));
	doip_entity->udp_server.broadcast.sin_family = AF_INET;
	doip_entity->udp_server.broadcast.sin_port = UDP_DISCOVERY;
	inet_pton(AF_INET, "225.225.225.225", &doip_entity->udp_server.broadcast.sin_addr);

	return fd;

finish:
	if (fd > 0) {
		close(fd);
		fd = 0;
	}
	return -1;
}

static void tcp_server_start(struct ev_loop *loop, doip_entity_t *doip_entity)
{
	if (!doip_entity) {
		return;
	}

	ev_io_init(doip_entity->tcp_server.watcher, accept_cb, doip_entity->tcp_server.handler, EV_READ);
	ev_io_start(loop, doip_entity->tcp_server.watcher);
}

static void udp_read_cb(EV_P_ ev_io *w, int e)
{
	int errcode;
	socklen_t socklen;
	doip_entity_t *doip_entity = ev_userdata(loop);
	doip_server_t *udp_server = &doip_entity->udp_server;

	socklen = sizeof(udp_server->target);
	ssize_t count = recvfrom(w->fd, udp_server->doip_pdu.payload, udp_server->doip_pdu.payload_cap, 0, (struct sockaddr *)&udp_server->target, &socklen);
	if (count == 0) {
		return; /* no data */
	}
	if (count < 0) {
		/* TODO: restart udp server */
		return;
	}

	if (count < 8) {
		return; /* header length */
	}

	disassemble_doip_header(udp_server->doip_pdu.payload, count, &udp_server->doip_pdu);

	if (udp_doip_header_verify(&udp_server->doip_pdu, &errcode) != 0) {
		udp_send_generic_header_nack(doip_entity, errcode);
		return;
	}

	uint16_t payload_type = udp_server->doip_pdu.payload_type;

	logd("payload_type:0x%04x (%s)\n", payload_type, show_message_info(payload_type));

	switch (payload_type) {
		case Generic_Doip_Header_Negative_Ack:
			return; /* ignore */
		case Vehicle_Identify_Request_Message:
			vehicle_identify_respon(doip_entity);
			return;
		case Vehicle_Identify_Request_Message_With_EID:
			vehicle_identify_respon_with_eid(doip_entity);
			return;
		case Vehicle_Identify_Request_Message_With_VIN:
			vehicle_identify_respon_with_vin(doip_entity);
			return;
		case Doip_Entity_Status_Request:
			doip_entity_status_respon(doip_entity);
			return;
		case Diagnotic_Powermode_Information_Request:
			diagnostic_powermode_information_respon(doip_entity);
			return;
		default:
			logd("unknow\n");
	}
}

static void vehicle_identify_announce_timer_callback(EV_P_ ev_timer *w, int e)
{
	static int count = 0;
	doip_entity_t *doip_entity = ev_userdata(loop);

	vehicle_identify_announce(doip_entity);

	if (++count >= doip_entity->announce_count) {
		count = 0;
		ev_timer_stop(loop, w);
		free(w);
	}
}

static void start_vehicle_identify_announce_timer(doip_entity_t *doip_entity)
{
	ev_timer *vehicle_identify_announce_timer = calloc(1, sizeof(ev_timer));

	ev_timer_init(vehicle_identify_announce_timer, vehicle_identify_announce_timer_callback, 0, doip_entity->announce_internal/1000);

	ev_timer_start(doip_entity->loop, vehicle_identify_announce_timer);
}

static void udp_server_start(struct ev_loop *loop, doip_entity_t *doip_entity)
{
	ev_io_init(doip_entity->udp_server.watcher, udp_read_cb, doip_entity->udp_server.handler, EV_READ);

	ev_io_start(loop, doip_entity->udp_server.watcher);

	start_vehicle_identify_announce_timer(doip_entity);
}

static void prepare_cb(EV_P_ ev_prepare *w, int e)
{
	doip_entity_t *doip_entity = (doip_entity_t *)ev_userdata(loop);

	if (doip_entity->tcp_server.status == UNINITIALIZED) {
		logd("tcp_server_init\n");
		/* TODO clear all clients */
		if (tcp_server_init(doip_entity) < 0) {
			return;
		}
		tcp_server_start(loop, doip_entity);
	}
	if (doip_entity->udp_server.status == UNINITIALIZED) {
		logd("udp_server_init\n");
		if (udp_server_init(doip_entity) < 0) {
			return;
		}
		udp_server_start(loop, doip_entity);
	}
}

static void doip_client_clean(doip_client_t *doip_client)
{
	doip_entity_t *doip_entity = doip_client->doip_entity;
	struct ev_loop *loop = doip_entity->loop;

	ev_io_stop(loop, doip_client->watcher);
	ev_timer_stop(loop, doip_client->initial_activity_timer);
	ev_timer_stop(loop, doip_client->general_activity_timer);
	close(doip_client->watcher->fd);
}

static void doip_tcp_server_clean(doip_server_t *tcp_server)
{
	doip_client_t *client, *temp;

	if (tcp_server->client_nums == 0) {
		return;
	}
	list_for_each_entry_safe(client, temp, &tcp_server->head, list) {

	}
}

static void doip_udp_server_clean(doip_server_t *udp_server)
{
	/* do nothing */
}

/* 集中处理需要关闭的客户端,重启服务器本身(服务器出问题的话) */
static void check_cb(EV_P_ ev_check *w, int e)
{
	doip_client_t *client, *temp;
	doip_entity_t *doip_entity = ev_userdata(loop);
	doip_server_t *tcp_server = &doip_entity->tcp_server;
	doip_server_t *udp_server = &doip_entity->udp_server;

	if (tcp_server->status == FINALIZATION) {

	}
	if (udp_server->status == FINALIZATION) {

	}

	if (tcp_server->client_nums == 0) {
		return;
	}

	list_for_each_entry_safe(client, temp, &tcp_server->head, list) {
		if (client->status == FINALIZATION) {
			list_del(&client->list);
		}
	}
}

static void doip_entity_init(doip_entity_t *doip_entity)
{
	if (!doip_entity) {
		return;
	}

	ev_prepare_init(doip_entity->prepare_w, prepare_cb);
	ev_prepare_start(doip_entity->loop, doip_entity->prepare_w);

	ev_check_init(doip_entity->check_w, check_cb);
	ev_check_start(doip_entity->loop, doip_entity->check_w);
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
	doip_entity->check_w = malloc(sizeof(ev_check));
	doip_entity->tcp_server.watcher = malloc(sizeof(ev_io));
	doip_entity->udp_server.watcher = malloc(sizeof(ev_io));
	doip_entity->udp_server.doip_pdu.payload_cap = MAX_DOIP_PDU_SIZE;
	doip_entity->tcp_server.doip_pdu.payload_cap = MAX_DOIP_PDU_SIZE;
	doip_entity->tcp_server.doip_pdu.payload = malloc(doip_entity->tcp_server.doip_pdu.payload_cap);
	doip_entity->udp_server.doip_pdu.payload = malloc(doip_entity->tcp_server.doip_pdu.payload_cap);

	doip_entity->tcp_server.doip_entity = doip_entity;
	doip_entity->udp_server.doip_entity = doip_entity;

	doip_assert(doip_entity->loop && \
			doip_entity->prepare_w && \
			doip_entity->check_w && \
			doip_entity->tcp_server.watcher && \
			doip_entity->udp_server.watcher && \
			doip_entity->tcp_server.doip_pdu.payload && \
			doip_entity->udp_server.doip_pdu.payload, "malloc failed");

	doip_entity->initial_activity_time = T_TCP_Initial_Inactivity;
	doip_entity->general_activity_time = T_TCP_General_Inactivity;
	doip_entity->announce_count = A_DoIP_Announce_Num;
	doip_entity->announce_internal = A_DoIP_Announce_Interval;
	doip_entity->announce_wait_time = A_DoIP_Announce_Wait;

	ev_set_userdata(doip_entity->loop, doip_entity);

	doip_entity_init(doip_entity);

	return doip_entity;
}

int doip_entity_start(doip_entity_t *doip_entity)
{
	if (!doip_entity) {
		return -1;
	}

	ev_run(doip_entity->loop, 0);

	return 0;
}
