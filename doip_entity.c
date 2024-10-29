#include "doip_entity.h"
#include "doip_stream.h"
#include "doip_utils.h"
#include "list.h"

#include <ev.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/*------------------------------------------------------------------------------------------------------*/

#ifndef EV_MULTIPLICITY
#error "libev must build with EV_MULTIPLICITY"
#endif

#define DOIP_PROTOCOL_VERSION           (0x02)
#define BACKLOG                         (128)
#define DOIP_CLIENTS_LIMITATION         (100)
#define MIN_DYNAMIC_PORT                (49152)
#define MAX_DYNAMIC_PORT                (65535)
#define DATA_COLLECTION_TIMEOUT         (60)
#define DOIP_UDP_PDU_SIZE               (256)
/*------------------------------------------------------------------------------------------------------*/

enum {
	DoIP_Connection_Socket_Uninitialized,
	DoIP_Connection_Socket_Initialized,
	DoIP_Connection_Pending_For_Authentication,
	DoIP_Connection_Pending_For_Confirmation,
	DoIP_Connection_RoutingActivated,
	DoIP_Connection_Finalization,
};  /* DoIP Connection Status */

typedef struct doip_pdu_t {
	uint8_t protocol;
	uint8_t inverse;
	uint16_t payload_type;
	uint32_t payload_len;
	uint32_t payload_cap;
	uint32_t data_len;
	uint8_t *payload;
} doip_pdu_t; /* doip pdu */

typedef struct doip_client {
	int status;
	int handler;
	int discard;
	uint16_t logic_addr;
	uint16_t port;
	char client[32];
	ev_io watcher;
	ev_timer data_collection_timer;
	ev_timer tcp_initial_activity_timer;
	ev_timer tcp_general_activity_timer;
	ev_timer tcp_alive_check_timer;
	doip_pdu_t doip_pdu;
	struct list_head list;
	doip_entity_t *doip_entity;
} doip_client_t; /* doip client */

typedef struct doip_server {
	int status;
	int handler;
	char addr[32];
	uint16_t port;
	uint16_t client_cap;  /* for tcp server */
	uint16_t client_nums; /* for tcp server */
#define MAX_DOIP_PDU_SIZE  (0x4000)
	doip_pdu_t doip_pdu;  /* for udp server */
	struct sockaddr_in broadcast; /* for udp server */
	struct sockaddr_in target;    /* for udp server */
	struct list_head head; /* for tcp server */
	ev_io watcher; /* for tcp and udp server */
	ev_timer vehicle_identify_announce_timer; /* for udp server */
	doip_entity_t *doip_entity;
} doip_server_t; /* doip server */

typedef struct uds_indication {
	int status;
	int handler;
	const char *sockfile;
	ev_io watcher;
	uint8_t buffer[4096];
	doip_entity_t *doip_entity;
} uds_indication_t;

typedef struct uds_request {
	int status;
	int handler;
	int cap;
	int len;
	uint8_t *buffer;
	const char *sockfile;
	struct sockaddr_un target;
	doip_entity_t *doip_entity;
} uds_request_t;

struct doip_entity {
	char vin[20];
	uint8_t eid[6];
	uint8_t gid[6];
	void *userdata;
	uint16_t logic_addr;
	uint16_t func_addr;
	uint16_t *white_list;
	uint16_t white_list_count;
	double tcp_initial_activity_time;
	double tcp_general_activity_time;
	double tcp_alive_check_time;
	double doip_announce_wait;
	int doip_announce_num;
	double doip_announce_interval;
	doip_server_t tcp_server;
	doip_server_t udp_server;
	uds_request_t uds_request;
	uds_indication_t uds_indication;
	ev_prepare prepare_w;
	ev_timer heartbeat_w;
	struct ev_loop *loop;
}; /* doip entity */

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

static char *doip_client_status(int status)
{
	switch (status) {
		case DoIP_Connection_Socket_Uninitialized:
			return "uninitialized";
		case DoIP_Connection_Socket_Initialized:
			return "initialized";
		case DoIP_Connection_Pending_For_Authentication:
			return "pending for authentication";
		case DoIP_Connection_Pending_For_Confirmation:
			return "pending for confirmation";
		case DoIP_Connection_RoutingActivated:
			return "routing activated";
		case DoIP_Connection_Finalization:
			return "finalized";
		default:
			return "unknow";
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

void doip_entity_set_white_list(doip_entity_t *doip_entity, unsigned short *addr, int count)
{
	if (doip_entity) {
		doip_entity->white_list_count = count;
		doip_entity->white_list = doip_malloc(count * sizeof(uint16_t));
		memcpy(doip_entity->white_list, (uint8_t *)addr, count * sizeof(uint16_t));
	}
}

void doip_entity_set_vin(doip_entity_t *doip_entity, const char *vin, int len)
{
	if (!(doip_entity && (len == 17))) {
		return;
	}

	bzero(doip_entity->vin, sizeof(doip_entity->vin));
	memcpy(doip_entity->vin, vin, sizeof(doip_entity->vin));
}

void doip_entity_set_eid(doip_entity_t *doip_entity, unsigned char *eid, int len)
{
	if (!(doip_entity && (len == 6))) {
		return;
	}

	bzero(doip_entity->eid, sizeof(doip_entity->eid));
	memcpy(doip_entity->eid, eid, sizeof(doip_entity->eid));
}

void doip_entity_set_gid(doip_entity_t *doip_entity, unsigned char *gid, int len)
{
	if (!(doip_entity && (len == 6))) {
		return;
	}

	bzero(doip_entity->gid, sizeof(doip_entity->gid));
	memcpy(doip_entity->gid, gid, sizeof(doip_entity->gid));
}

static void update_doip_header_len(uint8_t *data, int len, uint32_t payload_len)
{
	doip_stream_t strm;

	if (len > 8) {
		doip_stream_init(&strm, data, len);
		doip_stream_forward(&strm, 4);
		doip_stream_write_be32(&strm, payload_len);
	}
}

static int assemble_doip_header(uint8_t *data, int len, uint16_t payload_type, uint32_t payload_len)
{
	doip_stream_t strm;

	doip_stream_init(&strm, data, len);
	doip_stream_write_byte(&strm, DOIP_PROTOCOL_VERSION);
	doip_stream_write_byte(&strm, ~DOIP_PROTOCOL_VERSION);
	doip_stream_write_be16(&strm, payload_type);
	doip_stream_write_be32(&strm, payload_len);
	return doip_stream_len(&strm);
}

static ssize_t udp_server_send(doip_entity_t *doip_entity, uint8_t *data, int len)
{
	if (!(doip_entity && doip_entity->udp_server.status == DoIP_Connection_Socket_Initialized && \
				doip_entity->udp_server.handler > 0)) {
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
	doip_stream_t strm;
	uint8_t buffer[16] = {0};

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Generic_Doip_Header_Negative_Ack, 0));
	doip_stream_write_byte(&strm, nack);
	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	return doip_entity_tcp_send(doip_client, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
}

static ssize_t udp_send_generic_header_nack(doip_entity_t *doip_entity, int nack)
{
	doip_stream_t strm;
	uint8_t buffer[16] = {0};

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Generic_Doip_Header_Negative_Ack, 0));
	doip_stream_write_byte(&strm, nack);
	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	return udp_server_send(doip_entity, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
}

static int tcp_doip_header_verify(doip_pdu_t *doip_pdu, int *errcode)
{
	bool ret = false;

	/* [DoIP-041]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x00 if the protocol version or inverse protocol version (synchronization pattern)
	 * does not match the format specified in Table 11.
	 */
	if (!((doip_pdu->protocol == 0x00 && doip_pdu->inverse == 0xff) || \
		(doip_pdu->protocol == 0x01 && doip_pdu->inverse == 0xfe) || \
		(doip_pdu->protocol == 0x02 && doip_pdu->inverse == 0xfd))) {
		*errcode = Header_NACK_Incorrect_Pattern_Format;
		goto finish;
	}

	/* [DoIP-042]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x01 if the payload type is not supported by the DoIP entity.
	 */
	if (!((doip_pdu->payload_type == Routing_Activation_Request) || \
		(doip_pdu->payload_type == Alive_Check_Request) || \
		(doip_pdu->payload_type == Diagnostic_Message))) {
		*errcode = Header_NACK_Unknow_Payload_type;
		goto finish;
	}

	/* [DoIP-043]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x02 if the payload length exceeds the maximum DoIP message size supported by
	 * the DoIP entity regardless of the current memory utilization.
	 */
	if (doip_pdu->payload_len > (MAX_DOIP_PDU_SIZE - 64)) { /* just for testing */
		*errcode = Header_NACK_Message_Too_Large;
		goto finish;
	}

	/* [DoIP-044]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x03 if the payload length exceeds the currently available DoIP protocol handler
	 * memory of the DoIP entity.
	 */
	if (doip_pdu->payload_len > (MAX_DOIP_PDU_SIZE - 128)) { /* just for testing */
		*errcode = Header_NACK_Out_Of_Memory;
		goto finish;
	}

	/* [DoIP-045]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x04 if the payload length parameter does not match the expected length for the
	 * specific payload type. This includes payload-type-specific minimum length, fixed length and
	 * maximum length checks.
     */
	if (!((doip_pdu->payload_type == Routing_Activation_Request && doip_pdu->payload_len == 0x0b && doip_pdu->data_len >= 0x13) || \
		(doip_pdu->payload_type == Alive_Check_Request && doip_pdu->payload_len == 0x00 && doip_pdu->data_len >= 0x08) || \
		(doip_pdu->payload_type == Diagnostic_Message && doip_pdu->payload_len > 0 && doip_pdu->data_len > 0x0d && doip_pdu->data_len < MAX_DOIP_PDU_SIZE))) {
		*errcode = Header_NACK_Invalid_Payload_Len;
		goto finish;
	}
	ret = true;

finish:
	return ret;
}

static bool udp_doip_header_verify(doip_pdu_t *doip_pdu, int *errcode)
{
	bool ret = false;

	/* [DoIP-041]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x00 if the protocol version or inverse protocol version (synchronization pattern)
	 * does not match the format specified in Table 11.
	 */
	if (!((doip_pdu->protocol == 0x00 && doip_pdu->inverse == 0xff) || \
		(doip_pdu->protocol == 0x01 && doip_pdu->inverse == 0xfe) || \
		(doip_pdu->protocol == 0x02 && doip_pdu->inverse == 0xfd))) {
		*errcode = Header_NACK_Incorrect_Pattern_Format;
		goto finish;
	}

	/* [DoIP-042]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x01 if the payload type is not supported by the DoIP entity
	 */
	if (!((doip_pdu->payload_type == Generic_Doip_Header_Negative_Ack) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message_With_EID) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message_With_VIN) || \
		(doip_pdu->payload_type == Doip_Entity_Status_Request) || \
		(doip_pdu->payload_type == Diagnotic_Powermode_Information_Request))) {
		*errcode = Header_NACK_Unknow_Payload_type;
		goto finish;
	}

	/* [DoIP-043]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x02 if the payload length exceeds the maximum DoIP message size supported by
	 * the DoIP entity regardless of the current memory utilization
	 */
	if (doip_pdu->payload_len > (MAX_DOIP_PDU_SIZE - 64)) {
		*errcode = Header_NACK_Message_Too_Large; /* just for testing */
		goto finish;
	}

	/* [DoIP-044]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x03 if the payload length exceeds the currently available DoIP protocol handler
	 * memory of the DoIP entity
	 */
	if (doip_pdu->payload_len > (MAX_DOIP_PDU_SIZE - 128)) { /* just for testing */
		*errcode = Header_NACK_Out_Of_Memory;
		goto finish;
	}

	/* [DoIP-045]
	 * Each DoIP entity shall send a generic DoIP header negative acknowledge message with NACK
	 * code set to 0x04 if the payload length parameter does not match the expected length for the
	 * specific payload type. This includes payload-type-specific minimum length, fixed length and
	 * maximum length checks
	 */
	if (!((doip_pdu->payload_type == Generic_Doip_Header_Negative_Ack && doip_pdu->data_len == 9) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message && doip_pdu->data_len == 8) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message_With_EID && doip_pdu->data_len == 14) || \
		(doip_pdu->payload_type == Vehicle_Identify_Request_Message_With_VIN && doip_pdu->data_len == 25) || \
		(doip_pdu->payload_type == Doip_Entity_Status_Request && doip_pdu->data_len == 8) || \
		(doip_pdu->payload_type == Diagnotic_Powermode_Information_Request && doip_pdu->data_len == 8))) {
		*errcode = Header_NACK_Invalid_Payload_Len;
		goto finish;
	}

	/* length verify */
	if (doip_pdu->payload_len != (doip_pdu->data_len - 8)) {
		*errcode = Header_NACK_Invalid_Payload_Len;
		goto finish;
	}
	ret = true;

finish:
	return ret;
}

static int disassemble_doip_header(uint8_t *data, uint32_t len, doip_pdu_t *doip_pdu)
{
	doip_stream_t strm;

	if (len < 8) {
		return -1;
	}

	doip_stream_init(&strm, data, len);
	doip_pdu->protocol = doip_stream_read_byte(&strm);
	doip_pdu->inverse = doip_stream_read_byte(&strm);
	doip_pdu->payload_type = doip_stream_read_be16(&strm);
	doip_pdu->payload_len = doip_stream_read_be32(&strm);
	doip_pdu->data_len = len;

#if 0
	logd("protocol:0x%02x\n", doip_pdu->protocol);
	logd("inverse:0x%02x\n", doip_pdu->inverse);
	logd("payload_type:0x%04x\n", doip_pdu->payload_type);
	logd("payload_len:0x%x\n\n", doip_pdu->payload_len);
#endif

	return doip_stream_len(&strm);
}

static int vehicle_identify_announce(doip_entity_t *doip_entity)
{
	doip_stream_t strm;
	uint8_t buffer[64] = {0};
	doip_server_t *udp_server = &doip_entity->udp_server;

	if (!(udp_server->status == DoIP_Connection_Socket_Initialized && udp_server->handler > 0)) {
		return 0;
	}

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Vehicle_Announcememt_Message, 0));
	doip_stream_write_data(&strm, (uint8_t *)doip_entity->vin, 17);
	doip_stream_write_be16(&strm, doip_entity->logic_addr);
	doip_stream_write_data(&strm, doip_entity->eid, sizeof(doip_entity->eid));
	doip_stream_write_data(&strm, doip_entity->gid, sizeof(doip_entity->gid));
	doip_stream_write_byte(&strm, 0x00);
	doip_stream_write_byte(&strm, 0x00);

	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	return sendto(udp_server->handler, doip_stream_start_ptr(&strm), doip_stream_len(&strm), 0, \
			(struct sockaddr *)&doip_entity->udp_server.broadcast, sizeof(doip_entity->udp_server.broadcast));
}

static int vehicle_identify_respon(doip_entity_t *doip_entity)
{
	doip_stream_t strm;
	uint8_t buffer[64] = {0};
	doip_server_t *udp_server = &doip_entity->udp_server;

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Vehicle_Announcememt_Message, 0));
	doip_stream_write_data(&strm, (uint8_t *)doip_entity->vin, 17);
	doip_stream_write_be16(&strm, doip_entity->logic_addr);
	doip_stream_write_data(&strm, doip_entity->eid, sizeof(doip_entity->eid));
	doip_stream_write_data(&strm, doip_entity->gid, sizeof(doip_entity->gid));
	doip_stream_write_byte(&strm, 0x00);
	doip_stream_write_byte(&strm, 0x00);

	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	return sendto(udp_server->handler, doip_stream_start_ptr(&strm), doip_stream_len(&strm), 0, \
			(struct sockaddr *)&udp_server->target, sizeof(udp_server->target));
}

/* [DoIP-053]
 * Each DoIP entity shall send the vehicle identification response message as specified in Table 19
 * after receipt of a vehicle identification request message with EID (see Table 17), if the EID from
 * the request message matches the DoIP entity’s EID (e.g. one of the MAC addresses, if the DoIP
 * entity implements multiple network interfaces).
 */
static int vehicle_identify_respon_with_eid(doip_entity_t *doip_entity)
{
	if (memcmp(doip_entity->eid, &doip_entity->udp_server.doip_pdu.payload[8], 6) == 0) {
		return vehicle_identify_respon(doip_entity);
	}

	return 0;
}

/* [DoIP-052]
 * Each DoIP entity shall send the vehicle identification response message as specified in Table 19
 * after receipt of a vehicle identification request message with VIN (see Table 18), if the VIN from
 * the request message matches the DoIP entity’s programmed VIN.
 */
static int vehicle_identify_respon_with_vin(doip_entity_t *doip_entity)
{
	if (memcmp(doip_entity->vin, &doip_entity->udp_server.doip_pdu.payload[8], 17) == 0) {
		return vehicle_identify_respon(doip_entity);
	}

	return 0;
}

static int doip_entity_status_respon(doip_entity_t *doip_entity)
{
	doip_stream_t strm;
	uint8_t buffer[16] = {0};

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Doip_Entity_Status_Response, 0));
	doip_stream_write_byte(&strm, 0x01);
	doip_stream_write_byte(&strm, 2);
	doip_stream_write_byte(&strm, doip_entity->tcp_server.client_nums);
	doip_stream_write_be32(&strm, MAX_DOIP_PDU_SIZE);

	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	return udp_server_send(doip_entity, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
}

static bool tester_dynamic_port_verify(uint16_t port)
{
	return (port >= MIN_DYNAMIC_PORT && port <= MAX_DYNAMIC_PORT);
}

static bool tester_logic_addr_verify(doip_entity_t *doip_entity, uint16_t logic_addr)
{
	for (int i = 0; i < doip_entity->white_list_count; i++) {
		if (doip_entity->white_list[i] == logic_addr) {
			return true;
		}
	}

	return false;
}

static uint8_t routing_activation_type_verify(uint8_t active_type)
{
	return (active_type == 0x00 || active_type == 0x01);
}

static int diagnostic_powermode_information_respon(doip_entity_t *doip_entity)
{
	doip_stream_t strm;
	uint8_t buffer[16] = {0};

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Diagnotic_Powermode_Information_Response, 0));
	doip_stream_write_byte(&strm, 0x01);

	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	return udp_server_send(doip_entity, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
}

static ssize_t send_routing_activation_negative_respon(doip_client_t *doip_client, int errcode)
{
	doip_stream_t strm;
	uint8_t buffer[32] = {0};

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Routing_Activation_Response, 0));
	doip_stream_write_be16(&strm, doip_client->logic_addr);
	doip_stream_write_be16(&strm, doip_client->doip_entity->logic_addr);
	doip_stream_write_byte(&strm, errcode);
	doip_stream_write_be32(&strm, 0xffffffff);
	doip_stream_write_be32(&strm, 0xffffffff);

	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	return doip_entity_tcp_send(doip_client, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
}

static bool check_confirmation_is_required(doip_client_t *doip_client)
{
	return false;
}

static bool check_authentication_is_required(doip_client_t *doip_client)
{
	return false;
}

static char *routing_activation_failed_reason(int errcode)
{
	switch (errcode) {
		case Routine_Activation_Unknow_Address:
			return "routing activation unknown address";
		case Routine_Activation_All_Socket_Registered:
			return "routing activation all socket registered";
		case Routine_Activation_SA_Not_Match:
			return "routing activation sa not match";
		case Routine_Activation_SA_Already_Registered:
			return "routing activation sa already registered";
		case Routine_Activation_Missing_Authentication:
			return "routing activation missing authentication";
		case Routine_Activation_Rejected_Confirmation:
			return "routing activation rejected confirmation";
		case Routine_Activation_Unsupported_Activation_Type:
			return "routing activation unsupported activation type";
		default:
			return "unknow";
	}
}

static void doip_entity_send_alive_check_request_on_single_socket(doip_client_t *target)
{
	doip_stream_t strm;
	uint8_t buffer[16] = {0};

	if (target->status != DoIP_Connection_RoutingActivated) {
		return;
	}

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Alive_Check_Request, 0));
	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	doip_entity_tcp_send(target, doip_stream_start_ptr(&strm), doip_stream_len(&strm));

	ev_timer_start(target->doip_entity->loop, &target->tcp_alive_check_timer);
}

static void doip_entity_send_alive_check_request_on_all_tcp_socket(doip_client_t *doip_client)
{
	doip_client_t *pos;

	list_for_each_entry(pos, &doip_client->doip_entity->tcp_server.head, list) {
		if (pos->status == DoIP_Connection_RoutingActivated && pos->logic_addr && pos->handler) {
			doip_entity_send_alive_check_request_on_single_socket(pos);
		}
	}
}

static void doip_entity_send_alive_check_request(doip_client_t *target, bool all)
{
	if (all) {
		doip_entity_send_alive_check_request_on_all_tcp_socket(target);

	} else {
		doip_entity_send_alive_check_request_on_single_socket(target);
	}
}

static void routing_activation_request_handler(doip_client_t *doip_client)
{
	doip_stream_t strm;
	int errcode = -1;
	uint16_t logic_addr;
	uint8_t active_type;
	doip_client_t *pos;
	doip_entity_t *doip_entity = doip_client->doip_entity;
	doip_pdu_t *doip_pdu = &doip_client->doip_pdu;
	uint8_t buffer[32] = {0};

	doip_stream_init(&strm, doip_pdu->payload + 8, doip_pdu->payload_len);
	logic_addr = doip_stream_read_be16(&strm);
	active_type = doip_stream_read_byte(&strm);

	/* [DoIP-059]
	 * Each DoIP entity shall send the routing activation response message with the response code
	 * set to 0x00 after having received a routing activation request message if the source address in
	 * the request message is unknown
	 */
	if (!tester_logic_addr_verify(doip_entity, logic_addr)) {
		errcode = Routine_Activation_Unknow_Address;
		doip_client->status = DoIP_Connection_Finalization;
		goto finish;
	}

	/* [DoIP-151]
	 * Each DoIP entity shall send the routing activation response message with the response code
	 * set to 0x06 after having received a routing activation request message with a routing activation
	 * type that is not supported by the DoIP entity
	 */
	if (!routing_activation_type_verify(active_type)) {
		errcode = Routine_Activation_Unsupported_Activation_Type;
		doip_client->status = DoIP_Connection_Finalization;
		goto finish;
	}

	/* [DoIP-149]
	 * Each DoIP entity shall send the routing activation response message with the response code
	 * set to 0x02 after having received a routing activation request message if the SA differs from the
	 * table connection entry that was received on the already activated TCP_DATA socket
	 */
	if (doip_client->status == DoIP_Connection_RoutingActivated && doip_client->logic_addr != logic_addr) {
		errcode = Routine_Activation_SA_Not_Match;
		doip_client->status = DoIP_Connection_Finalization;
		goto finish;
	}

	/* [DoIP-150]
	 * Each DoIP entity shall send the routing activation response message with the response code
	 * set to 0x03 after having received a routing activation request message if SA is already registered
	 * and active on a different TCP_DATA socket
	 */
	list_for_each_entry(pos, &doip_entity->tcp_server.head, list) {
		if (pos->logic_addr == logic_addr && pos->handler != doip_client->handler) {
			doip_entity_send_alive_check_request(pos, 0);
			errcode = Routine_Activation_SA_Already_Registered;
			doip_client->status = DoIP_Connection_Finalization;
			goto finish;
		}
	}

	/* [DoIP-60]
	 * Each DoIP entity shall send the routing activation response message with the response code
	 * set to 0x01 after having received a routing activation request message if the TCP_DATA socket
	 * is unavailable according to the socket handler requirements in 7.2.4
	 */
	if (doip_entity->tcp_server.client_nums == doip_entity->tcp_server.client_cap && \
			doip_client->status == DoIP_Connection_RoutingActivated) {
		doip_entity_send_alive_check_request(doip_client, 1);
		errcode = Routine_Activation_All_Socket_Registered;
		doip_client->status = DoIP_Connection_Finalization;
		goto finish;
	}

	if (check_authentication_is_required(doip_client)) {
		doip_client->status = DoIP_Connection_Pending_For_Authentication;
		/* TODO authentication */
	}

	if (check_confirmation_is_required(doip_client)) {
		doip_client->status = DoIP_Connection_Pending_For_Confirmation;
		/* TODO confirmation */
	}

	doip_client->logic_addr = logic_addr;

	/* routing activation response */
	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Routing_Activation_Response, 0));
	doip_stream_write_be16(&strm, doip_client->logic_addr);
	doip_stream_write_be16(&strm, doip_entity->logic_addr);
	doip_stream_write_byte(&strm, Routine_Activation_Success);
	doip_stream_write_be32(&strm, 0xffffffff);
	doip_stream_write_be32(&strm, 0xffffffff);

	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	doip_entity_tcp_send(doip_client, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
	doip_client->status = DoIP_Connection_RoutingActivated;
	ev_timer_start(doip_entity->loop, &doip_client->tcp_general_activity_timer);
	return;

finish:
	logd("%s\n", routing_activation_failed_reason(errcode));
	send_routing_activation_negative_respon(doip_client, errcode);
}

static void alive_check_request_handler(doip_client_t *doip_client)
{
	doip_stream_t strm;
	uint8_t buffer[16];

	/* [DoIP-134]
	 * The DoIP alive check message shall only be sent on connections that are currently in one of
	 * the “Registered” connection states.
	 */
	if (doip_client->status != DoIP_Connection_RoutingActivated) {
		return;
	}

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Alive_Check_Response, 0));
	doip_stream_write_be16(&strm, doip_client->logic_addr);

	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	doip_entity_tcp_send(doip_client, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
}

static void alive_check_response_handler(doip_client_t *doip_client)
{
	/* [DoIP-078]
	 * Each DoIP entity shall receive and process alive check response messages according to the
	 * requirements in 7.2.4
	 * NOTE:
	 * The alive check response message can also be used by the external test equipment to keep a currently idle
	 * connection alive, i.e. it can be sent by the external test equipment even if it has not previously received an alive check
	 * request from a DoIP entity.
	 */

	ev_timer_stop(doip_client->doip_entity->loop, &doip_client->tcp_alive_check_timer);
}

static bool is_sa_registered(doip_client_t *doip_client, uint16_t sa)
{
	if (doip_client->logic_addr == sa && doip_client->status == DoIP_Connection_RoutingActivated) {
		return true;
	}

	return false;
}

static bool target_address_verify(doip_client_t *doip_client, uint16_t ta)
{
	doip_entity_t *doip_entity = doip_client->doip_entity;

	return (doip_entity->logic_addr == ta || doip_entity->func_addr == ta);
}

static bool diagnostic_message_size_verify(int size)
{
	/* TODO */
	return true;
}

static bool current_buffer_size_verify(int size)
{
	/* TODO */
	return true;
}

static bool is_ta_reachable(doip_client_t *doip_client, uint16_t ta)
{
	/* TODO */
	return true;
}

static bool pass_diagnostic_message_to_network(doip_pdu_t *doip_pdu)
{
	/* TODO */
	return true;
}

static size_t send_diagnostic_positive_acknowledge_code(doip_client_t *doip_client)
{
	doip_stream_t strm;
	uint8_t buffer[16] = {0};

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Diagnostic_Positive_ACK, 0));
	doip_stream_write_be16(&strm, doip_client->doip_entity->logic_addr);
	doip_stream_write_be16(&strm, doip_client->logic_addr);
	doip_stream_write_byte(&strm, 0x00);

	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	return doip_entity_tcp_send(doip_client, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
}

static size_t send_diagnostic_negative_acknowledge_code(doip_client_t *doip_client, int errcode)
{
	doip_stream_t strm;
	uint8_t buffer[16] = {0};

	doip_stream_init(&strm, buffer, sizeof(buffer));
	doip_stream_forward(&strm, assemble_doip_header(doip_stream_start_ptr(&strm), doip_stream_left_len(&strm), \
				Diagnostic_Negative_ACK, 0));
	doip_stream_write_be16(&strm, doip_client->doip_entity->logic_addr);
	doip_stream_write_be16(&strm, doip_client->logic_addr);
	doip_stream_write_byte(&strm, errcode);
	doip_stream_write_data(&strm, doip_client->doip_pdu.payload + 12, doip_client->doip_pdu.data_len - 12);

	update_doip_header_len(doip_stream_start_ptr(&strm), doip_stream_len(&strm), doip_stream_len(&strm) - 8);

	return doip_entity_tcp_send(doip_client, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
}

static const char *diagnostic_negative_reason(int errcode)
{
	switch (errcode) {
		case Diagnostic_Message_Invalid_Source_Address:
			return "diagnostic message, invalid source address";
		case Diagnostic_Message_Unknow_Target_Address:
			return "diagnostic message, unknow target address";
		case Diagnostic_Message_Too_Long:
			return "diagnostic message, message too long";
		case Diagnostic_Message_Out_Of_Memory:
			return "diagnostic message, out of memory";
		case Diagnostic_Message_Target_Unreachable:
			return "diagnostic message, target unreachable";
		case Diagnostic_Message_Unkonw_Network:
			return "diagnostic message, unknow network";
		case Diagnostic_Message_Transport_Protocol_Error:
			return "diagnostic message, transport protocol error";
		default:
			return "unknow";
	}
}

static int get_addr_type(uint8_t *data, int len)
{
	doip_stream_t strm;

	if (len < 12) {
		return 0;
	}
	doip_stream_init(&strm, data, len);
	doip_stream_forward(&strm, 10);
	return !!(doip_stream_read_be16(&strm) == 0xe400);
}

static int uds_service_handler(doip_client_t *doip_client)
{
	doip_entity_t *doip_entity = doip_client->doip_entity;
	uds_request_t *uds_request = &doip_entity->uds_request;

	if (uds_request->status != DoIP_Connection_Socket_Initialized) {
		return 0;
	}

	doip_stream_t strm = {0};
	doip_stream_init(&strm, uds_request->buffer, uds_request->cap);
	doip_stream_write_be16(&strm, doip_client->logic_addr);
	doip_stream_write_be16(&strm, doip_entity->logic_addr);
	doip_stream_write_byte(&strm, get_addr_type(doip_client->doip_pdu.payload, 12));
	doip_stream_write_data(&strm, doip_client->doip_pdu.payload + 12, doip_client->doip_pdu.payload_len - 4);

	doip_hexdump(doip_stream_start_ptr(&strm), doip_stream_len(&strm));

	return sendto(uds_request->handler, doip_stream_start_ptr(&strm), doip_stream_len(&strm), 0, \
			(struct sockaddr *)&uds_request->target, sizeof(uds_request->target));
}

static void disgnostic_message_handler(doip_client_t *doip_client)
{
	doip_stream_t strm;
	uint16_t ta, sa;
	int errcode = 0;
	doip_pdu_t *doip_pdu = &doip_client->doip_pdu;

	doip_stream_init(&strm, doip_pdu->payload, doip_pdu->data_len);
	doip_stream_forward(&strm, 8);
	sa = doip_stream_read_be16(&strm);
	ta = doip_stream_read_be16(&strm);

	/* [DoIP-131]
	 * Incoming DoIP messages, except the DoIP routing activation message or messages required
	 * for authentication or confirmation, shall not be processed nor be routed before the connection
	 * is in the state “Registered [Routing Active]”.
	 */
	if (doip_client->status != DoIP_Connection_RoutingActivated) {
		return;
	}

	/* [DoIP-070]
	 * Each DoIP entity shall send the diagnostic message negative acknowledgement with NACK
	 * code set to 0x02 (see Table 31) and close the TCP_DATA socket when the diagnostic message
	 * contains a source address which is not activated on the TCP_DATA socket on which the
	 * diagnostic message is receive.
	 */
	if (!is_sa_registered(doip_client, sa)) {
		errcode = Diagnostic_Message_Invalid_Source_Address;
		goto finish;
	}

	/* [DoIP-071]
	 * Each DoIP entity shall send the diagnostic message negative acknowledgement with NACK
	 * code set to 0x03 (see Table 31) when the diagnostic message contains an unknown target
	 * address (e.g. ECU not connected to the addressed DoIP gateway).
	 */
	if (!target_address_verify(doip_client, ta)) {
		errcode = Diagnostic_Message_Unknow_Target_Address;
		goto finish;
	}

	/* [DoIP-072]
	 * Each DoIP entity shall send the diagnostic message negative acknowledgement with NACK
	 * code set to 0x04 (see Table 31) when the diagnostic message exceeds the maximum supported
	 * length of the transport protocol of the target network or target ECU (e.g. messages larger than
	 * 4095 bytes on CAN or when an ECU-specific message size limit is exceeded).
	 */
	if (!diagnostic_message_size_verify(doip_pdu->payload_len)) {
		errcode = Diagnostic_Message_Too_Long;
		goto finish;
	}

	/* [DoIP-073]
	 * Each DoIP entity shall send the diagnostic message negative acknowledgement with NACK
	 * code set to 0x05 (see Table 31) when the diagnostic message is too large to be copied into
	 * the destination buffer (e.g. the transport protocol refuses the request to provide the necessary
	 * buffer).
	 */
	if (!current_buffer_size_verify(doip_pdu->payload_len)) {
		errcode = Diagnostic_Message_Out_Of_Memory;
		goto finish;
	}

	/* [DoIP-103]
	 * If supported, each DoIP entity shall send the diagnostic message negative acknowledgement
	 * with NACK code set to 0x06 (see Table 31) when the target address points to a device that can
	 * currently not be reache.
	 */
	if (!is_ta_reachable(doip_client, ta)) {
		errcode = Diagnostic_Message_Target_Unreachable;
		goto finish;
	}

	/* [DoIP-107]
	 * If supported and if an unknown target network or transport protocol error occurs that is not
	 * covered by the previous NACK codes, the DoIP entity shall send the diagnostic message
	 * negative acknowledgement with NACK code set to 0x07 or 0x08 (see Table 31).
	 */
	if (!pass_diagnostic_message_to_network(doip_pdu)) {
		errcode = Diagnostic_Message_Unkonw_Network;
		goto finish;
	}

	send_diagnostic_positive_acknowledge_code(doip_client);

	uds_service_handler(doip_client);

	return;

finish:
	/* according to [DoIP-070] */
	if (errcode == Diagnostic_Message_Invalid_Source_Address) {
		doip_client->status = DoIP_Connection_Finalization;
	}
	logd("%s\n", diagnostic_negative_reason(errcode));
	send_diagnostic_negative_acknowledge_code(doip_client, errcode);
}

static char *header_verify_fail_reason(int errcode)
{
	switch (errcode) {
		case Header_NACK_Incorrect_Pattern_Format:
			return "header nack incorrect pattern format";
		case Header_NACK_Unknow_Payload_type:
			return "header unknow payload type";
		case Header_NACK_Message_Too_Large:
			return "header nack message too large";
		case Header_NACK_Out_Of_Memory:
			return "header nack out of memory";
		case Header_NACK_Invalid_Payload_Len:
			return "header nack invalid payload len";
		default:
			return "unknown";
	}
}

static void tcp_read_cb(struct ev_loop *loop, ev_io *w, int e)
{
	int errcode = 0;
	ssize_t count, total = 0;
	doip_entity_t *doip_entity = ev_userdata(loop);
	doip_client_t *doip_client = (doip_client_t *)w->data;
	doip_pdu_t *doip_pdu = &doip_client->doip_pdu;

	/* flush general_activity_timer */
	if (doip_client->status == DoIP_Connection_RoutingActivated) {
		ev_timer_again(doip_entity->loop, &doip_client->tcp_general_activity_timer);
	}

	if (!ev_is_active(&doip_client->data_collection_timer)) {
		ev_timer_start(doip_entity->loop, &doip_client->data_collection_timer);
	}

	count = recv(w->fd, doip_pdu->payload + doip_pdu->data_len, doip_pdu->payload_cap - doip_pdu->data_len, MSG_PEEK);

	if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		logd("no data readable\n");
		goto finish_2;
	}

	/* peer disconnected or error occurred */
	if (count <= 0) {
		logd("%s\n", count == 0 ? "peer disconnected" : "system error");
		doip_client->status = DoIP_Connection_Finalization;
		goto finish_2;
	}

	doip_pdu->data_len += count;

	/* doip header is not yet fully collected */
	if (doip_pdu->data_len < 8) {
		goto finish_2;
	}

	/* doip header collection completed */
	disassemble_doip_header(doip_pdu->payload, doip_pdu->data_len, doip_pdu);

	logd("payload_type:0x%04x (%s)\n", doip_pdu->payload_type, show_message_info(doip_pdu->payload_type));

	if (!tcp_doip_header_verify(doip_pdu, &errcode)) {
		tcp_send_generic_header_nack(doip_client, errcode);
		logd("%s\n", header_verify_fail_reason(errcode));
		/* according to DoIP generic header handler [DoIP-045] */
		if (errcode == Header_NACK_Incorrect_Pattern_Format || errcode == Header_NACK_Invalid_Payload_Len) {
			doip_client->status = DoIP_Connection_Finalization;
			goto finish_2;
		}
		/* according to DoIP generic header handler [DoIP-087] */
		else if (errcode == Header_NACK_Unknow_Payload_type || \
				errcode == Header_NACK_Message_Too_Large || \
				errcode == Header_NACK_Out_Of_Memory) {
			doip_client->discard = 1;
		}
	}

	/* doip payload is not yet fully collected */
	if (doip_pdu->data_len < (doip_pdu->payload_len + 8)) {
		goto finish_2;
	}

	/* doip request collection completed */
	while ((count = recv(w->fd, doip_pdu->payload + total, doip_pdu->payload_len + 8 - total, 0)) > 0) {
		total += count;
	}

	if ((count == 0) || (count < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK))) {
		logd("%s\n", count == 0 ? "peer disconnected" : "system error");
		doip_client->status = DoIP_Connection_Finalization;
		goto finish_2;
	}

	ev_timer_stop(doip_entity->loop, &doip_client->data_collection_timer);

	/* do not handler, just discard */
	if (doip_client->discard == 1) {
		goto finish_1;
	}

	switch (doip_pdu->payload_type) {
		case Routing_Activation_Request:
			ev_timer_stop(doip_client->doip_entity->loop, &doip_client->tcp_initial_activity_timer);
			routing_activation_request_handler(doip_client);
			break;
		case Alive_Check_Request:
			alive_check_request_handler(doip_client);
			break;
		case Alive_Check_Response:
			alive_check_response_handler(doip_client);
			break;
		case Diagnostic_Message:
			disgnostic_message_handler(doip_client);
			break;
		default:
			logd("unknow payload_type\n");
			break;
	}

finish_1:
	doip_client->discard = 0;
	doip_pdu->data_len = 0;

finish_2:
	return;
}

static void general_activity_timer_callback(struct ev_loop *loop, ev_timer *w, int e)
{
	doip_client_t *doip_client = (doip_client_t *)w->data;

	ev_timer_stop(loop, w);
	logd("general_activity_timer timeout(%fs)\n", w->repeat);
	doip_client->status = DoIP_Connection_Finalization;
}

static void initial_activity_timer_callback(struct ev_loop *loop, ev_timer *w, int e)
{
	doip_client_t *doip_client = (doip_client_t *)w->data;

	ev_timer_stop(loop, w);
	logd("initial_activity_time timeout(%fs timeout)\n", w->repeat);
	doip_client->status = DoIP_Connection_Finalization;
}

static void alive_check_timer_callback(struct ev_loop *loop, ev_timer *w, int e)
{
	doip_client_t *doip_client = (doip_client_t *)w->data;

	doip_assert(!!doip_client, "doip_client is NULL\n");

	doip_client->status = DoIP_Connection_Finalization;
}

static void data_collection_timer_callback(struct ev_loop *loop, ev_timer *w, int e)
{
	doip_client_t *doip_client = (doip_client_t *)w->data;
	doip_pdu_t *doip_pdu = &doip_client->doip_pdu;

	doip_pdu->data_len = 0;
}

static void accept_cb(struct ev_loop *loop, ev_io *w, int e)
{
	struct sockaddr_in client;
	socklen_t socklen = sizeof(client);
	doip_client_t *doip_client = NULL;
	doip_entity_t *doip_entity = ev_userdata(loop);
	doip_server_t *tcp_server = &doip_entity->tcp_server;

	if (tcp_server->status == DoIP_Connection_Finalization) {
		logd("tcp server socket has been marked finalized\n");
		return;
	}

	int connfd = accept(w->fd, (struct sockaddr *)&client, &socklen);
	if ((connfd < 0) && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		/* no new connection */
		return;
	}

	if (connfd < 0) {
		/* some error occurred */
		logd("tcp server internal error occurred\n");
		doip_entity->tcp_server.status = DoIP_Connection_Finalization;
		return;
	}

	if (tcp_server->client_nums > tcp_server->client_cap) {
		logd("clients(%d) > limitaion(%d), just ingore new connections\n", tcp_server->client_nums, tcp_server->client_cap);
		close(connfd);
		return;
	}

	logd("new connection(fd:%d) from [%s:%d]\n", connfd, inet_ntoa(client.sin_addr), be16toh(client.sin_port));

	/* set nonblock */
	fcntl(connfd, F_SETFL, fcntl(connfd, F_GETFL, 0) | O_NONBLOCK);

	doip_client = doip_malloc(sizeof(*doip_client));
	doip_assert(!!doip_client, "doip_malloc failed\n");

	doip_client->doip_pdu.payload_cap = MAX_DOIP_PDU_SIZE;
	doip_client->doip_pdu.payload = doip_malloc(MAX_DOIP_PDU_SIZE);
	doip_assert(!!doip_client->doip_pdu.payload, "doip_malloc failed\n");

	doip_client->watcher.data = doip_client;
	doip_client->tcp_initial_activity_timer.data = doip_client;
	doip_client->tcp_general_activity_timer.data = doip_client;
	doip_client->tcp_alive_check_timer.data = doip_client;

	INIT_LIST_HEAD(&doip_client->list);
	doip_client->handler = connfd;
	doip_client->status = DoIP_Connection_Socket_Initialized;
	doip_client->doip_entity = doip_entity;
	doip_client->port = be16toh(client.sin_port);
	inet_ntop(AF_INET, &client.sin_addr, doip_client->client, sizeof(doip_client->client));

	/* set max priority */
	ev_set_priority(&doip_client->watcher, EV_MAXPRI);
	ev_io_init(&doip_client->watcher, tcp_read_cb, doip_client->handler, EV_READ);
	ev_io_start(loop, &doip_client->watcher);

	ev_timer_init(&doip_client->tcp_general_activity_timer, general_activity_timer_callback, \
			doip_entity->tcp_general_activity_time * 1e-3, doip_entity->tcp_general_activity_time * 1e-3);

	ev_timer_init(&doip_client->tcp_initial_activity_timer, initial_activity_timer_callback, \
			doip_entity->tcp_initial_activity_time * 1e-3, doip_entity->tcp_initial_activity_time * 1e-3);
	ev_timer_start(loop, &doip_client->tcp_initial_activity_timer);

	ev_timer_init(&doip_client->tcp_alive_check_timer, alive_check_timer_callback, \
			doip_entity->tcp_alive_check_time * 1e-3, doip_entity->tcp_alive_check_time * 1e-3);

	ev_timer_init(&doip_client->data_collection_timer, data_collection_timer_callback, DATA_COLLECTION_TIMEOUT, \
			DATA_COLLECTION_TIMEOUT);

	/* add client to list */
	list_add(&doip_client->list, &doip_entity->tcp_server.head);
	++doip_entity->tcp_server.client_nums;
}

static int tcp_server_init(doip_entity_t *doip_entity)
{
	struct sockaddr_in server;
	doip_server_t *tcp_server = &doip_entity->tcp_server;

	if ((tcp_server->handler = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return -1;
	}

	int opt = 1;
	setsockopt(tcp_server->handler, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	/* set nonblock */
	fcntl(tcp_server->handler, F_SETFL, fcntl(tcp_server->handler, F_GETFL, 0) | O_NONBLOCK);

	bzero((uint8_t *)&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htobe16(doip_entity->tcp_server.port);
	inet_pton(AF_INET, doip_entity->tcp_server.addr, &server.sin_addr);

	if (bind(tcp_server->handler, (struct sockaddr *)&server, sizeof(server)) < 0) {
		goto finish;
	}

	if (listen(tcp_server->handler, BACKLOG) < 0) {
		goto finish;
	}

	tcp_server->status = DoIP_Connection_Socket_Initialized;
	return tcp_server->handler;

finish:
	if (tcp_server->handler > 0) {
		close(tcp_server->handler);
		tcp_server->handler = -1;
	}
	return tcp_server->handler;
}

static void vehicle_identify_announce_timer_callback(struct ev_loop *loop, ev_timer *w, int e)
{
	static int count = 0;
	doip_entity_t *doip_entity = ev_userdata(loop);

	vehicle_identify_announce(doip_entity);

	if (++count >= doip_entity->doip_announce_num) {
		count = 0;
		ev_timer_stop(loop, w);
	}
}

static int udp_server_init(doip_entity_t *doip_entity)
{
	int broadcast = 1;
	struct sockaddr_in server;
	doip_server_t *udp_server = &doip_entity->udp_server;

	if ((udp_server->handler = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		return -1;
	}

	/* set nonblock */
	fcntl(udp_server->handler, F_SETFL, fcntl(udp_server->handler, F_GETFL, 0) | O_NONBLOCK);

	/* enable broadcast */
	setsockopt(udp_server->handler, SOL_SOCKET, SO_BROADCAST, (uint8_t *)&broadcast, sizeof(broadcast));

	bzero((uint8_t *)&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htobe16(doip_entity->udp_server.port);
	inet_pton(AF_INET, doip_entity->udp_server.addr, &server.sin_addr);

	if (bind(udp_server->handler, (struct sockaddr *)&server, sizeof(server)) < 0) {
		goto finish;
	}

	udp_server->status = DoIP_Connection_Socket_Initialized;

	/* init broadcast target */
	bzero(&doip_entity->udp_server.broadcast, sizeof(doip_entity->udp_server.broadcast));
	doip_entity->udp_server.broadcast.sin_family = AF_INET;
	doip_entity->udp_server.broadcast.sin_port = htobe16(UDP_DISCOVERY);
	inet_pton(AF_INET, UDP_BROADCAST_ADDR, &doip_entity->udp_server.broadcast.sin_addr);

	return udp_server->handler;

finish:
	if (udp_server->handler > 0) {
		close(udp_server->handler);
		udp_server->handler = -1;
	}
	return udp_server->handler;
}

static void tcp_server_start(struct ev_loop *loop, doip_entity_t *doip_entity)
{
	ev_io_init(&doip_entity->tcp_server.watcher, accept_cb, doip_entity->tcp_server.handler, EV_READ);
	ev_io_start(loop, &doip_entity->tcp_server.watcher);
}

static void udp_read_cb(struct ev_loop *loop, ev_io *w, int e)
{
	int errcode;
	socklen_t socklen;
	doip_entity_t *doip_entity = ev_userdata(loop);
	doip_server_t *udp_server = &doip_entity->udp_server;

	socklen = sizeof(udp_server->target);
	ssize_t count = recvfrom(w->fd, udp_server->doip_pdu.payload, udp_server->doip_pdu.payload_cap, 0, \
			(struct sockaddr *)&udp_server->target, &socklen);
	if (count == 0) {
		/* no data readable */
		goto finish;
	}
	if (count < 0) {
		/* server error occurred */
		udp_server->status = DoIP_Connection_Finalization;
		goto finish;
	}

	if (count < 8) {
		/* not valid header */
		goto finish;
	}

	/* [DoIP-135]
	 * The external test equipment shall transmit UDP messages to the DoIP entity with the UDP
	 * source port UDP_TEST_EQUIPMENT_REQUEST dynamically assigned within the dynamic
	 * port range (49 152…65 535)
	 */
	if (!tester_dynamic_port_verify(be16toh(udp_server->target.sin_port))) {
		logd("dynamic port range [%d ~ %d], %d is not allowed\n", MIN_DYNAMIC_PORT, MAX_DYNAMIC_PORT, \
				be16toh(udp_server->target.sin_port));
		goto finish;
	}

	disassemble_doip_header(udp_server->doip_pdu.payload, count, &udp_server->doip_pdu);

	if (!udp_doip_header_verify(&udp_server->doip_pdu, &errcode)) {
		udp_send_generic_header_nack(doip_entity, errcode);
		goto finish;
	}

	uint16_t payload_type = udp_server->doip_pdu.payload_type;

	logd("payload_type:0x%04x (%s)\n", payload_type, show_message_info(payload_type));

	switch (payload_type) {
		/* according to DoIP generic header handler */
		case Generic_Doip_Header_Negative_Ack:
		case Vehicle_Announcememt_Message:
			/* Ignore */
			break;
		case Vehicle_Identify_Request_Message:
			vehicle_identify_respon(doip_entity);
			break;
		case Vehicle_Identify_Request_Message_With_EID:
			vehicle_identify_respon_with_eid(doip_entity);
			break;
		case Vehicle_Identify_Request_Message_With_VIN:
			vehicle_identify_respon_with_vin(doip_entity);
			break;
		case Doip_Entity_Status_Request:
			doip_entity_status_respon(doip_entity);
			break;
		case Diagnotic_Powermode_Information_Request:
			diagnostic_powermode_information_respon(doip_entity);
			break;
		default:
			logd("unknow\n");
	}

finish:
	return;
}

static void udp_server_start(struct ev_loop *loop, doip_entity_t *doip_entity)
{
	ev_io_init(&doip_entity->udp_server.watcher, udp_read_cb, doip_entity->udp_server.handler, EV_READ);

	ev_io_start(loop, &doip_entity->udp_server.watcher);

	ev_timer_init(&doip_entity->udp_server.vehicle_identify_announce_timer, vehicle_identify_announce_timer_callback, \
			doip_entity->doip_announce_interval * 1e-3, doip_entity->doip_announce_interval * 1e-3);

	ev_timer_start(loop, &doip_entity->udp_server.vehicle_identify_announce_timer);
}

/* cleanup one tcp client */
static void tcp_client_cleanup(doip_client_t *doip_client)
{
	struct ev_loop *loop = doip_client->doip_entity->loop;

	doip_assert(doip_client->handler == doip_client->watcher.fd, \
			"doip_client->handler(%d) != doip_client->watcher->fd(%d)\n", doip_client->handler, doip_client->watcher.fd);
	ev_io_stop(loop, &doip_client->watcher);
	ev_timer_stop(loop, &doip_client->tcp_general_activity_timer);
	ev_timer_stop(loop, &doip_client->tcp_initial_activity_timer);
	ev_timer_stop(loop, &doip_client->tcp_alive_check_timer);
	ev_timer_stop(loop, &doip_client->data_collection_timer);
	close(doip_client->watcher.fd);
	logd("tcp_client_cleanup, fd:%d\n", doip_client->handler);
	list_del(&doip_client->list);
	doip_free(doip_client->doip_pdu.payload);
	bzero(doip_client, sizeof(*doip_client));
	doip_free(doip_client);
}

/* cleanup tcp server */
static void doip_tcp_server_cleanup(doip_entity_t *doip_entity)
{
	doip_client_t *client, *temp;
	struct ev_loop *loop = doip_entity->loop;
	doip_server_t *tcp_server = &doip_entity->tcp_server;

	list_for_each_entry_safe(client, temp, &tcp_server->head, list) {
		tcp_client_cleanup(client);
	}

	tcp_server->client_nums = 0;
	INIT_LIST_HEAD(&tcp_server->head);

	doip_assert(tcp_server->handler == tcp_server->watcher.fd, \
			"tcp_server->handler(%d) != tcp_server->watcher->fd(%d)\n", tcp_server->handler, tcp_server->watcher.fd);
	ev_io_stop(loop, &tcp_server->watcher);
	close(tcp_server->watcher.fd);
	tcp_server->handler = -1;
	bzero(&tcp_server->watcher, sizeof(ev_io));
	tcp_server->status = DoIP_Connection_Socket_Uninitialized;
}

/* cleanup udp server */
static void doip_udp_server_cleanup(doip_entity_t *doip_entity)
{
	doip_server_t *udp_server = &doip_entity->udp_server;

	ev_io_stop(doip_entity->loop, &udp_server->watcher);
	close(udp_server->watcher.fd);
	ev_timer_stop(doip_entity->loop, &udp_server->vehicle_identify_announce_timer);
	udp_server->status = DoIP_Connection_Socket_Uninitialized;
}

/* cleanup uds receiver */
static void uds_indication_cleanup(doip_entity_t *doip_entity)
{
	uds_indication_t *uds_indication = &doip_entity->uds_indication;

	ev_io_stop(doip_entity->loop, &uds_indication->watcher);
	close(uds_indication->watcher.fd);
	uds_indication->handler = -1;
	uds_indication->status = DoIP_Connection_Socket_Uninitialized;
}

/* cleanup uds sender */
static void uds_request_cleanup(doip_entity_t *doip_entity)
{
	uds_request_t *uds_request = &doip_entity->uds_request;

	close(uds_request->handler);
	uds_request->handler = -1;
	uds_request->status = DoIP_Connection_Socket_Uninitialized;
}

/* this function do all cleanup */
static void doip_entity_cleanup(struct ev_loop *loop)
{
	doip_client_t *client, *temp;
	doip_entity_t *doip_entity = ev_userdata(loop);
	doip_server_t *tcp_server = &doip_entity->tcp_server;
	doip_server_t *udp_server = &doip_entity->udp_server;
	uds_indication_t *uds_indication = &doip_entity->uds_indication;
	uds_request_t *uds_request = &doip_entity->uds_request;

	/* cleanup tcp server */
	if (tcp_server->status == DoIP_Connection_Finalization) {
		doip_tcp_server_cleanup(doip_entity);
	}

	/* cleanup udp server */
	if (udp_server->status == DoIP_Connection_Finalization) {
		doip_udp_server_cleanup(doip_entity);
	}

	/* cleanup uds_indication */
	if (uds_indication->status == DoIP_Connection_Finalization) {
		uds_indication_cleanup(doip_entity);
	}

	/* cleanup uds_request */
	if (uds_request->status == DoIP_Connection_Finalization) {
		uds_request_cleanup(doip_entity);
	}

	list_for_each_entry_safe(client, temp, &tcp_server->head, list) {
		if (client->status == DoIP_Connection_Finalization) {
			tcp_client_cleanup(client);
			doip_assert(tcp_server->client_nums > 0, "tcp_server->client_nums must > 0\n");
			--tcp_server->client_nums;
		}
	}
}

static int uds_indication_init(doip_entity_t *doip_entity)
{
	struct sockaddr_un server;
	uds_indication_t *uds_indication = &doip_entity->uds_indication;

	if ((uds_indication->handler = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		return -1;
	}

	/* delete socket file */
	unlink(uds_indication->sockfile);

	bzero(&server, sizeof(server));
	server.sun_family = AF_UNIX;
	memcpy(server.sun_path, uds_indication->sockfile, MIN(sizeof(server.sun_path), strlen(uds_indication->sockfile)));

	int opt = 1;
	setsockopt(uds_indication->handler, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if (bind(uds_indication->handler, (struct sockaddr *)&server, sizeof(server)) < 0) {
		goto finish;
	}

	uds_indication->status = DoIP_Connection_Socket_Initialized;
	return uds_indication->handler;

finish:
	close(uds_indication->handler);
	uds_indication->handler = -1;
	return -1;
}

static ssize_t uds_respon_dispatch(doip_entity_t *doip_entity, uint8_t *data, int len)
{
	doip_client_t *client;
	doip_stream_t strm = {0};

	if (len < 5) {
		return 0;
	}

	doip_stream_init(&strm, data, len);
	uint16_t sa = doip_stream_read_be16(&strm);
	uint16_t ta = doip_stream_read_be16(&strm);
	uint8_t type = doip_stream_read_byte(&strm);

	list_for_each_entry(client, &doip_entity->tcp_server.head, list) {
		if (client->logic_addr == sa) {
			break;
		}
	}

	if (!client) {
		logd("logic_addr(0x%04x) not found int registered entry\n", sa);
		return 0;
	}

	uint8_t buf[64] = {0};

	doip_stream_init(&strm, buf, sizeof(buf));
	assemble_doip_header(buf, sizeof(buf), Diagnostic_Message, 0);
	doip_stream_forward(&strm, 8);
	doip_stream_write_be16(&strm, ta);
	doip_stream_write_be16(&strm, sa);
	doip_stream_write_data(&strm, data + 5, len - 5);
	update_doip_header_len(buf, sizeof(buf), doip_stream_len(&strm) - 8);
	doip_hexdump(buf, doip_stream_len(&strm));
	return doip_entity_tcp_send(client, doip_stream_start_ptr(&strm), doip_stream_len(&strm));
}

static void uds_indication_cb(struct ev_loop *loop, ev_io *w, int e)
{
	doip_entity_t *doip_entity = ev_userdata(loop);
	uds_indication_t *uds_indication = &doip_entity->uds_indication;

	ssize_t count = recv(w->fd, uds_indication->buffer, sizeof(uds_indication->buffer), MSG_DONTWAIT);
	/* no data readable */
	if (count == 0) {
		return;
	}
	/* error */
	if (count < 0) {
		uds_indication->status = DoIP_Connection_Finalization;
		return;
	}

	/* send uds respon */
	uds_respon_dispatch(doip_entity, uds_indication->buffer, count);
}

static void start_uds_indication(struct ev_loop *loop, doip_entity_t *doip_entity)
{
	ev_io_init(&doip_entity->uds_indication.watcher, uds_indication_cb, doip_entity->uds_indication.handler, EV_READ);
	ev_io_start(loop, &doip_entity->uds_indication.watcher);
}

static int uds_request_init(doip_entity_t *doip_entity)
{
	uds_request_t *uds_request = &doip_entity->uds_request;

	if ((uds_request->handler = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		return -1;
	}

	bzero(&uds_request->target, sizeof(uds_request->target));
	uds_request->target.sun_family = AF_UNIX;
	snprintf(uds_request->target.sun_path, sizeof(uds_request->target.sun_path), "%s", uds_request->sockfile);

	fcntl(uds_request->handler, F_SETFL, fcntl(uds_request->handler, F_GETFL, 0) | O_NONBLOCK);
	uds_request->status = DoIP_Connection_Socket_Initialized;

	return uds_request->handler;
}

static void prepare_cb(struct ev_loop *loop, ev_prepare *w, int e)
{
	doip_entity_t *doip_entity = (doip_entity_t *)ev_userdata(loop);

	if (doip_entity->tcp_server.status == DoIP_Connection_Socket_Uninitialized) {
		logd("tcp_server_init\n");
		if (tcp_server_init(doip_entity) < 0) {
			return;
		}
		tcp_server_start(loop, doip_entity);
	}

	if (doip_entity->udp_server.status == DoIP_Connection_Socket_Uninitialized) {
		logd("udp_server_init\n");
		if (udp_server_init(doip_entity) < 0) {
			return;
		}
		udp_server_start(loop, doip_entity);
	}

	if (doip_entity->uds_indication.status == DoIP_Connection_Socket_Uninitialized) {
		logd("uds_indication_init\n");
		if (uds_indication_init(doip_entity) < 0) {
			return;
		}
		start_uds_indication(loop, doip_entity);
	}

	if (doip_entity->uds_request.status == DoIP_Connection_Socket_Uninitialized) {
		logd("uds_request_init\n");
		if (uds_request_init(doip_entity) < 0) {
			loge("uds_request_init failed\n");
		}
	}

	doip_entity_cleanup(loop);
}

static void heartbeat_cb(struct ev_loop *loop, ev_timer *w, int e)
{
	doip_client_t *pos;
	doip_entity_t *doip_entity = ev_userdata(loop);

	logd("%f timeout\n", w->repeat);
	ev_timer_again(loop, w);

	logd("Alive TCP_DATA count:%d\n", doip_entity->tcp_server.client_nums);
	list_for_each_entry(pos, &doip_entity->tcp_server.head, list) {
		logd("handler:%d, status:%s, [%s:%d]\n", pos->handler, doip_client_status(pos->status), pos->client, pos->port);
	}
}

static void doip_entity_init(doip_entity_t *doip_entity)
{
	if (!doip_entity) {
		return;
	}

	ev_prepare_init(&doip_entity->prepare_w, prepare_cb);
	ev_prepare_start(doip_entity->loop, &doip_entity->prepare_w);

	ev_timer_init(&doip_entity->heartbeat_w, heartbeat_cb, 3., 3.);
	ev_timer_start(doip_entity->loop, &doip_entity->heartbeat_w);
}

doip_entity_t *doip_entity_alloc(uint16_t logic_addr, uint16_t func_addr, const char *tcp_server, uint16_t tcp_port, \
		const char *udp_server, uint16_t udp_port)
{
	doip_entity_t *doip_entity = doip_malloc(sizeof(*doip_entity));

	if (!doip_entity) {
		return NULL;
	}

	bzero(doip_entity, sizeof(*doip_entity));
	doip_entity->loop = ev_default_loop(EVFLAG_NOENV);
	doip_entity->udp_server.doip_pdu.payload_cap = DOIP_UDP_PDU_SIZE;
	doip_entity->udp_server.doip_pdu.payload = doip_malloc(doip_entity->udp_server.doip_pdu.payload_cap);
	doip_entity->uds_request.cap = MAX_DOIP_PDU_SIZE;
	doip_entity->uds_request.buffer = doip_malloc(doip_entity->uds_request.cap);

	doip_entity->tcp_server.doip_entity = doip_entity;
	doip_entity->udp_server.doip_entity = doip_entity;
	doip_entity->uds_request.doip_entity = doip_entity;
	doip_entity->uds_indication.doip_entity = doip_entity;

	doip_assert(doip_entity->loop && doip_entity->udp_server.doip_pdu.payload && doip_entity->uds_request.buffer, \
			"doip_malloc failed\n");

	doip_entity->logic_addr = logic_addr;
	doip_entity->func_addr = func_addr;
	doip_entity->tcp_server.port = tcp_port;
	doip_entity->udp_server.port = udp_port;
	memcpy(doip_entity->tcp_server.addr, tcp_server, MIN(sizeof(doip_entity->tcp_server.addr), strlen(tcp_server)));
	memcpy(doip_entity->udp_server.addr, udp_server, MIN(sizeof(doip_entity->udp_server.addr), strlen(udp_server)));

	doip_entity->tcp_initial_activity_time = T_TCP_Initial_Inactivity;
	doip_entity->tcp_general_activity_time = T_TCP_General_Inactivity;
	doip_entity->tcp_alive_check_time = T_TCP_Alive_Check;
	doip_entity->doip_announce_num = A_DoIP_Announce_Num;
	doip_entity->doip_announce_interval = A_DoIP_Announce_Interval;
	doip_entity->doip_announce_wait = A_DoIP_Announce_Wait;

	ev_set_userdata(doip_entity->loop, doip_entity);

	INIT_LIST_HEAD(&doip_entity->tcp_server.head);
	doip_entity->tcp_server.client_cap = DOIP_CLIENTS_LIMITATION;

	doip_entity->uds_request.sockfile = UDS_REQUEST_SOCKFILE;
	doip_entity->uds_indication.sockfile = UDS_INDICATION_SOCKFILE;
	doip_entity->uds_request.status = DoIP_Connection_Socket_Uninitialized;
	doip_entity->uds_indication.status = DoIP_Connection_Socket_Uninitialized;

	doip_entity_init(doip_entity);

	return doip_entity;
}

static void doip_entity_info(doip_entity_t *doip_entity)
{
	doip_assert(!!doip_entity, "doip_entity invalid\n");

	logd("logic_addr:0x%04x\n", doip_entity->logic_addr);
	logd("func_addr:0x%04x\n", doip_entity->func_addr);
	logd("vin:%s\n", doip_entity->vin);
	logd("udp server %s:%d\n", doip_entity->udp_server.addr, doip_entity->udp_server.port);
	logd("tcp server %s:%d\n", doip_entity->tcp_server.addr, doip_entity->tcp_server.port);
	logd("tcp_general_activity_time:%.fms\n", doip_entity->tcp_general_activity_time);
	logd("tcp_initial_activity_time:%.fms\n", doip_entity->tcp_initial_activity_time);
	logd("doip_announce_wait:%.fms\n", doip_entity->doip_announce_wait);
	logd("doip_announce_num:%d, doip_announce_interval:%.fms\n", doip_entity->doip_announce_num, \
			doip_entity->doip_announce_interval);
}

int doip_entity_start(doip_entity_t *doip_entity)
{
	if (!doip_entity) {
		return -1;
	}

	signal(SIGPIPE, SIG_IGN);
	doip_entity_info(doip_entity);
	ev_run(doip_entity->loop, 0);
	return 0;
}
