#ifndef __DOIP_ENTITY_H__
#define __DOIP_ENTITY_H__

/*------------------------------------------------------------------------------------------------------------*/

#define GENERICDOIPHEADERNEGATIVEACKNOWLEDGE	       0x0000
#define VEHICLEIDENTIFICATIONREQUESTMESSAGE            0x0001
#define VEHICLEIDENTIFICATIONREQUESTMESSAGEWITHEID     0x0002
#define VEHICLEIDENTIFICATIONREQUESTMESSAGEWITHVIN     0x0003
#define VEHICLEANNOUNCEMENTMESSAGE                     0x0004
#define VEHICLEIDENTIFICATIONRESPONSE                  0x0004
#define ROUTINGACTIVATIONREQUEST                       0x0005
#define ROUTINGACTIVATIONRESPONSE                      0x0006
#define ALIVECHECKREQUEST                              0x0007
#define ALIVECHECKRESPONSE                             0x0008

/* 0x0009 ~ 0x4000 reserved by ISO */

#define DOIPENTITYSTATUSRESQUEST                       0x4001
#define DOIPENTITYSTATUSRESPONSE                       0x4002
#define DIAGNOSTICPOWERMODEINFORMATIONREQUEST          0x4003
#define DIAGNOSTICPOWERMODEINFORMATIONRESPONSE         0x4004
#define DIAGNOSTICMESSAGE                              0x8001
#define DIAGNOSTICMESSAGEPOSITIVEACKNOWLEDGEMENT       0x8002
#define DIAGNOSTICMESSAGENEGATIVEACKNOWLEDGEMENT       0x8003

/* 0x8004 ~ 0xEFFF reserved by ISO */
/* 0xF000 ~ 0xFFFF reserved by manufactory */

/*------------------------------------------------------------------------------------------------------------*/

struct doip_entity;

typedef struct doip_entity doip_entity_t;

/*------------------------------------------------------------------------------------------------------------*/

doip_entity_t *doip_entity_alloc();

int doip_entity_start();

void doip_entity_set_userdata(doip_entity_t *doip_entity, void *userdata);

void *doip_entity_userdata(doip_entity_t *doip_entity);

void doip_entity_set_initial_activity_time(doip_entity_t *doip_entity, int time);

void doip_entity_set_general_activity_time(doip_entity_t *doip_entity, int time);

void doip_entity_set_announce_wait_time(doip_entity_t *doip_entity, int time);

void doip_entity_set_announce_count(doip_entity_t *doip_entity, int count);

void doip_entity_set_announce_internal(doip_entity_t *doip_entity, int internal);

void doip_entity_set_tcp_server(doip_entity_t *doip_entity, const char *addr, unsigned short port);

void doip_entity_set_udp_server(doip_entity_t *doip_entity, const char *addr, unsigned short port);

void doip_entity_set_logic_addr(doip_entity_t *doip_entity, unsigned short addr);

void doip_entity_set_func_addr(doip_entity_t *doip_entity, unsigned short addr);

void doip_entity_set_white_list(doip_entity_t *doip_entity, unsigned short *addr, int count);

/*------------------------------------------------------------------------------------------------------------*/

#endif
