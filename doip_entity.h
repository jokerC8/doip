#ifndef __DOIP_ENTITY_H__
#define __DOIP_ENTITY_H__

/*------------------------------------------------------------------------------------------------------------*/

#define Generic_Doip_Header_Negative_Ack               0x0000
#define Vehicle_Identify_Request_Message               0x0001
#define Vehicle_Identify_Request_Message_With_EID      0x0002
#define Vehicle_Identify_Request_Message_With_VIN      0x0003
#define Vehicle_Announcememt_Message                   0x0004
#define Vehicle_Identify_Response                      0x0004
#define Routing_Activation_Request                     0x0005
#define Routing_Activation_Response                    0x0006
#define Alive_Check_Request                            0x0007
#define Alive_Check_Response                           0x0008

/* 0x0009 ~ 0x4000 reserved by ISO */

#define Doip_Entity_Status_Request                     0x4001
#define Doip_Entity_Status_Response                    0x4002
#define Diagnotic_Powermode_Information_Request        0x4003
#define Diagnotic_Powermode_Information_Response       0x4004
#define Diagnostic_Message                             0x8001
#define Diagnostic_Positive_ACK                        0x8002
#define Diagnostic_Negative_ACK                        0x8003

/* 0x8004 ~ 0xEFFF reserved by ISO */
/* 0xF000 ~ 0xFFFF reserved by manufactory */

#define A_DoIP_Ctrl                                    2000    /* 2s */
#define A_DoIP_Announce_Wait                           500     /* 500ms */
#define A_DoIP_Announce_Num                            3
#define A_DoIP_Announce_Interval                       500     /* 500ms */
#define A_DoIP_Diagnostic_Message                      2000    /* 2s */
#define T_TCP_General_Inactivity                       300000  /* 5m */
#define T_TCP_Initial_Inactivity                       2000    /* 2s */
#define T_TCP_Alive_Check                              500     /* 500ms */
#define A_Processing_Time                              2000    /* 2s */
#define A_Vehicle_Discovery_Timer                      5000    /* 5s */

#define UDP_DISCOVERY                                  13400
#define TCP_DATA                                       13400

#define Header_NACK_Incorrect_Pattern_Format           0x00
#define Header_NACK_Unknow_Payload_type                0x01
#define Header_NACK_Message_Too_Large                  0x02
#define Header_NACK_Out_Of_Memory                      0x03
#define Header_NACK_Invalid_Payload_Len                0x04

#define logd(format, args...) printf("[line:%d func:%s]:"format, __LINE__, __FUNCTION__, ##args);

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

void doip_entity_set_vin(doip_entity_t *doip_entity, const char *vin, int len);

void doip_entity_set_eid(doip_entity_t *doip_entity, unsigned char eid[6]);

void doip_entity_set_gid(doip_entity_t *doip_entity, unsigned char gid[6]);

/*------------------------------------------------------------------------------------------------------------*/

#endif
