#ifndef __DOIP_ENTITY_H__
#define __DOIP_ENTITY_H__

#include <stdint.h>

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

/*------------------------------------------------------------------------------------------------------------*/

#define TCP_DATA                                       13400
#define UDP_DISCOVERY                                  13400
#define UDP_BROADCAST_ADDR                             "255.255.255.255"
#define UDS_REQUEST_SOCKFILE                           "/tmp/doip2uds"
#define UDS_INDICATION_SOCKFILE                        "/tmp/uds2doip"
/*------------------------------------------------------------------------------------------------------------*/

#define Header_NACK_Incorrect_Pattern_Format           0x00
#define Header_NACK_Unknow_Payload_type                0x01
#define Header_NACK_Message_Too_Large                  0x02
#define Header_NACK_Out_Of_Memory                      0x03
#define Header_NACK_Invalid_Payload_Len                0x04
/*------------------------------------------------------------------------------------------------------------*/

#define Routine_Activation_Unknow_Address              0x00
#define Routine_Activation_All_Socket_Registered       0x01
#define Routine_Activation_SA_Not_Match                0x02
#define Routine_Activation_SA_Already_Registered       0x03
#define Routine_Activation_Missing_Authentication      0x04
#define Routine_Activation_Rejected_Confirmation       0x05
#define Routine_Activation_Unsupported_Activation_Type 0x06

/* 0x07 ~ 0x0F reserved by ISO 13400 */

#define Routine_Activation_Success                     0x10
#define Routine_Activation_Confirmation_Required       0x11
/* 0x12 ~ 0xDF reserved by ISO 13400 */
/* 0xE0 ~ FE vehicle-manufactory reserved */
/* 0xFF reserved by ISO 13400 */

/*------------------------------------------------------------------------------------------------------------*/

/* 0x00~0x01 reserved by ISO 13400 */
#define Diagnostic_Message_Invalid_Source_Address      0x02
#define Diagnostic_Message_Unknow_Target_Address       0x03
#define Diagnostic_Message_Too_Long                    0x04
#define Diagnostic_Message_Out_Of_Memory               0x05
#define Diagnostic_Message_Target_Unreachable          0x06
#define Diagnostic_Message_Unkonw_Network              0x07
#define Diagnostic_Message_Transport_Protocol_Error    0x08
/* 0x09~0xFF reserved by ISO 13400 */

#define DoIP_OK 1
#define DoIP_ERROR 0

/*------------------------------------------------------------------------------------------------------------*/

struct doip_entity;

typedef struct doip_entity doip_entity_t;

/*------------------------------------------------------------------------------------------------------------*/

doip_entity_t *doip_entity_alloc(uint16_t logic_addr, uint16_t func_addr, const char *tcp_server, \
		uint16_t tcp_port, const char *udp_server, uint16_t udp_port);

int doip_entity_start();

void doip_entity_set_userdata(doip_entity_t *doip_entity, void *userdata);

void *doip_entity_userdata(doip_entity_t *doip_entity);

void doip_entity_set_white_list(doip_entity_t *doip_entity, unsigned short *addr, int count);

void doip_entity_set_eid(doip_entity_t *doip_entity, unsigned char *eid, int len);

void doip_entity_set_gid(doip_entity_t *doip_entity, unsigned char *gid, int len);

void doip_entity_set_vin(doip_entity_t *doip_entity, const char *vin, int len);

/*------------------------------------------------------------------------------------------------------------*/

#endif
