#ifndef __DOIP_STREAM_H__
#define __DOIP_STREAM_H__

#include <stdint.h>

typedef struct STREAM_T {
    uint8_t	*StartPtr;
    uint8_t *CurPtr;
    uint32_t Len;
    uint32_t MaxLen;
} STREAM_T;

uint8_t YX_InitStrm(STREAM_T *Sp, uint8_t *Bp, uint32_t MaxLen);

uint32_t YX_GetStrmLeftLen(STREAM_T *Sp);

uint32_t YX_GetStrmLen(STREAM_T *Sp);

uint32_t YX_GetStrmMaxLen(STREAM_T *Sp);

uint8_t *YX_GetStrmPtr(STREAM_T *Sp);

uint8_t *YX_GetStrmStartPtr(STREAM_T *Sp);

void YX_MovStrmPtr(STREAM_T *Sp, uint32_t Len);

void YX_BackwardStrmPtr(STREAM_T *Sp, uint32_t Len);

void YX_WriteBYTE_Strm(STREAM_T *Sp, uint8_t writebyte);

void YX_WriteHWORD_Strm(STREAM_T *Sp, uint16_t writeword);

void YX_LE_WriteHWORD_Strm(STREAM_T *Sp, uint16_t writeword);

void YX_WriteLONG_Strm(STREAM_T *sp, uint32_t writelong);

void YX_LE_WriteLONG_Strm(STREAM_T *sp, uint32_t writelong);

void YX_LE_WriteLONGLONG_Strm(STREAM_T *sp,uint8_t writelonglong);

void YX_WriteLF_Strm(STREAM_T *Sp);

void YX_WriteCR_Strm(STREAM_T *Sp);

void YX_WriteSTR_Strm(STREAM_T *Sp, char *Ptr);

void YX_WriteDATA_Strm(STREAM_T *Sp, uint8_t *Ptr, uint32_t Len);

uint8_t YX_ReadBYTE_Strm(STREAM_T *Sp);

uint16_t YX_ReadHWORD_Strm(STREAM_T *Sp);

uint16_t YX_LE_ReadHWORD_Strm(STREAM_T *Sp);

uint32_t YX_ReadLONG_Strm(STREAM_T *Sp);

uint8_t YX_ReadLONGLONG_Strm(STREAM_T *Sp);

void YX_WriteLONGLONG_Strm(STREAM_T *sp, uint8_t writelonglong);

uint32_t YX_LE_ReadLONG_Strm(STREAM_T *Sp);

uint8_t YX_LE_ReadLONGLONG_Strm(STREAM_T *Sp);

void YX_ReadDATA_Strm(STREAM_T *Sp, uint8_t *Ptr, uint32_t Len);

STREAM_T *YX_STREAM_GetBufferStream(void);

#endif
