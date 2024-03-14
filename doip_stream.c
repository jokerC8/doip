#include "doip_stream.h"

typedef union {
	uint16_t hword;
#ifdef __BIG_ENDIAN
	struct {
		uint8_t  high;
		uint8_t  low;
	} bytes;
#else
	struct {
		uint8_t  low;
		uint8_t  high;
	} bytes;
#endif
} HWORD_UNION;

typedef union {
    uint32_t ulong;
#ifdef  __BIG_ENDIAN   
    struct {
		uint8_t  byte1;
		uint8_t  byte2;
        uint8_t  byte3;
		uint8_t  byte4;
	} bytes;
#else
    struct {
		uint8_t  byte4;
		uint8_t  byte3;
        uint8_t  byte2;
		uint8_t  byte1;
	} bytes;
#endif
} LONG_UNION;

uint8_t YX_InitStrm(STREAM_T *Sp, uint8_t *Bp, uint32_t MaxLen)
{
    if (Sp == 0) return 0;
	
    Sp->Len      = 0;
    Sp->MaxLen   = MaxLen;
    Sp->CurPtr   = Bp;
    Sp->StartPtr = Bp;
    return 1;
}

uint32_t YX_GetStrmLeftLen(STREAM_T *Sp)
{
    if (Sp->MaxLen >= Sp->Len) {
        return (Sp->MaxLen - Sp->Len);
    } else {
        return 0;
    }
}

uint32_t YX_GetStrmLen(STREAM_T *Sp)
{
    return (Sp->Len);
}

uint32_t YX_GetStrmMaxLen(STREAM_T *Sp)
{
    return (Sp->MaxLen);
}

uint8_t *YX_GetStrmPtr(STREAM_T *Sp)
{
    return (Sp->CurPtr);
}

uint8_t *YX_GetStrmStartPtr(STREAM_T *Sp)
{
    return (Sp->StartPtr);
}

void YX_MovStrmPtr(STREAM_T *Sp, uint32_t Len)
{
    if (Sp != 0) {
        if ((Sp->Len + Len) <= Sp->MaxLen) {
            Sp->Len    += Len;
            Sp->CurPtr += Len;
        } else {
            Sp->Len = Sp->MaxLen;
        }
    }
}

void YX_BackwardStrmPtr(STREAM_T *Sp, uint32_t Len)
{
    if (Sp != 0) {
        if(Sp->Len > Len){
            Sp->Len    -= Len;
            Sp->CurPtr -= Len;
        }else{
            Sp->Len     = 0;
        }
    }
}

void YX_WriteBYTE_Strm(STREAM_T *Sp, uint8_t writebyte)
{
    if (Sp != 0){
        if (Sp->Len < Sp->MaxLen) {
            *Sp->CurPtr++ = writebyte;
            Sp->Len++;
        }
    }
}

void YX_WriteHWORD_Strm(STREAM_T *Sp, uint16_t writeword)
{
    HWORD_UNION temp;
    
    temp.hword = writeword;
    YX_WriteBYTE_Strm(Sp, temp.bytes.high);
    YX_WriteBYTE_Strm(Sp, temp.bytes.low);
}

void YX_LE_WriteHWORD_Strm(STREAM_T *Sp, uint16_t writeword)
{
    HWORD_UNION temp;
    
    temp.hword = writeword;
    YX_WriteBYTE_Strm(Sp, temp.bytes.low);     
    YX_WriteBYTE_Strm(Sp, temp.bytes.high);
}

void YX_WriteLONG_Strm(STREAM_T *sp, uint32_t writelong)
{
    YX_WriteHWORD_Strm(sp, writelong >> 16);
    YX_WriteHWORD_Strm(sp, writelong);
}

void YX_LE_WriteLONG_Strm(STREAM_T *sp, uint32_t writelong)
{
    YX_LE_WriteHWORD_Strm(sp, writelong);
    YX_LE_WriteHWORD_Strm(sp, writelong >> 16);    //¸ß16Î»
}

void YX_WriteSTR_Strm(STREAM_T *Sp, char *Ptr)
{
    while(*Ptr)
    {
        YX_WriteBYTE_Strm(Sp, *Ptr++);
    }
}

void YX_WriteDATA_Strm(STREAM_T *Sp, uint8_t *Ptr, uint32_t Len)
{
    while(Len--)
    {
        YX_WriteBYTE_Strm(Sp, *Ptr++);
    }
}

uint8_t YX_ReadBYTE_Strm(STREAM_T *Sp)
{
    if (Sp->Len < Sp->MaxLen) {
        Sp->Len++;
        return (*Sp->CurPtr++);
    } else {
        return 0;
    }
}

uint16_t YX_ReadHWORD_Strm(STREAM_T *Sp)
{
    HWORD_UNION temp;
	
    temp.bytes.high = YX_ReadBYTE_Strm(Sp);
    temp.bytes.low  = YX_ReadBYTE_Strm(Sp);
    return temp.hword;
}

uint16_t YX_LE_ReadHWORD_Strm(STREAM_T *Sp)
{
    HWORD_UNION temp;
	
    temp.bytes.low   = YX_ReadBYTE_Strm(Sp);
    temp.bytes.high  = YX_ReadBYTE_Strm(Sp);
    return temp.hword;
}

uint32_t YX_ReadLONG_Strm(STREAM_T *Sp)
{
    uint32_t temp;
	
	temp = (YX_ReadHWORD_Strm(Sp) << 16);
	temp += YX_ReadHWORD_Strm(Sp);
    
    return temp;
}

uint32_t YX_LE_ReadLONG_Strm(STREAM_T *Sp)
{
    uint32_t temp;
	
	temp = YX_LE_ReadHWORD_Strm(Sp);
	temp += (YX_LE_ReadHWORD_Strm(Sp) << 16);
    
    return temp;
}

void YX_ReadDATA_Strm(STREAM_T *Sp, uint8_t *Ptr, uint32_t Len)
{
    while(Len--)
    {
        *Ptr++ = YX_ReadBYTE_Strm(Sp);
    }
}
