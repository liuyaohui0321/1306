#ifndef __XLLFIFO_DRV_H_
#define __XLLFIFO_DRV_H_

#define WORD_SIZE 4			/* Size of words in bytes */
#define MAX_PACKET_LEN 6
#define MAX_DATA_BUFFER_SIZE MAX_PACKET_LEN

int XLLFIFO_SysInit(void);
int XLLFIFO1_SysInit(void);
int TxSend     (u32 *SourceAddr, u32 len);
int RxReceive  (u32 *DestinationAddr,u32 *len);

#endif
