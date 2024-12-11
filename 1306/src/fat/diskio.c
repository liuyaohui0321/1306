/*-----------------------------------------------------------------------*/
/* Low level disk I/O module SKELETON for FatFs     (C)ChaN, 2019        */
/*-----------------------------------------------------------------------*/
/* If a working storage control module is available, it should be        */
/* attached to the FatFs via a glue function rather than modifying it.   */
/* This is an example of glue functions to attach various exsisting      */
/* storage control modules to the FatFs module with a defined API.       */
/*-----------------------------------------------------------------------*/

#include "ff.h"			/* Obtains integer types */
#include "diskio.h"		/* Declarations of disk functions */
#include "../nhc_amba.h"
//#include "xil_cache.h"
/* Definitions of physical drive number for each drive */
#define DEV_RAM		0	/* Example: Map Ramdisk to physical drive 0 */
#define DEV_MMC		1	/* Example: Map MMC/SD card to physical drive 1 */
#define DEV_USB		2	/* Example: Map USB MSD to physical drive 2 */


/*-----------------------------------------------------------------------*/
/* Get Drive Status                                                      */
/*-----------------------------------------------------------------------*/

DSTATUS disk_status (
	BYTE pdrv		/* Physical drive number to identify the drive */
)
{

	return 0;
}



/*-----------------------------------------------------------------------*/
/* Inidialize a Drive                                                    */
/*-----------------------------------------------------------------------*/

DSTATUS disk_initialize (
	BYTE pdrv				/* Physical drive number to identify the drive */
)
{

	return 0;
}



/*-----------------------------------------------------------------------*/
/* Read Sector(s)                                                        */
/*-----------------------------------------------------------------------*/

DRESULT disk_read (
	BYTE pdrv,		/* Physical drive nmuber to identify the drive */
	BYTE *buff,		/* Data buffer to store read data */
	LBA_t sector,	/* Start sector in LBA */
	UINT count		/* Number of sectors to read    读扇区数 一个扇区 4096字节*/
)
{
	uint64_t slba=sector*SECTORSIZE;
	uint32_t len=count*SECTORSIZE;
//	if(io_read2(NHC_NUM, 0x1, buff, sector*SECTORSIZE, count*SECTORSIZE, 0x0) != 0x2)
	if(io_read4(NHC_NUM,0x1, buff,slba, (uint32_t)len, 0x0) != 0x2)
	{
		xil_printf("I/O Read Failed!\n\n");
		return -1; // add by lyh 11.22
	}

    return RES_OK;
}

/*-----------------------------------------------------------------------*/
/* Read Sector(s)  FIFO                                                       */
/*-----------------------------------------------------------------------*/

DRESULT disk_read1 (
	BYTE pdrv,		/* Physical drive nmuber to identify the drive */
	BYTE *buff,		/* Data buffer to store read data */
	LBA_t sector,	/* Start sector in LBA */
	UINT count		/* Number of sectors to read    读扇区数 一个扇区 4096字节*/
)
{
	uint64_t slba=sector*SECTORSIZE;
	uint32_t len=count*SECTORSIZE;
//	if(io_read3(NHC_NUM,0x1, buff,sector*SECTORSIZE, (UINT)(count*SECTORSIZE), 0x0) != 0x2)
	if(io_read3(NHC_NUM,0x1, buff,slba, (uint32_t)len, 0x0) != 0x2)
	{
		xil_printf("I/O Read Failed!\n\n");
		return -1; // add by lyh 11.22
	}

    return RES_OK;
}

DRESULT disk_read2 (
	BYTE pdrv,		/* Physical drive nmuber to identify the drive */
	BYTE *buff,		/* Data buffer to store read data */
	LBA_t sector,	/* Start sector in LBA */
	UINT count		/* Number of sectors to read    读扇区数 一个扇区 4096字节*/
)
{
	uint64_t slba=sector*SECTORSIZE;
	uint32_t len=count*SECTORSIZE;
//	if(io_read3(NHC_NUM,0x1, buff,sector*SECTORSIZE, (UINT)(count*SECTORSIZE), 0x0) != 0x2)
	if(io_read3(NHC_NUM,0x1, buff,slba, (uint32_t)len, 0x0) != 0x2)
	{
		xil_printf("I/O Read Failed!\n\n");
		return -1; // add by lyh 11.22
	}

    return RES_OK;
}

/*-----------------------------------------------------------------------*/
/* Write Sector(s)                                                       */
/*-----------------------------------------------------------------------*/

#if FF_FS_READONLY == 0

DRESULT disk_write (
	BYTE pdrv,			/* Physical drive nmuber to identify the drive */
	const BYTE *buff,	/* Data to be written */
	LBA_t sector,		/* Start sector in LBA */
	UINT count			/* Number of sectors to write */
)
{
	//sector lba
//	if(io_write(NHC_NUM,0x1, buff,sector*SECTORSIZE, (uint32_t)(count*SECTORSIZE*2), 0x0) != 0x2)//wfeng
	if(io_write2(NHC_NUM,0x1, buff,sector*SECTORSIZE, (uint32_t)(count*SECTORSIZE), 0x0) != 0x2)//lyh
	{
		xil_printf("I/O Write Failed!\n\n");
		return -1; // add by lyh 11.22
	}
	return RES_OK;
}

DRESULT disk_write1 (
	BYTE pdrv,			/* Physical drive nmuber to identify the drive */
	const BYTE *buff,	/* Data to be written */
	LBA_t sector,		/* Start sector in LBA */
	UINT count			/* Number of sectors to write */
)
{
	//sector lba
	if(io_write2(NHC_NUM,0x1, buff,sector*SECTORSIZE, (uint32_t)(count*SECTORSIZE), 0x0) != 0x2)//lyh
	{
		xil_printf("I/O Write Failed!\n\n");
		return -1; // add by lyh 11.22
	}
	return RES_OK;
}
#endif


/*-----------------------------------------------------------------------*/
/* Miscellaneous Functions                                               */
/*-----------------------------------------------------------------------*/

DRESULT disk_ioctl (
	BYTE pdrv,		/* Physical drive nmuber (0..) */
	BYTE cmd,		/* Control code */
	void *buff		/* Buffer to send/receive control data */
)
{
	DRESULT res;
	int result;

	switch (cmd) {
	case (BYTE)CTRL_SYNC:
		return RES_OK;
	case (BYTE)GET_BLOCK_SIZE:
		*(WORD *)buff = BLOCKSIZE;
		return RES_OK;
	case (BYTE)GET_SECTOR_SIZE:
		*(WORD *)buff = SECTORSIZE;
		return RES_OK;
	case (BYTE)GET_SECTOR_COUNT:
//		*(DWORD *)buff = SECTORCNT;
		*(QWORD *)buff = SECTORCNT; // 12.1 LYH改
//		*(QWORD *)buff = 0x40000000;
		return RES_OK;
	default:
		res = RES_PARERR;
		break;
	return RES_PARERR;
	}
}
