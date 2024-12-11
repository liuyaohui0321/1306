/*----------------------------------------------------------------------------/
/  FatFs - Generic FAT Filesystem Module  R0.15 w/patch1                      /
/-----------------------------------------------------------------------------/
/
/ Copyright (C) 2022, ChaN, all right reserved.
/
/ FatFs module is an open source software. Redistribution and use of FatFs in
/ source and binary forms, with or without modification, are permitted provided
/ that the following condition is met:
/
/ 1. Redistributions of source code must retain the above copyright notice,
/    this condition and the following disclaimer.
/
/ This software is provided by the copyright holder and contributors "AS IS"
/ and any warranties related to this software are DISCLAIMED.
/ The copyright owner or contributors be NOT LIABLE for any damages caused
/ by use of this software.
/
/----------------------------------------------------------------------------*/


#include <string.h>
#include "ff.h"			/* Declarations of FatFs API */
#include "diskio.h"		/* Declarations of device I/O functions */
#include "xil_cache.h"
#define MAX_PATHNAME_DEPTH  512+1 //
static UINT bw=0;
static UINT br=0;
QWORD  LOSS=1141269767783;
QWORD  TOTAL_CAP = 4000000000000;
//extern FATFS fs;
/*--------------------------------------------------------------------------

   Module Private Definitions

---------------------------------------------------------------------------*/

#if FF_DEFINED != 80286	/* Revision ID */
#error Wrong include file (ff.h).
#endif


/* Limits and boundaries */
#define MAX_DIR		0x200000		/* Max size of FAT directory */
#define MAX_DIR_EX	0x10000000		/* Max size of exFAT directory */
#define MAX_FAT12	0xFF5			/* Max FAT12 clusters (differs from specs, but right for real DOS/Windows behavior) */
#define MAX_FAT16	0xFFF5			/* Max FAT16 clusters (differs from specs, but right for real DOS/Windows behavior) */
#define MAX_FAT32	0x0FFFFFF5		/* Max FAT32 clusters (not specified, practical limit) */
#define MAX_EXFAT	0x7FFFFFFD		/* Max exFAT clusters (differs from specs, implementation limit) */


/* Character code support macros */
#define IsUpper(c)		((c) >= 'A' && (c) <= 'Z')
#define IsLower(c)		((c) >= 'a' && (c) <= 'z')
#define IsDigit(c)		((c) >= '0' && (c) <= '9')
#define IsSeparator(c)	((c) == '/' || (c) == '\\')
#define IsTerminator(c)	((UINT)(c) < (FF_USE_LFN ? ' ' : '!'))
#define IsSurrogate(c)	((c) >= 0xD800 && (c) <= 0xDFFF)
#define IsSurrogateH(c)	((c) >= 0xD800 && (c) <= 0xDBFF)
#define IsSurrogateL(c)	((c) >= 0xDC00 && (c) <= 0xDFFF)


/* Additional file access control and file status flags for internal use */
#define FA_SEEKEND	0x20	/* Seek to end of the file on file open */
#define FA_MODIFIED	0x40	/* File has been modified */
#define FA_DIRTY	0x80	/* FIL.buf[] needs to be written-back */


/* Additional file attribute bits for internal use */
#define AM_VOL		0x08	/* Volume label */
#define AM_LFN		0x0F	/* LFN entry */
#define AM_MASK		0x3F	/* Mask of defined bits in FAT */
#define AM_MASKX	0x37	/* Mask of defined bits in exFAT */


/* Name status flags in fn[11] */
#define NSFLAG		11		/* Index of the name status byte */
#define NS_LOSS		0x01	/* Out of 8.3 format */
#define NS_LFN		0x02	/* Force to create LFN entry */
#define NS_LAST		0x04	/* Last segment */
#define NS_BODY		0x08	/* Lower case flag (body) */
#define NS_EXT		0x10	/* Lower case flag (ext) */
#define NS_DOT		0x20	/* Dot entry */
#define NS_NOLFN	0x40	/* Do not find LFN */
#define NS_NONAME	0x80	/* Not followed */


/* exFAT directory entry types */
#define	ET_BITMAP	0x81	/* Allocation bitmap */
#define	ET_UPCASE	0x82	/* Up-case table */
#define	ET_VLABEL	0x83	/* Volume label */
#define	ET_FILEDIR	0x85	/* File and directory */
#define	ET_STREAM	0xC0	/* Stream extension */
#define	ET_FILENAME	0xC1	/* Name extension */


/* FatFs refers the FAT structure as simple byte array instead of structure member
/ because the C structure is not binary compatible between different platforms */

#define BS_JmpBoot			0		/* x86 jump instruction (3-byte) */
#define BS_OEMName			3		/* OEM name (8-byte) */
#define BPB_BytsPerSec		11		/* Sector size [byte] (WORD) */
#define BPB_SecPerClus		13		/* Cluster size [sector] (BYTE) */
#define BPB_RsvdSecCnt		14		/* Size of reserved area [sector] (WORD) */
#define BPB_NumFATs			16		/* Number of FATs (BYTE) */
#define BPB_RootEntCnt		17		/* Size of root directory area for FAT [entry] (WORD) */
#define BPB_TotSec16		19		/* Volume size (16-bit) [sector] (WORD) */
#define BPB_Media			21		/* Media descriptor byte (BYTE) */
#define BPB_FATSz16			22		/* FAT size (16-bit) [sector] (WORD) */
#define BPB_SecPerTrk		24		/* Number of sectors per track for int13h [sector] (WORD) */
#define BPB_NumHeads		26		/* Number of heads for int13h (WORD) */
#define BPB_HiddSec			28		/* Volume offset from top of the drive (DWORD) */
#define BPB_TotSec32		32		/* Volume size (32-bit) [sector] (DWORD) */
#define BS_DrvNum			36		/* Physical drive number for int13h (BYTE) */
#define BS_NTres			37		/* WindowsNT error flag (BYTE) */
#define BS_BootSig			38		/* Extended boot signature (BYTE) */
#define BS_VolID			39		/* Volume serial number (DWORD) */
#define BS_VolLab			43		/* Volume label string (8-byte) */
#define BS_FilSysType		54		/* Filesystem type string (8-byte) */
#define BS_BootCode			62		/* Boot code (448-byte) */
#define BS_55AA				510		/* Signature word (WORD) */

#define BPB_FATSz32			36		/* FAT32: FAT size [sector] (DWORD) */
#define BPB_ExtFlags32		40		/* FAT32: Extended flags (WORD) */
#define BPB_FSVer32			42		/* FAT32: Filesystem version (WORD) */
#define BPB_RootClus32		44		/* FAT32: Root directory cluster (DWORD) */
#define BPB_FSInfo32		48		/* FAT32: Offset of FSINFO sector (WORD) */
#define BPB_BkBootSec32		50		/* FAT32: Offset of backup boot sector (WORD) */
#define BS_DrvNum32			64		/* FAT32: Physical drive number for int13h (BYTE) */
#define BS_NTres32			65		/* FAT32: Error flag (BYTE) */
#define BS_BootSig32		66		/* FAT32: Extended boot signature (BYTE) */
#define BS_VolID32			67		/* FAT32: Volume serial number (DWORD) */
#define BS_VolLab32			71		/* FAT32: Volume label string (8-byte) */
#define BS_FilSysType32		82		/* FAT32: Filesystem type string (8-byte) */
#define BS_BootCode32		90		/* FAT32: Boot code (420-byte) */

#define BPB_ZeroedEx		11		/* exFAT: MBZ field (53-byte) */
#define BPB_VolOfsEx		64		/* exFAT: Volume offset from top of the drive [sector] (QWORD) */
#define BPB_TotSecEx		72		/* exFAT: Volume size [sector] (QWORD) */
#define BPB_FatOfsEx		80		/* exFAT: FAT offset from top of the volume [sector] (DWORD) */
#define BPB_FatSzEx			84		/* exFAT: FAT size [sector] (DWORD) */
#define BPB_DataOfsEx		88		/* exFAT: Data offset from top of the volume [sector] (DWORD) */
#define BPB_NumClusEx		92		/* exFAT: Number of clusters (DWORD) */
#define BPB_RootClusEx		96		/* exFAT: Root directory start cluster (DWORD) */
#define BPB_VolIDEx			100		/* exFAT: Volume serial number (DWORD) */
#define BPB_FSVerEx			104		/* exFAT: Filesystem version (WORD) */
#define BPB_VolFlagEx		106		/* exFAT: Volume flags (WORD) */
#define BPB_BytsPerSecEx	108		/* exFAT: Log2 of sector size in unit of byte (BYTE) */
#define BPB_SecPerClusEx	109		/* exFAT: Log2 of cluster size in unit of sector (BYTE) */
#define BPB_NumFATsEx		110		/* exFAT: Number of FATs (BYTE) */
#define BPB_DrvNumEx		111		/* exFAT: Physical drive number for int13h (BYTE) */
#define BPB_PercInUseEx		112		/* exFAT: Percent in use (BYTE) */
#define BPB_RsvdEx			113		/* exFAT: Reserved (7-byte) */
#define BS_BootCodeEx		120		/* exFAT: Boot code (390-byte) */

#define DIR_Name			0		/* Short file name (11-byte) */
#define DIR_Attr			11		/* Attribute (BYTE) */
#define DIR_NTres			12		/* Lower case flag (BYTE) */
#define DIR_CrtTime10		13		/* Created time sub-second (BYTE) */
#define DIR_CrtTime			14		/* Created time (DWORD) */
#define DIR_LstAccDate		18		/* Last accessed date (WORD) */
#define DIR_FstClusHI		20		/* Higher 16-bit of first cluster (WORD) */
#define DIR_ModTime			22		/* Modified time (DWORD) */
#define DIR_FstClusLO		26		/* Lower 16-bit of first cluster (WORD) */
#define DIR_FileSize		28		/* File size (DWORD) */
#define LDIR_Ord			0		/* LFN: LFN order and LLE flag (BYTE) */
#define LDIR_Attr			11		/* LFN: LFN attribute (BYTE) */
#define LDIR_Type			12		/* LFN: Entry type (BYTE) */
#define LDIR_Chksum			13		/* LFN: Checksum of the SFN (BYTE) */
#define LDIR_FstClusLO		26		/* LFN: MBZ field (WORD) */
#define XDIR_Type			0		/* exFAT: Type of exFAT directory entry (BYTE) */
#define XDIR_NumLabel		1		/* exFAT: Number of volume label characters (BYTE) */
#define XDIR_Label			2		/* exFAT: Volume label (11-WORD) */
#define XDIR_CaseSum		4		/* exFAT: Sum of case conversion table (DWORD) */
#define XDIR_NumSec			1		/* exFAT: Number of secondary entries (BYTE) */
#define XDIR_SetSum			2		/* exFAT: Sum of the set of directory entries (WORD) */
#define XDIR_Attr			4		/* exFAT: File attribute (WORD) */
#define XDIR_CrtTime		8		/* exFAT: Created time (DWORD) */
#define XDIR_ModTime		12		/* exFAT: Modified time (DWORD) */
#define XDIR_AccTime		16		/* exFAT: Last accessed time (DWORD) */
#define XDIR_CrtTime10		20		/* exFAT: Created time subsecond (BYTE) */
#define XDIR_ModTime10		21		/* exFAT: Modified time subsecond (BYTE) */
#define XDIR_CrtTZ			22		/* exFAT: Created timezone (BYTE) */
#define XDIR_ModTZ			23		/* exFAT: Modified timezone (BYTE) */
#define XDIR_AccTZ			24		/* exFAT: Last accessed timezone (BYTE) */
#define XDIR_GenFlags		33		/* exFAT: General secondary flags (BYTE) */
#define XDIR_NumName		35		/* exFAT: Number of file name characters (BYTE) */
#define XDIR_NameHash		36		/* exFAT: Hash of file name (WORD) */
#define XDIR_ValidFileSize	40		/* exFAT: Valid file size (QWORD) */
#define XDIR_FstClus		52		/* exFAT: First cluster of the file data (DWORD) */
#define XDIR_FileSize		56		/* exFAT: File/Directory size (QWORD) */

#define SZDIRE				32		/* Size of a directory entry */
#define DDEM				0xE5	/* Deleted directory entry mark set to DIR_Name[0] */
#define RDDEM				0x05	/* Replacement of the character collides with DDEM */
#define LLEF				0x40	/* Last long entry flag in LDIR_Ord */

#define FSI_LeadSig			0		/* FAT32 FSI: Leading signature (DWORD) */
#define FSI_StrucSig		484		/* FAT32 FSI: Structure signature (DWORD) */
#define FSI_Free_Count		488		/* FAT32 FSI: Number of free clusters (DWORD) */
#define FSI_Nxt_Free		492		/* FAT32 FSI: Last allocated cluster (DWORD) */

#define MBR_Table			446		/* MBR: Offset of partition table in the MBR */
#define SZ_PTE				16		/* MBR: Size of a partition table entry */
#define PTE_Boot			0		/* MBR PTE: Boot indicator */
#define PTE_StHead			1		/* MBR PTE: Start head */
#define PTE_StSec			2		/* MBR PTE: Start sector */
#define PTE_StCyl			3		/* MBR PTE: Start cylinder */
#define PTE_System			4		/* MBR PTE: System ID */
#define PTE_EdHead			5		/* MBR PTE: End head */
#define PTE_EdSec			6		/* MBR PTE: End sector */
#define PTE_EdCyl			7		/* MBR PTE: End cylinder */
#define PTE_StLba			8		/* MBR PTE: Start in LBA */
#define PTE_SizLba			12		/* MBR PTE: Size in LBA */

#define GPTH_Sign			0		/* GPT HDR: Signature (8-byte) */
#define GPTH_Rev			8		/* GPT HDR: Revision (DWORD) */
#define GPTH_Size			12		/* GPT HDR: Header size (DWORD) */
#define GPTH_Bcc			16		/* GPT HDR: Header BCC (DWORD) */
#define GPTH_CurLba			24		/* GPT HDR: This header LBA (QWORD) */
#define GPTH_BakLba			32		/* GPT HDR: Another header LBA (QWORD) */
#define GPTH_FstLba			40		/* GPT HDR: First LBA for partition data (QWORD) */
#define GPTH_LstLba			48		/* GPT HDR: Last LBA for partition data (QWORD) */
#define GPTH_DskGuid		56		/* GPT HDR: Disk GUID (16-byte) */
#define GPTH_PtOfs			72		/* GPT HDR: Partition table LBA (QWORD) */
#define GPTH_PtNum			80		/* GPT HDR: Number of table entries (DWORD) */
#define GPTH_PteSize		84		/* GPT HDR: Size of table entry (DWORD) */
#define GPTH_PtBcc			88		/* GPT HDR: Partition table BCC (DWORD) */
#define SZ_GPTE				128		/* GPT PTE: Size of partition table entry */
#define GPTE_PtGuid			0		/* GPT PTE: Partition type GUID (16-byte) */
#define GPTE_UpGuid			16		/* GPT PTE: Partition unique GUID (16-byte) */
#define GPTE_FstLba			32		/* GPT PTE: First LBA of partition (QWORD) */
#define GPTE_LstLba			40		/* GPT PTE: Last LBA of partition (QWORD) */
#define GPTE_Flags			48		/* GPT PTE: Partition flags (QWORD) */
#define GPTE_Name			56		/* GPT PTE: Partition name */


/* Post process on fatal error in the file operations */
#define ABORT(fs, res)		{ fp->err = (BYTE)(res); LEAVE_FF(fs, res); }


/* Re-entrancy related */
#if FF_FS_REENTRANT
#if FF_USE_LFN == 1
#error Static LFN work area cannot be used in thread-safe configuration
#endif
#define LEAVE_FF(fs, res)	{ unlock_volume(fs, res); return res; }
#else
#define LEAVE_FF(fs, res)	return res
#endif


/* Definitions of logical drive - physical location conversion */
#if FF_MULTI_PARTITION
#define LD2PD(vol) VolToPart[vol].pd	/* Get physical drive number */
#define LD2PT(vol) VolToPart[vol].pt	/* Get partition number (0:auto search, 1..:forced partition number) */
#else
#define LD2PD(vol) (BYTE)(vol)	/* Each logical drive is associated with the same physical drive number */
#define LD2PT(vol) 0			/* Auto partition search */
#endif


/* Definitions of sector size */
#if (FF_MAX_SS < FF_MIN_SS) || (FF_MAX_SS != 512 && FF_MAX_SS != 1024 && FF_MAX_SS != 2048 && FF_MAX_SS != 4096) || (FF_MIN_SS != 512 && FF_MIN_SS != 1024 && FF_MIN_SS != 2048 && FF_MIN_SS != 4096)
#error Wrong sector size configuration
#endif
#if FF_MAX_SS == FF_MIN_SS
#define SS(fs)	((UINT)FF_MAX_SS)	/* Fixed sector size */
#else
#define SS(fs)	((fs)->ssize)	/* Variable sector size */
#endif


/* Timestamp */
#if FF_FS_NORTC == 1
#if FF_NORTC_YEAR < 1980 || FF_NORTC_YEAR > 2107 || FF_NORTC_MON < 1 || FF_NORTC_MON > 12 || FF_NORTC_MDAY < 1 || FF_NORTC_MDAY > 31
#error Invalid FF_FS_NORTC settings
#endif
#define GET_FATTIME()	((DWORD)(FF_NORTC_YEAR - 1980) << 25 | (DWORD)FF_NORTC_MON << 21 | (DWORD)FF_NORTC_MDAY << 16)
#else
#define GET_FATTIME()	get_fattime()
#endif


/* File lock controls */
#if FF_FS_LOCK
#if FF_FS_READONLY
#error FF_FS_LOCK must be 0 at read-only configuration
#endif
typedef struct {
	FATFS* fs;		/* Object ID 1, volume (NULL:blank entry) */
	DWORD clu;		/* Object ID 2, containing directory (0:root) */
	DWORD ofs;		/* Object ID 3, offset in the directory */
	UINT ctr;		/* Object open counter, 0:none, 0x01..0xFF:read mode open count, 0x100:write mode */
} FILESEM;
#endif


/* SBCS up-case tables (\x80-\xFF) */
#define TBL_CT437  {0x80,0x9A,0x45,0x41,0x8E,0x41,0x8F,0x80,0x45,0x45,0x45,0x49,0x49,0x49,0x8E,0x8F, \
					0x90,0x92,0x92,0x4F,0x99,0x4F,0x55,0x55,0x59,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0x41,0x49,0x4F,0x55,0xA5,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT720  {0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F, \
					0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT737  {0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F, \
					0x90,0x92,0x92,0x93,0x94,0x95,0x96,0x97,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87, \
					0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F,0x90,0x91,0xAA,0x92,0x93,0x94,0x95,0x96, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0x97,0xEA,0xEB,0xEC,0xE4,0xED,0xEE,0xEF,0xF5,0xF0,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT771  {0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F, \
					0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDC,0xDE,0xDE, \
					0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0xF0,0xF0,0xF2,0xF2,0xF4,0xF4,0xF6,0xF6,0xF8,0xF8,0xFA,0xFA,0xFC,0xFC,0xFE,0xFF}
#define TBL_CT775  {0x80,0x9A,0x91,0xA0,0x8E,0x95,0x8F,0x80,0xAD,0xED,0x8A,0x8A,0xA1,0x8D,0x8E,0x8F, \
					0x90,0x92,0x92,0xE2,0x99,0x95,0x96,0x97,0x97,0x99,0x9A,0x9D,0x9C,0x9D,0x9E,0x9F, \
					0xA0,0xA1,0xE0,0xA3,0xA3,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xB5,0xB6,0xB7,0xB8,0xBD,0xBE,0xC6,0xC7,0xA5,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE5,0xE5,0xE6,0xE3,0xE8,0xE8,0xEA,0xEA,0xEE,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT850  {0x43,0x55,0x45,0x41,0x41,0x41,0x41,0x43,0x45,0x45,0x45,0x49,0x49,0x49,0x41,0x41, \
					0x45,0x92,0x92,0x4F,0x4F,0x4F,0x55,0x55,0x59,0x4F,0x55,0x4F,0x9C,0x4F,0x9E,0x9F, \
					0x41,0x49,0x4F,0x55,0xA5,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0x41,0x41,0x41,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0x41,0x41,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD1,0xD1,0x45,0x45,0x45,0x49,0x49,0x49,0x49,0xD9,0xDA,0xDB,0xDC,0xDD,0x49,0xDF, \
					0x4F,0xE1,0x4F,0x4F,0x4F,0x4F,0xE6,0xE8,0xE8,0x55,0x55,0x55,0x59,0x59,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT852  {0x80,0x9A,0x90,0xB6,0x8E,0xDE,0x8F,0x80,0x9D,0xD3,0x8A,0x8A,0xD7,0x8D,0x8E,0x8F, \
					0x90,0x91,0x91,0xE2,0x99,0x95,0x95,0x97,0x97,0x99,0x9A,0x9B,0x9B,0x9D,0x9E,0xAC, \
					0xB5,0xD6,0xE0,0xE9,0xA4,0xA4,0xA6,0xA6,0xA8,0xA8,0xAA,0x8D,0xAC,0xB8,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBD,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC6,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD1,0xD1,0xD2,0xD3,0xD2,0xD5,0xD6,0xD7,0xB7,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE3,0xD5,0xE6,0xE6,0xE8,0xE9,0xE8,0xEB,0xED,0xED,0xDD,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xEB,0xFC,0xFC,0xFE,0xFF}
#define TBL_CT855  {0x81,0x81,0x83,0x83,0x85,0x85,0x87,0x87,0x89,0x89,0x8B,0x8B,0x8D,0x8D,0x8F,0x8F, \
					0x91,0x91,0x93,0x93,0x95,0x95,0x97,0x97,0x99,0x99,0x9B,0x9B,0x9D,0x9D,0x9F,0x9F, \
					0xA1,0xA1,0xA3,0xA3,0xA5,0xA5,0xA7,0xA7,0xA9,0xA9,0xAB,0xAB,0xAD,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB6,0xB6,0xB8,0xB8,0xB9,0xBA,0xBB,0xBC,0xBE,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC7,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD1,0xD1,0xD3,0xD3,0xD5,0xD5,0xD7,0xD7,0xDD,0xD9,0xDA,0xDB,0xDC,0xDD,0xE0,0xDF, \
					0xE0,0xE2,0xE2,0xE4,0xE4,0xE6,0xE6,0xE8,0xE8,0xEA,0xEA,0xEC,0xEC,0xEE,0xEE,0xEF, \
					0xF0,0xF2,0xF2,0xF4,0xF4,0xF6,0xF6,0xF8,0xF8,0xFA,0xFA,0xFC,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT857  {0x80,0x9A,0x90,0xB6,0x8E,0xB7,0x8F,0x80,0xD2,0xD3,0xD4,0xD8,0xD7,0x49,0x8E,0x8F, \
					0x90,0x92,0x92,0xE2,0x99,0xE3,0xEA,0xEB,0x98,0x99,0x9A,0x9D,0x9C,0x9D,0x9E,0x9E, \
					0xB5,0xD6,0xE0,0xE9,0xA5,0xA5,0xA6,0xA6,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC7,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0x49,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE5,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xDE,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT860  {0x80,0x9A,0x90,0x8F,0x8E,0x91,0x86,0x80,0x89,0x89,0x92,0x8B,0x8C,0x98,0x8E,0x8F, \
					0x90,0x91,0x92,0x8C,0x99,0xA9,0x96,0x9D,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0x86,0x8B,0x9F,0x96,0xA5,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT861  {0x80,0x9A,0x90,0x41,0x8E,0x41,0x8F,0x80,0x45,0x45,0x45,0x8B,0x8B,0x8D,0x8E,0x8F, \
					0x90,0x92,0x92,0x4F,0x99,0x8D,0x55,0x97,0x97,0x99,0x9A,0x9D,0x9C,0x9D,0x9E,0x9F, \
					0xA4,0xA5,0xA6,0xA7,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT862  {0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F, \
					0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0x41,0x49,0x4F,0x55,0xA5,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT863  {0x43,0x55,0x45,0x41,0x41,0x41,0x86,0x43,0x45,0x45,0x45,0x49,0x49,0x8D,0x41,0x8F, \
					0x45,0x45,0x45,0x4F,0x45,0x49,0x55,0x55,0x98,0x4F,0x55,0x9B,0x9C,0x55,0x55,0x9F, \
					0xA0,0xA1,0x4F,0x55,0xA4,0xA5,0xA6,0xA7,0x49,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT864  {0x80,0x9A,0x45,0x41,0x8E,0x41,0x8F,0x80,0x45,0x45,0x45,0x49,0x49,0x49,0x8E,0x8F, \
					0x90,0x92,0x92,0x4F,0x99,0x4F,0x55,0x55,0x59,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0x41,0x49,0x4F,0x55,0xA5,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT865  {0x80,0x9A,0x90,0x41,0x8E,0x41,0x8F,0x80,0x45,0x45,0x45,0x49,0x49,0x49,0x8E,0x8F, \
					0x90,0x92,0x92,0x4F,0x99,0x4F,0x55,0x55,0x59,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0x41,0x49,0x4F,0x55,0xA5,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT866  {0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F, \
					0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF, \
					0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F, \
					0xF0,0xF0,0xF2,0xF2,0xF4,0xF4,0xF6,0xF6,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}
#define TBL_CT869  {0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F, \
					0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x86,0x9C,0x8D,0x8F,0x90, \
					0x91,0x90,0x92,0x95,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF, \
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xA4,0xA5,0xA6,0xD9,0xDA,0xDB,0xDC,0xA7,0xA8,0xDF, \
					0xA9,0xAA,0xAC,0xAD,0xB5,0xB6,0xB7,0xB8,0xBD,0xBE,0xC6,0xC7,0xCF,0xCF,0xD0,0xEF, \
					0xF0,0xF1,0xD1,0xD2,0xD3,0xF5,0xD4,0xF7,0xF8,0xF9,0xD5,0x96,0x95,0x98,0xFE,0xFF}


/* DBCS code range |----- 1st byte -----|  |----------- 2nd byte -----------| */
/*                  <------>    <------>    <------>    <------>    <------>  */
#define TBL_DC932 {0x81, 0x9F, 0xE0, 0xFC, 0x40, 0x7E, 0x80, 0xFC, 0x00, 0x00}
#define TBL_DC936 {0x81, 0xFE, 0x00, 0x00, 0x40, 0x7E, 0x80, 0xFE, 0x00, 0x00}
#define TBL_DC949 {0x81, 0xFE, 0x00, 0x00, 0x41, 0x5A, 0x61, 0x7A, 0x81, 0xFE}
#define TBL_DC950 {0x81, 0xFE, 0x00, 0x00, 0x40, 0x7E, 0xA1, 0xFE, 0x00, 0x00}


/* Macros for table definitions */
#define MERGE_2STR(a, b) a ## b
#define MKCVTBL(hd, cp) MERGE_2STR(hd, cp)




/*--------------------------------------------------------------------------

   Module Private Work Area

---------------------------------------------------------------------------*/
/* Remark: Variables defined here without initial value shall be guaranteed
/  zero/null at start-up. If not, the linker option or start-up routine is
/  not compliance with C standard. */

/*--------------------------------*/
/* File/Volume controls           */
/*--------------------------------*/

#if FF_VOLUMES < 1 || FF_VOLUMES > 10
#error Wrong FF_VOLUMES setting
#endif
static FATFS *FatFs[FF_VOLUMES];	/* Pointer to the filesystem objects (logical drives) */
static WORD Fsid;					/* Filesystem mount ID */

#if FF_FS_RPATH != 0
static BYTE CurrVol;				/* Current drive set by f_chdrive() */
#endif

#if FF_FS_LOCK != 0
static FILESEM Files[FF_FS_LOCK];	/* Open object lock semaphores */
#if FF_FS_REENTRANT
static BYTE SysLock;				/* System lock flag (0:no mutex, 1:unlocked, 2:locked) */
#endif
#endif

#if FF_STR_VOLUME_ID
#ifdef FF_VOLUME_STRS
static const char *const VolumeStr[FF_VOLUMES] = {FF_VOLUME_STRS};	/* Pre-defined volume ID */
#endif
#endif

#if FF_LBA64
#if FF_MIN_GPT > 0x100000000
#error Wrong FF_MIN_GPT setting
#endif
static const BYTE GUID_MS_Basic[16] = {0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7};
#endif



/*--------------------------------*/
/* LFN/Directory working buffer   */
/*--------------------------------*/

#if FF_USE_LFN == 0		/* Non-LFN configuration */
#if FF_FS_EXFAT
#error LFN must be enabled when enable exFAT
#endif
#define DEF_NAMBUF
#define INIT_NAMBUF(fs)
#define FREE_NAMBUF()
#define LEAVE_MKFS(res)	return res

#else					/* LFN configurations */
#if FF_MAX_LFN < 12 || FF_MAX_LFN > 255
#error Wrong setting of FF_MAX_LFN
#endif
#if FF_LFN_BUF < FF_SFN_BUF || FF_SFN_BUF < 12
#error Wrong setting of FF_LFN_BUF or FF_SFN_BUF
#endif
#if FF_LFN_UNICODE < 0 || FF_LFN_UNICODE > 3
#error Wrong setting of FF_LFN_UNICODE
#endif
static const BYTE LfnOfs[] = {1,3,5,7,9,14,16,18,20,22,24,28,30};	/* FAT: Offset of LFN characters in the directory entry */
#define MAXDIRB(nc)	((nc + 44U) / 15 * SZDIRE)	/* exFAT: Size of directory entry block scratchpad buffer needed for the name length */

#if FF_USE_LFN == 1		/* LFN enabled with static working buffer */
#if FF_FS_EXFAT
static BYTE	DirBuf[MAXDIRB(FF_MAX_LFN)];	/* Directory entry block scratchpad buffer */
#endif
static WCHAR LfnBuf[FF_MAX_LFN + 1];		/* LFN working buffer */
#define DEF_NAMBUF
#define INIT_NAMBUF(fs)
#define FREE_NAMBUF()
#define LEAVE_MKFS(res)	return res

#elif FF_USE_LFN == 2 	/* LFN enabled with dynamic working buffer on the stack */
#if FF_FS_EXFAT
#define DEF_NAMBUF		WCHAR lbuf[FF_MAX_LFN+1]; BYTE dbuf[MAXDIRB(FF_MAX_LFN)];	/* LFN working buffer and directory entry block scratchpad buffer */
#define INIT_NAMBUF(fs)	{ (fs)->lfnbuf = lbuf; (fs)->dirbuf = dbuf; }
#define FREE_NAMBUF()
#else
#define DEF_NAMBUF		WCHAR lbuf[FF_MAX_LFN+1];	/* LFN working buffer */
#define INIT_NAMBUF(fs)	{ (fs)->lfnbuf = lbuf; }
#define FREE_NAMBUF()
#endif
#define LEAVE_MKFS(res)	return res

#elif FF_USE_LFN == 3 	/* LFN enabled with dynamic working buffer on the heap */
#if FF_FS_EXFAT
#define DEF_NAMBUF		WCHAR *lfn;	/* Pointer to LFN working buffer and directory entry block scratchpad buffer */
#define INIT_NAMBUF(fs)	{ lfn = ff_memalloc((FF_MAX_LFN+1)*2 + MAXDIRB(FF_MAX_LFN)); if (!lfn) LEAVE_FF(fs, FR_NOT_ENOUGH_CORE); (fs)->lfnbuf = lfn; (fs)->dirbuf = (BYTE*)(lfn+FF_MAX_LFN+1); }
#define FREE_NAMBUF()	ff_memfree(lfn)
#else
#define DEF_NAMBUF		WCHAR *lfn;	/* Pointer to LFN working buffer */
#define INIT_NAMBUF(fs)	{ lfn = ff_memalloc((FF_MAX_LFN+1)*2); if (!lfn) LEAVE_FF(fs, FR_NOT_ENOUGH_CORE); (fs)->lfnbuf = lfn; }
#define FREE_NAMBUF()	ff_memfree(lfn)
#endif
#define LEAVE_MKFS(res)	{ if (!work) ff_memfree(buf); return res; }
#define MAX_MALLOC	0x8000	/* Must be >=FF_MAX_SS */

#else
#error Wrong setting of FF_USE_LFN

#endif	/* FF_USE_LFN == 1 */
#endif	/* FF_USE_LFN == 0 */

void delay(void)
{
    int i=0xFFFF;
	while(i)
	{
		i--;
	}
}

/*--------------------------------*/
/* Code conversion tables         */
/*--------------------------------*/

#if FF_CODE_PAGE == 0	/* Run-time code page configuration */
#define CODEPAGE CodePage
static WORD CodePage;	/* Current code page */
static const BYTE* ExCvt;	/* Ptr to SBCS up-case table Ct???[] (null:not used) */
static const BYTE* DbcTbl;	/* Ptr to DBCS code range table Dc???[] (null:not used) */

static const BYTE Ct437[] = TBL_CT437;
static const BYTE Ct720[] = TBL_CT720;
static const BYTE Ct737[] = TBL_CT737;
static const BYTE Ct771[] = TBL_CT771;
static const BYTE Ct775[] = TBL_CT775;
static const BYTE Ct850[] = TBL_CT850;
static const BYTE Ct852[] = TBL_CT852;
static const BYTE Ct855[] = TBL_CT855;
static const BYTE Ct857[] = TBL_CT857;
static const BYTE Ct860[] = TBL_CT860;
static const BYTE Ct861[] = TBL_CT861;
static const BYTE Ct862[] = TBL_CT862;
static const BYTE Ct863[] = TBL_CT863;
static const BYTE Ct864[] = TBL_CT864;
static const BYTE Ct865[] = TBL_CT865;
static const BYTE Ct866[] = TBL_CT866;
static const BYTE Ct869[] = TBL_CT869;
static const BYTE Dc932[] = TBL_DC932;
static const BYTE Dc936[] = TBL_DC936;
static const BYTE Dc949[] = TBL_DC949;
static const BYTE Dc950[] = TBL_DC950;

#elif FF_CODE_PAGE < 900	/* Static code page configuration (SBCS) */
#define CODEPAGE FF_CODE_PAGE
static const BYTE ExCvt[] = MKCVTBL(TBL_CT, FF_CODE_PAGE);

#else					/* Static code page configuration (DBCS) */
#define CODEPAGE FF_CODE_PAGE
static const BYTE DbcTbl[] = MKCVTBL(TBL_DC, FF_CODE_PAGE);

#endif




/*--------------------------------------------------------------------------

   Module Private Functions

---------------------------------------------------------------------------*/


/*-----------------------------------------------------------------------*/
/* Load/Store multi-byte word in the FAT structure                       */
/*-----------------------------------------------------------------------*/

static WORD ld_word (const BYTE* ptr)	/*	 Load a 2-byte little-endian word */
{
	WORD rv;

	rv = ptr[1];
	rv = rv << 8 | ptr[0];
	return rv;
}

static DWORD ld_dword (const BYTE* ptr)	/* Load a 4-byte little-endian word */
{
	DWORD rv;

	rv = ptr[3];
	rv = rv << 8 | ptr[2];
	rv = rv << 8 | ptr[1];
	rv = rv << 8 | ptr[0];
	return rv;
}

#if FF_FS_EXFAT
static QWORD ld_qword (const BYTE* ptr)	/* Load an 8-byte little-endian word */
{
	QWORD rv;

	rv = ptr[7];
	rv = rv << 8 | ptr[6];
	rv = rv << 8 | ptr[5];
	rv = rv << 8 | ptr[4];
	rv = rv << 8 | ptr[3];
	rv = rv << 8 | ptr[2];
	rv = rv << 8 | ptr[1];
	rv = rv << 8 | ptr[0];
	return rv;
}
#endif

#if !FF_FS_READONLY
static void st_word (BYTE* ptr, WORD val)	/* Store a 2-byte word in little-endian */
{
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val;
}

static void st_dword (BYTE* ptr, DWORD val)	/* Store a 4-byte word in little-endian */
{
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val;
}

#if FF_FS_EXFAT
static void st_qword (BYTE* ptr, QWORD val)	/* Store an 8-byte word in little-endian */
{
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val; val >>= 8;
	*ptr++ = (BYTE)val;
}
#endif
#endif	/* !FF_FS_READONLY */



/*-----------------------------------------------------------------------*/
/* String functions                                                      */
/*-----------------------------------------------------------------------*/

/* Test if the byte is DBC 1st byte */
static int dbc_1st (BYTE c)
{
#if FF_CODE_PAGE == 0		/* Variable code page */
	if (DbcTbl && c >= DbcTbl[0]) {
		if (c <= DbcTbl[1]) return 1;					/* 1st byte range 1 */
		if (c >= DbcTbl[2] && c <= DbcTbl[3]) return 1;	/* 1st byte range 2 */
	}
#elif FF_CODE_PAGE >= 900	/* DBCS fixed code page */
	if (c >= DbcTbl[0]) {
		if (c <= DbcTbl[1]) return 1;
		if (c >= DbcTbl[2] && c <= DbcTbl[3]) return 1;
	}
#else						/* SBCS fixed code page */
	if (c != 0) return 0;	/* Always false */
#endif
	return 0;
}


/* Test if the byte is DBC 2nd byte */
static int dbc_2nd (BYTE c)
{
#if FF_CODE_PAGE == 0		/* Variable code page */
	if (DbcTbl && c >= DbcTbl[4]) {
		if (c <= DbcTbl[5]) return 1;					/* 2nd byte range 1 */
		if (c >= DbcTbl[6] && c <= DbcTbl[7]) return 1;	/* 2nd byte range 2 */
		if (c >= DbcTbl[8] && c <= DbcTbl[9]) return 1;	/* 2nd byte range 3 */
	}
#elif FF_CODE_PAGE >= 900	/* DBCS fixed code page */
	if (c >= DbcTbl[4]) {
		if (c <= DbcTbl[5]) return 1;
		if (c >= DbcTbl[6] && c <= DbcTbl[7]) return 1;
		if (c >= DbcTbl[8] && c <= DbcTbl[9]) return 1;
	}
#else						/* SBCS fixed code page */
	if (c != 0) return 0;	/* Always false */
#endif
	return 0;
}


#if FF_USE_LFN

/* Get a Unicode code point from the TCHAR string in defined API encodeing */
static DWORD tchar2uni (	/* Returns a character in UTF-16 encoding (>=0x10000 on surrogate pair, 0xFFFFFFFF on decode error) */
	const TCHAR** str		/* Pointer to pointer to TCHAR string in configured encoding */
)
{
	DWORD uc;
	const TCHAR *p = *str;

#if FF_LFN_UNICODE == 1		/* UTF-16 input */
	WCHAR wc;

	uc = *p++;	/* Get a unit */
	if (IsSurrogate(uc)) {	/* Surrogate? */
		wc = *p++;		/* Get low surrogate */
		if (!IsSurrogateH(uc) || !IsSurrogateL(wc)) return 0xFFFFFFFF;	/* Wrong surrogate? */
		uc = uc << 16 | wc;
	}

#elif FF_LFN_UNICODE == 2	/* UTF-8 input */
	BYTE b;
	int nf;

	uc = (BYTE)*p++;	/* Get an encoding unit */
	if (uc & 0x80) {	/* Multiple byte code? */
		if        ((uc & 0xE0) == 0xC0) {	/* 2-byte sequence? */
			uc &= 0x1F; nf = 1;
		} else if ((uc & 0xF0) == 0xE0) {	/* 3-byte sequence? */
			uc &= 0x0F; nf = 2;
		} else if ((uc & 0xF8) == 0xF0) {	/* 4-byte sequence? */
			uc &= 0x07; nf = 3;
		} else {							/* Wrong sequence */
			return 0xFFFFFFFF;
		}
		do {	/* Get trailing bytes */
			b = (BYTE)*p++;
			if ((b & 0xC0) != 0x80) return 0xFFFFFFFF;	/* Wrong sequence? */
			uc = uc << 6 | (b & 0x3F);
		} while (--nf != 0);
		if (uc < 0x80 || IsSurrogate(uc) || uc >= 0x110000) return 0xFFFFFFFF;	/* Wrong code? */
		if (uc >= 0x010000) uc = 0xD800DC00 | ((uc - 0x10000) << 6 & 0x3FF0000) | (uc & 0x3FF);	/* Make a surrogate pair if needed */
	}

#elif FF_LFN_UNICODE == 3	/* UTF-32 input */
	uc = (TCHAR)*p++;	/* Get a unit */
	if (uc >= 0x110000 || IsSurrogate(uc)) return 0xFFFFFFFF;	/* Wrong code? */
	if (uc >= 0x010000) uc = 0xD800DC00 | ((uc - 0x10000) << 6 & 0x3FF0000) | (uc & 0x3FF);	/* Make a surrogate pair if needed */

#else		/* ANSI/OEM input */
	BYTE b;
	WCHAR wc;

	wc = (BYTE)*p++;			/* Get a byte */
	if (dbc_1st((BYTE)wc)) {	/* Is it a DBC 1st byte? */
		b = (BYTE)*p++;			/* Get 2nd byte */
		if (!dbc_2nd(b)) return 0xFFFFFFFF;	/* Invalid code? */
		wc = (wc << 8) + b;		/* Make a DBC */
	}
	if (wc != 0) {
		wc = ff_oem2uni(wc, CODEPAGE);	/* ANSI/OEM ==> Unicode */
		if (wc == 0) return 0xFFFFFFFF;	/* Invalid code? */
	}
	uc = wc;

#endif
	*str = p;	/* Next read pointer */
	return uc;
}


/* Store a Unicode char in defined API encoding */
static UINT put_utf (	/* Returns number of encoding units written (0:buffer overflow or wrong encoding) */
	DWORD chr,	/* UTF-16 encoded character (Surrogate pair if >=0x10000) */
	TCHAR* buf,	/* Output buffer */
	UINT szb	/* Size of the buffer */
)
{
#if FF_LFN_UNICODE == 1	/* UTF-16 output */
	WCHAR hs, wc;

	hs = (WCHAR)(chr >> 16);
	wc = (WCHAR)chr;
	if (hs == 0) {	/* Single encoding unit? */
		if (szb < 1 || IsSurrogate(wc)) return 0;	/* Buffer overflow or wrong code? */
		*buf = wc;
		return 1;
	}
	if (szb < 2 || !IsSurrogateH(hs) || !IsSurrogateL(wc)) return 0;	/* Buffer overflow or wrong surrogate? */
	*buf++ = hs;
	*buf++ = wc;
	return 2;

#elif FF_LFN_UNICODE == 2	/* UTF-8 output */
	DWORD hc;

	if (chr < 0x80) {	/* Single byte code? */
		if (szb < 1) return 0;	/* Buffer overflow? */
		*buf = (TCHAR)chr;
		return 1;
	}
	if (chr < 0x800) {	/* 2-byte sequence? */
		if (szb < 2) return 0;	/* Buffer overflow? */
		*buf++ = (TCHAR)(0xC0 | (chr >> 6 & 0x1F));
		*buf++ = (TCHAR)(0x80 | (chr >> 0 & 0x3F));
		return 2;
	}
	if (chr < 0x10000) {	/* 3-byte sequence? */
		if (szb < 3 || IsSurrogate(chr)) return 0;	/* Buffer overflow or wrong code? */
		*buf++ = (TCHAR)(0xE0 | (chr >> 12 & 0x0F));
		*buf++ = (TCHAR)(0x80 | (chr >> 6 & 0x3F));
		*buf++ = (TCHAR)(0x80 | (chr >> 0 & 0x3F));
		return 3;
	}
	/* 4-byte sequence */
	if (szb < 4) return 0;	/* Buffer overflow? */
	hc = ((chr & 0xFFFF0000) - 0xD8000000) >> 6;	/* Get high 10 bits */
	chr = (chr & 0xFFFF) - 0xDC00;					/* Get low 10 bits */
	if (hc >= 0x100000 || chr >= 0x400) return 0;	/* Wrong surrogate? */
	chr = (hc | chr) + 0x10000;
	*buf++ = (TCHAR)(0xF0 | (chr >> 18 & 0x07));
	*buf++ = (TCHAR)(0x80 | (chr >> 12 & 0x3F));
	*buf++ = (TCHAR)(0x80 | (chr >> 6 & 0x3F));
	*buf++ = (TCHAR)(0x80 | (chr >> 0 & 0x3F));
	return 4;

#elif FF_LFN_UNICODE == 3	/* UTF-32 output */
	DWORD hc;

	if (szb < 1) return 0;	/* Buffer overflow? */
	if (chr >= 0x10000) {	/* Out of BMP? */
		hc = ((chr & 0xFFFF0000) - 0xD8000000) >> 6;	/* Get high 10 bits */
		chr = (chr & 0xFFFF) - 0xDC00;					/* Get low 10 bits */
		if (hc >= 0x100000 || chr >= 0x400) return 0;	/* Wrong surrogate? */
		chr = (hc | chr) + 0x10000;
	}
	*buf++ = (TCHAR)chr;
	return 1;

#else						/* ANSI/OEM output */
	WCHAR wc;

	wc = ff_uni2oem(chr, CODEPAGE);
	if (wc >= 0x100) {	/* Is this a DBC? */
		if (szb < 2) return 0;
		*buf++ = (char)(wc >> 8);	/* Store DBC 1st byte */
		*buf++ = (TCHAR)wc;			/* Store DBC 2nd byte */
		return 2;
	}
	if (wc == 0 || szb < 1) return 0;	/* Invalid char or buffer overflow? */
	*buf++ = (TCHAR)wc;					/* Store the character */
	return 1;
#endif
}
#endif	/* FF_USE_LFN */


#if FF_FS_REENTRANT
/*-----------------------------------------------------------------------*/
/* Request/Release grant to access the volume                            */
/*-----------------------------------------------------------------------*/

static int lock_volume (	/* 1:Ok, 0:timeout */
	FATFS* fs,				/* Filesystem object to lock */
	int syslock				/* System lock required */
)
{
	int rv;


#if FF_FS_LOCK
	rv = ff_mutex_take(fs->ldrv);	/* Lock the volume */
	if (rv && syslock) {			/* System lock reqiered? */
		rv = ff_mutex_take(FF_VOLUMES);	/* Lock the system */
		if (rv) {
			SysLock = 2;				/* System lock succeeded */
		} else {
			ff_mutex_give(fs->ldrv);	/* Failed system lock */
		}
	}
#else
	rv = syslock ? ff_mutex_take(fs->ldrv) : ff_mutex_take(fs->ldrv);	/* Lock the volume (this is to prevent compiler warning) */
#endif
	return rv;
}


static void unlock_volume (
	FATFS* fs,		/* Filesystem object */
	FRESULT res		/* Result code to be returned */
)
{
	if (fs && res != FR_NOT_ENABLED && res != FR_INVALID_DRIVE && res != FR_TIMEOUT) {
#if FF_FS_LOCK
		if (SysLock == 2) {	/* Is the system locked? */
			SysLock = 1;
			ff_mutex_give(FF_VOLUMES);
		}
#endif
		ff_mutex_give(fs->ldrv);	/* Unlock the volume */
	}
}

#endif



#if FF_FS_LOCK
/*-----------------------------------------------------------------------*/
/* File shareing control functions                                       */
/*-----------------------------------------------------------------------*/

static FRESULT chk_share (	/* Check if the file can be accessed */
	DIR* dp,		/* Directory object pointing the file to be checked */
	int acc			/* Desired access type (0:Read mode open, 1:Write mode open, 2:Delete or rename) */
)
{
	UINT i, be;

	/* Search open object table for the object */
	be = 0;
	for (i = 0; i < FF_FS_LOCK; i++) {
		if (Files[i].fs) {	/* Existing entry */
			if (Files[i].fs == dp->obj.fs &&	 	/* Check if the object matches with an open object */
				Files[i].clu == dp->obj.sclust &&
				Files[i].ofs == dp->dptr) break;
		} else {			/* Blank entry */
			be = 1;
		}
	}
	if (i == FF_FS_LOCK) {	/* The object has not been opened */
		return (!be && acc != 2) ? FR_TOO_MANY_OPEN_FILES : FR_OK;	/* Is there a blank entry for new object? */
	}

	/* The object was opened. Reject any open against writing file and all write mode open */
	return (acc != 0 || Files[i].ctr == 0x100) ? FR_LOCKED : FR_OK;
}


static int enq_share (void)	/* Check if an entry is available for a new object */
{
	UINT i;

	for (i = 0; i < FF_FS_LOCK && Files[i].fs; i++) ;	/* Find a free entry */
	return (i == FF_FS_LOCK) ? 0 : 1;
}


static UINT inc_share (	/* Increment object open counter and returns its index (0:Internal error) */
	DIR* dp,	/* Directory object pointing the file to register or increment */
	int acc		/* Desired access (0:Read, 1:Write, 2:Delete/Rename) */
)
{
	UINT i;


	for (i = 0; i < FF_FS_LOCK; i++) {	/* Find the object */
		if (Files[i].fs == dp->obj.fs
		 && Files[i].clu == dp->obj.sclust
		 && Files[i].ofs == dp->dptr) break;
	}

	if (i == FF_FS_LOCK) {			/* Not opened. Register it as new. */
		for (i = 0; i < FF_FS_LOCK && Files[i].fs; i++) ;	/* Find a free entry */
		if (i == FF_FS_LOCK) return 0;	/* No free entry to register (int err) */
		Files[i].fs = dp->obj.fs;
		Files[i].clu = dp->obj.sclust;
		Files[i].ofs = dp->dptr;
		Files[i].ctr = 0;
	}

	if (acc >= 1 && Files[i].ctr) return 0;	/* Access violation (int err) */

	Files[i].ctr = acc ? 0x100 : Files[i].ctr + 1;	/* Set semaphore value */

	return i + 1;	/* Index number origin from 1 */
}


static FRESULT dec_share (	/* Decrement object open counter */
	UINT i			/* Semaphore index (1..) */
)
{
	UINT n;
	FRESULT res;


	if (--i < FF_FS_LOCK) {	/* Index number origin from 0 */
		n = Files[i].ctr;
		if (n == 0x100) n = 0;	/* If write mode open, delete the object semaphore */
		if (n > 0) n--;			/* Decrement read mode open count */
		Files[i].ctr = n;
		if (n == 0) {			/* Delete the object semaphore if open count becomes zero */
			Files[i].fs = 0;	/* Free the entry <<<If this memory write operation is not in atomic, FF_FS_REENTRANT == 1 and FF_VOLUMES > 1, there is a potential error in this process >>> */
		}
		res = FR_OK;
	} else {
		res = FR_INT_ERR;		/* Invalid index number */
	}
	return res;
}


static void clear_share (	/* Clear all lock entries of the volume */
	FATFS* fs
)
{
	UINT i;

	for (i = 0; i < FF_FS_LOCK; i++) {
		if (Files[i].fs == fs) Files[i].fs = 0;
	}
}

#endif	/* FF_FS_LOCK */



/*-----------------------------------------------------------------------*/
/* Move/Flush disk access window in the filesystem object                */
/*-----------------------------------------------------------------------*/
#if !FF_FS_READONLY
static FRESULT sync_window (	/* Returns FR_OK or FR_DISK_ERR */
	FATFS* fs			/* Filesystem object */
)
{
	FRESULT res = FR_OK;

//disk_write(fs->pdrv, fs->win, fs->winsect, 1)
	if (fs->wflag) {	/* Is the disk access window dirty? */
		memcpy((BYTE *)(0xA0001000),fs->win,SECTORSIZE*1);
//		Xil_L1DCacheFlush(); //8.20 add
		if (disk_write1(fs->pdrv,(BYTE *)(0xA0001000), fs->winsect, 1) == RES_OK) {	/* Write it back into the volume *///9.3
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
			fs->wflag = 0;	/* Clear window dirty flag */
			if (fs->winsect - fs->fatbase < fs->fsize) {	/* Is it in the 1st FAT? */
				if (fs->n_fats == 2) 
				{
					memcpy((BYTE *)(0xA0001000),fs->win,SECTORSIZE*1);
//					Xil_L1DCacheFlush(); //8.20 add
					disk_write1(fs->pdrv, (BYTE *)(0xA0001000), fs->winsect + fs->fsize, 1);	/* Reflect it to 2nd FAT if needed *///9.3
					memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
				}
				
			}
		} else {
			res = FR_DISK_ERR;
		}
	}
	return res;
}
#endif



//static FRESULT move_window (	/* Returns FR_OK or FR_DISK_ERR */
//	FATFS* fs,		/* Filesystem object */
//	LBA_t sect		/* Sector LBA to make appearance in the fs->win[] */
//)
//{
//	FRESULT res = FR_OK;
//
//	BYTE wbuffer[4096] = {0};
//	BYTE rbuffer[4096] = {0};
//
//	BYTE i = 0;
//	int index0 = 0;
//
//
//	if (sect != fs->winsect) {	/* Window offset changed? */
//#if !FF_FS_READONLY
//		res = sync_window(fs);		/* Flush the window */
//#endif
//		if (res == FR_OK) {			/* Fill sector window with new data */
////			if (disk_read(fs->pdrv, (BYTE *)(0xA0001000), sect, 1) != RES_OK) {
////				memcpy(fs->win,(BYTE *)(0xA0001000),SECTORSIZE*1);
////				memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
////				sect = (LBA_t)0 - 1;	/* Invalidate window if read data is not valid */
////				res = FR_DISK_ERR;
////			}
////			memcpy(fs->win,(BYTE *)(0xA0001000),SECTORSIZE*1);   // MBR f->win511闂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾惧湱锟界懓瀚崳纾嬨亹閹烘垹鍊為悷婊冾樀瀵悂寮介鐔哄幐闂佹悶鍎崕閬嶆倶閳哄啰纾奸柟閭﹀弾濞堟粓鏌″畝瀣瘈鐎规洖鐖奸弫鎰板川椤掞拷椤ユ岸姊绘担鑺ョ《闁哥姵鍔欏畷鐟扳攽閸垻鐒兼繛鎾寸啲閹风兘鏌嶉妷顖滅暤濠碘剝鎮傞崺鈩冪瑹閿熶粙宕崼鏇熲拺缂備焦蓱椤ュ牓鏌￠敓浠嬫焼瀹ュ棗浠鹃梺鍛婄☉閻°劑鍩涢幒鎳ㄥ綊鏁愰崟顕呭妳闂佺粯甯＄粻鏍蓟閿熺姴閱囨い鎰╁灩椤偊姊洪崨濠傜瑲閻㈩垱甯￠幃鎯р攽鐎ｎ亞顦板銈嗗釜閹风兘鏌涢幙鍐ㄥ籍婵﹨娅ｅ☉鐢稿川椤斿吋閿梻鍌氬�哥�氼剛锟芥矮鍗抽獮鍐灳閺傘儲鐎婚梺瑙勫劤椤曨參宕㈤柆宥嗏拺闁荤喐澹嗛幗鐘绘煟閻旀潙鍔﹂柡浣规崌閹崇偤濡疯閳峰牓姊虹捄銊ユ灆濠殿喓鍊濋幃銏ゎ敆閸曨偆顔嗛梺璺ㄥ櫐閹凤拷512闂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾惧湱锟界懓瀚崳纾嬨亹閹烘垹鍊為悷婊冾樀瀵悂寮介鐔哄幐闂佹悶鍎崕閬嶆倶閳哄啰纾奸柟閭﹀弾濞堟粓鏌″畝瀣瘈鐎规洖鐖奸弫鎰板川椤掞拷椤ユ岸姊绘担鑺ョ《闁哥姵鍔欏畷鐟扳攽閸垻鐒兼繛鎾寸啲閹风兘鏌嶉妷顖滅暤濠碘剝鎮傞崺鈩冪瑹閿熶粙宕崼鏇熲拺缂備焦蓱椤ュ牓鏌￠敓浠嬫焼瀹ュ棗浠鹃梺鍛婄☉閻°劑鍩涢幒鎳ㄥ綊鏁愰崟顕呭妳闂佺粯甯＄粻鏍蓟閿熺姴閱囨い鎰╁灩椤偆绱撴笟鍥ф灍闁荤啿鏅犻悰顔撅拷锝庡枟閺呮繈鏌ㄩ悢鍓佺煓鐎殿喖鎲￠幏鍛存嚃濠靛洦顥堥柡浣瑰姍瀹曘劑顢橀悢鍓插敼闂傚倷鑳剁划顖炲箰婵犳碍鍋＄憸鏃堝极閹剧粯鍋╅悘鐐村劤濞堝矂鏌ｆ惔銏犲毈闁告ê銈搁垾锕傚垂椤斻儳鍠愰幏鍛村即椤忓棛蓱缂備胶绮换鍌烇綖濠靛鏁囬柣妯诲絻缁犵偤姊婚崒娆掑厡缂侇噮鍨跺濠氬Ω閳轰胶鐤呴梺鐐藉劚绾绢參寮抽敂鎾呮嫹閻у憡瀚归梺鍛婃处閸撴盯宕㈤幖浣圭厽闊洦娲栨禒鈺傘亜閺囧棗瀚崣蹇涙煕瀹�锟介崑鐐烘偂濞嗘劑浜滈柡鍌涘閹牓鏌ｈ箛姘毢闁跨喎锟界噥娼愭繛鎻掔箻瀹曟繂顓奸崶銊ュ簥濠电娀娼ч鍛矆鐎ｎ偁浜滈煫鍥ㄦ尰椤ョ娀鏌ㄥ☉姘灈婵﹤顭峰畷鎺戭潩椤掑﹥瀚瑰瀣捣閻棗霉閿濆牊顏犵紒锟芥繝鍌楁斀闁绘ê寮剁涵钘夘熆閼搁潧濮囩紒鐘差煼閺岋綁骞嬮弮锟藉▍鏃堟煙妞嬪骸鍘撮柡浣稿暣瀹曟帒顫濇鏍ㄐㄩ梻鍌欐祰濞夋洟宕抽敃鍌氱闁跨噦鎷�55
////			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
//
//			   // MBR f->win511闂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾惧湱锟界懓瀚崳纾嬨亹閹烘垹鍊為悷婊冾樀瀵悂寮介鐔哄幐闂佹悶鍎崕閬嶆倶閳哄啰纾奸柟閭﹀弾濞堟粓鏌″畝瀣瘈鐎规洖鐖奸弫鎰板川椤掞拷椤ユ岸姊绘担鑺ョ《闁哥姵鍔欏畷鐟扳攽閸垻鐒兼繛鎾寸啲閹风兘鏌嶉妷顖滅暤濠碘剝鎮傞崺鈩冪瑹閿熶粙宕崼鏇熲拺缂備焦蓱椤ュ牓鏌￠敓浠嬫焼瀹ュ棗浠鹃梺鍛婄☉閻°劑鍩涢幒鎳ㄥ綊鏁愰崟顕呭妳闂佺粯甯＄粻鏍蓟閿熺姴閱囨い鎰╁灩椤偊姊洪崨濠傜瑲閻㈩垱甯￠幃鎯р攽鐎ｎ亞顦板銈嗗釜閹风兘鏌涢幙鍐ㄥ籍婵﹨娅ｅ☉鐢稿川椤斿吋閿梻鍌氬�哥�氼剛锟芥矮鍗抽獮鍐灳閺傘儲鐎婚梺瑙勫劤椤曨參宕㈤柆宥嗏拺闁荤喐澹嗛幗鐘绘煟閻旀潙鍔﹂柡浣规崌閹崇偤濡疯閳峰牓姊虹捄銊ユ灆濠殿喓鍊濋幃銏ゎ敆閸曨偆顔嗛梺璺ㄥ櫐閹凤拷512闂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾惧湱锟界懓瀚崳纾嬨亹閹烘垹鍊為悷婊冾樀瀵悂寮介鐔哄幐闂佹悶鍎崕閬嶆倶閳哄啰纾奸柟閭﹀弾濞堟粓鏌″畝瀣瘈鐎规洖鐖奸弫鎰板川椤掞拷椤ユ岸姊绘担鑺ョ《闁哥姵鍔欏畷鐟扳攽閸垻鐒兼繛鎾寸啲閹风兘鏌嶉妷顖滅暤濠碘剝鎮傞崺鈩冪瑹閿熶粙宕崼鏇熲拺缂備焦蓱椤ュ牓鏌￠敓浠嬫焼瀹ュ棗浠鹃梺鍛婄☉閻°劑鍩涢幒鎳ㄥ綊鏁愰崟顕呭妳闂佺粯甯＄粻鏍蓟閿熺姴閱囨い鎰╁灩椤偆绱撴笟鍥ф灍闁荤啿鏅犻悰顔撅拷锝庡枟閺呮繈鏌ㄩ悢鍓佺煓鐎殿喖鎲￠幏鍛存嚃濠靛洦顥堥柡浣瑰姍瀹曘劑顢橀悢鍓插敼闂傚倷鑳剁划顖炲箰婵犳碍鍋＄憸鏃堝极閹剧粯鍋╅悘鐐村劤濞堝矂鏌ｆ惔銏犲毈闁告ê銈搁垾锕傚垂椤斻儳鍠愰幏鍛村即椤忓棛蓱缂備胶绮换鍌烇綖濠靛鏁囬柣妯诲絻缁犵偤姊婚崒娆掑厡缂侇噮鍨跺濠氬Ω閳轰胶鐤呴梺鐐藉劚绾绢參寮抽敂鎾呮嫹閻у憡瀚归梺鍛婃处閸撴盯宕㈤幖浣圭厽闊洦娲栨禒鈺傘亜閺囧棗瀚崣蹇涙煕瀹�锟介崑鐐烘偂濞嗘劑浜滈柡鍌涘閹牓鏌ｈ箛姘毢闁跨喎锟界噥娼愭繛鎻掔箻瀹曟繂顓奸崶銊ュ簥濠电娀娼ч鍛矆鐎ｎ偁浜滈煫鍥ㄦ尰椤ョ娀鏌ㄥ☉姘灈婵﹤顭峰畷鎺戭潩椤掑﹥瀚瑰瀣捣閻棗霉閿濆牊顏犵紒锟芥繝鍌楁斀闁绘ê寮剁涵钘夘熆閼搁潧濮囩紒鐘差煼閺岋綁骞嬮弮锟藉▍鏃堟煙妞嬪骸鍘撮柡浣稿暣瀹曟帒顫濇鏍ㄐㄩ梻鍌欐祰濞夋洟宕抽敃鍌氱闁跨噦鎷�55
//			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
//			fs->winsect = sect;
//		}
//	}
//	return res;
//}

static FRESULT move_window (	/* Returns FR_OK or FR_DISK_ERR */
	FATFS* fs,		/* Filesystem object */
	LBA_t sect		/* Sector LBA to make appearance in the fs->win[] */
)
{
	FRESULT res = FR_OK;


	if (sect != fs->winsect) {	/* Window offset changed? */
#if !FF_FS_READONLY
		res = sync_window(fs);		/* Flush the window */
#endif
		if (res == FR_OK) {			/* Fill sector window with new data */
//			if (disk_read(fs->pdrv, (BYTE *)(0xA0001000), sect, 1) != RES_OK) {//9.3
			if (disk_read2(fs->pdrv, (BYTE *)(0xA0001000), sect, 1) != RES_OK) {
				Xil_L1DCacheFlush(); //8.20 add
				memcpy(fs->win,(BYTE *)(0xA0001000),SECTORSIZE*1);
				memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
				sect = (LBA_t)0 - 1;	/* Invalidate window if read data is not valid */
				res = FR_DISK_ERR;
			}
			Xil_L1DCacheFlush(); //
			memcpy(fs->win,(BYTE *)(0xA0001000),SECTORSIZE*1);
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
			fs->winsect = sect;
		}
	}
	return res;
}

#if !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* Synchronize filesystem and data on the storage                        */
/*-----------------------------------------------------------------------*/

static FRESULT sync_fs (	/* Returns FR_OK or FR_DISK_ERR */
	FATFS* fs		/* Filesystem object */
)
{
	FRESULT res;


	res = sync_window(fs);
	if (res == FR_OK) {
		if (fs->fs_type == FS_FAT32 && fs->fsi_flag == 1) {	/* FAT32: Update FSInfo sector if needed */
			/* Create FSInfo structure */
			memset(fs->win, 0, sizeof fs->win);
			st_word(fs->win + BS_55AA, 0xAA55);					/* Boot signature */
			st_dword(fs->win + FSI_LeadSig, 0x41615252);		/* Leading signature */
			st_dword(fs->win + FSI_StrucSig, 0x61417272);		/* Structure signature */
			st_dword(fs->win + FSI_Free_Count, fs->free_clst);	/* Number of free clusters */
			st_dword(fs->win + FSI_Nxt_Free, fs->last_clst);	/* Last allocated culuster */
			fs->winsect = fs->volbase + 1;						/* Write it into the FSInfo sector (Next to VBR) */
			memcpy((BYTE *)(0xA0001000),fs->win,SECTORSIZE*1);
			disk_write(fs->pdrv, (BYTE *)(0xA0001000), fs->winsect, 1);
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
			fs->fsi_flag = 0;
		}
		/* Make sure that no pending write process in the lower layer */
		if (disk_ioctl(fs->pdrv, CTRL_SYNC, 0) != RES_OK) res = FR_DISK_ERR;
	}

	return res;
}

#endif



/*-----------------------------------------------------------------------*/
/* Get physical sector number from cluster number                        */
/*-----------------------------------------------------------------------*/

static LBA_t clst2sect (	/* !=0:Sector number, 0:Failed (invalid cluster#) */
	FATFS* fs,		/* Filesystem object */
	DWORD clst		/* Cluster# to be converted */
)
{
	clst -= 2;		/* Cluster number is origin from 2 */
	if (clst >= fs->n_fatent - 2) return 0;		/* Is it invalid cluster number? */
	return fs->database + (LBA_t)fs->csize * clst;	/* Start sector number of the cluster */
}




/*-----------------------------------------------------------------------*/
/* FAT access - Read value of an FAT entry                               */
/*-----------------------------------------------------------------------*/

static DWORD get_fat (		/* 0xFFFFFFFF:Disk error, 1:Internal error, 2..0x7FFFFFFF:Cluster status */
	FFOBJID* obj,	/* Corresponding object */
	DWORD clst		/* Cluster number to get the value */
)
{
	UINT wc, bc;
	DWORD val;
	FATFS *fs = obj->fs;


	if (clst < 2 || clst >= fs->n_fatent) {	/* Check if in valid range */
		val = 1;	/* Internal error */

	} else {
		val = 0xFFFFFFFF;	/* Default value falls on disk error */

		switch (fs->fs_type) {
		case FS_FAT12 :
			bc = (UINT)clst; bc += bc / 2;
			if (move_window(fs, fs->fatbase + (bc / SS(fs))) != FR_OK) break;
			wc = fs->win[bc++ % SS(fs)];		/* Get 1st byte of the entry */
			if (move_window(fs, fs->fatbase + (bc / SS(fs))) != FR_OK) break;
			wc |= fs->win[bc % SS(fs)] << 8;	/* Merge 2nd byte of the entry */
			val = (clst & 1) ? (wc >> 4) : (wc & 0xFFF);	/* Adjust bit position */
			break;

		case FS_FAT16 :
			if (move_window(fs, fs->fatbase + (clst / (SS(fs) / 2))) != FR_OK) break;
			val = ld_word(fs->win + clst * 2 % SS(fs));		/* Simple WORD array */
			break;

		case FS_FAT32 :
			if (move_window(fs, fs->fatbase + (clst / (SS(fs) / 4))) != FR_OK) break;
			val = ld_dword(fs->win + clst * 4 % SS(fs)) & 0x0FFFFFFF;	/* Simple DWORD array but mask out upper 4 bits */
			break;
#if FF_FS_EXFAT
		case FS_EXFAT :
			if ((obj->objsize != 0 && obj->sclust != 0) || obj->stat == 0) {	/* Object except root dir must have valid data length */
				DWORD cofs = clst - obj->sclust;	/* Offset from start cluster */
				DWORD clen = (DWORD)((LBA_t)((obj->objsize - 1) / SS(fs)) / fs->csize);	/* Number of clusters - 1 */

				if (obj->stat == 2 && cofs <= clen) {	/* Is it a contiguous chain? */
					val = (cofs == clen) ? 0x7FFFFFFF : clst + 1;	/* No data on the FAT, generate the value */
					break;
				}
				if (obj->stat == 3 && cofs < obj->n_cont) {	/* Is it in the 1st fragment? */
					val = clst + 1; 	/* Generate the value */
					break;
				}
				if (obj->stat != 2) {	/* Get value from FAT if FAT chain is valid */
					if (obj->n_frag != 0) {	/* Is it on the growing edge? */
						val = 0x7FFFFFFF;	/* Generate EOC */
					} else {
						if (move_window(fs, fs->fatbase + (clst / (SS(fs) / 4))) != FR_OK) break;
						val = ld_dword(fs->win + clst * 4 % SS(fs)) & 0x7FFFFFFF;
					}
					break;
				}
			}
			val = 1;	/* Internal error */
			break;
#endif
		default:
			val = 1;	/* Internal error */
		}
	}

	return val;
}




#if !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* FAT access - Change value of an FAT entry                             */
/*-----------------------------------------------------------------------*/

static FRESULT put_fat (	/* FR_OK(0):succeeded, !=0:error */
	FATFS* fs,		/* Corresponding filesystem object */
	DWORD clst,		/* FAT index number (cluster number) to be changed */
	DWORD val		/* New value to be set to the entry */
)
{
	UINT bc;
	BYTE *p;
	FRESULT res = FR_INT_ERR;


	if (clst >= 2 && clst < fs->n_fatent) {	/* Check if in valid range */
		switch (fs->fs_type) {
		case FS_FAT12:
			bc = (UINT)clst; bc += bc / 2;	/* bc: byte offset of the entry */
			res = move_window(fs, fs->fatbase + (bc / SS(fs)));
			if (res != FR_OK) break;
			p = fs->win + bc++ % SS(fs);
			*p = (clst & 1) ? ((*p & 0x0F) | ((BYTE)val << 4)) : (BYTE)val;	/* Update 1st byte */
			fs->wflag = 1;
			res = move_window(fs, fs->fatbase + (bc / SS(fs)));
			if (res != FR_OK) break;
			p = fs->win + bc % SS(fs);
			*p = (clst & 1) ? (BYTE)(val >> 4) : ((*p & 0xF0) | ((BYTE)(val >> 8) & 0x0F));	/* Update 2nd byte */
			fs->wflag = 1;
			break;

		case FS_FAT16:
			res = move_window(fs, fs->fatbase + (clst / (SS(fs) / 2)));
			if (res != FR_OK) break;
			st_word(fs->win + clst * 2 % SS(fs), (WORD)val);	/* Simple WORD array */
			fs->wflag = 1;
			break;

		case FS_FAT32:
#if FF_FS_EXFAT
		case FS_EXFAT:
#endif
			res = move_window(fs, fs->fatbase + (clst / (SS(fs) / 4)));
			if (res != FR_OK) break;
			if (!FF_FS_EXFAT || fs->fs_type != FS_EXFAT) {
				val = (val & 0x0FFFFFFF) | (ld_dword(fs->win + clst * 4 % SS(fs)) & 0xF0000000);
			}
			st_dword(fs->win + clst * 4 % SS(fs), val);
			fs->wflag = 1;
			break;
		}
	}
	return res;
}

#endif /* !FF_FS_READONLY */




#if FF_FS_EXFAT && !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* exFAT: Accessing FAT and Allocation Bitmap                            */
/*-----------------------------------------------------------------------*/

/*--------------------------------------*/
/* Find a contiguous free cluster block */
/*--------------------------------------*/

static DWORD find_bitmap (	/* 0:Not found, 2..:Cluster block found, 0xFFFFFFFF:Disk error */
	FATFS* fs,	/* Filesystem object */
	DWORD clst,	/* Cluster number to scan from */
	DWORD ncl	/* Number of contiguous clusters to find (1..) */
)
{
	BYTE bm, bv;
	UINT i;
	DWORD val, scl, ctr;


	clst -= 2;	/* The first bit in the bitmap corresponds to cluster #2 */
	if (clst >= fs->n_fatent - 2) clst = 0;
	scl = val = clst; ctr = 0;
	for (;;) {
		if (move_window(fs, fs->bitbase + val / 8 / SS(fs)) != FR_OK) return 0xFFFFFFFF;
		i = val / 8 % SS(fs); bm = 1 << (val % 8);
		do {
			do {
				bv = fs->win[i] & bm; bm <<= 1;		/* Get bit value */
				if (++val >= fs->n_fatent - 2) {	/* Next cluster (with wrap-around) */
					val = 0; bm = 0; i = SS(fs);
				}
				if (bv == 0) {	/* Is it a free cluster? */
					if (++ctr == ncl) return scl + 2;	/* Check if run length is sufficient for required */
				} else {
					scl = val; ctr = 0;		/* Encountered a cluster in-use, restart to scan */
				}
				if (val == clst) return 0;	/* All cluster scanned? */
			} while (bm != 0);
			bm = 1;
		} while (++i < SS(fs));
	}
}


/*----------------------------------------*/
/* Set/Clear a block of allocation bitmap */
/*----------------------------------------*/

static FRESULT change_bitmap (
	FATFS* fs,	/* Filesystem object */
	DWORD clst,	/* Cluster number to change from */
	DWORD ncl,	/* Number of clusters to be changed */
	int bv		/* bit value to be set (0 or 1) */
)
{
	BYTE bm;
	UINT i;
	LBA_t sect;


	clst -= 2;	/* The first bit corresponds to cluster #2 */
	sect = fs->bitbase + clst / 8 / SS(fs);	/* Sector address */
	i = clst / 8 % SS(fs);					/* Byte offset in the sector */
	bm = 1 << (clst % 8);					/* Bit mask in the byte */
	for (;;) {
		if (move_window(fs, sect++) != FR_OK) return FR_DISK_ERR;
		do {
			do {
				if (bv == (int)((fs->win[i] & bm) != 0)) return FR_INT_ERR;	/* Is the bit expected value? */
				fs->win[i] ^= bm;	/* Flip the bit */
				fs->wflag = 1;
				if (--ncl == 0) return FR_OK;	/* All bits processed? */
			} while (bm <<= 1);		/* Next bit */
			bm = 1;
		} while (++i < SS(fs));		/* Next byte */
		i = 0;
	}
}


/*---------------------------------------------*/
/* Fill the first fragment of the FAT chain    */
/*---------------------------------------------*/

static FRESULT fill_first_frag (
	FFOBJID* obj	/* Pointer to the corresponding object */
)
{
	FRESULT res;
	DWORD cl, n;


	if (obj->stat == 3) {	/* Has the object been changed 'fragmented' in this session? */
		for (cl = obj->sclust, n = obj->n_cont; n; cl++, n--) {	/* Create cluster chain on the FAT */
			res = put_fat(obj->fs, cl, cl + 1);
			if (res != FR_OK) return res;
		}
		obj->stat = 0;	/* Change status 'FAT chain is valid' */
	}
	return FR_OK;
}


/*---------------------------------------------*/
/* Fill the last fragment of the FAT chain     */
/*---------------------------------------------*/

static FRESULT fill_last_frag (
	FFOBJID* obj,	/* Pointer to the corresponding object */
	DWORD lcl,		/* Last cluster of the fragment */
	DWORD term		/* Value to set the last FAT entry */
)
{
	FRESULT res;


	while (obj->n_frag > 0) {	/* Create the chain of last fragment */
		res = put_fat(obj->fs, lcl - obj->n_frag + 1, (obj->n_frag > 1) ? lcl - obj->n_frag + 2 : term);
		if (res != FR_OK) return res;
		obj->n_frag--;
	}
	return FR_OK;
}

#endif	/* FF_FS_EXFAT && !FF_FS_READONLY */



#if !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* FAT handling - Remove a cluster chain                                 */
/*-----------------------------------------------------------------------*/

static FRESULT remove_chain (	/* FR_OK(0):succeeded, !=0:error */
	FFOBJID* obj,		/* Corresponding object */
	DWORD clst,			/* Cluster to remove a chain from */
	DWORD pclst			/* Previous cluster of clst (0 if entire chain) */
)
{
	FRESULT res = FR_OK;
	DWORD nxt;
	FATFS *fs = obj->fs;
#if FF_FS_EXFAT || FF_USE_TRIM
	DWORD scl = clst, ecl = clst;
#endif
#if FF_USE_TRIM
	LBA_t rt[2];
#endif

	if (clst < 2 || clst >= fs->n_fatent) return FR_INT_ERR;	/* Check if in valid range */

	/* Mark the previous cluster 'EOC' on the FAT if it exists */
	if (pclst != 0 && (!FF_FS_EXFAT || fs->fs_type != FS_EXFAT || obj->stat != 2)) {
		res = put_fat(fs, pclst, 0xFFFFFFFF);
		if (res != FR_OK) return res;
	}

	/* Remove the chain */
	do {
		nxt = get_fat(obj, clst);			/* Get cluster status */
		if (nxt == 0) break;				/* Empty cluster? */
		if (nxt == 1) return FR_INT_ERR;	/* Internal error? */
		if (nxt == 0xFFFFFFFF) return FR_DISK_ERR;	/* Disk error? */
		if (!FF_FS_EXFAT || fs->fs_type != FS_EXFAT) {
			res = put_fat(fs, clst, 0);		/* Mark the cluster 'free' on the FAT */
			if (res != FR_OK) return res;
		}
		if (fs->free_clst < fs->n_fatent - 2) {	/* Update FSINFO */
			fs->free_clst++;
			fs->fsi_flag |= 1;
		}
#if FF_FS_EXFAT || FF_USE_TRIM
		if (ecl + 1 == nxt) {	/* Is next cluster contiguous? */
			ecl = nxt;
		} else {				/* End of contiguous cluster block */
#if FF_FS_EXFAT
			if (fs->fs_type == FS_EXFAT) {
				res = change_bitmap(fs, scl, ecl - scl + 1, 0);	/* Mark the cluster block 'free' on the bitmap */
				if (res != FR_OK) return res;
			}
#endif
#if FF_USE_TRIM
			rt[0] = clst2sect(fs, scl);					/* Start of data area to be freed */
			rt[1] = clst2sect(fs, ecl) + fs->csize - 1;	/* End of data area to be freed */
			disk_ioctl(fs->pdrv, CTRL_TRIM, rt);		/* Inform storage device that the data in the block may be erased */
#endif
			scl = ecl = nxt;
		}
#endif
		clst = nxt;					/* Next cluster */
	} while (clst < fs->n_fatent);	/* Repeat while not the last link */

#if FF_FS_EXFAT
	/* Some post processes for chain status */
	if (fs->fs_type == FS_EXFAT) {
		if (pclst == 0) {	/* Has the entire chain been removed? */
			obj->stat = 0;		/* Change the chain status 'initial' */
		} else {
			if (obj->stat == 0) {	/* Is it a fragmented chain from the beginning of this session? */
				clst = obj->sclust;		/* Follow the chain to check if it gets contiguous */
				while (clst != pclst) {
					nxt = get_fat(obj, clst);
					if (nxt < 2) return FR_INT_ERR;
					if (nxt == 0xFFFFFFFF) return FR_DISK_ERR;
					if (nxt != clst + 1) break;	/* Not contiguous? */
					clst++;
				}
				if (clst == pclst) {	/* Has the chain got contiguous again? */
					obj->stat = 2;		/* Change the chain status 'contiguous' */
				}
			} else {
				if (obj->stat == 3 && pclst >= obj->sclust && pclst <= obj->sclust + obj->n_cont) {	/* Was the chain fragmented in this session and got contiguous again? */
					obj->stat = 2;	/* Change the chain status 'contiguous' */
				}
			}
		}
	}
#endif
	return FR_OK;
}




/*-----------------------------------------------------------------------*/
/* FAT handling - Stretch a chain or Create a new chain                  */
/*-----------------------------------------------------------------------*/

static DWORD create_chain (	/* 0:No free cluster, 1:Internal error, 0xFFFFFFFF:Disk error, >=2:New cluster# */
	FFOBJID* obj,		/* Corresponding object */
	DWORD clst			/* Cluster# to stretch, 0:Create a new chain */
)
{
	DWORD cs, ncl, scl;
	FRESULT res;
	FATFS *fs = obj->fs;


	if (clst == 0) {	/* Create a new chain */
		scl = fs->last_clst;				/* Suggested cluster to start to find */
		if (scl == 0 || scl >= fs->n_fatent) scl = 1;
	}
	else {				/* Stretch a chain */
		cs = get_fat(obj, clst);			/* Check the cluster status */
		if (cs < 2) return 1;				/* Test for insanity */
		if (cs == 0xFFFFFFFF) return cs;	/* Test for disk error */
		if (cs < fs->n_fatent) return cs;	/* It is already followed by next cluster */
		scl = clst;							/* Cluster to start to find */
	}
	if (fs->free_clst == 0) return 0;		/* No free cluster */

#if FF_FS_EXFAT
	if (fs->fs_type == FS_EXFAT) {	/* On the exFAT volume */
		ncl = find_bitmap(fs, scl, 1);				/* Find a free cluster */
		if (ncl == 0 || ncl == 0xFFFFFFFF) return ncl;	/* No free cluster or hard error? */
		res = change_bitmap(fs, ncl, 1, 1);			/* Mark the cluster 'in use' */
		if (res == FR_INT_ERR) return 1;
		if (res == FR_DISK_ERR) return 0xFFFFFFFF;
		if (clst == 0) {							/* Is it a new chain? */
			obj->stat = 2;							/* Set status 'contiguous' */
		} else {									/* It is a stretched chain */
			if (obj->stat == 2 && ncl != scl + 1) {	/* Is the chain got fragmented? */
				obj->n_cont = scl - obj->sclust;	/* Set size of the contiguous part */
				obj->stat = 3;						/* Change status 'just fragmented' */
			}
		}
		if (obj->stat != 2) {	/* Is the file non-contiguous? */
			if (ncl == clst + 1) {	/* Is the cluster next to previous one? */
				obj->n_frag = obj->n_frag ? obj->n_frag + 1 : 2;	/* Increment size of last framgent */
			} else {				/* New fragment */
				if (obj->n_frag == 0) obj->n_frag = 1;
//				xil_printf("wfeng: fun = %s, line = %d\n", __func__, __LINE__);
				res = fill_last_frag(obj, clst, ncl);	/* Fill last fragment on the FAT and link it to new one */
				if (res == FR_OK) obj->n_frag = 1;
			}
		}
	} else
#endif
	{	/* On the FAT/FAT32 volume */
		ncl = 0;
		if (scl == clst) {						/* Stretching an existing chain? */
			ncl = scl + 1;						/* Test if next cluster is free */
			if (ncl >= fs->n_fatent) ncl = 2;
			cs = get_fat(obj, ncl);				/* Get next cluster status */
			if (cs == 1 || cs == 0xFFFFFFFF) return cs;	/* Test for error */
			if (cs != 0) {						/* Not free? */
				cs = fs->last_clst;				/* Start at suggested cluster if it is valid */
				if (cs >= 2 && cs < fs->n_fatent) scl = cs;
				ncl = 0;
			}
		}
		if (ncl == 0) {	/* The new cluster cannot be contiguous and find another fragment */
			ncl = scl;	/* Start cluster */
			for (;;) {
				ncl++;							/* Next cluster */
				if (ncl >= fs->n_fatent) {		/* Check wrap-around */
					ncl = 2;
					if (ncl > scl) return 0;	/* No free cluster found? */
				}
				cs = get_fat(obj, ncl);			/* Get the cluster status */
				if (cs == 0) break;				/* Found a free cluster? */
				if (cs == 1 || cs == 0xFFFFFFFF) return cs;	/* Test for error */
				if (ncl == scl) return 0;		/* No free cluster found? */
			}
		}
		res = put_fat(fs, ncl, 0xFFFFFFFF);		/* Mark the new cluster 'EOC' */
		if (res == FR_OK && clst != 0) {
			res = put_fat(fs, clst, ncl);		/* Link it from the previous one if needed */
		}
	}

	if (res == FR_OK) {			/* Update FSINFO if function succeeded. */
		fs->last_clst = ncl;
		if (fs->free_clst <= fs->n_fatent - 2) fs->free_clst--;
		fs->fsi_flag |= 1;
	} else {
		ncl = (res == FR_DISK_ERR) ? 0xFFFFFFFF : 1;	/* Failed. Generate error status */
	}

	return ncl;		/* Return new cluster number or error status */
}

#endif /* !FF_FS_READONLY */




#if FF_USE_FASTSEEK
/*-----------------------------------------------------------------------*/
/* FAT handling - Convert offset into cluster with link map table        */
/*-----------------------------------------------------------------------*/

static DWORD clmt_clust (	/* <2:Error, >=2:Cluster number */
	FIL* fp,		/* Pointer to the file object */
	FSIZE_t ofs		/* File offset to be converted to cluster# */
)
{
	DWORD cl, ncl;
	DWORD *tbl;
	FATFS *fs = fp->obj.fs;


	tbl = fp->cltbl + 1;	/* Top of CLMT */
	cl = (DWORD)(ofs / SS(fs) / fs->csize);	/* Cluster order from top of the file */
	for (;;) {
		ncl = *tbl++;			/* Number of cluters in the fragment */
		if (ncl == 0) return 0;	/* End of table? (error) */
		if (cl < ncl) break;	/* In this fragment? */
		cl -= ncl; tbl++;		/* Next fragment */
	}
	return cl + *tbl;	/* Return the cluster number */
}

#endif	/* FF_USE_FASTSEEK */




/*-----------------------------------------------------------------------*/
/* Directory handling - Fill a cluster with zeros                        */
/*-----------------------------------------------------------------------*/

#if !FF_FS_READONLY
static FRESULT dir_clear (	/* Returns FR_OK or FR_DISK_ERR */
	FATFS *fs,		/* Filesystem object */
	DWORD clst		/* Directory table to clear */
)
{
	LBA_t sect;
	UINT n, szb;
	BYTE *ibuf;


	if (sync_window(fs) != FR_OK) return FR_DISK_ERR;	/* Flush disk access window */
	sect = clst2sect(fs, clst);		/* Top of the cluster */
	fs->winsect = sect;				/* Set window to top of the cluster */
	memset(fs->win, 0, sizeof fs->win);	/* Clear window buffer */
#if FF_USE_LFN == 3		/* Quick table clear by using multi-secter write */
	/* Allocate a temporary buffer */
	for (szb = ((DWORD)fs->csize * SS(fs) >= MAX_MALLOC) ? MAX_MALLOC : fs->csize * SS(fs), ibuf = 0; szb > SS(fs) && (ibuf = ff_memalloc(szb)) == 0; szb /= 2) ;
	if (szb > SS(fs)) {		/* Buffer allocated? */
		memset(ibuf, 0, szb);
		szb /= SS(fs);		/* Bytes -> Sectors */
		for (n = 0; n < fs->csize && disk_write(fs->pdrv, ibuf, sect + n, szb) == RES_OK; n += szb) ;	/* Fill the cluster with 0 */
		ff_memfree(ibuf);
	} else
#endif
	{
		ibuf = fs->win; szb = 1;	/* Use window buffer (many single-sector writes may take a time) */
		memcpy((BYTE *)(0xA0001000),ibuf,SECTORSIZE*szb);
		for (n = 0; n < fs->csize && disk_write1(fs->pdrv, (BYTE *)(0xA0001000), sect + n, szb) == RES_OK; n += szb) ;	/* Fill the cluster with 0 *///9.3
//		memcpy((BYTE *)(0xA0001000),ibuf,SECTORSIZE*szb);
		memset((BYTE *)(0xA0001000),0,SECTORSIZE*szb);
	}
	return (n == fs->csize) ? FR_OK : FR_DISK_ERR;
}
#endif	/* !FF_FS_READONLY */




/*-----------------------------------------------------------------------*/
/* Directory handling - Set directory index                              */
/*-----------------------------------------------------------------------*/

static FRESULT dir_sdi (	/* FR_OK(0):succeeded, !=0:error */
	DIR* dp,		/* Pointer to directory object */
	DWORD ofs		/* Offset of directory table */
)
{
	DWORD csz, clst;
	FATFS *fs = dp->obj.fs;


	if (ofs >= (DWORD)((FF_FS_EXFAT && fs->fs_type == FS_EXFAT) ? MAX_DIR_EX : MAX_DIR) || ofs % SZDIRE) {	/* Check range of offset and alignment */
		return FR_INT_ERR;
	}
	dp->dptr = ofs;				/* Set current offset */
	clst = dp->obj.sclust;		/* Table start cluster (0:root) */
	if (clst == 0 && fs->fs_type >= FS_FAT32) {	/* Replace cluster# 0 with root cluster# */
		clst = (DWORD)fs->dirbase;
		if (FF_FS_EXFAT) dp->obj.stat = 0;	/* exFAT: Root dir has an FAT chain */
	}

	if (clst == 0) {	/* Static table (root-directory on the FAT volume) */
		if (ofs / SZDIRE >= fs->n_rootdir) return FR_INT_ERR;	/* Is index out of range? */
		dp->sect = fs->dirbase;

	} else {			/* Dynamic table (sub-directory or root-directory on the FAT32/exFAT volume) */
		csz = (DWORD)fs->csize * SS(fs);	/* Bytes per cluster */
		while (ofs >= csz) {				/* Follow cluster chain */
			clst = get_fat(&dp->obj, clst);				/* Get next cluster */
			if (clst == 0xFFFFFFFF) return FR_DISK_ERR;	/* Disk error */
			if (clst < 2 || clst >= fs->n_fatent) return FR_INT_ERR;	/* Reached to end of table or internal error */
			ofs -= csz;
		}
		dp->sect = clst2sect(fs, clst);
	}
	dp->clust = clst;					/* Current cluster# */
	if (dp->sect == 0) return FR_INT_ERR;
	dp->sect += ofs / SS(fs);			/* Sector# of the directory entry */
	dp->dir = fs->win + (ofs % SS(fs));	/* Pointer to the entry in the win[] */

	return FR_OK;
}




/*-----------------------------------------------------------------------*/
/* Directory handling - Move directory table index next                  */
/*-----------------------------------------------------------------------*/

static FRESULT dir_next (	/* FR_OK(0):succeeded, FR_NO_FILE:End of table, FR_DENIED:Could not stretch */
	DIR* dp,				/* Pointer to the directory object */
	int stretch				/* 0: Do not stretch table, 1: Stretch table if needed */
)
{
	DWORD ofs, clst;
	FATFS *fs = dp->obj.fs;


	ofs = dp->dptr + SZDIRE;	/* Next entry */
	if (ofs >= (DWORD)((FF_FS_EXFAT && fs->fs_type == FS_EXFAT) ? MAX_DIR_EX : MAX_DIR)) dp->sect = 0;	/* Disable it if the offset reached the max value */
	if (dp->sect == 0) return FR_NO_FILE;	/* Report EOT if it has been disabled */

	if (ofs % SS(fs) == 0) {	/* Sector changed? */
		dp->sect++;				/* Next sector */

		if (dp->clust == 0) {	/* Static table */
			if (ofs / SZDIRE >= fs->n_rootdir) {	/* Report EOT if it reached end of static table */
				dp->sect = 0; return FR_NO_FILE;
			}
		}
		else {					/* Dynamic table */
			if ((ofs / SS(fs) & (fs->csize - 1)) == 0) {	/* Cluster changed? */
				clst = get_fat(&dp->obj, dp->clust);		/* Get next cluster */
				if (clst <= 1) return FR_INT_ERR;			/* Internal error */
				if (clst == 0xFFFFFFFF) return FR_DISK_ERR;	/* Disk error */
				if (clst >= fs->n_fatent) {					/* It reached end of dynamic table */
#if !FF_FS_READONLY
					if (!stretch) {								/* If no stretch, report EOT */
						dp->sect = 0; return FR_NO_FILE;
					}
					clst = create_chain(&dp->obj, dp->clust);	/* Allocate a cluster */
					if (clst == 0) return FR_DENIED;			/* No free cluster */
					if (clst == 1) return FR_INT_ERR;			/* Internal error */
					if (clst == 0xFFFFFFFF) return FR_DISK_ERR;	/* Disk error */
					if (dir_clear(fs, clst) != FR_OK) return FR_DISK_ERR;	/* Clean up the stretched table */
					if (FF_FS_EXFAT) dp->obj.stat |= 4;			/* exFAT: The directory has been stretched */
#else
					if (!stretch) dp->sect = 0;					/* (this line is to suppress compiler warning) */
					dp->sect = 0; return FR_NO_FILE;			/* Report EOT */
#endif
				}
				dp->clust = clst;		/* Initialize data for new cluster */
				dp->sect = clst2sect(fs, clst);
			}
		}
	}
	dp->dptr = ofs;						/* Current entry */
	dp->dir = fs->win + ofs % SS(fs);	/* Pointer to the entry in the win[] */

	return FR_OK;
}




#if !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* Directory handling - Reserve a block of directory entries             */
/*-----------------------------------------------------------------------*/

static FRESULT dir_alloc (	/* FR_OK(0):succeeded, !=0:error */
	DIR* dp,				/* Pointer to the directory object */
	UINT n_ent				/* Number of contiguous entries to allocate */
)
{
	FRESULT res;
	UINT n;
	FATFS *fs = dp->obj.fs;


	res = dir_sdi(dp, 0);
	if (res == FR_OK) {
		n = 0;
		do {
			res = move_window(fs, dp->sect);
			if (res != FR_OK) break;
#if FF_FS_EXFAT
			if ((fs->fs_type == FS_EXFAT) ? (int)((dp->dir[XDIR_Type] & 0x80) == 0) : (int)(dp->dir[DIR_Name] == DDEM || dp->dir[DIR_Name] == 0)) {	/* Is the entry free? */
#else
			if (dp->dir[DIR_Name] == DDEM || dp->dir[DIR_Name] == 0) {	/* Is the entry free? */
#endif
				if (++n == n_ent) break;	/* Is a block of contiguous free entries found? */
			} else {
				n = 0;				/* Not a free entry, restart to search */
			}
			res = dir_next(dp, 1);	/* Next entry with table stretch enabled */
		} while (res == FR_OK);
	}

	if (res == FR_NO_FILE) res = FR_DENIED;	/* No directory entry to allocate */
	return res;
}

#endif	/* !FF_FS_READONLY */




/*-----------------------------------------------------------------------*/
/* FAT: Directory handling - Load/Store start cluster number             */
/*-----------------------------------------------------------------------*/

static DWORD ld_clust (	/* Returns the top cluster value of the SFN entry */
	FATFS* fs,			/* Pointer to the fs object */
	const BYTE* dir		/* Pointer to the key entry */
)
{
	DWORD cl;

	cl = ld_word(dir + DIR_FstClusLO);
	if (fs->fs_type == FS_FAT32) {
		cl |= (DWORD)ld_word(dir + DIR_FstClusHI) << 16;
	}

	return cl;
}


#if !FF_FS_READONLY
static void st_clust (
	FATFS* fs,	/* Pointer to the fs object */
	BYTE* dir,	/* Pointer to the key entry */
	DWORD cl	/* Value to be set */
)
{
	st_word(dir + DIR_FstClusLO, (WORD)cl);
	if (fs->fs_type == FS_FAT32) {
		st_word(dir + DIR_FstClusHI, (WORD)(cl >> 16));
	}
}
#endif



#if FF_USE_LFN
/*--------------------------------------------------------*/
/* FAT-LFN: Compare a part of file name with an LFN entry */
/*--------------------------------------------------------*/

static int cmp_lfn (		/* 1:matched, 0:not matched */
	const WCHAR* lfnbuf,	/* Pointer to the LFN working buffer to be compared */
	BYTE* dir				/* Pointer to the directory entry containing the part of LFN */
)
{
	UINT i, s;
	WCHAR wc, uc;


	if (ld_word(dir + LDIR_FstClusLO) != 0) return 0;	/* Check LDIR_FstClusLO */

	i = ((dir[LDIR_Ord] & 0x3F) - 1) * 13;	/* Offset in the LFN buffer */

	for (wc = 1, s = 0; s < 13; s++) {		/* Process all characters in the entry */
		uc = ld_word(dir + LfnOfs[s]);		/* Pick an LFN character */
		if (wc != 0) {
			if (i >= FF_MAX_LFN + 1 || ff_wtoupper(uc) != ff_wtoupper(lfnbuf[i++])) {	/* Compare it */
				return 0;					/* Not matched */
			}
			wc = uc;
		} else {
			if (uc != 0xFFFF) return 0;		/* Check filler */
		}
	}

	if ((dir[LDIR_Ord] & LLEF) && wc && lfnbuf[i]) return 0;	/* Last segment matched but different length */

	return 1;		/* The part of LFN matched */
}


#if FF_FS_MINIMIZE <= 1 || FF_FS_RPATH >= 2 || FF_USE_LABEL || FF_FS_EXFAT
/*-----------------------------------------------------*/
/* FAT-LFN: Pick a part of file name from an LFN entry */
/*-----------------------------------------------------*/

static int pick_lfn (	/* 1:succeeded, 0:buffer overflow or invalid LFN entry */
	WCHAR* lfnbuf,		/* Pointer to the LFN working buffer */
	BYTE* dir			/* Pointer to the LFN entry */
)
{
	UINT i, s;
	WCHAR wc, uc;


	if (ld_word(dir + LDIR_FstClusLO) != 0) return 0;	/* Check LDIR_FstClusLO is 0 */

	i = ((dir[LDIR_Ord] & ~LLEF) - 1) * 13;	/* Offset in the LFN buffer */

	for (wc = 1, s = 0; s < 13; s++) {		/* Process all characters in the entry */
		uc = ld_word(dir + LfnOfs[s]);		/* Pick an LFN character */
		if (wc != 0) {
			if (i >= FF_MAX_LFN + 1) return 0;	/* Buffer overflow? */
			lfnbuf[i++] = wc = uc;			/* Store it */
		} else {
			if (uc != 0xFFFF) return 0;		/* Check filler */
		}
	}

	if (dir[LDIR_Ord] & LLEF && wc != 0) {	/* Put terminator if it is the last LFN part and not terminated */
		if (i >= FF_MAX_LFN + 1) return 0;	/* Buffer overflow? */
		lfnbuf[i] = 0;
	}

	return 1;		/* The part of LFN is valid */
}
#endif


#if !FF_FS_READONLY
/*-----------------------------------------*/
/* FAT-LFN: Create an entry of LFN entries */
/*-----------------------------------------*/

static void put_lfn (
	const WCHAR* lfn,	/* Pointer to the LFN */
	BYTE* dir,			/* Pointer to the LFN entry to be created */
	BYTE ord,			/* LFN order (1-20) */
	BYTE sum			/* Checksum of the corresponding SFN */
)
{
	UINT i, s;
	WCHAR wc;


	dir[LDIR_Chksum] = sum;			/* Set checksum */
	dir[LDIR_Attr] = AM_LFN;		/* Set attribute. LFN entry */
	dir[LDIR_Type] = 0;
	st_word(dir + LDIR_FstClusLO, 0);

	i = (ord - 1) * 13;				/* Get offset in the LFN working buffer */
	s = wc = 0;
	do {
		if (wc != 0xFFFF) wc = lfn[i++];	/* Get an effective character */
		st_word(dir + LfnOfs[s], wc);		/* Put it */
		if (wc == 0) wc = 0xFFFF;			/* Padding characters for following items */
	} while (++s < 13);
	if (wc == 0xFFFF || !lfn[i]) ord |= LLEF;	/* Last LFN part is the start of LFN sequence */
	dir[LDIR_Ord] = ord;			/* Set the LFN order */
}

#endif	/* !FF_FS_READONLY */
#endif	/* FF_USE_LFN */



#if FF_USE_LFN && !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* FAT-LFN: Create a Numbered SFN                                        */
/*-----------------------------------------------------------------------*/

static void gen_numname (
	BYTE* dst,			/* Pointer to the buffer to store numbered SFN */
	const BYTE* src,	/* Pointer to SFN in directory form */
	const WCHAR* lfn,	/* Pointer to LFN */
	UINT seq			/* Sequence number */
)
{
	BYTE ns[8], c;
	UINT i, j;
	WCHAR wc;
	DWORD sreg;


	memcpy(dst, src, 11);	/* Prepare the SFN to be modified */

	if (seq > 5) {	/* In case of many collisions, generate a hash number instead of sequential number */
		sreg = seq;
		while (*lfn) {	/* Create a CRC as hash value */
			wc = *lfn++;
			for (i = 0; i < 16; i++) {
				sreg = (sreg << 1) + (wc & 1);
				wc >>= 1;
				if (sreg & 0x10000) sreg ^= 0x11021;
			}
		}
		seq = (UINT)sreg;
	}

	/* Make suffix (~ + hexadecimal) */
	i = 7;
	do {
		c = (BYTE)((seq % 16) + '0'); seq /= 16;
		if (c > '9') c += 7;
		ns[i--] = c;
	} while (i && seq);
	ns[i] = '~';

	/* Append the suffix to the SFN body */
	for (j = 0; j < i && dst[j] != ' '; j++) {	/* Find the offset to append */
		if (dbc_1st(dst[j])) {	/* To avoid DBC break up */
			if (j == i - 1) break;
			j++;
		}
	}
	do {	/* Append the suffix */
		dst[j++] = (i < 8) ? ns[i++] : ' ';
	} while (j < 8);
}
#endif	/* FF_USE_LFN && !FF_FS_READONLY */



#if FF_USE_LFN
/*-----------------------------------------------------------------------*/
/* FAT-LFN: Calculate checksum of an SFN entry                           */
/*-----------------------------------------------------------------------*/

static BYTE sum_sfn (
	const BYTE* dir		/* Pointer to the SFN entry */
)
{
	BYTE sum = 0;
	UINT n = 11;

	do {
		sum = (sum >> 1) + (sum << 7) + *dir++;
	} while (--n);
	return sum;
}

#endif	/* FF_USE_LFN */



#if FF_FS_EXFAT
/*-----------------------------------------------------------------------*/
/* exFAT: Checksum                                                       */
/*-----------------------------------------------------------------------*/

static WORD xdir_sum (	/* Get checksum of the directoly entry block */
	const BYTE* dir		/* Directory entry block to be calculated */
)
{
	UINT i, szblk;
	WORD sum;


	szblk = (dir[XDIR_NumSec] + 1) * SZDIRE;	/* Number of bytes of the entry block */
	for (i = sum = 0; i < szblk; i++) {
		if (i == XDIR_SetSum) {	/* Skip 2-byte sum field */
			i++;
		} else {
			sum = ((sum & 1) ? 0x8000 : 0) + (sum >> 1) + dir[i];
		}
	}
	return sum;
}



static WORD xname_sum (	/* Get check sum (to be used as hash) of the file name */
	const WCHAR* name	/* File name to be calculated */
)
{
	WCHAR chr;
	WORD sum = 0;


	while ((chr = *name++) != 0) {
		chr = (WCHAR)ff_wtoupper(chr);		/* File name needs to be up-case converted */
		sum = ((sum & 1) ? 0x8000 : 0) + (sum >> 1) + (chr & 0xFF);
		sum = ((sum & 1) ? 0x8000 : 0) + (sum >> 1) + (chr >> 8);
	}
	return sum;
}


//#if !FF_FS_READONLY && FF_USE_MKFS   //wfeng
static DWORD xsum32 (	/* Returns 32-bit checksum */
	BYTE  dat,			/* Byte to be calculated (byte-by-byte processing) */
	DWORD sum			/* Previous sum value */
)
{
	sum = ((sum & 1) ? 0x80000000 : 0) + (sum >> 1) + dat;
	return sum;
}
//#endif



/*------------------------------------*/
/* exFAT: Get a directory entry block */
/*------------------------------------*/

static FRESULT load_xdir (	/* FR_INT_ERR: invalid entry block */
	DIR* dp					/* Reading directory object pointing top of the entry block to load */
)
{
	FRESULT res;
	UINT i, sz_ent;
	BYTE *dirb = dp->obj.fs->dirbuf;	/* Pointer to the on-memory directory entry block 85+C0+C1s */


	/* Load file directory entry */
	res = move_window(dp->obj.fs, dp->sect);
	if (res != FR_OK) return res;
	if (dp->dir[XDIR_Type] != ET_FILEDIR) return FR_INT_ERR;	/* Invalid order */
	memcpy(dirb + 0 * SZDIRE, dp->dir, SZDIRE);
	sz_ent = (dirb[XDIR_NumSec] + 1) * SZDIRE;
	if (sz_ent < 3 * SZDIRE || sz_ent > 19 * SZDIRE) return FR_INT_ERR;

	/* Load stream extension entry */
	res = dir_next(dp, 0);
	if (res == FR_NO_FILE) res = FR_INT_ERR;	/* It cannot be */
	if (res != FR_OK) return res;
	res = move_window(dp->obj.fs, dp->sect);
	if (res != FR_OK) return res;
	if (dp->dir[XDIR_Type] != ET_STREAM) return FR_INT_ERR;	/* Invalid order */
	memcpy(dirb + 1 * SZDIRE, dp->dir, SZDIRE);
	if (MAXDIRB(dirb[XDIR_NumName]) > sz_ent) return FR_INT_ERR;

	/* Load file name entries */
	i = 2 * SZDIRE;	/* Name offset to load */
	do {
		res = dir_next(dp, 0);
		if (res == FR_NO_FILE) res = FR_INT_ERR;	/* It cannot be */
		if (res != FR_OK) return res;
		res = move_window(dp->obj.fs, dp->sect);
		if (res != FR_OK) return res;
		if (dp->dir[XDIR_Type] != ET_FILENAME) return FR_INT_ERR;	/* Invalid order */
		if (i < MAXDIRB(FF_MAX_LFN)) memcpy(dirb + i, dp->dir, SZDIRE);
	} while ((i += SZDIRE) < sz_ent);

	/* Sanity check (do it for only accessible object) */
	if (i <= MAXDIRB(FF_MAX_LFN)) {
		if (xdir_sum(dirb) != ld_word(dirb + XDIR_SetSum)) return FR_INT_ERR;
	}
	return FR_OK;
}


/*------------------------------------------------------------------*/
/* exFAT: Initialize object allocation info with loaded entry block */
/*------------------------------------------------------------------*/

static void init_alloc_info (
	FATFS* fs,		/* Filesystem object */
	FFOBJID* obj	/* Object allocation information to be initialized */
)
{
	obj->sclust = ld_dword(fs->dirbuf + XDIR_FstClus);		/* Start cluster */
	obj->objsize = ld_qword(fs->dirbuf + XDIR_FileSize);	/* Size */
	obj->stat = fs->dirbuf[XDIR_GenFlags] & 2;				/* Allocation status */
	obj->n_frag = 0;										/* No last fragment info */
}



#if !FF_FS_READONLY || FF_FS_RPATH != 0
/*------------------------------------------------*/
/* exFAT: Load the object's directory entry block */
/*------------------------------------------------*/

static FRESULT load_obj_xdir (
	DIR* dp,			/* Blank directory object to be used to access containing directory */
	const FFOBJID* obj	/* Object with its containing directory information */
)
{
	FRESULT res;

	/* Open object containing directory */
	dp->obj.fs = obj->fs;
	dp->obj.sclust = obj->c_scl;
	dp->obj.stat = (BYTE)obj->c_size;
	dp->obj.objsize = obj->c_size & 0xFFFFFF00;
	dp->obj.n_frag = 0;
	dp->blk_ofs = obj->c_ofs;

	res = dir_sdi(dp, dp->blk_ofs);	/* Goto object's entry block */
	if (res == FR_OK) {
		res = load_xdir(dp);		/* Load the object's entry block */
	}
	return res;
}
#endif


#if !FF_FS_READONLY
/*----------------------------------------*/
/* exFAT: Store the directory entry block */
/*----------------------------------------*/

static FRESULT store_xdir (
	DIR* dp				/* Pointer to the directory object */
)
{
	FRESULT res;
	UINT nent;
	BYTE *dirb = dp->obj.fs->dirbuf;	/* Pointer to the directory entry block 85+C0+C1s */

	/* Create set sum */
	st_word(dirb + XDIR_SetSum, xdir_sum(dirb));
	nent = dirb[XDIR_NumSec] + 1;

	/* Store the directory entry block to the directory */
	res = dir_sdi(dp, dp->blk_ofs);
	while (res == FR_OK) {
		res = move_window(dp->obj.fs, dp->sect);
		if (res != FR_OK) break;
		memcpy(dp->dir, dirb, SZDIRE);
		dp->obj.fs->wflag = 1;
		if (--nent == 0) break;
		dirb += SZDIRE;
		res = dir_next(dp, 0);
	}
	return (res == FR_OK || res == FR_DISK_ERR) ? res : FR_INT_ERR;
}



/*-------------------------------------------*/
/* exFAT: Create a new directory entry block */
/*-------------------------------------------*/

static void create_xdir (
	BYTE* dirb,			/* Pointer to the directory entry block buffer */
	const WCHAR* lfn	/* Pointer to the object name */
)
{
	UINT i;
	BYTE nc1, nlen;
	WCHAR wc;


	/* Create file-directory and stream-extension entry */
	memset(dirb, 0, 2 * SZDIRE);
	dirb[0 * SZDIRE + XDIR_Type] = ET_FILEDIR;
	dirb[1 * SZDIRE + XDIR_Type] = ET_STREAM;

	/* Create file-name entries */
	i = SZDIRE * 2;	/* Top of file_name entries */
	nlen = nc1 = 0; wc = 1;
	do {
		dirb[i++] = ET_FILENAME; dirb[i++] = 0;
		do {	/* Fill name field */
			if (wc != 0 && (wc = lfn[nlen]) != 0) nlen++;	/* Get a character if exist */
			st_word(dirb + i, wc); 	/* Store it */
			i += 2;
		} while (i % SZDIRE != 0);
		nc1++;
	} while (lfn[nlen]);	/* Fill next entry if any char follows */

	dirb[XDIR_NumName] = nlen;		/* Set name length */
	dirb[XDIR_NumSec] = 1 + nc1;	/* Set secondary count (C0 + C1s) */
	st_word(dirb + XDIR_NameHash, xname_sum(lfn));	/* Set name hash */
}

#endif	/* !FF_FS_READONLY */
#endif	/* FF_FS_EXFAT */



#if FF_FS_MINIMIZE <= 1 || FF_FS_RPATH >= 2 || FF_USE_LABEL || FF_FS_EXFAT
/*-----------------------------------------------------------------------*/
/* Read an object from the directory                                     */
/*-----------------------------------------------------------------------*/

#define DIR_READ_FILE(dp) dir_read(dp, 0)
#define DIR_READ_LABEL(dp) dir_read(dp, 1)

static FRESULT dir_read (
	DIR* dp,		/* Pointer to the directory object */
	int vol			/* Filtered by 0:file/directory or 1:volume label */
)
{
	FRESULT res = FR_NO_FILE;
	FATFS *fs = dp->obj.fs;
	BYTE attr, b;
#if FF_USE_LFN
	BYTE ord = 0xFF, sum = 0xFF;
#endif

	while (dp->sect) {
		res = move_window(fs, dp->sect);
		if (res != FR_OK) break;
		b = dp->dir[DIR_Name];	/* Test for the entry type */
		if (b == 0) {
			res = FR_NO_FILE; break; /* Reached to end of the directory */
		}
#if FF_FS_EXFAT
		if (fs->fs_type == FS_EXFAT) {	/* On the exFAT volume */
			if (FF_USE_LABEL && vol) {
				if (b == ET_VLABEL) break;	/* Volume label entry? */
			} else {
				if (b == ET_FILEDIR) {		/* Start of the file entry block? */
					dp->blk_ofs = dp->dptr;	/* Get location of the block */
					res = load_xdir(dp);	/* Load the entry block */
					if (res == FR_OK) {
						dp->obj.attr = fs->dirbuf[XDIR_Attr] & AM_MASK;	/* Get attribute */
					}
					break;
				}
			}
		} else
#endif
		{	/* On the FAT/FAT32 volume */
			dp->obj.attr = attr = dp->dir[DIR_Attr] & AM_MASK;	/* Get attribute */
#if FF_USE_LFN		/* LFN configuration */
			if (b == DDEM || b == '.' || (int)((attr & ~AM_ARC) == AM_VOL) != vol) {	/* An entry without valid data */
				ord = 0xFF;
			} else {
				if (attr == AM_LFN) {	/* An LFN entry is found */
					if (b & LLEF) {		/* Is it start of an LFN sequence? */
						sum = dp->dir[LDIR_Chksum];
						b &= (BYTE)~LLEF; ord = b;
						dp->blk_ofs = dp->dptr;
					}
					/* Check LFN validity and capture it */
					ord = (b == ord && sum == dp->dir[LDIR_Chksum] && pick_lfn(fs->lfnbuf, dp->dir)) ? ord - 1 : 0xFF;
				} else {				/* An SFN entry is found */
					if (ord != 0 || sum != sum_sfn(dp->dir)) {	/* Is there a valid LFN? */
						dp->blk_ofs = 0xFFFFFFFF;	/* It has no LFN. */
					}
					break;
				}
			}
#else		/* Non LFN configuration */
			if (b != DDEM && b != '.' && attr != AM_LFN && (int)((attr & ~AM_ARC) == AM_VOL) == vol) {	/* Is it a valid entry? */
				break;
			}
#endif
		}
		res = dir_next(dp, 0);		/* Next entry */
		if (res != FR_OK) break;
	}

	if (res != FR_OK) dp->sect = 0;		/* Terminate the read operation on error or EOT */
	return res;
}

#endif	/* FF_FS_MINIMIZE <= 1 || FF_USE_LABEL || FF_FS_RPATH >= 2 */



/*-----------------------------------------------------------------------*/
/* Directory handling - Find an object in the directory                  */
/*-----------------------------------------------------------------------*/

static FRESULT dir_find (	/* FR_OK(0):succeeded, !=0:error */
	DIR* dp					/* Pointer to the directory object with the file name */
)
{
	FRESULT res;
	FATFS *fs = dp->obj.fs;
	BYTE c;
#if FF_USE_LFN
	BYTE a, ord, sum;
#endif

	res = dir_sdi(dp, 0);			/* Rewind directory object */
	if (res != FR_OK) return res;
#if FF_FS_EXFAT
	if (fs->fs_type == FS_EXFAT) {	/* On the exFAT volume */
		BYTE nc;
		UINT di, ni;
		WORD hash = xname_sum(fs->lfnbuf);		/* Hash value of the name to find */

		while ((res = DIR_READ_FILE(dp)) == FR_OK) {	/* Read an item */
#if FF_MAX_LFN < 255
			if (fs->dirbuf[XDIR_NumName] > FF_MAX_LFN) continue;		/* Skip comparison if inaccessible object name */
#endif
			if (ld_word(fs->dirbuf + XDIR_NameHash) != hash) continue;	/* Skip comparison if hash mismatched */
			for (nc = fs->dirbuf[XDIR_NumName], di = SZDIRE * 2, ni = 0; nc; nc--, di += 2, ni++) {	/* Compare the name */
				if ((di % SZDIRE) == 0) di += 2;
				if (ff_wtoupper(ld_word(fs->dirbuf + di)) != ff_wtoupper(fs->lfnbuf[ni])) break;
			}
			if (nc == 0 && !fs->lfnbuf[ni]) break;	/* Name matched? */
		}
		return res;
	}
#endif
	/* On the FAT/FAT32 volume */
#if FF_USE_LFN
	ord = sum = 0xFF; dp->blk_ofs = 0xFFFFFFFF;	/* Reset LFN sequence */
#endif
	do {
		res = move_window(fs, dp->sect);
		if (res != FR_OK) break;
		c = dp->dir[DIR_Name];
		if (c == 0) { res = FR_NO_FILE; break; }	/* Reached to end of table */
#if FF_USE_LFN		/* LFN configuration */
		dp->obj.attr = a = dp->dir[DIR_Attr] & AM_MASK;
		if (c == DDEM || ((a & AM_VOL) && a != AM_LFN)) {	/* An entry without valid data */
			ord = 0xFF; dp->blk_ofs = 0xFFFFFFFF;	/* Reset LFN sequence */
		} else {
			if (a == AM_LFN) {			/* An LFN entry is found */
				if (!(dp->fn[NSFLAG] & NS_NOLFN)) {
					if (c & LLEF) {		/* Is it start of LFN sequence? */
						sum = dp->dir[LDIR_Chksum];
						c &= (BYTE)~LLEF; ord = c;	/* LFN start order */
						dp->blk_ofs = dp->dptr;	/* Start offset of LFN */
					}
					/* Check validity of the LFN entry and compare it with given name */
					ord = (c == ord && sum == dp->dir[LDIR_Chksum] && cmp_lfn(fs->lfnbuf, dp->dir)) ? ord - 1 : 0xFF;
				}
			} else {					/* An SFN entry is found */
				if (ord == 0 && sum == sum_sfn(dp->dir)) break;	/* LFN matched? */
				if (!(dp->fn[NSFLAG] & NS_LOSS) && !memcmp(dp->dir, dp->fn, 11)) break;	/* SFN matched? */
				ord = 0xFF; dp->blk_ofs = 0xFFFFFFFF;	/* Reset LFN sequence */
			}
		}
#else		/* Non LFN configuration */
		dp->obj.attr = dp->dir[DIR_Attr] & AM_MASK;
		if (!(dp->dir[DIR_Attr] & AM_VOL) && !memcmp(dp->dir, dp->fn, 11)) break;	/* Is it a valid entry? */
#endif
		res = dir_next(dp, 0);	/* Next entry */
	} while (res == FR_OK);

	return res;
}




#if !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* Register an object to the directory                                   */
/*-----------------------------------------------------------------------*/

static FRESULT dir_register (	/* FR_OK:succeeded, FR_DENIED:no free entry or too many SFN collision, FR_DISK_ERR:disk error */
	DIR* dp						/* Target directory with object name to be created */
)
{
	FRESULT res;
	FATFS *fs = dp->obj.fs;
#if FF_USE_LFN		/* LFN configuration */
	UINT n, len, n_ent;
	BYTE sn[12], sum;


	if (dp->fn[NSFLAG] & (NS_DOT | NS_NONAME)) return FR_INVALID_NAME;	/* Check name validity */
	for (len = 0; fs->lfnbuf[len]; len++) ;	/* Get lfn length */

#if FF_FS_EXFAT
	if (fs->fs_type == FS_EXFAT) {	/* On the exFAT volume */
		n_ent = (len + 14) / 15 + 2;	/* Number of entries to allocate (85+C0+C1s) */
		res = dir_alloc(dp, n_ent);		/* Allocate directory entries */
		if (res != FR_OK) return res;
		dp->blk_ofs = dp->dptr - SZDIRE * (n_ent - 1);	/* Set the allocated entry block offset */

		if (dp->obj.stat & 4) {			/* Has the directory been stretched by new allocation? */
			dp->obj.stat &= ~4;
			res = fill_first_frag(&dp->obj);	/* Fill the first fragment on the FAT if needed */
			if (res != FR_OK) return res;
			res = fill_last_frag(&dp->obj, dp->clust, 0xFFFFFFFF);	/* Fill the last fragment on the FAT if needed */
			if (res != FR_OK) return res;
			if (dp->obj.sclust != 0) {		/* Is it a sub-directory? */
				DIR dj;

				res = load_obj_xdir(&dj, &dp->obj);	/* Load the object status */
				if (res != FR_OK) return res;
				dp->obj.objsize += (DWORD)fs->csize * SS(fs);		/* Increase the directory size by cluster size */
				st_qword(fs->dirbuf + XDIR_FileSize, dp->obj.objsize);
				st_qword(fs->dirbuf + XDIR_ValidFileSize, dp->obj.objsize);
				fs->dirbuf[XDIR_GenFlags] = dp->obj.stat | 1;		/* Update the allocation status */
				res = store_xdir(&dj);				/* Store the object status */
				if (res != FR_OK) return res;
			}
		}

		create_xdir(fs->dirbuf, fs->lfnbuf);	/* Create on-memory directory block to be written later */
		return FR_OK;
	}
#endif
	/* On the FAT/FAT32 volume */
	memcpy(sn, dp->fn, 12);
	if (sn[NSFLAG] & NS_LOSS) {			/* When LFN is out of 8.3 format, generate a numbered name */
		dp->fn[NSFLAG] = NS_NOLFN;		/* Find only SFN */
		for (n = 1; n < 100; n++) {
			gen_numname(dp->fn, sn, fs->lfnbuf, n);	/* Generate a numbered name */
			res = dir_find(dp);				/* Check if the name collides with existing SFN */
			if (res != FR_OK) break;
		}
		if (n == 100) return FR_DENIED;		/* Abort if too many collisions */
		if (res != FR_NO_FILE) return res;	/* Abort if the result is other than 'not collided' */
		dp->fn[NSFLAG] = sn[NSFLAG];
	}

	/* Create an SFN with/without LFNs. */
	n_ent = (sn[NSFLAG] & NS_LFN) ? (len + 12) / 13 + 1 : 1;	/* Number of entries to allocate */
	res = dir_alloc(dp, n_ent);		/* Allocate entries */
	if (res == FR_OK && --n_ent) {	/* Set LFN entry if needed */
		res = dir_sdi(dp, dp->dptr - n_ent * SZDIRE);
		if (res == FR_OK) {
			sum = sum_sfn(dp->fn);	/* Checksum value of the SFN tied to the LFN */
			do {					/* Store LFN entries in bottom first */
				res = move_window(fs, dp->sect);
				if (res != FR_OK) break;
				put_lfn(fs->lfnbuf, dp->dir, (BYTE)n_ent, sum);
				fs->wflag = 1;
				res = dir_next(dp, 0);	/* Next entry */
			} while (res == FR_OK && --n_ent);
		}
	}

#else	/* Non LFN configuration */
	res = dir_alloc(dp, 1);		/* Allocate an entry for SFN */

#endif

	/* Set SFN entry */
	if (res == FR_OK) {
		res = move_window(fs, dp->sect);
		if (res == FR_OK) {
			memset(dp->dir, 0, SZDIRE);	/* Clean the entry */
			memcpy(dp->dir + DIR_Name, dp->fn, 11);	/* Put SFN */
#if FF_USE_LFN
			dp->dir[DIR_NTres] = dp->fn[NSFLAG] & (NS_BODY | NS_EXT);	/* Put NT flag */
#endif
			fs->wflag = 1;
		}
	}

	return res;
}

#endif /* !FF_FS_READONLY */



#if !FF_FS_READONLY && FF_FS_MINIMIZE == 0
/*-----------------------------------------------------------------------*/
/* Remove an object from the directory                                   */
/*-----------------------------------------------------------------------*/

static FRESULT dir_remove (	/* FR_OK:Succeeded, FR_DISK_ERR:A disk error */
	DIR* dp					/* Directory object pointing the entry to be removed */
)
{
	FRESULT res;
	FATFS *fs = dp->obj.fs;
#if FF_USE_LFN		/* LFN configuration */
	DWORD last = dp->dptr;

	res = (dp->blk_ofs == 0xFFFFFFFF) ? FR_OK : dir_sdi(dp, dp->blk_ofs);	/* Goto top of the entry block if LFN is exist */
	if (res == FR_OK) {
		do {
			res = move_window(fs, dp->sect);
			if (res != FR_OK) break;
			if (FF_FS_EXFAT && fs->fs_type == FS_EXFAT) {	/* On the exFAT volume */
				dp->dir[XDIR_Type] &= 0x7F;	/* Clear the entry InUse flag. */
			} else {										/* On the FAT/FAT32 volume */
				dp->dir[DIR_Name] = DDEM;	/* Mark the entry 'deleted'. */
			}
			fs->wflag = 1;
			if (dp->dptr >= last) break;	/* If reached last entry then all entries of the object has been deleted. */
			res = dir_next(dp, 0);	/* Next entry */
		} while (res == FR_OK);
		if (res == FR_NO_FILE) res = FR_INT_ERR;
	}
#else			/* Non LFN configuration */

	res = move_window(fs, dp->sect);
	if (res == FR_OK) {
		dp->dir[DIR_Name] = DDEM;	/* Mark the entry 'deleted'.*/
		fs->wflag = 1;
	}
#endif

	return res;
}

#endif /* !FF_FS_READONLY && FF_FS_MINIMIZE == 0 */



#if FF_FS_MINIMIZE <= 1 || FF_FS_RPATH >= 2
/*-----------------------------------------------------------------------*/
/* Get file information from directory entry                             */
/*-----------------------------------------------------------------------*/

static void get_fileinfo (
	DIR* dp,			/* Pointer to the directory object */
	FILINFO* fno		/* Pointer to the file information to be filled */
)
{
	UINT si, di;
#if FF_USE_LFN
	BYTE lcf;
	WCHAR wc, hs;
	FATFS *fs = dp->obj.fs;
	UINT nw;
#else
	TCHAR c;
#endif


	fno->fname[0] = 0;			/* Invaidate file info */
	if (dp->sect == 0) return;	/* Exit if read pointer has reached end of directory */

#if FF_USE_LFN		/* LFN configuration */
#if FF_FS_EXFAT
	if (fs->fs_type == FS_EXFAT) {	/* exFAT volume */
		UINT nc = 0;

		si = SZDIRE * 2; di = 0;	/* 1st C1 entry in the entry block */
		hs = 0;
		while (nc < fs->dirbuf[XDIR_NumName]) {
			if (si >= MAXDIRB(FF_MAX_LFN)) {	/* Truncated directory block? */
				di = 0; break;
			}
			if ((si % SZDIRE) == 0) si += 2;	/* Skip entry type field */
			wc = ld_word(fs->dirbuf + si); si += 2; nc++;	/* Get a character */
			if (hs == 0 && IsSurrogate(wc)) {	/* Is it a surrogate? */
				hs = wc; continue;				/* Get low surrogate */
			}
			nw = put_utf((DWORD)hs << 16 | wc, &fno->fname[di], FF_LFN_BUF - di);	/* Store it in API encoding */
			if (nw == 0) {						/* Buffer overflow or wrong char? */
				di = 0; break;
			}
			di += nw;
			hs = 0;
		}
		if (hs != 0) di = 0;					/* Broken surrogate pair? */
		if (di == 0) fno->fname[di++] = '\?';	/* Inaccessible object name? */
		fno->fname[di] = 0;						/* Terminate the name */
		fno->altname[0] = 0;					/* exFAT does not support SFN */

		fno->fattrib = fs->dirbuf[XDIR_Attr] & AM_MASKX;		/* Attribute */
		fno->fsize = (fno->fattrib & AM_DIR) ? 0 : ld_qword(fs->dirbuf + XDIR_FileSize);	/* Size */
		fno->ftime = ld_word(fs->dirbuf + XDIR_ModTime + 0);	/* Time */
		fno->fdate = ld_word(fs->dirbuf + XDIR_ModTime + 2);	/* Date */
		return;
	} else
#endif
	{	/* FAT/FAT32 volume */
		if (dp->blk_ofs != 0xFFFFFFFF) {	/* Get LFN if available */
			si = di = 0;
			hs = 0;
			while (fs->lfnbuf[si] != 0) {
				wc = fs->lfnbuf[si++];		/* Get an LFN character (UTF-16) */
				if (hs == 0 && IsSurrogate(wc)) {	/* Is it a surrogate? */
					hs = wc; continue;		/* Get low surrogate */
				}
				nw = put_utf((DWORD)hs << 16 | wc, &fno->fname[di], FF_LFN_BUF - di);	/* Store it in API encoding */
				if (nw == 0) {				/* Buffer overflow or wrong char? */
					di = 0; break;
				}
				di += nw;
				hs = 0;
			}
			if (hs != 0) di = 0;	/* Broken surrogate pair? */
			fno->fname[di] = 0;		/* Terminate the LFN (null string means LFN is invalid) */
		}
	}

	si = di = 0;
	while (si < 11) {		/* Get SFN from SFN entry */
		wc = dp->dir[si++];			/* Get a char */
		if (wc == ' ') continue;	/* Skip padding spaces */
		if (wc == RDDEM) wc = DDEM;	/* Restore replaced DDEM character */
		if (si == 9 && di < FF_SFN_BUF) fno->altname[di++] = '.';	/* Insert a . if extension is exist */
#if FF_LFN_UNICODE >= 1	/* Unicode output */
		if (dbc_1st((BYTE)wc) && si != 8 && si != 11 && dbc_2nd(dp->dir[si])) {	/* Make a DBC if needed */
			wc = wc << 8 | dp->dir[si++];
		}
		wc = ff_oem2uni(wc, CODEPAGE);		/* ANSI/OEM -> Unicode */
		if (wc == 0) {				/* Wrong char in the current code page? */
			di = 0; break;
		}
		nw = put_utf(wc, &fno->altname[di], FF_SFN_BUF - di);	/* Store it in API encoding */
		if (nw == 0) {				/* Buffer overflow? */
			di = 0; break;
		}
		di += nw;
#else					/* ANSI/OEM output */
		fno->altname[di++] = (TCHAR)wc;	/* Store it without any conversion */
#endif
	}
	fno->altname[di] = 0;	/* Terminate the SFN  (null string means SFN is invalid) */

	if (fno->fname[0] == 0) {	/* If LFN is invalid, altname[] needs to be copied to fname[] */
		if (di == 0) {	/* If LFN and SFN both are invalid, this object is inaccessible */
			fno->fname[di++] = '\?';
		} else {
			for (si = di = 0, lcf = NS_BODY; fno->altname[si]; si++, di++) {	/* Copy altname[] to fname[] with case information */
				wc = (WCHAR)fno->altname[si];
				if (wc == '.') lcf = NS_EXT;
				if (IsUpper(wc) && (dp->dir[DIR_NTres] & lcf)) wc += 0x20;
				fno->fname[di] = (TCHAR)wc;
			}
		}
		fno->fname[di] = 0;	/* Terminate the LFN */
		if (!dp->dir[DIR_NTres]) fno->altname[0] = 0;	/* Altname is not needed if neither LFN nor case info is exist. */
	}

#else	/* Non-LFN configuration */
	si = di = 0;
	while (si < 11) {		/* Copy name body and extension */
		c = (TCHAR)dp->dir[si++];
		if (c == ' ') continue;		/* Skip padding spaces */
		if (c == RDDEM) c = DDEM;	/* Restore replaced DDEM character */
		if (si == 9) fno->fname[di++] = '.';/* Insert a . if extension is exist */
		fno->fname[di++] = c;
	}
	fno->fname[di] = 0;		/* Terminate the SFN */
#endif

	fno->fattrib = dp->dir[DIR_Attr] & AM_MASK;			/* Attribute */
	fno->fsize = ld_dword(dp->dir + DIR_FileSize);		/* Size */
	fno->ftime = ld_word(dp->dir + DIR_ModTime + 0);	/* Time */
	fno->fdate = ld_word(dp->dir + DIR_ModTime + 2);	/* Date */
}

#endif /* FF_FS_MINIMIZE <= 1 || FF_FS_RPATH >= 2 */



#if FF_USE_FIND && FF_FS_MINIMIZE <= 1
/*-----------------------------------------------------------------------*/
/* Pattern matching                                                      */
/*-----------------------------------------------------------------------*/

#define FIND_RECURS	4	/* Maximum number of wildcard terms in the pattern to limit recursion */


static DWORD get_achar (	/* Get a character and advance ptr */
	const TCHAR** ptr		/* Pointer to pointer to the ANSI/OEM or Unicode string */
)
{
	DWORD chr;


#if FF_USE_LFN && FF_LFN_UNICODE >= 1	/* Unicode input */
	chr = tchar2uni(ptr);
	if (chr == 0xFFFFFFFF) chr = 0;		/* Wrong UTF encoding is recognized as end of the string */
	chr = ff_wtoupper(chr);

#else									/* ANSI/OEM input */
	chr = (BYTE)*(*ptr)++;				/* Get a byte */
	if (IsLower(chr)) chr -= 0x20;		/* To upper ASCII char */
#if FF_CODE_PAGE == 0
	if (ExCvt && chr >= 0x80) chr = ExCvt[chr - 0x80];	/* To upper SBCS extended char */
#elif FF_CODE_PAGE < 900
	if (chr >= 0x80) chr = ExCvt[chr - 0x80];	/* To upper SBCS extended char */
#endif
#if FF_CODE_PAGE == 0 || FF_CODE_PAGE >= 900
	if (dbc_1st((BYTE)chr)) {	/* Get DBC 2nd byte if needed */
		chr = dbc_2nd((BYTE)**ptr) ? chr << 8 | (BYTE)*(*ptr)++ : 0;
	}
#endif

#endif
	return chr;
}


static int pattern_match (	/* 0:mismatched, 1:matched */
	const TCHAR* pat,	/* Matching pattern */
	const TCHAR* nam,	/* String to be tested */
	UINT skip,			/* Number of pre-skip chars (number of ?s, b8:infinite (* specified)) */
	UINT recur			/* Recursion count */
)
{
	const TCHAR *pptr;
	const TCHAR *nptr;
	DWORD pchr, nchr;
	UINT sk;


	while ((skip & 0xFF) != 0) {		/* Pre-skip name chars */
		if (!get_achar(&nam)) return 0;	/* Branch mismatched if less name chars */
		skip--;
	}
	if (*pat == 0 && skip) return 1;	/* Matched? (short circuit) */

	do {
		pptr = pat; nptr = nam;			/* Top of pattern and name to match */
		for (;;) {
			if (*pptr == '\?' || *pptr == '*') {	/* Wildcard term? */
				if (recur == 0) return 0;	/* Too many wildcard terms? */
				sk = 0;
				do {	/* Analyze the wildcard term */
					if (*pptr++ == '\?') {
						sk++;
					} else {
						sk |= 0x100;
					}
				} while (*pptr == '\?' || *pptr == '*');
				if (pattern_match(pptr, nptr, sk, recur - 1)) return 1;	/* Test new branch (recursive call) */
				nchr = *nptr; break;	/* Branch mismatched */
			}
			pchr = get_achar(&pptr);	/* Get a pattern char */
			nchr = get_achar(&nptr);	/* Get a name char */
			if (pchr != nchr) break;	/* Branch mismatched? */
			if (pchr == 0) return 1;	/* Branch matched? (matched at end of both strings) */
		}
		get_achar(&nam);			/* nam++ */
	} while (skip && nchr);		/* Retry until end of name if infinite search is specified */

	return 0;
}

#endif /* FF_USE_FIND && FF_FS_MINIMIZE <= 1 */



/*-----------------------------------------------------------------------*/
/* Pick a top segment and create the object name in directory form       */
/*-----------------------------------------------------------------------*/

static FRESULT create_name (	/* FR_OK: successful, FR_INVALID_NAME: could not create */
	DIR* dp,					/* Pointer to the directory object */
	const TCHAR** path			/* Pointer to pointer to the segment in the path string */
)
{
#if FF_USE_LFN		/* LFN configuration */
	BYTE b, cf;
	WCHAR wc;
	WCHAR *lfn;
	const TCHAR* p;
	DWORD uc;
	UINT i, ni, si, di;


	/* Create LFN into LFN working buffer */
	p = *path; lfn = dp->obj.fs->lfnbuf; di = 0;
	for (;;) {
		uc = tchar2uni(&p);			/* Get a character */
		if (uc == 0xFFFFFFFF) return FR_INVALID_NAME;		/* Invalid code or UTF decode error */
		if (uc >= 0x10000) lfn[di++] = (WCHAR)(uc >> 16);	/* Store high surrogate if needed */
		wc = (WCHAR)uc;
		if (wc < ' ' || IsSeparator(wc)) break;	/* Break if end of the path or a separator is found */
		if (wc < 0x80 && strchr("*:<>|\"\?\x7F", (int)wc)) return FR_INVALID_NAME;	/* Reject illegal characters for LFN */
		if (di >= FF_MAX_LFN) return FR_INVALID_NAME;	/* Reject too long name */
		lfn[di++] = wc;				/* Store the Unicode character */
	}
	if (wc < ' ') {				/* Stopped at end of the path? */
		cf = NS_LAST;			/* Last segment */
	} else {					/* Stopped at a separator */
		while (IsSeparator(*p)) p++;	/* Skip duplicated separators if exist */
		cf = 0;					/* Next segment may follow */
		if (IsTerminator(*p)) cf = NS_LAST;	/* Ignore terminating separator */
	}
	*path = p;					/* Return pointer to the next segment */

#if FF_FS_RPATH != 0
	if ((di == 1 && lfn[di - 1] == '.') ||
		(di == 2 && lfn[di - 1] == '.' && lfn[di - 2] == '.')) {	/* Is this segment a dot name? */
		lfn[di] = 0;
		for (i = 0; i < 11; i++) {	/* Create dot name for SFN entry */
			dp->fn[i] = (i < di) ? '.' : ' ';
		}
		dp->fn[i] = cf | NS_DOT;	/* This is a dot entry */
		return FR_OK;
	}
#endif
	while (di) {					/* Snip off trailing spaces and dots if exist */
		wc = lfn[di - 1];
		if (wc != ' ' && wc != '.') break;
		di--;
	}
	lfn[di] = 0;							/* LFN is created into the working buffer */
	if (di == 0) return FR_INVALID_NAME;	/* Reject null name */

	/* Create SFN in directory form */
	for (si = 0; lfn[si] == ' '; si++) ;	/* Remove leading spaces */
	if (si > 0 || lfn[si] == '.') cf |= NS_LOSS | NS_LFN;	/* Is there any leading space or dot? */
	while (di > 0 && lfn[di - 1] != '.') di--;	/* Find last dot (di<=si: no extension) */

	memset(dp->fn, ' ', 11);
	i = b = 0; ni = 8;
	for (;;) {
		wc = lfn[si++];					/* Get an LFN character */
		if (wc == 0) break;				/* Break on end of the LFN */
		if (wc == ' ' || (wc == '.' && si != di)) {	/* Remove embedded spaces and dots */
			cf |= NS_LOSS | NS_LFN;
			continue;
		}

		if (i >= ni || si == di) {		/* End of field? */
			if (ni == 11) {				/* Name extension overflow? */
				cf |= NS_LOSS | NS_LFN;
				break;
			}
			if (si != di) cf |= NS_LOSS | NS_LFN;	/* Name body overflow? */
			if (si > di) break;						/* No name extension? */
			si = di; i = 8; ni = 11; b <<= 2;		/* Enter name extension */
			continue;
		}

		if (wc >= 0x80) {	/* Is this an extended character? */
			cf |= NS_LFN;	/* LFN entry needs to be created */
#if FF_CODE_PAGE == 0
			if (ExCvt) {	/* In SBCS cfg */
				wc = ff_uni2oem(wc, CODEPAGE);			/* Unicode ==> ANSI/OEM code */
				if (wc & 0x80) wc = ExCvt[wc & 0x7F];	/* Convert extended character to upper (SBCS) */
			} else {		/* In DBCS cfg */
				wc = ff_uni2oem(ff_wtoupper(wc), CODEPAGE);	/* Unicode ==> Up-convert ==> ANSI/OEM code */
			}
#elif FF_CODE_PAGE < 900	/* In SBCS cfg */
			wc = ff_uni2oem(wc, CODEPAGE);			/* Unicode ==> ANSI/OEM code */
			if (wc & 0x80) wc = ExCvt[wc & 0x7F];	/* Convert extended character to upper (SBCS) */
#else						/* In DBCS cfg */
			wc = ff_uni2oem(ff_wtoupper(wc), CODEPAGE);	/* Unicode ==> Up-convert ==> ANSI/OEM code */
#endif
		}

		if (wc >= 0x100) {				/* Is this a DBC? */
			if (i >= ni - 1) {			/* Field overflow? */
				cf |= NS_LOSS | NS_LFN;
				i = ni; continue;		/* Next field */
			}
			dp->fn[i++] = (BYTE)(wc >> 8);	/* Put 1st byte */
		} else {						/* SBC */
			if (wc == 0 || strchr("+,;=[]", (int)wc)) {	/* Replace illegal characters for SFN */
				wc = '_'; cf |= NS_LOSS | NS_LFN;/* Lossy conversion */
			} else {
				if (IsUpper(wc)) {		/* ASCII upper case? */
					b |= 2;
				}
				if (IsLower(wc)) {		/* ASCII lower case? */
					b |= 1; wc -= 0x20;
				}
			}
		}
		dp->fn[i++] = (BYTE)wc;
	}

	if (dp->fn[0] == DDEM) dp->fn[0] = RDDEM;	/* If the first character collides with DDEM, replace it with RDDEM */

	if (ni == 8) b <<= 2;				/* Shift capital flags if no extension */
	if ((b & 0x0C) == 0x0C || (b & 0x03) == 0x03) cf |= NS_LFN;	/* LFN entry needs to be created if composite capitals */
	if (!(cf & NS_LFN)) {				/* When LFN is in 8.3 format without extended character, NT flags are created */
		if (b & 0x01) cf |= NS_EXT;		/* NT flag (Extension has small capital letters only) */
		if (b & 0x04) cf |= NS_BODY;	/* NT flag (Body has small capital letters only) */
	}

	dp->fn[NSFLAG] = cf;	/* SFN is created into dp->fn[] */

	return FR_OK;


#else	/* FF_USE_LFN : Non-LFN configuration */
	BYTE c, d;
	BYTE *sfn;
	UINT ni, si, i;
	const char *p;

	/* Create file name in directory form */
	p = *path; sfn = dp->fn;
	memset(sfn, ' ', 11);
	si = i = 0; ni = 8;
#if FF_FS_RPATH != 0
	if (p[si] == '.') { /* Is this a dot entry? */
		for (;;) {
			c = (BYTE)p[si++];
			if (c != '.' || si >= 3) break;
			sfn[i++] = c;
		}
		if (!IsSeparator(c) && c > ' ') return FR_INVALID_NAME;
		*path = p + si;					/* Return pointer to the next segment */
		sfn[NSFLAG] = (c <= ' ') ? NS_LAST | NS_DOT : NS_DOT;	/* Set last segment flag if end of the path */
		return FR_OK;
	}
#endif
	for (;;) {
		c = (BYTE)p[si++];				/* Get a byte */
		if (c <= ' ') break; 			/* Break if end of the path name */
		if (IsSeparator(c)) {			/* Break if a separator is found */
			while (IsSeparator(p[si])) si++;	/* Skip duplicated separator if exist */
			break;
		}
		if (c == '.' || i >= ni) {		/* End of body or field overflow? */
			if (ni == 11 || c != '.') return FR_INVALID_NAME;	/* Field overflow or invalid dot? */
			i = 8; ni = 11;				/* Enter file extension field */
			continue;
		}
#if FF_CODE_PAGE == 0
		if (ExCvt && c >= 0x80) {		/* Is SBC extended character? */
			c = ExCvt[c & 0x7F];		/* To upper SBC extended character */
		}
#elif FF_CODE_PAGE < 900
		if (c >= 0x80) {				/* Is SBC extended character? */
			c = ExCvt[c & 0x7F];		/* To upper SBC extended character */
		}
#endif
		if (dbc_1st(c)) {				/* Check if it is a DBC 1st byte */
			d = (BYTE)p[si++];			/* Get 2nd byte */
			if (!dbc_2nd(d) || i >= ni - 1) return FR_INVALID_NAME;	/* Reject invalid DBC */
			sfn[i++] = c;
			sfn[i++] = d;
		} else {						/* SBC */
			if (strchr("*+,:;<=>[]|\"\?\x7F", (int)c)) return FR_INVALID_NAME;	/* Reject illegal chrs for SFN */
			if (IsLower(c)) c -= 0x20;	/* To upper */
			sfn[i++] = c;
		}
	}
	*path = &p[si];						/* Return pointer to the next segment */
	if (i == 0) return FR_INVALID_NAME;	/* Reject nul string */

	if (sfn[0] == DDEM) sfn[0] = RDDEM;	/* If the first character collides with DDEM, replace it with RDDEM */
	sfn[NSFLAG] = (c <= ' ' || p[si] <= ' ') ? NS_LAST : 0;	/* Set last segment flag if end of the path */

	return FR_OK;
#endif /* FF_USE_LFN */
}




/*-----------------------------------------------------------------------*/
/* Follow a file path                                                    */
/*-----------------------------------------------------------------------*/

static FRESULT follow_path (	/* FR_OK(0): successful, !=0: error code */
	DIR* dp,					/* Directory object to return last directory and found object */
	const TCHAR* path			/* Full-path string to find a file or directory */
)
{
	FRESULT res;
	BYTE ns;
	FATFS *fs = dp->obj.fs;


#if FF_FS_RPATH != 0
	if (!IsSeparator(*path) && (FF_STR_VOLUME_ID != 2 || !IsTerminator(*path))) {	/* Without heading separator */
		dp->obj.sclust = fs->cdir;			/* Start at the current directory */
	} else
#endif
	{										/* With heading separator */
		while (IsSeparator(*path)) path++;	/* Strip separators */
		dp->obj.sclust = 0;					/* Start from the root directory */
	}
#if FF_FS_EXFAT
	dp->obj.n_frag = 0;	/* Invalidate last fragment counter of the object */
#if FF_FS_RPATH != 0
	if (fs->fs_type == FS_EXFAT && dp->obj.sclust) {	/* exFAT: Retrieve the sub-directory's status */
		DIR dj;

		dp->obj.c_scl = fs->cdc_scl;
		dp->obj.c_size = fs->cdc_size;
		dp->obj.c_ofs = fs->cdc_ofs;
		res = load_obj_xdir(&dj, &dp->obj);
		if (res != FR_OK) return res;
		dp->obj.objsize = ld_dword(fs->dirbuf + XDIR_FileSize);
		dp->obj.stat = fs->dirbuf[XDIR_GenFlags] & 2;
	}
#endif
#endif

	if ((UINT)*path < ' ') {				/* Null path name is the origin directory itself */
		dp->fn[NSFLAG] = NS_NONAME;
		res = dir_sdi(dp, 0);

	} else {								/* Follow path */
		for (;;) {
			res = create_name(dp, &path);	/* Get a segment name of the path */
			if (res != FR_OK) break;
			res = dir_find(dp);				/* Find an object with the segment name */
			ns = dp->fn[NSFLAG];
			if (res != FR_OK) {				/* Failed to find the object */
				if (res == FR_NO_FILE) {	/* Object is not found */
					if (FF_FS_RPATH && (ns & NS_DOT)) {	/* If dot entry is not exist, stay there */
						if (!(ns & NS_LAST)) continue;	/* Continue to follow if not last segment */
						dp->fn[NSFLAG] = NS_NONAME;
						res = FR_OK;
					} else {							/* Could not find the object */
						if (!(ns & NS_LAST)) res = FR_NO_PATH;	/* Adjust error code if not last segment */
					}
				}
				break;
			}
			if (ns & NS_LAST) break;		/* Last segment matched. Function completed. */
			/* Get into the sub-directory */
			if (!(dp->obj.attr & AM_DIR)) {	/* It is not a sub-directory and cannot follow */
				res = FR_NO_PATH; break;
			}
#if FF_FS_EXFAT
			if (fs->fs_type == FS_EXFAT) {	/* Save containing directory information for next dir */
				dp->obj.c_scl = dp->obj.sclust;
				dp->obj.c_size = ((DWORD)dp->obj.objsize & 0xFFFFFF00) | dp->obj.stat;
				dp->obj.c_ofs = dp->blk_ofs;
				init_alloc_info(fs, &dp->obj);	/* Open next directory */
			} else
#endif
			{
				dp->obj.sclust = ld_clust(fs, fs->win + dp->dptr % SS(fs));	/* Open next directory */
			}
		}
	}

	return res;
}




/*-----------------------------------------------------------------------*/
/* Get logical drive number from path name                               */
/*-----------------------------------------------------------------------*/

static int get_ldnumber (	/* Returns logical drive number (-1:invalid drive number or null pointer) */
	const TCHAR** path		/* Pointer to pointer to the path name */
)
{
	const TCHAR *tp;
	const TCHAR *tt;
	TCHAR tc;
	int i;
	int vol = -1;
#if FF_STR_VOLUME_ID		/* Find string volume ID */
	const char *sp;
	char c;
#endif
	tt = tp = *path;
	if (!tp) return vol;	/* Invalid path name? */
	do {					/* Find a colon in the path */
		tc = *tt++;
	} while (!IsTerminator(tc) && tc != ':');

	if (tc == ':') {	/* DOS/Windows style volume ID? */
		i = FF_VOLUMES;
		if (IsDigit(*tp) && tp + 2 == tt) {	/* Is there a numeric volume ID + colon? */
			i = (int)*tp - '0';	/* Get the LD number */
		}
#if FF_STR_VOLUME_ID == 1	/* Arbitrary string is enabled */
		else {
			i = 0;
			do {
				sp = VolumeStr[i]; tp = *path;	/* This string volume ID and path name */
				do {	/* Compare the volume ID with path name */
					c = *sp++; tc = *tp++;
					if (IsLower(c)) c -= 0x20;
					if (IsLower(tc)) tc -= 0x20;
				} while (c && (TCHAR)c == tc);
			} while ((c || tp != tt) && ++i < FF_VOLUMES);	/* Repeat for each id until pattern match */
		}
#endif
		if (i < FF_VOLUMES) {	/* If a volume ID is found, get the drive number and strip it */
			vol = i;		/* Drive number */
			*path = tt;		/* Snip the drive prefix off */
		}
		return vol;
	}
#if FF_STR_VOLUME_ID == 2		/* Unix style volume ID is enabled */
	if (*tp == '/') {			/* Is there a volume ID? */
		while (*(tp + 1) == '/') tp++;	/* Skip duplicated separator */
		i = 0;
		do {
			tt = tp; sp = VolumeStr[i]; /* Path name and this string volume ID */
			do {	/* Compare the volume ID with path name */
				c = *sp++; tc = *(++tt);
				if (IsLower(c)) c -= 0x20;
				if (IsLower(tc)) tc -= 0x20;
			} while (c && (TCHAR)c == tc);
		} while ((c || (tc != '/' && !IsTerminator(tc))) && ++i < FF_VOLUMES);	/* Repeat for each ID until pattern match */
		if (i < FF_VOLUMES) {	/* If a volume ID is found, get the drive number and strip it */
			vol = i;		/* Drive number */
			*path = tt;		/* Snip the drive prefix off */
		}
		return vol;
	}
#endif
	/* No drive prefix is found */
#if FF_FS_RPATH != 0
	vol = CurrVol;	/* Default drive is current drive */
#else
	vol = 0;		/* Default drive is 0 */
#endif
	return vol;		/* Return the default drive */
}




/*-----------------------------------------------------------------------*/
/* GPT support functions                                                 */
/*-----------------------------------------------------------------------*/

#if FF_LBA64

/* Calculate CRC32 in byte-by-byte */

static DWORD crc32 (	/* Returns next CRC value */
	DWORD crc,			/* Current CRC value */
	BYTE d				/* A byte to be processed */
)
{
	BYTE b;


	for (b = 1; b; b <<= 1) {
		crc ^= (d & b) ? 1 : 0;
		crc = (crc & 1) ? crc >> 1 ^ 0xEDB88320 : crc >> 1;
	}
	return crc;
}


/* Check validity of GPT header */

static int test_gpt_header (	/* 0:Invalid, 1:Valid */
	const BYTE* gpth			/* Pointer to the GPT header */
)
{
	UINT i;
	DWORD bcc, hlen;


	if (memcmp(gpth + GPTH_Sign, "EFI PART" "\0\0\1", 12)) return 0;	/* Check signature and version (1.0) */
	hlen = ld_dword(gpth + GPTH_Size);						/* Check header size */
	if (hlen < 92 || hlen > FF_MIN_SS) return 0;
	for (i = 0, bcc = 0xFFFFFFFF; i < hlen; i++) {			/* Check header BCC */
		bcc = crc32(bcc, i - GPTH_Bcc < 4 ? 0 : gpth[i]);
	}
	if (~bcc != ld_dword(gpth + GPTH_Bcc)) return 0;
	if (ld_dword(gpth + GPTH_PteSize) != SZ_GPTE) return 0;	/* Table entry size (must be SZ_GPTE bytes) */
	if (ld_dword(gpth + GPTH_PtNum) > 128) return 0;		/* Table size (must be 128 entries or less) */

	return 1;
}

//#if !FF_FS_READONLY && FF_USE_MKFS  //wfeng

/* Generate random value */
static DWORD make_rand (
	DWORD seed,		/* Seed value */
	BYTE *buff,		/* Output buffer */
	UINT n			/* Data length */
)
{
	UINT r;


	if (seed == 0) seed = 1;
	do {
		for (r = 0; r < 8; r++) seed = seed & 1 ? seed >> 1 ^ 0xA3000000 : seed >> 1;	/* Shift 8 bits the 32-bit LFSR */
		*buff++ = (BYTE)seed;
	} while (--n);
	return seed;
}

//#endif
#endif



/*-----------------------------------------------------------------------*/
/* Load a sector and check if it is an FAT VBR                           */
/*-----------------------------------------------------------------------*/

/* Check what the sector is */

static UINT check_fs (	/* 0:FAT/FAT32 VBR, 1:exFAT VBR, 2:Not FAT and valid BS, 3:Not FAT and invalid BS, 4:Disk error */
	FATFS* fs,			/* Filesystem object */
	LBA_t sect			/* Sector to load and check if it is an FAT-VBR or not */
)
{
	WORD w, sign;
	BYTE b;
	fs->wflag = 0; fs->winsect = (LBA_t)0 - 1;		/* Invaidate window */
	if (move_window(fs, sect) != FR_OK) return 4;	/* Load the boot sector */
	sign = ld_word(fs->win + BS_55AA);
#if FF_FS_EXFAT
			//xil_printf("wfeng: fun = %s, line = %d sign = 0x%x   %s\n", __func__, __LINE__,sign,fs->win + BS_JmpBoot);
	if (sign == 0xAA55 && !memcmp(fs->win + BS_JmpBoot, "\xEB\x76\x90" "EXFAT   ", 11)) return 1;	/* It is an exFAT VBR */
#endif
	b = fs->win[BS_JmpBoot];
	if (b == 0xEB || b == 0xE9 || b == 0xE8) {	/* Valid JumpBoot code? (short jump, near jump or near call) */
		if (sign == 0xAA55 && !memcmp(fs->win + BS_FilSysType32, "FAT32   ", 8)) {
			return 0;	/* It is an FAT32 VBR */
		}
		/* FAT volumes formatted with early MS-DOS lack BS_55AA and BS_FilSysType, so FAT VBR needs to be identified without them. */
		w = ld_word(fs->win + BPB_BytsPerSec);
		b = fs->win[BPB_SecPerClus];
		if ((w & (w - 1)) == 0 && w >= FF_MIN_SS && w <= FF_MAX_SS	/* Properness of sector size (512-4096 and 2^n) */
			&& b != 0 && (b & (b - 1)) == 0				/* Properness of cluster size (2^n) */
			&& ld_word(fs->win + BPB_RsvdSecCnt) != 0	/* Properness of reserved sectors (MNBZ) */
			&& (UINT)fs->win[BPB_NumFATs] - 1 <= 1		/* Properness of FATs (1 or 2) */
			&& ld_word(fs->win + BPB_RootEntCnt) != 0	/* Properness of root dir entries (MNBZ) */
			&& (ld_word(fs->win + BPB_TotSec16) >= 128 || ld_dword(fs->win + BPB_TotSec32) >= 0x10000)	/* Properness of volume sectors (>=128) */
			&& ld_word(fs->win + BPB_FATSz16) != 0) {	/* Properness of FAT size (MNBZ) */
				return 0;	/* It can be presumed an FAT VBR */
		}
	}
	//xil_printf("wfeng: fun = %s, line = %d sign = %x\n", __func__, __LINE__,sign == 0xAA55 ? 2 : 3);
	return sign == 0xAA55 ? 2 : 3;	/* Not an FAT VBR (valid or invalid BS) */
}


/* Find an FAT volume */
/* (It supports only generic partitioning rules, MBR, GPT and SFD) */

static UINT find_volume (	/* Returns BS status found in the hosting drive */
	FATFS* fs,		/* Filesystem object */
	UINT part		/* Partition to fined = 0:find as SFD and partitions, >0:forced partition number */
)
{
	UINT fmt, i;
	DWORD mbr_pt[4];
	fmt = check_fs(fs, 0);				/* Load sector 0 and check if it is an FAT VBR as SFD format */
	if (fmt != 2 && (fmt >= 3 || part == 0)) return fmt;	/* Returns if it is an FAT VBR as auto scan, not a BS or disk error */

	/* Sector 0 is not an FAT VBR or forced partition number wants a partition */

#if FF_LBA64
	if (fs->win[MBR_Table + PTE_System] == 0xEE) {	/* GPT protective MBR? */
		DWORD n_ent, v_ent, ofs;
		QWORD pt_lba;

		if (move_window(fs, 1) != FR_OK) return 4;	/* Load GPT header sector (next to MBR) */
		if (!test_gpt_header(fs->win)) return 3;	/* Check if GPT header is valid */
		n_ent = ld_dword(fs->win + GPTH_PtNum);		/* Number of entries */
		pt_lba = ld_qword(fs->win + GPTH_PtOfs);	/* Table location */
		for (v_ent = i = 0; i < n_ent; i++) {		/* Find FAT partition */
			if (move_window(fs, pt_lba + i * SZ_GPTE / SS(fs)) != FR_OK) return 4;	/* PT sector */
			ofs = i * SZ_GPTE % SS(fs);												/* Offset in the sector */
			if (!memcmp(fs->win + ofs + GPTE_PtGuid, GUID_MS_Basic, 16)) {	/* MS basic data partition? */
				v_ent++;
				fmt = check_fs(fs, ld_qword(fs->win + ofs + GPTE_FstLba));	/* Load VBR and check status */
				if (part == 0 && fmt <= 1) return fmt;			/* Auto search (valid FAT volume found first) */
				if (part != 0 && v_ent == part) return fmt;		/* Forced partition order (regardless of it is valid or not) */
			}
		}
		return 3;	/* Not found */
	}
#endif
	if (FF_MULTI_PARTITION && part > 4) return 3;	/* MBR has 4 partitions max */
	for (i = 0; i < 4; i++) {		/* Load partition offset in the MBR */
		mbr_pt[i] = ld_dword(fs->win + MBR_Table + i * SZ_PTE + PTE_StLba);
//		xil_printf("%s %d\r\n", __FUNCTION__, __LINE__);  // 9.21
	}
	i = part ? part - 1 : 0;		/* Table index to find first */
	do {							/* Find an FAT volume */
		fmt = mbr_pt[i] ? check_fs(fs, mbr_pt[i]) : 3;	/* Check if the partition is FAT */
	} while (part == 0 && fmt >= 2 && ++i < 4);
	return fmt;
}




/*-----------------------------------------------------------------------*/
/* Determine logical drive number and mount the volume if needed         */
/*-----------------------------------------------------------------------*/

static FRESULT mount_volume (	/* FR_OK(0): successful, !=0: an error occurred */
	const TCHAR** path,			/* Pointer to pointer to the path name (drive number) */
	FATFS** rfs,				/* Pointer to pointer to the found filesystem object */
	BYTE mode					/* Desiered access mode to check write protection */
)
{
	int vol;
	FATFS *fs;
	DSTATUS stat;
	LBA_t bsect;
	DWORD tsect, sysect, fasize, nclst, szbfat;
	WORD nrsv;
	UINT fmt;


	/* Get logical drive number */
	*rfs = 0;
	vol = get_ldnumber(path);
	if (vol < 0) return FR_INVALID_DRIVE;
//	xil_printf("wfeng: fun = %s, line = %d\n", __func__, __LINE__);
	/* Check if the filesystem object is valid or not */
	fs = FatFs[vol];					/* Get pointer to the filesystem object */
	if (!fs) return FR_NOT_ENABLED;		/* Is the filesystem object available? */
#if FF_FS_REENTRANT
	if (!lock_volume(fs, 1)) return FR_TIMEOUT;	/* Lock the volume, and system if needed */
#endif
	*rfs = fs;							/* Return pointer to the filesystem object */

	mode &= (BYTE)~FA_READ;				/* Desired access mode, write access or not */
	if (fs->fs_type != 0) {				/* If the volume has been mounted */
		stat = disk_status(fs->pdrv);
		if (!(stat & STA_NOINIT)) {		/* and the physical drive is kept initialized */
			if (!FF_FS_READONLY && mode && (stat & STA_PROTECT)) {	/* Check write protection if needed */
				return FR_WRITE_PROTECTED;
			}
			return FR_OK;				/* The filesystem object is already valid */
		}
	}

	/* The filesystem object is not valid. */
	/* Following code attempts to mount the volume. (find an FAT volume, analyze the BPB and initialize the filesystem object) */

	fs->fs_type = 0;					/* Invalidate the filesystem object */
	stat = disk_initialize(fs->pdrv);	/* Initialize the volume hosting physical drive */
	if (stat & STA_NOINIT) { 			/* Check if the initialization succeeded */
		return FR_NOT_READY;			/* Failed to initialize due to no medium or hard error */
	}
	if (!FF_FS_READONLY && mode && (stat & STA_PROTECT)) { /* Check disk write protection if needed */
		return FR_WRITE_PROTECTED;
	}
#if FF_MAX_SS != FF_MIN_SS				/* Get sector size (multiple sector size cfg only) */
	if (disk_ioctl(fs->pdrv, GET_SECTOR_SIZE, &SS(fs)) != RES_OK) return FR_DISK_ERR;
	if (SS(fs) > FF_MAX_SS || SS(fs) < FF_MIN_SS || (SS(fs) & (SS(fs) - 1))) return FR_DISK_ERR;
#endif
//	xil_printf("wfeng: fun = %s, line = %d\n", __func__, __LINE__);
	/* Find an FAT volume on the hosting drive */
	fmt = find_volume(fs, LD2PT(vol));
	if (fmt == 4) return FR_DISK_ERR;		/* An error occurred in the disk I/O layer */
	if (fmt >= 2) return FR_NO_FILESYSTEM;	/* No FAT volume is found */
	bsect = fs->winsect;					/* Volume offset in the hosting physical drive */
	/* An FAT volume is found (bsect). Following code initializes the filesystem object */

#if FF_FS_EXFAT
	if (fmt == 1) {
		QWORD maxlba;
		DWORD so, cv, bcl, i;
		Xil_L1DCacheFlush();
		for (i = BPB_ZeroedEx; i < BPB_ZeroedEx + 53 && fs->win[i] == 0; i++) ;	/* Check zero filler */
		if (i < BPB_ZeroedEx + 53) return FR_NO_FILESYSTEM;

		if (ld_word(fs->win + BPB_FSVerEx) != 0x100) return FR_NO_FILESYSTEM;	/* Check exFAT version (must be version 1.0) */

		if (1 << fs->win[BPB_BytsPerSecEx] != SS(fs)) {	/* (BPB_BytsPerSecEx must be equal to the physical sector size) */
			return FR_NO_FILESYSTEM;
		}

		maxlba = ld_qword(fs->win + BPB_TotSecEx) + bsect;	/* Last LBA of the volume + 1 */
		if (!FF_LBA64 && maxlba >= 0x100000000) return FR_NO_FILESYSTEM;	/* (It cannot be accessed in 32-bit LBA) */

		fs->fsize = ld_dword(fs->win + BPB_FatSzEx);	/* Number of sectors per FAT */
		fs->n_fats = fs->win[BPB_NumFATsEx];			/* Number of FATs */
		if (fs->n_fats != 1) return FR_NO_FILESYSTEM;	/* (Supports only 1 FAT) */
		fs->csize = 1 << fs->win[BPB_SecPerClusEx];		/* Cluster size */
		if (fs->csize == 0)	return FR_NO_FILESYSTEM;	/* (Must be 1..32768 sectors) */

		nclst = ld_dword(fs->win + BPB_NumClusEx);		/* Number of clusters */
		if (nclst > MAX_EXFAT) return FR_NO_FILESYSTEM;	/* (Too many clusters) */
		fs->n_fatent = nclst + 2;

		/* Boundaries and Limits */
		fs->volbase = bsect;
		fs->database = bsect + ld_dword(fs->win + BPB_DataOfsEx);
		fs->fatbase = bsect + ld_dword(fs->win + BPB_FatOfsEx);
		if (maxlba < (QWORD)fs->database + nclst * fs->csize) return FR_NO_FILESYSTEM;	/* (Volume size must not be smaller than the size required) */
		fs->dirbase = ld_dword(fs->win + BPB_RootClusEx);

		/* Get bitmap location and check if it is contiguous (implementation assumption) */
		so = i = 0;
		for (;;) {	/* Find the bitmap entry in the root directory (in only first cluster) */
			if (i == 0) {
				if (so >= fs->csize) return FR_NO_FILESYSTEM;	/* Not found? */
				if (move_window(fs, clst2sect(fs, (DWORD)fs->dirbase) + so) != FR_OK) return FR_DISK_ERR;
				so++;
			}
			if (fs->win[i] == ET_BITMAP) break;			/* Is it a bitmap entry? */
			i = (i + SZDIRE) % SS(fs);	/* Next entry */
		}
		bcl = ld_dword(fs->win + i + 20);				/* Bitmap cluster */
		if (bcl < 2 || bcl >= fs->n_fatent) return FR_NO_FILESYSTEM;	/* (Wrong cluster#) */
		fs->bitbase = fs->database + fs->csize * (bcl - 2);	/* Bitmap sector */
		for (;;) {	/* Check if bitmap is contiguous */
			if (move_window(fs, fs->fatbase + bcl / (SS(fs) / 4)) != FR_OK) return FR_DISK_ERR;
			cv = ld_dword(fs->win + bcl % (SS(fs) / 4) * 4);
			if (cv == 0xFFFFFFFF) break;				/* Last link? */
			if (cv != ++bcl) return FR_NO_FILESYSTEM;	/* Fragmented bitmap? */
		}

#if !FF_FS_READONLY
		fs->last_clst = fs->free_clst = 0xFFFFFFFF;		/* Initialize cluster allocation information */
#endif
		fmt = FS_EXFAT;			/* FAT sub-type */
	} else
#endif	/* FF_FS_EXFAT */
	{
		if (ld_word(fs->win + BPB_BytsPerSec) != SS(fs)) return FR_NO_FILESYSTEM;	/* (BPB_BytsPerSec must be equal to the physical sector size) */

		fasize = ld_word(fs->win + BPB_FATSz16);		/* Number of sectors per FAT */
		if (fasize == 0) fasize = ld_dword(fs->win + BPB_FATSz32);
		fs->fsize = fasize;

		fs->n_fats = fs->win[BPB_NumFATs];				/* Number of FATs */
		if (fs->n_fats != 1 && fs->n_fats != 2) return FR_NO_FILESYSTEM;	/* (Must be 1 or 2) */
		fasize *= fs->n_fats;							/* Number of sectors for FAT area */

		fs->csize = fs->win[BPB_SecPerClus];			/* Cluster size */
		if (fs->csize == 0 || (fs->csize & (fs->csize - 1))) return FR_NO_FILESYSTEM;	/* (Must be power of 2) */

		fs->n_rootdir = ld_word(fs->win + BPB_RootEntCnt);	/* Number of root directory entries */
		if (fs->n_rootdir % (SS(fs) / SZDIRE)) return FR_NO_FILESYSTEM;	/* (Must be sector aligned) */

		tsect = ld_word(fs->win + BPB_TotSec16);		/* Number of sectors on the volume */
		if (tsect == 0) tsect = ld_dword(fs->win + BPB_TotSec32);

		nrsv = ld_word(fs->win + BPB_RsvdSecCnt);		/* Number of reserved sectors */
		if (nrsv == 0) return FR_NO_FILESYSTEM;			/* (Must not be 0) */

		/* Determine the FAT sub type */
		sysect = nrsv + fasize + fs->n_rootdir / (SS(fs) / SZDIRE);	/* RSV + FAT + DIR */
		if (tsect < sysect) return FR_NO_FILESYSTEM;	/* (Invalid volume size) */
		nclst = (tsect - sysect) / fs->csize;			/* Number of clusters */
		if (nclst == 0) return FR_NO_FILESYSTEM;		/* (Invalid volume size) */
		fmt = 0;
		if (nclst <= MAX_FAT32) fmt = FS_FAT32;
		if (nclst <= MAX_FAT16) fmt = FS_FAT16;
		if (nclst <= MAX_FAT12) fmt = FS_FAT12;
		if (fmt == 0) return FR_NO_FILESYSTEM;

		/* Boundaries and Limits */
		fs->n_fatent = nclst + 2;						/* Number of FAT entries */
		fs->volbase = bsect;							/* Volume start sector */
		fs->fatbase = bsect + nrsv; 					/* FAT start sector */
		fs->database = bsect + sysect;					/* Data start sector */
		if (fmt == FS_FAT32) {
			if (ld_word(fs->win + BPB_FSVer32) != 0) return FR_NO_FILESYSTEM;	/* (Must be FAT32 revision 0.0) */
			if (fs->n_rootdir != 0) return FR_NO_FILESYSTEM;	/* (BPB_RootEntCnt must be 0) */
			fs->dirbase = ld_dword(fs->win + BPB_RootClus32);	/* Root directory start cluster */
			szbfat = fs->n_fatent * 4;					/* (Needed FAT size) */
		} else {
			if (fs->n_rootdir == 0)	return FR_NO_FILESYSTEM;	/* (BPB_RootEntCnt must not be 0) */
			fs->dirbase = fs->fatbase + fasize;			/* Root directory start sector */
			szbfat = (fmt == FS_FAT16) ?				/* (Needed FAT size) */
				fs->n_fatent * 2 : fs->n_fatent * 3 / 2 + (fs->n_fatent & 1);
		}
		if (fs->fsize < (szbfat + (SS(fs) - 1)) / SS(fs)) return FR_NO_FILESYSTEM;	/* (BPB_FATSz must not be less than the size needed) */

#if !FF_FS_READONLY
		/* Get FSInfo if available */
		fs->last_clst = fs->free_clst = 0xFFFFFFFF;		/* Initialize cluster allocation information */
		fs->fsi_flag = 0x80;
#if (FF_FS_NOFSINFO & 3) != 3
		if (fmt == FS_FAT32				/* Allow to update FSInfo only if BPB_FSInfo32 == 1 */
			&& ld_word(fs->win + BPB_FSInfo32) == 1
			&& move_window(fs, bsect + 1) == FR_OK)
		{
			fs->fsi_flag = 0;
			if (ld_word(fs->win + BS_55AA) == 0xAA55	/* Load FSInfo data if available */
				&& ld_dword(fs->win + FSI_LeadSig) == 0x41615252
				&& ld_dword(fs->win + FSI_StrucSig) == 0x61417272)
			{
#if (FF_FS_NOFSINFO & 1) == 0
				fs->free_clst = ld_dword(fs->win + FSI_Free_Count);
#endif
#if (FF_FS_NOFSINFO & 2) == 0
				fs->last_clst = ld_dword(fs->win + FSI_Nxt_Free);
#endif
			}
		}
#endif	/* (FF_FS_NOFSINFO & 3) != 3 */
#endif	/* !FF_FS_READONLY */
	}

	fs->fs_type = (BYTE)fmt;/* FAT sub-type (the filesystem object gets valid) */
	fs->id = ++Fsid;		/* Volume mount ID */
#if FF_USE_LFN == 1
	fs->lfnbuf = LfnBuf;	/* Static LFN working buffer */
#if FF_FS_EXFAT
	fs->dirbuf = DirBuf;	/* Static directory block scratchpad buuffer */
#endif
#endif
#if FF_FS_RPATH != 0
	fs->cdir = 0;			/* Initialize current directory */
#endif
#if FF_FS_LOCK				/* Clear file lock semaphores */
	clear_share(fs);
#endif
	return FR_OK;
}




/*-----------------------------------------------------------------------*/
/* Check if the file/directory object is valid or not                    */
/*-----------------------------------------------------------------------*/

static FRESULT validate (	/* Returns FR_OK or FR_INVALID_OBJECT */
	FFOBJID* obj,			/* Pointer to the FFOBJID, the 1st member in the FIL/DIR structure, to check validity */
	FATFS** rfs				/* Pointer to pointer to the owner filesystem object to return */
)
{
//	FRESULT res=FR_OK;
	FRESULT res = FR_INVALID_OBJECT;


	if (obj && obj->fs && obj->fs->fs_type && obj->id == obj->fs->id) {	/* Test if the object is valid */
#if FF_FS_REENTRANT
		if (lock_volume(obj->fs, 0)) {	/* Take a grant to access the volume */
			if (!(disk_status(obj->fs->pdrv) & STA_NOINIT)) { /* Test if the hosting phsical drive is kept initialized */
				res = FR_OK;
			} else {
				unlock_volume(obj->fs, FR_OK);	/* Invalidated volume, abort to access */
			}
		} else {	/* Could not take */
			res = FR_TIMEOUT;
		}
#else
		if (!(disk_status(obj->fs->pdrv) & STA_NOINIT)) { /* Test if the hosting phsical drive is kept initialized */
			res = FR_OK;
		}
#endif
	}
	*rfs = (res == FR_OK) ? obj->fs : 0;	/* Return corresponding filesystem object if it is valid */
	return res;
}




/*---------------------------------------------------------------------------

   Public Functions (FatFs API)

----------------------------------------------------------------------------*/



/*-----------------------------------------------------------------------*/
/* Mount/Unmount a Logical Drive                                         */
/*-----------------------------------------------------------------------*/

FRESULT f_mount (
	FATFS* fs,			/* Pointer to the filesystem object to be registered (NULL:unmount)*/
	const TCHAR* path,	/* Logical drive number to be mounted/unmounted */
	BYTE opt			/* Mount option: 0=Do not mount (delayed mount), 1=Mount immediately */
)
{
	FATFS *cfs;
	int vol;
	FRESULT res;
	const TCHAR *rp = path;


	/* Get volume ID (logical drive number) */
	vol = get_ldnumber(&rp);
	if (vol < 0) return FR_INVALID_DRIVE;
	cfs = FatFs[vol];			/* Pointer to the filesystem object of the volume */
	if (cfs) {					/* Unregister current filesystem object if regsitered */
		FatFs[vol] = 0;
#if FF_FS_LOCK
		clear_share(cfs);
#endif
#if FF_FS_REENTRANT				/* Discard mutex of the current volume */
		ff_mutex_delete(vol);
#endif
		cfs->fs_type = 0;		/* Invalidate the filesystem object to be unregistered */
	}

	if (fs) {					/* Register new filesystem object */
		fs->pdrv = LD2PD(vol);	/* Volume hosting physical drive */
#if FF_FS_REENTRANT				/* Create a volume mutex */
		fs->ldrv = (BYTE)vol;	/* Owner volume ID */
		if (!ff_mutex_create(vol)) return FR_INT_ERR;
#if FF_FS_LOCK
		if (SysLock == 0) {		/* Create a system mutex if needed */
			if (!ff_mutex_create(FF_VOLUMES)) {
				ff_mutex_delete(vol);
				return FR_INT_ERR;
			}
			SysLock = 1;		/* System mutex is ready */
		}
#endif
#endif
		fs->fs_type = 0;		/* Invalidate the new filesystem object */
		FatFs[vol] = fs;		/* Register new fs object */
	}

	if (opt == 0) return FR_OK;	/* Do not mount now, it will be mounted in subsequent file functions */
	res = mount_volume(&path, &fs, 0);	/* Force mounted the volume */
	LEAVE_FF(fs, res);
}




/*-----------------------------------------------------------------------*/
/* Open or Create a File                                                 */
/*-----------------------------------------------------------------------*/

FRESULT f_open (
	FIL* fp,			/* Pointer to the blank file object */
	const TCHAR* path,	/* Pointer to the file name */
	BYTE mode			/* Access mode and open mode flags */
)
{
	FRESULT res;
	DIR dj;
	FATFS *fs;
#if !FF_FS_READONLY
	DWORD cl, bcs, clst, tm;
	LBA_t sc;
	FSIZE_t ofs;
#endif
	DEF_NAMBUF


	if (!fp) return FR_INVALID_OBJECT;

	/* Get logical drive number */
	mode &= FF_FS_READONLY ? FA_READ : FA_READ | FA_WRITE | FA_CREATE_ALWAYS | FA_CREATE_NEW | FA_OPEN_ALWAYS | FA_OPEN_APPEND;
	res = mount_volume(&path, &fs, mode);
	if (res == FR_OK) {
		dj.obj.fs = fs;
		INIT_NAMBUF(fs);
		res = follow_path(&dj, path);	/* Follow the file path */
#if !FF_FS_READONLY	/* Read/Write configuration */
		if (res == FR_OK) {
			if (dj.fn[NSFLAG] & NS_NONAME) {	/* Origin directory itself? */
				res = FR_INVALID_NAME;
			}
#if FF_FS_LOCK
			else {
				res = chk_share(&dj, (mode & ~FA_READ) ? 1 : 0);	/* Check if the file can be used */
			}
#endif
		}
		/* Create or Open a file */
		if (mode & (FA_CREATE_ALWAYS | FA_OPEN_ALWAYS | FA_CREATE_NEW)) {
			if (res != FR_OK) {					/* No file, create new */
				if (res == FR_NO_FILE) {		/* There is no file to open, create a new entry */
#if FF_FS_LOCK
					res = enq_share() ? dir_register(&dj) : FR_TOO_MANY_OPEN_FILES;
#else
					res = dir_register(&dj);
#endif
				}
				mode |= FA_CREATE_ALWAYS;		/* File is created */
			}
			else {								/* Any object with the same name is already existing */
				if (dj.obj.attr & (AM_RDO | AM_DIR)) {	/* Cannot overwrite it (R/O or DIR) */
					res = FR_DENIED;
				} else {
					if (mode & FA_CREATE_NEW) res = FR_EXIST;	/* Cannot create as new file */
				}
			}
			if (res == FR_OK && (mode & FA_CREATE_ALWAYS)) {	/* Truncate the file if overwrite mode */
#if FF_FS_EXFAT
				if (fs->fs_type == FS_EXFAT) {
					/* Get current allocation info */
					fp->obj.fs = fs;
					init_alloc_info(fs, &fp->obj);
					/* Set directory entry block initial state */
					memset(fs->dirbuf + 2, 0, 30);	/* Clear 85 entry except for NumSec */
					memset(fs->dirbuf + 38, 0, 26);	/* Clear C0 entry except for NumName and NameHash */
					fs->dirbuf[XDIR_Attr] = AM_ARC;
					st_dword(fs->dirbuf + XDIR_CrtTime, GET_FATTIME());
					fs->dirbuf[XDIR_GenFlags] = 1;
					res = store_xdir(&dj);
					if (res == FR_OK && fp->obj.sclust != 0) {	/* Remove the cluster chain if exist */
						res = remove_chain(&fp->obj, fp->obj.sclust, 0);
						fs->last_clst = fp->obj.sclust - 1;		/* Reuse the cluster hole */
					}
				} else
#endif
				{
					/* Set directory entry initial state */
					tm = GET_FATTIME();					/* Set created time */
					st_dword(dj.dir + DIR_CrtTime, tm);
					st_dword(dj.dir + DIR_ModTime, tm);
					cl = ld_clust(fs, dj.dir);			/* Get current cluster chain */
					dj.dir[DIR_Attr] = AM_ARC;			/* Reset attribute */
					st_clust(fs, dj.dir, 0);			/* Reset file allocation info */
					st_dword(dj.dir + DIR_FileSize, 0);
					fs->wflag = 1;
					if (cl != 0) {						/* Remove the cluster chain if exist */
						sc = fs->winsect;
						res = remove_chain(&dj.obj, cl, 0);
						if (res == FR_OK) {
							res = move_window(fs, sc);
							fs->last_clst = cl - 1;		/* Reuse the cluster hole */
						}
					}
				}
			}
		}
		else {	/* Open an existing file */
			if (res == FR_OK) {					/* Is the object exsiting? */
				if (dj.obj.attr & AM_DIR) {		/* File open against a directory */
					res = FR_NO_FILE;
				} else {
					if ((mode & FA_WRITE) && (dj.obj.attr & AM_RDO)) { /* Write mode open against R/O file */
						res = FR_DENIED;
					}
				}
			}
		}
		if (res == FR_OK) {
			if (mode & FA_CREATE_ALWAYS) mode |= FA_MODIFIED;	/* Set file change flag if created or overwritten */
			fp->dir_sect = fs->winsect;			/* Pointer to the directory entry */
			fp->dir_ptr = dj.dir;
#if FF_FS_LOCK
			fp->obj.lockid = inc_share(&dj, (mode & ~FA_READ) ? 1 : 0);	/* Lock the file for this session */
			if (fp->obj.lockid == 0) res = FR_INT_ERR;
#endif
		}
#else		/* R/O configuration */
		if (res == FR_OK) {
			if (dj.fn[NSFLAG] & NS_NONAME) {	/* Is it origin directory itself? */
				res = FR_INVALID_NAME;
			} else {
				if (dj.obj.attr & AM_DIR) {		/* Is it a directory? */
					res = FR_NO_FILE;
				}
			}
		}
#endif

		if (res == FR_OK) {
#if FF_FS_EXFAT
			if (fs->fs_type == FS_EXFAT) {
				fp->obj.c_scl = dj.obj.sclust;							/* Get containing directory info */
				fp->obj.c_size = ((DWORD)dj.obj.objsize & 0xFFFFFF00) | dj.obj.stat;
				fp->obj.c_ofs = dj.blk_ofs;
				init_alloc_info(fs, &fp->obj);
			} else
#endif
			{
				fp->obj.sclust = ld_clust(fs, dj.dir);					/* Get object allocation info */
				fp->obj.objsize = ld_dword(dj.dir + DIR_FileSize);
			}
#if FF_USE_FASTSEEK
			fp->cltbl = 0;		/* Disable fast seek mode */
#endif
			fp->obj.fs = fs;	/* Validate the file object */
			fp->obj.id = fs->id;
			fp->flag = mode;	/* Set file access mode */
			fp->err = 0;		/* Clear error flag */
			fp->sect = 0;		/* Invalidate current data sector */
			fp->fptr = 0;		/* Set file pointer top of the file */
#if !FF_FS_READONLY
#if !FF_FS_TINY
			memset(fp->buf, 0, sizeof fp->buf);	/* Clear sector buffer */
#endif
			if ((mode & FA_SEEKEND) && fp->obj.objsize > 0) {	/* Seek to end of file if FA_OPEN_APPEND is specified */
				fp->fptr = fp->obj.objsize;			/* Offset to seek */
				bcs = (DWORD)fs->csize * SS(fs);	/* Cluster size in byte */
				clst = fp->obj.sclust;				/* Follow the cluster chain */
				for (ofs = fp->obj.objsize; res == FR_OK && ofs > bcs; ofs -= bcs) {
					clst = get_fat(&fp->obj, clst);
					if (clst <= 1) res = FR_INT_ERR;
					if (clst == 0xFFFFFFFF) res = FR_DISK_ERR;
				}
				fp->clust = clst;
				if (res == FR_OK && ofs % SS(fs)) {	/* Fill sector buffer if not on the sector boundary */
					sc = clst2sect(fs, clst);
					if (sc == 0) {
						res = FR_INT_ERR;
					} else {
						fp->sect = sc + (DWORD)(ofs / SS(fs));
#if !FF_FS_TINY
//						if (disk_read(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) res = FR_DISK_ERR;//9.3
						if (disk_read2(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) res = FR_DISK_ERR;
						memcpy(fp->buf,(BYTE *)(0xA0001000),SECTORSIZE*1);
#endif
					}
				}
#if FF_FS_LOCK
				if (res != FR_OK) dec_share(fp->obj.lockid); /* Decrement file open counter if seek failed */
#endif
			}
#endif
		}

		FREE_NAMBUF();
	}

	if (res != FR_OK) fp->obj.fs = 0;	/* Invalidate file object on error */

	LEAVE_FF(fs, res);
}


/*-----------------------------------------------------------------------*/
/* Read File1                                                             */
/*-----------------------------------------------------------------------*/

FRESULT f_read1 (
	FIL* fp, 	/* Open file to be read */
	void* buff,	/* Data buffer to store the read data */
	UINT btr,	/* Number of bytes to read */
	UINT* br	/* Number of bytes read */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD clst;
	LBA_t sect;
	FSIZE_t remain;
	UINT rcnt, cc, csect;
	BYTE *rbuff = (BYTE*)buff;


	*br = 0;	/* Clear read byte counter */
	res = validate(&fp->obj, &fs);				/* Check validity of the file object */
	if (res != FR_OK || (res = (FRESULT)fp->err) != FR_OK) LEAVE_FF(fs, res);	/* Check validity */
	if (!(fp->flag & FA_READ)) LEAVE_FF(fs, FR_DENIED); /* Check access mode */
	remain = fp->obj.objsize - fp->fptr;
	if (btr > remain) btr = (UINT)remain;		/* Truncate btr by remaining bytes */
	for ( ; btr > 0; btr -= rcnt, *br += rcnt, rbuff += rcnt/2, fp->fptr += rcnt) {	/* Repeat until btr bytes read */
		if (fp->fptr % SS(fs) == 0) {			/* On the sector boundary? */
			csect = (UINT)(fp->fptr / SS(fs) & (fs->csize - 1));	/* Sector offset in the cluster */
			if (csect == 0) {					/* On the cluster boundary? */
				if (fp->fptr == 0) {			/* On the top of the file? */
					clst = fp->obj.sclust;		/* Follow cluster chain from the origin */
				} else {						/* Middle or end of the file */
#if FF_USE_FASTSEEK
					if (fp->cltbl) {
						clst = clmt_clust(fp, fp->fptr);	/* Get cluster# from the CLMT */
					} else
#endif
					{
						clst = get_fat(&fp->obj, fp->clust);	/* Follow cluster chain on the FAT */
					}
				}
				if (clst < 2) ABORT(fs, FR_INT_ERR);
				if (clst == 0xFFFFFFFF) ABORT(fs, FR_DISK_ERR);
				fp->clust = clst;				/* Update current cluster */
			}
			sect = clst2sect(fs, fp->clust);	/* Get current sector */
			if (sect == 0) ABORT(fs, FR_INT_ERR);
			sect += csect;
			cc = btr / SS(fs);					/* When remaining bytes >= sector size, */
			if (cc > 0) {						/* Read maximum contiguous sectors directly */
				if (csect + cc > fs->csize) {	/* Clip at cluster boundary */
					cc = fs->csize - csect;
				}
				if (disk_read1(fs->pdrv, rbuff, sect, cc) != RES_OK) ABORT(fs, FR_DISK_ERR);
//				xil_printf(" sect:%llx\r\n",sect);
				//memcpy(rbuff,(BYTE *)(0xA0001000),SECTORSIZE*cc);
#if !FF_FS_READONLY && FF_FS_MINIMIZE <= 2		/* Replace one of the read sectors with cached data if it contains a dirty sector */
#if FF_FS_TINY
				if (fs->wflag && fs->winsect - sect < cc) {
					memcpy(rbuff + ((fs->winsect - sect) * SS(fs)), fs->win, SS(fs));
				}
#else
				if ((fp->flag & FA_DIRTY) && fp->sect - sect < cc) {
					memcpy(rbuff + ((fp->sect - sect) * SS(fs)), fp->buf, SS(fs));
				}
#endif
#endif
				rcnt = SS(fs) * cc;				/* Number of bytes transferred */
				continue;
			}
#if !FF_FS_TINY
			if (fp->sect != sect) {			/* Load data sector if not in cache */
#if !FF_FS_READONLY
				if (fp->flag & FA_DIRTY) {		/* Write-back dirty sector cache */
					memcpy((BYTE *)(0xA0001000),fp->buf,SECTORSIZE*1);
					if (disk_write(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);
					fp->flag &= (BYTE)~FA_DIRTY;
				}
#endif
				if (disk_read1(fs->pdrv, (BYTE *)(0xA0001000), sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);	/* Fill sector cache */
					memcpy(fp->buf,(BYTE *)(0xA0001000),SECTORSIZE*1);
			}
#endif
			fp->sect = sect;
		}
		rcnt = SS(fs) - (UINT)fp->fptr % SS(fs);	/* Number of bytes remains in the sector */
		if (rcnt > btr) rcnt = btr;					/* Clip it by btr if needed */
#if FF_FS_TINY
		if (move_window(fs, fp->sect) != FR_OK) ABORT(fs, FR_DISK_ERR);	/* Move sector window */
		memcpy(rbuff, fs->win + fp->fptr % SS(fs), rcnt);	/* Extract partial sector */
#else
		memcpy(rbuff, fp->buf + fp->fptr % SS(fs), rcnt);	/* Extract partial sector */
#endif
	}
	LEAVE_FF(fs, FR_OK);
}

/*-----------------------------------------------------------------------*/
/* Read File                                                             */
/*-----------------------------------------------------------------------*/

FRESULT f_read (
	FIL* fp, 	/* Open file to be read */
	void* buff,	/* Data buffer to store the read data */
	UINT btr,	/* Number of bytes to read */
	UINT* br	/* Number of bytes read */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD clst;
	LBA_t sect;
	FSIZE_t remain;
	UINT rcnt, cc, csect;
	BYTE *rbuff = (BYTE*)buff;


	*br = 0;	/* Clear read byte counter */
	res = validate(&fp->obj, &fs);				/* Check validity of the file object */
	if (res != FR_OK || (res = (FRESULT)fp->err) != FR_OK) LEAVE_FF(fs, res);	/* Check validity */
	if (!(fp->flag & FA_READ)) LEAVE_FF(fs, FR_DENIED); /* Check access mode */
	remain = fp->obj.objsize - fp->fptr;
	if (btr > remain) btr = (UINT)remain;		/* Truncate btr by remaining bytes */	
	for ( ; btr > 0; btr -= rcnt, *br += rcnt, rbuff += rcnt, fp->fptr += rcnt) {	/* Repeat until btr bytes read */
		if (fp->fptr % SS(fs) == 0) {			/* On the sector boundary? */
			csect = (UINT)(fp->fptr / SS(fs) & (fs->csize - 1));	/* Sector offset in the cluster */
			if (csect == 0) {					/* On the cluster boundary? */
				if (fp->fptr == 0) {			/* On the top of the file? */
					clst = fp->obj.sclust;		/* Follow cluster chain from the origin */
				} else {						/* Middle or end of the file */
#if FF_USE_FASTSEEK
					if (fp->cltbl) {
						clst = clmt_clust(fp, fp->fptr);	/* Get cluster# from the CLMT */
					} else
#endif
					{
						clst = get_fat(&fp->obj, fp->clust);	/* Follow cluster chain on the FAT */
					}
				}
				if (clst < 2) ABORT(fs, FR_INT_ERR);
				if (clst == 0xFFFFFFFF) ABORT(fs, FR_DISK_ERR);
				fp->clust = clst;				/* Update current cluster */
			}
			sect = clst2sect(fs, fp->clust);	/* Get current sector */
			if (sect == 0) ABORT(fs, FR_INT_ERR);
			sect += csect;
			cc = btr / SS(fs);					/* When remaining bytes >= sector size, */
			if (cc > 0) {						/* Read maximum contiguous sectors directly */
				if (csect + cc > fs->csize) {	/* Clip at cluster boundary */
					cc = fs->csize - csect;
				}
				if (disk_read1(fs->pdrv, rbuff, sect, cc) != RES_OK) ABORT(fs, FR_DISK_ERR);
				//memcpy(rbuff,(BYTE *)(0xA0001000),SECTORSIZE*cc);
#if !FF_FS_READONLY && FF_FS_MINIMIZE <= 2		/* Replace one of the read sectors with cached data if it contains a dirty sector */
#if FF_FS_TINY
				if (fs->wflag && fs->winsect - sect < cc) {
					memcpy(rbuff + ((fs->winsect - sect) * SS(fs)), fs->win, SS(fs));
				}
#else
				if ((fp->flag & FA_DIRTY) && fp->sect - sect < cc) {
					memcpy(rbuff + ((fp->sect - sect) * SS(fs)), fp->buf, SS(fs));
				}
#endif
#endif
				rcnt = SS(fs) * cc;				/* Number of bytes transferred */
				continue;
			}
#if !FF_FS_TINY
			if (fp->sect != sect) {			/* Load data sector if not in cache */
#if !FF_FS_READONLY
				if (fp->flag & FA_DIRTY) {		/* Write-back dirty sector cache */
					memcpy((BYTE *)(0xA0001000),fp->buf,SECTORSIZE*1);
					if (disk_write(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);
					fp->flag &= (BYTE)~FA_DIRTY;
				}
#endif
				if (disk_read1(fs->pdrv, (BYTE *)(0xA0001000), sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);	/* Fill sector cache */
					memcpy(fp->buf,(BYTE *)(0xA0001000),SECTORSIZE*1);
			}
#endif
			fp->sect = sect;
		}
		rcnt = SS(fs) - (UINT)fp->fptr % SS(fs);	/* Number of bytes remains in the sector */
		if (rcnt > btr) rcnt = btr;					/* Clip it by btr if needed */
#if FF_FS_TINY
		if (move_window(fs, fp->sect) != FR_OK) ABORT(fs, FR_DISK_ERR);	/* Move sector window */
		memcpy(rbuff, fs->win + fp->fptr % SS(fs), rcnt);	/* Extract partial sector */
#else
		memcpy(rbuff, fp->buf + fp->fptr % SS(fs), rcnt);	/* Extract partial sector */
#endif
	}
	LEAVE_FF(fs, FR_OK);
}




#if !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* Write File                                                            */
/*-----------------------------------------------------------------------*/

FRESULT f_write (
	FIL* fp,			/* Open file to be written */
	const void* buff,	/* Data to be written */
	UINT btw,			/* Number of bytes to write */
	UINT* bw			/* Number of bytes written */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD clst;
	LBA_t sect;
	UINT wcnt, cc, csect;
	const BYTE *wbuff = (const BYTE*)buff;


	*bw = 0;	/* Clear write byte counter */
	res = validate(&fp->obj, &fs);			/* Check validity of the file object */
	if (res != FR_OK || (res = (FRESULT)fp->err) != FR_OK) LEAVE_FF(fs, res);	/* Check validity */
	if (!(fp->flag & FA_WRITE)) LEAVE_FF(fs, FR_DENIED);	/* Check access mode */

	/* Check fptr wrap-around (file size cannot reach 4 GiB at FAT volume) */
	if ((!FF_FS_EXFAT || fs->fs_type != FS_EXFAT) && (DWORD)(fp->fptr + btw) < (DWORD)fp->fptr) {
		btw = (UINT)(0xFFFFFFFF - (DWORD)fp->fptr);
	}

	for ( ; btw > 0; btw -= wcnt, *bw += wcnt, wbuff += wcnt, fp->fptr += wcnt, fp->obj.objsize = (fp->fptr > fp->obj.objsize) ? fp->fptr : fp->obj.objsize) {	/* Repeat until all data written */
		if (fp->fptr % SS(fs) == 0) {		/* On the sector boundary? */
			csect = (UINT)(fp->fptr / SS(fs)) & (fs->csize - 1);	/* Sector offset in the cluster */
			if (csect == 0) {				/* On the cluster boundary? */
				if (fp->fptr == 0) {		/* On the top of the file? */
					clst = fp->obj.sclust;	/* Follow from the origin */
					if (clst == 0) {		/* If no cluster is allocated, */
						clst = create_chain(&fp->obj, 0);	/* create a new cluster chain */
					}
				} else {					/* On the middle or end of the file */
#if FF_USE_FASTSEEK
					if (fp->cltbl) {
						clst = clmt_clust(fp, fp->fptr);	/* Get cluster# from the CLMT */
					} else
#endif
					{
						clst = create_chain(&fp->obj, fp->clust);	/* Follow or stretch cluster chain on the FAT */
					}
				}
				if (clst == 0) break;		/* Could not allocate a new cluster (disk full) */
				if (clst == 1) ABORT(fs, FR_INT_ERR);
				if (clst == 0xFFFFFFFF) ABORT(fs, FR_DISK_ERR);
				fp->clust = clst;			/* Update current cluster */
				if (fp->obj.sclust == 0) fp->obj.sclust = clst;	/* Set start cluster if the first write */
			}
#if FF_FS_TINY
			if (fs->winsect == fp->sect && sync_window(fs) != FR_OK) ABORT(fs, FR_DISK_ERR);	/* Write-back sector cache */
#else
			if (fp->flag & FA_DIRTY) {		/* Write-back sector cache */
				memcpy((BYTE *)(0xA0001000),fp->buf,SECTORSIZE*1);
				if (disk_write(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);
				fp->flag &= (BYTE)~FA_DIRTY;
			}
#endif
			sect = clst2sect(fs, fp->clust);	/* Get current sector */
			if (sect == 0) ABORT(fs, FR_INT_ERR);
			sect += csect;
			cc = btw / SS(fs);				/* When remaining bytes >= sector size, */
			
			if (cc > 0) {					/* Write maximum contiguous sectors directly */
				if (csect + cc > fs->csize) {	/* Clip at cluster boundary */
					cc = fs->csize - csect;
				}
				//memcpy((BYTE *)(0xA0001000),wbuff,SECTORSIZE*cc);//wfeng
				if (disk_write(fs->pdrv, wbuff, sect, cc) != RES_OK) ABORT(fs, FR_DISK_ERR);
						
#if FF_FS_MINIMIZE <= 2
#if FF_FS_TINY
				if (fs->winsect - sect < cc) {	/* Refill sector cache if it gets invalidated by the direct write */
					memcpy(fs->win, wbuff + ((fs->winsect - sect) * SS(fs)), SS(fs));
					fs->wflag = 0;
				}
#else
				if (fp->sect - sect < cc) { /* Refill sector cache if it gets invalidated by the direct write */
					memcpy(fp->buf, wbuff + ((fp->sect - sect) * SS(fs)), SS(fs));
					fp->flag &= (BYTE)~FA_DIRTY;
				}
#endif
#endif
				wcnt = SS(fs) * cc;		/* Number of bytes transferred */
				continue;
			}
#if FF_FS_TINY
			if (fp->fptr >= fp->obj.objsize) {	/* Avoid silly cache filling on the growing edge */
				if (sync_window(fs) != FR_OK) ABORT(fs, FR_DISK_ERR);
				fs->winsect = sect;
			}
#else
			if (fp->sect != sect && 		/* Fill sector cache with file data */
				fp->fptr < fp->obj.objsize &&
				disk_read1(fs->pdrv, (BYTE *)(0xA0001000), sect, 1) != RES_OK) {
					ABORT(fs, FR_DISK_ERR);
			}
			memcpy(fp->buf,(BYTE *)(0xA0001000),SECTORSIZE*1);
#endif
			fp->sect = sect;
		}          /*If On the sector boundary? */
		wcnt = SS(fs) - (UINT)fp->fptr % SS(fs);	/* Number of bytes remains in the sector */
		if (wcnt > btw) wcnt = btw;					/* Clip it by btw if needed */
#if FF_FS_TINY
		if (move_window(fs, fp->sect) != FR_OK) ABORT(fs, FR_DISK_ERR);	/* Move sector window */
		memcpy(fs->win + fp->fptr % SS(fs), wbuff, wcnt);	/* Fit data to the sector */
		fs->wflag = 1;
#else
		memcpy(fp->buf + fp->fptr % SS(fs), wbuff, wcnt);	/* Fit data to the sector */
		fp->flag |= FA_DIRTY;
#endif
	}

	fp->flag |= FA_MODIFIED;				/* Set file change flag */

	LEAVE_FF(fs, FR_OK);
}

FRESULT f_write1 (
	FIL* fp,			/* Open file to be written */
	const void* buff,	/* Data to be written */
	UINT btw,			/* Number of bytes to write */
	UINT* bw			/* Number of bytes written */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD clst;
	LBA_t sect;
	UINT wcnt, cc, csect;
	const BYTE *wbuff = (const BYTE*)buff;


	*bw = 0;	/* Clear write byte counter */
	res = validate(&fp->obj, &fs);			/* Check validity of the file object */
	if (res != FR_OK || (res = (FRESULT)fp->err) != FR_OK) LEAVE_FF(fs, res);	/* Check validity */
	if (!(fp->flag & FA_WRITE)) LEAVE_FF(fs, FR_DENIED);	/* Check access mode */

	/* Check fptr wrap-around (file size cannot reach 4 GiB at FAT volume) */
	if ((!FF_FS_EXFAT || fs->fs_type != FS_EXFAT) && (DWORD)(fp->fptr + btw) < (DWORD)fp->fptr) {
		btw = (UINT)(0xFFFFFFFF - (DWORD)fp->fptr);
	}

	for ( ; btw > 0; btw -= wcnt, *bw += wcnt, wbuff += wcnt/2, fp->fptr += wcnt, fp->obj.objsize = (fp->fptr > fp->obj.objsize) ? fp->fptr : fp->obj.objsize) {	/* Repeat until all data written */
		if (fp->fptr % SS(fs) == 0) {		/* On the sector boundary? */
			csect = (UINT)(fp->fptr / SS(fs)) & (fs->csize - 1);	/* Sector offset in the cluster */
			if (csect == 0) {				/* On the cluster boundary? */
				if (fp->fptr == 0) {		/* On the top of the file? */
					clst = fp->obj.sclust;	/* Follow from the origin */
					if (clst == 0) {		/* If no cluster is allocated, */
						clst = create_chain(&fp->obj, 0);	/* create a new cluster chain */
					}
				} else {					/* On the middle or end of the file */
#if FF_USE_FASTSEEK
					if (fp->cltbl) {
						clst = clmt_clust(fp, fp->fptr);	/* Get cluster# from the CLMT */
					} else
#endif
					{
						clst = create_chain(&fp->obj, fp->clust);	/* Follow or stretch cluster chain on the FAT */
					}
				}
				if (clst == 0) break;		/* Could not allocate a new cluster (disk full) */
				if (clst == 1) ABORT(fs, FR_INT_ERR);
				if (clst == 0xFFFFFFFF) ABORT(fs, FR_DISK_ERR);
				fp->clust = clst;			/* Update current cluster */
				if (fp->obj.sclust == 0) fp->obj.sclust = clst;	/* Set start cluster if the first write */
			}
#if FF_FS_TINY
			if (fs->winsect == fp->sect && sync_window(fs) != FR_OK) ABORT(fs, FR_DISK_ERR);	/* Write-back sector cache */
#else
			if (fp->flag & FA_DIRTY) {		/* Write-back sector cache */
				memcpy((BYTE *)(0xA0001000),fp->buf,SECTORSIZE*1);
				if (disk_write1(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);//9.3
				fp->flag &= (BYTE)~FA_DIRTY;
			}
#endif
			sect = clst2sect(fs, fp->clust);	/* Get current sector */
			if (sect == 0) ABORT(fs, FR_INT_ERR);
			sect += csect;
			cc = btw / SS(fs);				/* When remaining bytes >= sector size, */

			if (cc > 0) {					/* Write maximum contiguous sectors directly */
				if (csect + cc > fs->csize) {	/* Clip at cluster boundary */
					cc = fs->csize - csect;
				}
				//memcpy((BYTE *)(0xA0001000),wbuff,SECTORSIZE*cc);//wfeng
				if (disk_write(fs->pdrv, wbuff, sect, cc) != RES_OK) ABORT(fs, FR_DISK_ERR);
//				xil_printf("  sect:%llx\r\n",sect);
#if FF_FS_MINIMIZE <= 2
#if FF_FS_TINY
				if (fs->winsect - sect < cc) {	/* Refill sector cache if it gets invalidated by the direct write */
					memcpy(fs->win, wbuff + ((fs->winsect - sect) * SS(fs)), SS(fs));
					fs->wflag = 0;
				}
#else
				if (fp->sect - sect < cc) { /* Refill sector cache if it gets invalidated by the direct write */
					memcpy(fp->buf, wbuff + ((fp->sect - sect) * SS(fs)), SS(fs));
					fp->flag &= (BYTE)~FA_DIRTY;
				}
#endif
#endif
				wcnt = SS(fs) * cc;		/* Number of bytes transferred */
				continue;
			}
#if FF_FS_TINY
			if (fp->fptr >= fp->obj.objsize) {	/* Avoid silly cache filling on the growing edge */
				if (sync_window(fs) != FR_OK) ABORT(fs, FR_DISK_ERR);
				fs->winsect = sect;
			}
#else
			if (fp->sect != sect && 		/* Fill sector cache with file data */
				fp->fptr < fp->obj.objsize &&
				disk_read1(fs->pdrv, (BYTE *)(0xA0001000), sect, 1) != RES_OK) {
					ABORT(fs, FR_DISK_ERR);
			}
			memcpy(fp->buf,(BYTE *)(0xA0001000),SECTORSIZE*1);
#endif
			fp->sect = sect;
		}          /*If On the sector boundary? */
		wcnt = SS(fs) - (UINT)fp->fptr % SS(fs);	/* Number of bytes remains in the sector */
		if (wcnt > btw) wcnt = btw;					/* Clip it by btw if needed */
#if FF_FS_TINY
		if (move_window(fs, fp->sect) != FR_OK) ABORT(fs, FR_DISK_ERR);	/* Move sector window */
		memcpy(fs->win + fp->fptr % SS(fs), wbuff, wcnt);	/* Fit data to the sector */
		fs->wflag = 1;
#else
		memcpy(fp->buf + fp->fptr % SS(fs), wbuff, wcnt);	/* Fit data to the sector */
		fp->flag |= FA_DIRTY;
#endif
	}

	fp->flag |= FA_MODIFIED;				/* Set file change flag */

	LEAVE_FF(fs, FR_OK);
}

//FRESULT f_write2 (
//	FIL* fp,			/* Open file to be written */
//	const void* buff,	/* Data to be written */
//	UINT btw,			/* Number of bytes to write */
//	UINT* bw			/* Number of bytes written */
//)    // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙缁炬儳娼￠弻锝夊閵忊晝鍔哥紓浣哄Х婵烇拷闁哄本鐩俊鐑筋敊閻撳寒娼绘繝娈垮枦椤鎮￠敓鐘茶摕闁绘梻鈷堥弫鍥煟閺冨牆鍔戠紒灞剧瑓te2
//{
//	FRESULT res;
//	FATFS *fs;
//	DWORD clst;
//	LBA_t sect;
//	LBA_t sect1;
//	UINT wcnt, cc, csect;
//	const BYTE *wbuff = (const BYTE*)buff;
//	UINT sign=0;
//
//	*bw = 0;	/* Clear write byte counter */
//	res = validate(&fp->obj, &fs);			/* Check validity of the file object */
//	if (res != FR_OK || (res = (FRESULT)fp->err) != FR_OK) LEAVE_FF(fs, res);	/* Check validity */
//	if (!(fp->flag & FA_WRITE)) LEAVE_FF(fs, FR_DENIED);	/* Check access mode */
//
//	/* Check fptr wrap-around (file size cannot reach 4 GiB at FAT volume) */
//	if ((!FF_FS_EXFAT || fs->fs_type != FS_EXFAT) && (DWORD)(fp->fptr + btw) < (DWORD)fp->fptr) {
//		btw = (UINT)(0xFFFFFFFF - (DWORD)fp->fptr);
//	}
//
//	for ( ; btw > 0; btw -= wcnt, *bw += wcnt, wbuff += wcnt, fp->fptr += wcnt, fp->obj.objsize = (fp->fptr > fp->obj.objsize) ? fp->fptr : fp->obj.objsize) {	/* Repeat until all data written */
//		if (fp->fptr % SS(fs) == 0) {		/* On the sector boundary? */
//			csect = (UINT)(fp->fptr / SS(fs)) & (fs->csize - 1);	/* Sector offset in the cluster */
//			if (csect == 0) {				/* On the cluster boundary? */
//				if (fp->fptr == 0) {		/* On the top of the file? */
//					clst = fp->obj.sclust;	/* Follow from the origin */
//					if (clst == 0) {		/* If no cluster is allocated, */
//						clst = create_chain(&fp->obj, 0);	/* create a new cluster chain */
//					}
//				} else {					/* On the middle or end of the file */
//#if FF_USE_FASTSEEK
//					if (fp->cltbl) {
//						clst = clmt_clust(fp, fp->fptr);	/* Get cluster# from the CLMT */
//					} else
//#endif
//					{
//						clst = create_chain(&fp->obj, fp->clust);	/* Follow or stretch cluster chain on the FAT */
//					}
//				}
//				if (clst == 0) break;		/* Could not allocate a new cluster (disk full) */
//				if (clst == 1) ABORT(fs, FR_INT_ERR);
//				if (clst == 0xFFFFFFFF) ABORT(fs, FR_DISK_ERR);
//				fp->clust = clst;			/* Update current cluster */
//				if (fp->obj.sclust == 0) fp->obj.sclust = clst;	/* Set start cluster if the first write */
//				sign++;
//			}
//#if FF_FS_TINY
//			if (fs->winsect == fp->sect && sync_window(fs) != FR_OK) ABORT(fs, FR_DISK_ERR);	/* Write-back sector cache */
//#else
//			if (fp->flag & FA_DIRTY) {		/* Write-back sector cache */
//				memcpy((BYTE *)(0xA0001000),fp->buf,SECTORSIZE*1);
//				if (disk_write(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);
//				fp->flag &= (BYTE)~FA_DIRTY;
//			}
//#endif
//			sect = clst2sect(fs, fp->clust);	/* Get current sector */
//			if (sect == 0) ABORT(fs, FR_INT_ERR);
//			sect += csect;
//			if(sign==1)
//			{
//				sect1=sect;
//			}
//			cc = btw / SS(fs);				/* When remaining bytes >= sector size, */
//
//			if (cc > 0) {					/* Write maximum contiguous sectors directly */
//				if (csect + cc > fs->csize) {	/* Clip at cluster boundary */
//					cc = fs->csize - csect;
//				}
//				if(sign==32)
//				{
//					if (disk_write(fs->pdrv, wbuff, sect1, cc*20) != RES_OK) ABORT(fs, FR_DISK_ERR);
//				}
//
//
//#if FF_FS_MINIMIZE <= 2
//#if FF_FS_TINY
//				if (fs->winsect - sect < cc) {	/* Refill sector cache if it gets invalidated by the direct write */
//					memcpy(fs->win, wbuff + ((fs->winsect - sect) * SS(fs)), SS(fs));
//					fs->wflag = 0;
//				}
//#else
//				if (fp->sect - sect < cc) { /* Refill sector cache if it gets invalidated by the direct write */
//					memcpy(fp->buf, wbuff + ((fp->sect - sect) * SS(fs)), SS(fs));
//					fp->flag &= (BYTE)~FA_DIRTY;
//				}
//#endif
//#endif
//				wcnt = SS(fs) * cc;		/* Number of bytes transferred */
//				continue;
//			}
//#if FF_FS_TINY
//			if (fp->fptr >= fp->obj.objsize) {	/* Avoid silly cache filling on the growing edge */
//				if (sync_window(fs) != FR_OK) ABORT(fs, FR_DISK_ERR);
//				fs->winsect = sect;
//			}
//#else
//			if (fp->sect != sect && 		/* Fill sector cache with file data */
//				fp->fptr < fp->obj.objsize &&
//				disk_read1(fs->pdrv, (BYTE *)(0xA0001000), sect, 1) != RES_OK) {
//					ABORT(fs, FR_DISK_ERR);
//			}
//			memcpy(fp->buf,(BYTE *)(0xA0001000),SECTORSIZE*1);
//#endif
//			fp->sect = sect;
//		}          /*If On the sector boundary? */
//		wcnt = SS(fs) - (UINT)fp->fptr % SS(fs);	/* Number of bytes remains in the sector */
//		if (wcnt > btw) wcnt = btw;					/* Clip it by btw if needed */
//#if FF_FS_TINY
//		if (move_window(fs, fp->sect) != FR_OK) ABORT(fs, FR_DISK_ERR);	/* Move sector window */
//		memcpy(fs->win + fp->fptr % SS(fs), wbuff, wcnt);	/* Fit data to the sector */
//		fs->wflag = 1;
//#else
//		memcpy(fp->buf + fp->fptr % SS(fs), wbuff, wcnt);	/* Fit data to the sector */
//		fp->flag |= FA_DIRTY;
//#endif
//	}
//
//	fp->flag |= FA_MODIFIED;				/* Set file change flag */
//
//	LEAVE_FF(fs, FR_OK);
//}
/*-----------------------------------------------------------------------*/
/* Synchronize the File                                                  */
/*-----------------------------------------------------------------------*/

FRESULT f_sync (
	FIL* fp		/* Open file to be synced */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD tm;
	BYTE *dir;


	res = validate(&fp->obj, &fs);	/* Check validity of the file object */
	if (res == FR_OK) {
		if (fp->flag & FA_MODIFIED) {	/* Is there any change to the file? */
#if !FF_FS_TINY
			if (fp->flag & FA_DIRTY) {	/* Write-back cached data if needed */
				memcpy((BYTE *)(0xA0001000),fp->buf,SECTORSIZE*1);
				if (disk_write1(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) LEAVE_FF(fs, FR_DISK_ERR);//9.3
				fp->flag &= (BYTE)~FA_DIRTY;
			}
#endif
			/* Update the directory entry */
			tm = GET_FATTIME();				/* Modified time */
#if FF_FS_EXFAT
			if (fs->fs_type == FS_EXFAT) {
				res = fill_first_frag(&fp->obj);	/* Fill first fragment on the FAT if needed */
				if (res == FR_OK) {
					res = fill_last_frag(&fp->obj, fp->clust, 0xFFFFFFFF);	/* Fill last fragment on the FAT if needed */
				}
				if (res == FR_OK) {
					DIR dj;
					DEF_NAMBUF

					INIT_NAMBUF(fs);
					res = load_obj_xdir(&dj, &fp->obj);	/* Load directory entry block */
					if (res == FR_OK) {
						fs->dirbuf[XDIR_Attr] |= AM_ARC;				/* Set archive attribute to indicate that the file has been changed */
						fs->dirbuf[XDIR_GenFlags] = fp->obj.stat | 1;	/* Update file allocation information */
						st_dword(fs->dirbuf + XDIR_FstClus, fp->obj.sclust);		/* Update start cluster */
						st_qword(fs->dirbuf + XDIR_FileSize, fp->obj.objsize);		/* Update file size */
						st_qword(fs->dirbuf + XDIR_ValidFileSize, fp->obj.objsize);	/* (FatFs does not support Valid File Size feature) */
						st_dword(fs->dirbuf + XDIR_ModTime, tm);		/* Update modified time */
						fs->dirbuf[XDIR_ModTime10] = 0;
						st_dword(fs->dirbuf + XDIR_AccTime, 0);
						res = store_xdir(&dj);	/* Restore it to the directory */
						if (res == FR_OK) {
							res = sync_fs(fs);
							fp->flag &= (BYTE)~FA_MODIFIED;
						}
					}
					FREE_NAMBUF();
				}
			} else
#endif
			{
				res = move_window(fs, fp->dir_sect);
				if (res == FR_OK) {
					dir = fp->dir_ptr;
					dir[DIR_Attr] |= AM_ARC;						/* Set archive attribute to indicate that the file has been changed */
					st_clust(fp->obj.fs, dir, fp->obj.sclust);		/* Update file allocation information  */
					st_dword(dir + DIR_FileSize, (DWORD)fp->obj.objsize);	/* Update file size */
					st_dword(dir + DIR_ModTime, tm);				/* Update modified time */
					st_word(dir + DIR_LstAccDate, 0);
					fs->wflag = 1;
					res = sync_fs(fs);					/* Restore it to the directory */
					fp->flag &= (BYTE)~FA_MODIFIED;
				}
			}
		}
	}

	LEAVE_FF(fs, res);
}

#endif /* !FF_FS_READONLY */




/*-----------------------------------------------------------------------*/
/* Close File                                                            */
/*-----------------------------------------------------------------------*/

FRESULT f_close (
	FIL* fp		/* Open file to be closed */
)
{
	FRESULT res;
	FATFS *fs;

#if !FF_FS_READONLY
	res = f_sync(fp);					/* Flush cached data */
	if (res == FR_OK)
#endif
	{
		res = validate(&fp->obj, &fs);	/* Lock volume */
		if (res == FR_OK) {
#if FF_FS_LOCK
			res = dec_share(fp->obj.lockid);		/* Decrement file open counter */
			if (res == FR_OK) fp->obj.fs = 0;	/* Invalidate file object */
#else
			fp->obj.fs = 0;	/* Invalidate file object */
#endif
#if FF_FS_REENTRANT
			unlock_volume(fs, FR_OK);		/* Unlock volume */
#endif
		}
	}
	return res;
}




#if FF_FS_RPATH >= 1
/*-----------------------------------------------------------------------*/
/* Change Current Directory or Current Drive, Get Current Directory      */
/*-----------------------------------------------------------------------*/

FRESULT f_chdrive (
	const TCHAR* path		/* Drive number to set */
)
{
	int vol;


	/* Get logical drive number */
	vol = get_ldnumber(&path);
	if (vol < 0) return FR_INVALID_DRIVE;
	CurrVol = (BYTE)vol;	/* Set it as current volume */

	return FR_OK;
}



FRESULT f_chdir (
	const TCHAR* path	/* Pointer to the directory path */
)
{
#if FF_STR_VOLUME_ID == 2
	UINT i;
#endif
	FRESULT res;
	DIR dj;
	FATFS *fs;
	DEF_NAMBUF


	/* Get logical drive */
	res = mount_volume(&path, &fs, 0);
	if (res == FR_OK) {
		dj.obj.fs = fs;
		INIT_NAMBUF(fs);
		res = follow_path(&dj, path);		/* Follow the path */
		if (res == FR_OK) {					/* Follow completed */
			if (dj.fn[NSFLAG] & NS_NONAME) {	/* Is it the start directory itself? */
				fs->cdir = dj.obj.sclust;
#if FF_FS_EXFAT
				if (fs->fs_type == FS_EXFAT) {
					fs->cdc_scl = dj.obj.c_scl;
					fs->cdc_size = dj.obj.c_size;
					fs->cdc_ofs = dj.obj.c_ofs;
				}
#endif
			} else {
				if (dj.obj.attr & AM_DIR) {	/* It is a sub-directory */
#if FF_FS_EXFAT
					if (fs->fs_type == FS_EXFAT) {
						fs->cdir = ld_dword(fs->dirbuf + XDIR_FstClus);		/* Sub-directory cluster */
						fs->cdc_scl = dj.obj.sclust;						/* Save containing directory information */
						fs->cdc_size = ((DWORD)dj.obj.objsize & 0xFFFFFF00) | dj.obj.stat;
						fs->cdc_ofs = dj.blk_ofs;
					} else
#endif
					{
						fs->cdir = ld_clust(fs, dj.dir);					/* Sub-directory cluster */
					}
				} else {
					res = FR_NO_PATH;		/* Reached but a file */
				}
			}
		}
		FREE_NAMBUF();
		if (res == FR_NO_FILE) res = FR_NO_PATH;
#if FF_STR_VOLUME_ID == 2	/* Also current drive is changed if in Unix style volume ID */
		if (res == FR_OK) {
			for (i = FF_VOLUMES - 1; i && fs != FatFs[i]; i--) ;	/* Set current drive */
			CurrVol = (BYTE)i;
		}
#endif
	}

	LEAVE_FF(fs, res);
}


#if FF_FS_RPATH >= 2
FRESULT f_getcwd (
	TCHAR* buff,	/* Pointer to the directory path */
	UINT len		/* Size of buff in unit of TCHAR */
)
{
	FRESULT res;
	DIR dj;
	FATFS *fs;
	UINT i, n;
	DWORD ccl;
	TCHAR *tp = buff;
#if FF_VOLUMES >= 2
	UINT vl;
#if FF_STR_VOLUME_ID
	const char *vp;
#endif
#endif
	FILINFO fno;
	DEF_NAMBUF


	/* Get logical drive */
	buff[0] = 0;	/* Set null string to get current volume */
	res = mount_volume((const TCHAR**)&buff, &fs, 0);	/* Get current volume */
	if (res == FR_OK) {
		dj.obj.fs = fs;
		INIT_NAMBUF(fs);

		/* Follow parent directories and create the path */
		i = len;			/* Bottom of buffer (directory stack base) */
		if (!FF_FS_EXFAT || fs->fs_type != FS_EXFAT) {	/* (Cannot do getcwd on exFAT and returns root path) */
			dj.obj.sclust = fs->cdir;				/* Start to follow upper directory from current directory */
			while ((ccl = dj.obj.sclust) != 0) {	/* Repeat while current directory is a sub-directory */
				res = dir_sdi(&dj, 1 * SZDIRE);	/* Get parent directory */
				if (res != FR_OK) break;
				res = move_window(fs, dj.sect);
				if (res != FR_OK) break;
				dj.obj.sclust = ld_clust(fs, dj.dir);	/* Goto parent directory */
				res = dir_sdi(&dj, 0);
				if (res != FR_OK) break;
				do {							/* Find the entry links to the child directory */
					res = DIR_READ_FILE(&dj);
					if (res != FR_OK) break;
					if (ccl == ld_clust(fs, dj.dir)) break;	/* Found the entry */
					res = dir_next(&dj, 0);
				} while (res == FR_OK);
				if (res == FR_NO_FILE) res = FR_INT_ERR;/* It cannot be 'not found'. */
				if (res != FR_OK) break;
				get_fileinfo(&dj, &fno);		/* Get the directory name and push it to the buffer */
				for (n = 0; fno.fname[n]; n++) ;	/* Name length */
				if (i < n + 1) {	/* Insufficient space to store the path name? */
					res = FR_NOT_ENOUGH_CORE; break;
				}
				while (n) buff[--i] = fno.fname[--n];	/* Stack the name */
				buff[--i] = '/';
			}
		}
		if (res == FR_OK) {
			if (i == len) buff[--i] = '/';	/* Is it the root-directory? */
#if FF_VOLUMES >= 2			/* Put drive prefix */
			vl = 0;
#if FF_STR_VOLUME_ID >= 1	/* String volume ID */
			for (n = 0, vp = (const char*)VolumeStr[CurrVol]; vp[n]; n++) ;
			if (i >= n + 2) {
				if (FF_STR_VOLUME_ID == 2) *tp++ = (TCHAR)'/';
				for (vl = 0; vl < n; *tp++ = (TCHAR)vp[vl], vl++) ;
				if (FF_STR_VOLUME_ID == 1) *tp++ = (TCHAR)':';
				vl++;
			}
#else						/* Numeric volume ID */
			if (i >= 3) {
				*tp++ = (TCHAR)'0' + CurrVol;
				*tp++ = (TCHAR)':';
				vl = 2;
			}
#endif
			if (vl == 0) res = FR_NOT_ENOUGH_CORE;
#endif
			/* Add current directory path */
			if (res == FR_OK) {
				do {	/* Copy stacked path string */
					*tp++ = buff[i++];
				} while (i < len);
			}
		}
		FREE_NAMBUF();
	}

	*tp = 0;
	LEAVE_FF(fs, res);
}

#endif /* FF_FS_RPATH >= 2 */
#endif /* FF_FS_RPATH >= 1 */



#if FF_FS_MINIMIZE <= 2
/*-----------------------------------------------------------------------*/
/* Seek File Read/Write Pointer                                          */
/*-----------------------------------------------------------------------*/

FRESULT f_lseek (
	FIL* fp,		/* Pointer to the file object */
	FSIZE_t ofs		/* File pointer from top of file */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD clst, bcs;
	LBA_t nsect;
	FSIZE_t ifptr;
#if FF_USE_FASTSEEK
	DWORD cl, pcl, ncl, tcl, tlen, ulen;
	DWORD *tbl;
	LBA_t dsc;
#endif

	res = validate(&fp->obj, &fs);		/* Check validity of the file object */
	if (res == FR_OK) res = (FRESULT)fp->err;
#if FF_FS_EXFAT && !FF_FS_READONLY
	if (res == FR_OK && fs->fs_type == FS_EXFAT) {
		res = fill_last_frag(&fp->obj, fp->clust, 0xFFFFFFFF);	/* Fill last fragment on the FAT if needed */
	}
#endif
	if (res != FR_OK) LEAVE_FF(fs, res);

#if FF_USE_FASTSEEK
	if (fp->cltbl) {	/* Fast seek */
		if (ofs == CREATE_LINKMAP) {	/* Create CLMT */
			tbl = fp->cltbl;
			tlen = *tbl++; ulen = 2;	/* Given table size and required table size */
			cl = fp->obj.sclust;		/* Origin of the chain */
			if (cl != 0) {
				do {
					/* Get a fragment */
					tcl = cl; ncl = 0; ulen += 2;	/* Top, length and used items */
					do {
						pcl = cl; ncl++;
						cl = get_fat(&fp->obj, cl);
						if (cl <= 1) ABORT(fs, FR_INT_ERR);
						if (cl == 0xFFFFFFFF) ABORT(fs, FR_DISK_ERR);
					} while (cl == pcl + 1);
					if (ulen <= tlen) {		/* Store the length and top of the fragment */
						*tbl++ = ncl; *tbl++ = tcl;
					}
				} while (cl < fs->n_fatent);	/* Repeat until end of chain */
			}
			*fp->cltbl = ulen;	/* Number of items used */
			if (ulen <= tlen) {
				*tbl = 0;		/* Terminate table */
			} else {
				res = FR_NOT_ENOUGH_CORE;	/* Given table size is smaller than required */
			}
		} else {						/* Fast seek */
			if (ofs > fp->obj.objsize) ofs = fp->obj.objsize;	/* Clip offset at the file size */
			fp->fptr = ofs;				/* Set file pointer */
			if (ofs > 0) {
				fp->clust = clmt_clust(fp, ofs - 1);
				dsc = clst2sect(fs, fp->clust);
				if (dsc == 0) ABORT(fs, FR_INT_ERR);
				dsc += (DWORD)((ofs - 1) / SS(fs)) & (fs->csize - 1);
				if (fp->fptr % SS(fs) && dsc != fp->sect) {	/* Refill sector cache if needed */
#if !FF_FS_TINY
#if !FF_FS_READONLY
					if (fp->flag & FA_DIRTY) {		/* Write-back dirty sector cache */
						memcpy((BYTE *)(0xA0001000),fp->buf,SECTORSIZE*1);
						if (disk_write(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);
						fp->flag &= (BYTE)~FA_DIRTY;
					}
#endif
					if (disk_read1(fs->pdrv, (BYTE *)(0xA0001000), dsc, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);	/* Load current sector */
					memcpy(fp->buf,(BYTE *)(0xA0001000),SECTORSIZE*1);
#endif
					fp->sect = dsc;
				}
			}
		}
	} else
#endif

	/* Normal Seek */
	{
#if FF_FS_EXFAT
		if (fs->fs_type != FS_EXFAT && ofs >= 0x100000000) ofs = 0xFFFFFFFF;	/* Clip at 4 GiB - 1 if at FATxx */
#endif
		if (ofs > fp->obj.objsize && (FF_FS_READONLY || !(fp->flag & FA_WRITE))) {	/* In read-only mode, clip offset with the file size */
			ofs = fp->obj.objsize;
		}
		ifptr = fp->fptr;
		fp->fptr = nsect = 0;
		if (ofs > 0) {
			bcs = (DWORD)fs->csize * SS(fs);	/* Cluster size (byte) */
			if (ifptr > 0 &&
				(ofs - 1) / bcs >= (ifptr - 1) / bcs) {	/* When seek to same or following cluster, */
				fp->fptr = (ifptr - 1) & ~(FSIZE_t)(bcs - 1);	/* start from the current cluster */
				ofs -= fp->fptr;
				clst = fp->clust;
			} else {									/* When seek to back cluster, */
				clst = fp->obj.sclust;					/* start from the first cluster */
#if !FF_FS_READONLY
				if (clst == 0) {						/* If no cluster chain, create a new chain */
					clst = create_chain(&fp->obj, 0);
					if (clst == 1) ABORT(fs, FR_INT_ERR);
					if (clst == 0xFFFFFFFF) ABORT(fs, FR_DISK_ERR);
					fp->obj.sclust = clst;
				}
#endif
				fp->clust = clst;
			}
			if (clst != 0) {
				while (ofs > bcs) {						/* Cluster following loop */
					ofs -= bcs; fp->fptr += bcs;
#if !FF_FS_READONLY
					if (fp->flag & FA_WRITE) {			/* Check if in write mode or not */
						if (FF_FS_EXFAT && fp->fptr > fp->obj.objsize) {	/* No FAT chain object needs correct objsize to generate FAT value */
							fp->obj.objsize = fp->fptr;
							fp->flag |= FA_MODIFIED;
						}
						clst = create_chain(&fp->obj, clst);	/* Follow chain with forceed stretch */
						if (clst == 0) {				/* Clip file size in case of disk full */
							ofs = 0; break;
						}
					} else
#endif
					{
						clst = get_fat(&fp->obj, clst);	/* Follow cluster chain if not in write mode */
					}
					if (clst == 0xFFFFFFFF) ABORT(fs, FR_DISK_ERR);
					if (clst <= 1 || clst >= fs->n_fatent) ABORT(fs, FR_INT_ERR);
					fp->clust = clst;
				}
				fp->fptr += ofs;
				if (ofs % SS(fs)) {
					nsect = clst2sect(fs, clst);	/* Current sector */
					if (nsect == 0) ABORT(fs, FR_INT_ERR);
					nsect += (DWORD)(ofs / SS(fs));
				}
			}
		}
		if (!FF_FS_READONLY && fp->fptr > fp->obj.objsize) {	/* Set file change flag if the file size is extended */
			fp->obj.objsize = fp->fptr;
			fp->flag |= FA_MODIFIED;
		}
		if (fp->fptr % SS(fs) && nsect != fp->sect) {	/* Fill sector cache if needed */
#if !FF_FS_TINY
#if !FF_FS_READONLY
			if (fp->flag & FA_DIRTY) {			/* Write-back dirty sector cache */
				memcpy((BYTE *)(0xA0001000),fp->buf,SECTORSIZE*1);
				if (disk_write(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);
				fp->flag &= (BYTE)~FA_DIRTY;
			}
#endif
			if (disk_read1(fs->pdrv, (BYTE *)(0xA0001000), nsect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);	/* Fill sector cache */
			memcpy(fp->buf,(BYTE *)(0xA0001000),SECTORSIZE*1);
#endif
			fp->sect = nsect;
		}
	}

	LEAVE_FF(fs, res);
}



#if FF_FS_MINIMIZE <= 1
/*-----------------------------------------------------------------------*/
/* Create a Directory Object                                             */
/*-----------------------------------------------------------------------*/

FRESULT f_opendir (
	DIR* dp,			/* Pointer to directory object to create */
	const TCHAR* path	/* Pointer to the directory path */
)
{
	FRESULT res;
	FATFS *fs;
	DEF_NAMBUF


	if (!dp) return FR_INVALID_OBJECT;

	/* Get logical drive */
	res = mount_volume(&path, &fs, 0);
	if (res == FR_OK) {
		dp->obj.fs = fs;
		INIT_NAMBUF(fs);
		res = follow_path(dp, path);			/* Follow the path to the directory */
		if (res == FR_OK) {						/* Follow completed */
			if (!(dp->fn[NSFLAG] & NS_NONAME)) {	/* It is not the origin directory itself */
				if (dp->obj.attr & AM_DIR) {		/* This object is a sub-directory */
#if FF_FS_EXFAT
					if (fs->fs_type == FS_EXFAT) {
						dp->obj.c_scl = dp->obj.sclust;	/* Get containing directory inforamation */
						dp->obj.c_size = ((DWORD)dp->obj.objsize & 0xFFFFFF00) | dp->obj.stat;
						dp->obj.c_ofs = dp->blk_ofs;
						init_alloc_info(fs, &dp->obj);	/* Get object allocation info */
					} else
#endif
					{
						dp->obj.sclust = ld_clust(fs, dp->dir);	/* Get object allocation info */
					}
				} else {						/* This object is a file */
					res = FR_NO_PATH;
				}
			}
			if (res == FR_OK) {
				dp->obj.id = fs->id;
				res = dir_sdi(dp, 0);			/* Rewind directory */
#if FF_FS_LOCK
				if (res == FR_OK) {
					if (dp->obj.sclust != 0) {
						dp->obj.lockid = inc_share(dp, 0);	/* Lock the sub directory */
						if (!dp->obj.lockid) res = FR_TOO_MANY_OPEN_FILES;
					} else {
						dp->obj.lockid = 0;	/* Root directory need not to be locked */
					}
				}
#endif
			}
		}
		FREE_NAMBUF();
		if (res == FR_NO_FILE) res = FR_NO_PATH;
	}
	if (res != FR_OK) dp->obj.fs = 0;		/* Invalidate the directory object if function failed */

	LEAVE_FF(fs, res);
}




/*-----------------------------------------------------------------------*/
/* Close Directory                                                       */
/*-----------------------------------------------------------------------*/

FRESULT f_closedir (
	DIR *dp		/* Pointer to the directory object to be closed */
)
{
	FRESULT res;
	FATFS *fs;


	res = validate(&dp->obj, &fs);	/* Check validity of the file object */
	if (res == FR_OK) {
#if FF_FS_LOCK
		if (dp->obj.lockid) res = dec_share(dp->obj.lockid);	/* Decrement sub-directory open counter */
		if (res == FR_OK) dp->obj.fs = 0;	/* Invalidate directory object */
#else
		dp->obj.fs = 0;	/* Invalidate directory object */
#endif
#if FF_FS_REENTRANT
		unlock_volume(fs, FR_OK);	/* Unlock volume */
#endif
	}
	return res;
}




/*-----------------------------------------------------------------------*/
/* Read Directory Entries in Sequence                                    */
/*-----------------------------------------------------------------------*/

FRESULT f_readdir (
	DIR* dp,			/* Pointer to the open directory object */
	FILINFO* fno		/* Pointer to file information to return */
)
{
	FRESULT res;
	FATFS *fs;
	DEF_NAMBUF


	res = validate(&dp->obj, &fs);	/* Check validity of the directory object */
	if (res == FR_OK) {
		if (!fno) {
			res = dir_sdi(dp, 0);		/* Rewind the directory object */
		} else {
			INIT_NAMBUF(fs);
			res = DIR_READ_FILE(dp);		/* Read an item */
			if (res == FR_NO_FILE) res = FR_OK;	/* Ignore end of directory */
			if (res == FR_OK) {				/* A valid entry is found */
				get_fileinfo(dp, fno);		/* Get the object information */
				res = dir_next(dp, 0);		/* Increment index for next */
				if (res == FR_NO_FILE) res = FR_OK;	/* Ignore end of directory now */
			}
			FREE_NAMBUF();
		}
	}
	LEAVE_FF(fs, res);
}



#if FF_USE_FIND
/*-----------------------------------------------------------------------*/
/* Find Next File                                                        */
/*-----------------------------------------------------------------------*/

FRESULT f_findnext (
	DIR* dp,		/* Pointer to the open directory object */
	FILINFO* fno	/* Pointer to the file information structure */
)
{
	FRESULT res;


	for (;;) {
		res = f_readdir(dp, fno);		/* Get a directory item */
		if (res != FR_OK || !fno || !fno->fname[0]) break;	/* Terminate if any error or end of directory */
		if (pattern_match(dp->pat, fno->fname, 0, FIND_RECURS)) break;		/* Test for the file name */
#if FF_USE_LFN && FF_USE_FIND == 2
		if (pattern_match(dp->pat, fno->altname, 0, FIND_RECURS)) break;	/* Test for alternative name if exist */
#endif
	}
	return res;
}



/*-----------------------------------------------------------------------*/
/* Find First File                                                       */
/*-----------------------------------------------------------------------*/

FRESULT f_findfirst (
	DIR* dp,				/* Pointer to the blank directory object */
	FILINFO* fno,			/* Pointer to the file information structure */
	const TCHAR* path,		/* Pointer to the directory to open */
	const TCHAR* pattern	/* Pointer to the matching pattern */
)
{
	FRESULT res;


	dp->pat = pattern;		/* Save pointer to pattern string */
	res = f_opendir(dp, path);		/* Open the target directory */
	if (res == FR_OK) {
		res = f_findnext(dp, fno);	/* Find the first item */
	}
	return res;
}

#endif	/* FF_USE_FIND */



#if FF_FS_MINIMIZE == 0
/*-----------------------------------------------------------------------*/
/* Get File Status                                                       */
/*-----------------------------------------------------------------------*/

FRESULT f_stat (
	const TCHAR* path,	/* Pointer to the file path */
	FILINFO* fno		/* Pointer to file information to return */
)
{
	FRESULT res;
	DIR dj;
	DEF_NAMBUF


	/* Get logical drive */
	res = mount_volume(&path, &dj.obj.fs, 0);
	if (res == FR_OK) {
		INIT_NAMBUF(dj.obj.fs);
		res = follow_path(&dj, path);	/* Follow the file path */
		if (res == FR_OK) {				/* Follow completed */
			if (dj.fn[NSFLAG] & NS_NONAME) {	/* It is origin directory */
				res = FR_INVALID_NAME;
			} else {							/* Found an object */
				if (fno) get_fileinfo(&dj, fno);
			}
		}
		FREE_NAMBUF();
	}

	LEAVE_FF(dj.obj.fs, res);
}



#if !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* Get Number of Free Clusters                                           */
/*-----------------------------------------------------------------------*/

FRESULT f_getfree (
	const TCHAR* path,	/* Logical drive number */
	DWORD* nclst,		/* Pointer to a variable to return number of free clusters */
	FATFS** fatfs		/* Pointer to return pointer to corresponding filesystem object */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD nfree, clst, stat;
	LBA_t sect;
	UINT i;
	FFOBJID obj;


	/* Get logical drive */
	res = mount_volume(&path, &fs, 0);
	if (res == FR_OK) {
		*fatfs = fs;				/* Return ptr to the fs object */
		/* If free_clst is valid, return it without full FAT scan */
		if (fs->free_clst <= fs->n_fatent - 2) {
			*nclst = fs->free_clst;
		} else {
			/* Scan FAT to obtain number of free clusters */
			nfree = 0;
			if (fs->fs_type == FS_FAT12) {	/* FAT12: Scan bit field FAT entries */
				clst = 2; obj.fs = fs;
				do {
					stat = get_fat(&obj, clst);
					if (stat == 0xFFFFFFFF) {
						res = FR_DISK_ERR; break;
					}
					if (stat == 1) {
						res = FR_INT_ERR; break;
					}
					if (stat == 0) nfree++;
				} while (++clst < fs->n_fatent);
			} else {
#if FF_FS_EXFAT
//				xil_printf("wfeng: fun = %s, line = %d fs->n_fatent = %lu\n", __func__, __LINE__, fs->n_fatent);
				if (fs->fs_type == FS_EXFAT) {	/* exFAT: Scan allocation bitmap */
					BYTE bm;
					UINT b;

					clst = fs->n_fatent - 2;	/* Number of clusters */
					sect = fs->bitbase;			/* Bitmap sector */
					i = 0;						/* Offset in the sector */
					do {	/* Counts numbuer of bits with zero in the bitmap */
						if (i == 0) {	/* New sector? */
							res = move_window(fs, sect++);
							if (res != FR_OK) break;
						}
						for (b = 8, bm = ~fs->win[i]; b && clst; b--, clst--) {
							nfree += bm & 1;
							bm >>= 1;
						}
						i = (i + 1) % SS(fs);
					} while (clst);
				} else
#endif
				{	/* FAT16/32: Scan WORD/DWORD FAT entries */
					clst = fs->n_fatent;	/* Number of entries */
					sect = fs->fatbase;		/* Top of the FAT */
					i = 0;					/* Offset in the sector */
					do {	/* Counts numbuer of entries with zero in the FAT */
						if (i == 0) {	/* New sector? */
							res = move_window(fs, sect++);
							if (res != FR_OK) break;
						}
						if (fs->fs_type == FS_FAT16) {
							if (ld_word(fs->win + i) == 0) nfree++;
							i += 2;
						} else {
							if ((ld_dword(fs->win + i) & 0x0FFFFFFF) == 0) nfree++;
							i += 4;
						}
						i %= SS(fs);
					} while (--clst);
				}
			}
			if (res == FR_OK) {		/* Update parameters if succeeded */
				*nclst = nfree;			/* Return the free clusters */
				fs->free_clst = nfree;	/* Now free_clst is valid */
				fs->fsi_flag |= 1;		/* FAT32: FSInfo is to be updated */
			}
		}
	}

	LEAVE_FF(fs, res);
}




/*-----------------------------------------------------------------------*/
/* Truncate File                                                         */
/*-----------------------------------------------------------------------*/

FRESULT f_truncate (
	FIL* fp		/* Pointer to the file object */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD ncl;


	res = validate(&fp->obj, &fs);	/* Check validity of the file object */
	if (res != FR_OK || (res = (FRESULT)fp->err) != FR_OK) LEAVE_FF(fs, res);
	if (!(fp->flag & FA_WRITE)) LEAVE_FF(fs, FR_DENIED);	/* Check access mode */

	if (fp->fptr < fp->obj.objsize) {	/* Process when fptr is not on the eof */
		if (fp->fptr == 0) {	/* When set file size to zero, remove entire cluster chain */
			res = remove_chain(&fp->obj, fp->obj.sclust, 0);
			fp->obj.sclust = 0;
		} else {				/* When truncate a part of the file, remove remaining clusters */
			ncl = get_fat(&fp->obj, fp->clust);
			res = FR_OK;
			if (ncl == 0xFFFFFFFF) res = FR_DISK_ERR;
			if (ncl == 1) res = FR_INT_ERR;
			if (res == FR_OK && ncl < fs->n_fatent) {
				res = remove_chain(&fp->obj, ncl, fp->clust);
			}
		}
		fp->obj.objsize = fp->fptr;	/* Set file size to current read/write point */
		fp->flag |= FA_MODIFIED;
#if !FF_FS_TINY
		if (res == FR_OK && (fp->flag & FA_DIRTY)) {
			memcpy((BYTE *)(0xA0001000),fp->buf,SECTORSIZE*1);
			if (disk_write(fs->pdrv, (BYTE *)(0xA0001000), fp->sect, 1) != RES_OK) {
				res = FR_DISK_ERR;
			} else {
				fp->flag &= (BYTE)~FA_DIRTY;
			}
		}
#endif
		if (res != FR_OK) ABORT(fs, res);
	}

	LEAVE_FF(fs, res);
}




/*-----------------------------------------------------------------------*/
/* Delete a File/Directory                                               */
/*-----------------------------------------------------------------------*/

FRESULT f_unlink (
	const TCHAR* path		/* Pointer to the file or directory path */
)
{
	FRESULT res;
	FATFS *fs;
	DIR dj, sdj;
	DWORD dclst = 0;
#if FF_FS_EXFAT
	FFOBJID obj;
#endif
	DEF_NAMBUF


	/* Get logical drive */
	res = mount_volume(&path, &fs, FA_WRITE);
	if (res == FR_OK) {
		dj.obj.fs = fs;
		INIT_NAMBUF(fs);
		res = follow_path(&dj, path);		/* Follow the file path */
		if (FF_FS_RPATH && res == FR_OK && (dj.fn[NSFLAG] & NS_DOT)) {
			res = FR_INVALID_NAME;			/* Cannot remove dot entry */
		}
#if FF_FS_LOCK
		if (res == FR_OK) res = chk_share(&dj, 2);	/* Check if it is an open object */
#endif
		if (res == FR_OK) {					/* The object is accessible */
			if (dj.fn[NSFLAG] & NS_NONAME) {
				res = FR_INVALID_NAME;		/* Cannot remove the origin directory */
			} else {
				if (dj.obj.attr & AM_RDO) {
					res = FR_DENIED;		/* Cannot remove R/O object */
				}
			}
			if (res == FR_OK) {
#if FF_FS_EXFAT
				obj.fs = fs;
				if (fs->fs_type == FS_EXFAT) {
					init_alloc_info(fs, &obj);
					dclst = obj.sclust;
				} else
#endif
				{
					dclst = ld_clust(fs, dj.dir);
				}
				if (dj.obj.attr & AM_DIR) {			/* Is it a sub-directory? */
#if FF_FS_RPATH != 0
					if (dclst == fs->cdir) {	 	/* Is it the current directory? */
						res = FR_DENIED;
					} else
#endif
					{
						sdj.obj.fs = fs;			/* Open the sub-directory */
						sdj.obj.sclust = dclst;
#if FF_FS_EXFAT
						if (fs->fs_type == FS_EXFAT) {
							sdj.obj.objsize = obj.objsize;
							sdj.obj.stat = obj.stat;
						}
#endif
						res = dir_sdi(&sdj, 0);
						if (res == FR_OK) {
							res = DIR_READ_FILE(&sdj);			/* Test if the directory is empty */
							if (res == FR_OK) res = FR_DENIED;	/* Not empty? */
							if (res == FR_NO_FILE) res = FR_OK;	/* Empty? */
						}
					}
				}
			}
			if (res == FR_OK) {
				res = dir_remove(&dj);			/* Remove the directory entry */
				if (res == FR_OK && dclst != 0) {	/* Remove the cluster chain if exist */
#if FF_FS_EXFAT
					res = remove_chain(&obj, dclst, 0);
#else
					res = remove_chain(&dj.obj, dclst, 0);
#endif
				}
				if (res == FR_OK) res = sync_fs(fs);
			}
		}
		FREE_NAMBUF();
	}

	LEAVE_FF(fs, res);
}




/*-----------------------------------------------------------------------*/
/* Create a Directory                                                    */
/*-----------------------------------------------------------------------*/

FRESULT f_mkdir (
	const TCHAR* path		/* Pointer to the directory path */
)
{
	FRESULT res;
	FATFS *fs;
	DIR dj;
	FFOBJID sobj;
	DWORD dcl, pcl, tm;
	DEF_NAMBUF


	res = mount_volume(&path, &fs, FA_WRITE);	/* Get logical drive */

	if (res == FR_OK) {
		dj.obj.fs = fs;
		INIT_NAMBUF(fs);
		res = follow_path(&dj, path);			/* Follow the file path */

		if (res == FR_OK) res = FR_EXIST;		/* Name collision? */

		if (FF_FS_RPATH && res == FR_NO_FILE && (dj.fn[NSFLAG] & NS_DOT)) {	/* Invalid name? */
			res = FR_INVALID_NAME;
		}
		if (res == FR_NO_FILE) {				/* It is clear to create a new directory */
			sobj.fs = fs;						/* New object id to create a new chain */

			dcl = create_chain(&sobj, 0);		/* Allocate a cluster for the new directory */
			res = FR_OK;
			if (dcl == 0) res = FR_DENIED;		/* No space to allocate a new cluster? */
			if (dcl == 1) res = FR_INT_ERR;		/* Any insanity? */
			if (dcl == 0xFFFFFFFF) res = FR_DISK_ERR;	/* Disk error? */
			tm = GET_FATTIME();
			if (res == FR_OK) {
				res = dir_clear(fs, dcl);		/* Clean up the new table */
				if (res == FR_OK) {
					if (!FF_FS_EXFAT || fs->fs_type != FS_EXFAT) {	/* Create dot entries (FAT only) */
						memset(fs->win + DIR_Name, ' ', 11);	/* Create "." entry */
						fs->win[DIR_Name] = '.';
						fs->win[DIR_Attr] = AM_DIR;
						st_dword(fs->win + DIR_ModTime, tm);
						st_clust(fs, fs->win, dcl);
						memcpy(fs->win + SZDIRE, fs->win, SZDIRE);	/* Create ".." entry */
						fs->win[SZDIRE + 1] = '.'; pcl = dj.obj.sclust;
						st_clust(fs, fs->win + SZDIRE, pcl);
						fs->wflag = 1;
					}
					res = dir_register(&dj);	/* Register the object to the parent directoy */
				}
			}
			if (res == FR_OK) {
#if FF_FS_EXFAT

				if (fs->fs_type == FS_EXFAT) {	/* Initialize directory entry block */
					st_dword(fs->dirbuf + XDIR_ModTime, tm);	/* Created time */
					st_dword(fs->dirbuf + XDIR_FstClus, dcl);	/* Table start cluster */
					st_dword(fs->dirbuf + XDIR_FileSize, (DWORD)fs->csize * SS(fs));	/* Directory size needs to be valid */
					st_dword(fs->dirbuf + XDIR_ValidFileSize, (DWORD)fs->csize * SS(fs));
					fs->dirbuf[XDIR_GenFlags] = 3;				/* Initialize the object flag */
					fs->dirbuf[XDIR_Attr] = AM_DIR;				/* Attribute */
					res = store_xdir(&dj);

				} else
#endif
				{
					st_dword(dj.dir + DIR_ModTime, tm);	/* Created time */
					st_clust(fs, dj.dir, dcl);			/* Table start cluster */
					dj.dir[DIR_Attr] = AM_DIR;			/* Attribute */
					fs->wflag = 1;
				}
				if (res == FR_OK) {
					res = sync_fs(fs);
				}
			} else {
				remove_chain(&sobj, dcl, 0);		/* Could not register, remove the allocated cluster */
			}
		}

		FREE_NAMBUF();
	}

	LEAVE_FF(fs, res);
}




/*-----------------------------------------------------------------------*/
/* Rename a File/Directory                                               */
/*-----------------------------------------------------------------------*/

FRESULT  f_rename(
	const TCHAR* path_old,	/* Pointer to the object name to be renamed */
	const TCHAR* path_new	/* Pointer to the new name */
)
{
	FRESULT res;
	FATFS *fs;
	DIR djo, djn;
	BYTE buf[FF_FS_EXFAT ? SZDIRE * 2 : SZDIRE], *dir;
	LBA_t sect;
	DEF_NAMBUF


	get_ldnumber(&path_new);						/* Snip the drive number of new name off */
	res = mount_volume(&path_old, &fs, FA_WRITE);	/* Get logical drive of the old object */
	if (res == FR_OK) {
		djo.obj.fs = fs;
		INIT_NAMBUF(fs);
		res = follow_path(&djo, path_old);			/* Check old object */
		if (res == FR_OK && (djo.fn[NSFLAG] & (NS_DOT | NS_NONAME))) res = FR_INVALID_NAME;	/* Check validity of name */
#if FF_FS_LOCK
		if (res == FR_OK) {
			res = chk_share(&djo, 2);
		}
#endif
		if (res == FR_OK) {					/* Object to be renamed is found */
#if FF_FS_EXFAT
			if (fs->fs_type == FS_EXFAT) {	/* At exFAT volume */
				BYTE nf, nn;
				WORD nh;

				memcpy(buf, fs->dirbuf, SZDIRE * 2);	/* Save 85+C0 entry of old object */
				memcpy(&djn, &djo, sizeof djo);
				res = follow_path(&djn, path_new);		/* Make sure if new object name is not in use */
				if (res == FR_OK) {						/* Is new name already in use by any other object? */
					res = (djn.obj.sclust == djo.obj.sclust && djn.dptr == djo.dptr) ? FR_NO_FILE : FR_EXIST;
				}
				if (res == FR_NO_FILE) { 				/* It is a valid path and no name collision */
					res = dir_register(&djn);			/* Register the new entry */
					if (res == FR_OK) {
						nf = fs->dirbuf[XDIR_NumSec]; nn = fs->dirbuf[XDIR_NumName];
						nh = ld_word(fs->dirbuf + XDIR_NameHash);
						memcpy(fs->dirbuf, buf, SZDIRE * 2);	/* Restore 85+C0 entry */
						fs->dirbuf[XDIR_NumSec] = nf; fs->dirbuf[XDIR_NumName] = nn;
						st_word(fs->dirbuf + XDIR_NameHash, nh);
						if (!(fs->dirbuf[XDIR_Attr] & AM_DIR)) fs->dirbuf[XDIR_Attr] |= AM_ARC;	/* Set archive attribute if it is a file */
/* Start of critical section where an interruption can cause a cross-link */
						res = store_xdir(&djn);
					}
				}
			} else
#endif
			{	/* At FAT/FAT32 volume */
				memcpy(buf, djo.dir, SZDIRE);			/* Save directory entry of the object */
				memcpy(&djn, &djo, sizeof (DIR));		/* Duplicate the directory object */
				res = follow_path(&djn, path_new);		/* Make sure if new object name is not in use */
				if (res == FR_OK) {						/* Is new name already in use by any other object? */
					res = (djn.obj.sclust == djo.obj.sclust && djn.dptr == djo.dptr) ? FR_NO_FILE : FR_EXIST;
				}
				if (res == FR_NO_FILE) { 				/* It is a valid path and no name collision */
					res = dir_register(&djn);			/* Register the new entry */
					if (res == FR_OK) {
						dir = djn.dir;					/* Copy directory entry of the object except name */
						memcpy(dir + 13, buf + 13, SZDIRE - 13);
						dir[DIR_Attr] = buf[DIR_Attr];
						if (!(dir[DIR_Attr] & AM_DIR)) dir[DIR_Attr] |= AM_ARC;	/* Set archive attribute if it is a file */
						fs->wflag = 1;
						if ((dir[DIR_Attr] & AM_DIR) && djo.obj.sclust != djn.obj.sclust) {	/* Update .. entry in the sub-directory if needed */
							sect = clst2sect(fs, ld_clust(fs, dir));
							if (sect == 0) {
								res = FR_INT_ERR;
							} else {
/* Start of critical section where an interruption can cause a cross-link */
								res = move_window(fs, sect);
								dir = fs->win + SZDIRE * 1;	/* Ptr to .. entry */
								if (res == FR_OK && dir[1] == '.') {
									st_clust(fs, dir, djn.obj.sclust);
									fs->wflag = 1;
								}
							}
						}
					}
				}
			}
			if (res == FR_OK) {
				res = dir_remove(&djo);		/* Remove old entry */
				if (res == FR_OK) {
					res = sync_fs(fs);
				}
			}
/* End of the critical section */
		}
		FREE_NAMBUF();
	}

	LEAVE_FF(fs, res);
}

#endif /* !FF_FS_READONLY */
#endif /* FF_FS_MINIMIZE == 0 */
#endif /* FF_FS_MINIMIZE <= 1 */
#endif /* FF_FS_MINIMIZE <= 2 */



#if FF_USE_CHMOD && !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* Change Attribute                                                      */
/*-----------------------------------------------------------------------*/

FRESULT f_chmod (
	const TCHAR* path,	/* Pointer to the file path */
	BYTE attr,			/* Attribute bits */
	BYTE mask			/* Attribute mask to change */
)
{
	FRESULT res;
	FATFS *fs;
	DIR dj;
	DEF_NAMBUF


	res = mount_volume(&path, &fs, FA_WRITE);	/* Get logical drive */
	if (res == FR_OK) {
		dj.obj.fs = fs;
		INIT_NAMBUF(fs);
		res = follow_path(&dj, path);	/* Follow the file path */
		if (res == FR_OK && (dj.fn[NSFLAG] & (NS_DOT | NS_NONAME))) res = FR_INVALID_NAME;	/* Check object validity */
		if (res == FR_OK) {
			mask &= AM_RDO|AM_HID|AM_SYS|AM_ARC;	/* Valid attribute mask */
#if FF_FS_EXFAT
			if (fs->fs_type == FS_EXFAT) {
				fs->dirbuf[XDIR_Attr] = (attr & mask) | (fs->dirbuf[XDIR_Attr] & (BYTE)~mask);	/* Apply attribute change */
				res = store_xdir(&dj);
			} else
#endif
			{
				dj.dir[DIR_Attr] = (attr & mask) | (dj.dir[DIR_Attr] & (BYTE)~mask);	/* Apply attribute change */
				fs->wflag = 1;
			}
			if (res == FR_OK) {
				res = sync_fs(fs);
			}
		}
		FREE_NAMBUF();
	}

	LEAVE_FF(fs, res);
}




/*-----------------------------------------------------------------------*/
/* Change Timestamp                                                      */
/*-----------------------------------------------------------------------*/

FRESULT f_utime (
	const TCHAR* path,	/* Pointer to the file/directory name */
	const FILINFO* fno	/* Pointer to the timestamp to be set */
)
{
	FRESULT res;
	FATFS *fs;
	DIR dj;
	DEF_NAMBUF


	res = mount_volume(&path, &fs, FA_WRITE);	/* Get logical drive */
	if (res == FR_OK) {
		dj.obj.fs = fs;
		INIT_NAMBUF(fs);
		res = follow_path(&dj, path);	/* Follow the file path */
		if (res == FR_OK && (dj.fn[NSFLAG] & (NS_DOT | NS_NONAME))) res = FR_INVALID_NAME;	/* Check object validity */
		if (res == FR_OK) {
#if FF_FS_EXFAT
			if (fs->fs_type == FS_EXFAT) {
				st_dword(fs->dirbuf + XDIR_ModTime, (DWORD)fno->fdate << 16 | fno->ftime);
				res = store_xdir(&dj);
			} else
#endif
			{
				st_dword(dj.dir + DIR_ModTime, (DWORD)fno->fdate << 16 | fno->ftime);
				fs->wflag = 1;
			}
			if (res == FR_OK) {
				res = sync_fs(fs);
			}
		}
		FREE_NAMBUF();
	}

	LEAVE_FF(fs, res);
}

#endif	/* FF_USE_CHMOD && !FF_FS_READONLY */



#if FF_USE_LABEL
/*-----------------------------------------------------------------------*/
/* Get Volume Label                                                      */
/*-----------------------------------------------------------------------*/

FRESULT f_getlabel (
	const TCHAR* path,	/* Logical drive number */
	TCHAR* label,		/* Buffer to store the volume label */
	DWORD* vsn			/* Variable to store the volume serial number */
)
{
	FRESULT res;
	FATFS *fs;
	DIR dj;
	UINT si, di;
	WCHAR wc;

	/* Get logical drive */
	res = mount_volume(&path, &fs, 0);

	/* Get volume label */
	if (res == FR_OK && label) {
		dj.obj.fs = fs; dj.obj.sclust = 0;	/* Open root directory */
		res = dir_sdi(&dj, 0);
		if (res == FR_OK) {
		 	res = DIR_READ_LABEL(&dj);		/* Find a volume label entry */
		 	if (res == FR_OK) {
#if FF_FS_EXFAT
				if (fs->fs_type == FS_EXFAT) {
					WCHAR hs;
					UINT nw;

					for (si = di = hs = 0; si < dj.dir[XDIR_NumLabel]; si++) {	/* Extract volume label from 83 entry */
						wc = ld_word(dj.dir + XDIR_Label + si * 2);
						if (hs == 0 && IsSurrogate(wc)) {	/* Is the code a surrogate? */
							hs = wc; continue;
						}
						nw = put_utf((DWORD)hs << 16 | wc, &label[di], 4);	/* Store it in API encoding */
						if (nw == 0) {		/* Encode error? */
							di = 0; break;
						}
						di += nw;
						hs = 0;
					}
					if (hs != 0) di = 0;	/* Broken surrogate pair? */
					label[di] = 0;
				} else
#endif
				{
					si = di = 0;		/* Extract volume label from AM_VOL entry */
					while (si < 11) {
						wc = dj.dir[si++];
#if FF_USE_LFN && FF_LFN_UNICODE >= 1 	/* Unicode output */
						if (dbc_1st((BYTE)wc) && si < 11) wc = wc << 8 | dj.dir[si++];	/* Is it a DBC? */
						wc = ff_oem2uni(wc, CODEPAGE);		/* Convert it into Unicode */
						if (wc == 0) {		/* Invalid char in current code page? */
							di = 0; break;
						}
						di += put_utf(wc, &label[di], 4);	/* Store it in Unicode */
#else									/* ANSI/OEM output */
						label[di++] = (TCHAR)wc;
#endif
					}
					do {				/* Truncate trailing spaces */
						label[di] = 0;
						if (di == 0) break;
					} while (label[--di] == ' ');
				}
			}
		}
		if (res == FR_NO_FILE) {	/* No label entry and return nul string */
			label[0] = 0;
			res = FR_OK;
		}
	}

	/* Get volume serial number */
	if (res == FR_OK && vsn) {
		res = move_window(fs, fs->volbase);
		if (res == FR_OK) {
			switch (fs->fs_type) {
			case FS_EXFAT:
				di = BPB_VolIDEx;
				break;

			case FS_FAT32:
				di = BS_VolID32;
				break;

			default:
				di = BS_VolID;
			}
			*vsn = ld_dword(fs->win + di);
		}
	}

	LEAVE_FF(fs, res);
}



#if !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* Set Volume Label                                                      */
/*-----------------------------------------------------------------------*/

FRESULT f_setlabel (
	const TCHAR* label	/* Volume label to set with heading logical drive number */
)
{
	FRESULT res;
	FATFS *fs;
	DIR dj;
	BYTE dirvn[22];
	UINT di;
	WCHAR wc;
	static const char badchr[18] = "+.,;=[]" "/*:<>|\\\"\?\x7F";	/* [0..16] for FAT, [7..16] for exFAT */
#if FF_USE_LFN
	DWORD dc;
#endif

	/* Get logical drive */
	res = mount_volume(&label, &fs, FA_WRITE);
	if (res != FR_OK) LEAVE_FF(fs, res);

#if FF_FS_EXFAT
	if (fs->fs_type == FS_EXFAT) {	/* On the exFAT volume */
		memset(dirvn, 0, 22);
		di = 0;
		while ((UINT)*label >= ' ') {	/* Create volume label */
			dc = tchar2uni(&label);	/* Get a Unicode character */
			if (dc >= 0x10000) {
				if (dc == 0xFFFFFFFF || di >= 10) {	/* Wrong surrogate or buffer overflow */
					dc = 0;
				} else {
					st_word(dirvn + di * 2, (WCHAR)(dc >> 16)); di++;
				}
			}
			if (dc == 0 || strchr(&badchr[7], (int)dc) || di >= 11) {	/* Check validity of the volume label */
				LEAVE_FF(fs, FR_INVALID_NAME);
			}
			st_word(dirvn + di * 2, (WCHAR)dc); di++;
		}
	} else
#endif
	{	/* On the FAT/FAT32 volume */
		memset(dirvn, ' ', 11);
		di = 0;
		while ((UINT)*label >= ' ') {	/* Create volume label */
#if FF_USE_LFN
			dc = tchar2uni(&label);
			wc = (dc < 0x10000) ? ff_uni2oem(ff_wtoupper(dc), CODEPAGE) : 0;
#else									/* ANSI/OEM input */
			wc = (BYTE)*label++;
			if (dbc_1st((BYTE)wc)) wc = dbc_2nd((BYTE)*label) ? wc << 8 | (BYTE)*label++ : 0;
			if (IsLower(wc)) wc -= 0x20;		/* To upper ASCII characters */
#if FF_CODE_PAGE == 0
			if (ExCvt && wc >= 0x80) wc = ExCvt[wc - 0x80];	/* To upper extended characters (SBCS cfg) */
#elif FF_CODE_PAGE < 900
			if (wc >= 0x80) wc = ExCvt[wc - 0x80];	/* To upper extended characters (SBCS cfg) */
#endif
#endif
			if (wc == 0 || strchr(&badchr[0], (int)wc) || di >= (UINT)((wc >= 0x100) ? 10 : 11)) {	/* Reject invalid characters for volume label */
				LEAVE_FF(fs, FR_INVALID_NAME);
			}
			if (wc >= 0x100) dirvn[di++] = (BYTE)(wc >> 8);
			dirvn[di++] = (BYTE)wc;
		}
		if (dirvn[0] == DDEM) LEAVE_FF(fs, FR_INVALID_NAME);	/* Reject illegal name (heading DDEM) */
		while (di && dirvn[di - 1] == ' ') di--;				/* Snip trailing spaces */
	}

	/* Set volume label */
	dj.obj.fs = fs; dj.obj.sclust = 0;	/* Open root directory */
	res = dir_sdi(&dj, 0);
	if (res == FR_OK) {
		res = DIR_READ_LABEL(&dj);	/* Get volume label entry */
		if (res == FR_OK) {
			if (FF_FS_EXFAT && fs->fs_type == FS_EXFAT) {
				dj.dir[XDIR_NumLabel] = (BYTE)di;	/* Change the volume label */
				memcpy(dj.dir + XDIR_Label, dirvn, 22);
			} else {
				if (di != 0) {
					memcpy(dj.dir, dirvn, 11);	/* Change the volume label */
				} else {
					dj.dir[DIR_Name] = DDEM;	/* Remove the volume label */
				}
			}
			fs->wflag = 1;
			res = sync_fs(fs);
		} else {			/* No volume label entry or an error */
			if (res == FR_NO_FILE) {
				res = FR_OK;
				if (di != 0) {	/* Create a volume label entry */
					res = dir_alloc(&dj, 1);	/* Allocate an entry */
					if (res == FR_OK) {
						memset(dj.dir, 0, SZDIRE);	/* Clean the entry */
						if (FF_FS_EXFAT && fs->fs_type == FS_EXFAT) {
							dj.dir[XDIR_Type] = ET_VLABEL;	/* Create volume label entry */
							dj.dir[XDIR_NumLabel] = (BYTE)di;
							memcpy(dj.dir + XDIR_Label, dirvn, 22);
						} else {
							dj.dir[DIR_Attr] = AM_VOL;		/* Create volume label entry */
							memcpy(dj.dir, dirvn, 11);
						}
						fs->wflag = 1;
						res = sync_fs(fs);
					}
				}
			}
		}
	}

	LEAVE_FF(fs, res);
}

#endif /* !FF_FS_READONLY */
#endif /* FF_USE_LABEL */



#if FF_USE_EXPAND && !FF_FS_READONLY
/*-----------------------------------------------------------------------*/
/* Allocate a Contiguous Blocks to the File                              */
/*-----------------------------------------------------------------------*/

FRESULT f_expand (
	FIL* fp,		/* Pointer to the file object */
	FSIZE_t fsz,	/* File size to be expanded to */
	BYTE opt		/* Operation mode 0:Find and prepare or 1:Find and allocate */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD n, clst, stcl, scl, ncl, tcl, lclst;


	res = validate(&fp->obj, &fs);		/* Check validity of the file object */
	if (res != FR_OK || (res = (FRESULT)fp->err) != FR_OK) LEAVE_FF(fs, res);
	if (fsz == 0 || fp->obj.objsize != 0 || !(fp->flag & FA_WRITE)) LEAVE_FF(fs, FR_DENIED);
#if FF_FS_EXFAT
	if (fs->fs_type != FS_EXFAT && fsz >= 0x100000000) LEAVE_FF(fs, FR_DENIED);	/* Check if in size limit */
#endif
	n = (DWORD)fs->csize * SS(fs);	/* Cluster size */
	tcl = (DWORD)(fsz / n) + ((fsz & (n - 1)) ? 1 : 0);	/* Number of clusters required */
	stcl = fs->last_clst; lclst = 0;
	if (stcl < 2 || stcl >= fs->n_fatent) stcl = 2;

#if FF_FS_EXFAT
	if (fs->fs_type == FS_EXFAT) {
		scl = find_bitmap(fs, stcl, tcl);			/* Find a contiguous cluster block */
		if (scl == 0) res = FR_DENIED;				/* No contiguous cluster block was found */
		if (scl == 0xFFFFFFFF) res = FR_DISK_ERR;
		if (res == FR_OK) {	/* A contiguous free area is found */
			if (opt) {		/* Allocate it now */
				res = change_bitmap(fs, scl, tcl, 1);	/* Mark the cluster block 'in use' */
				lclst = scl + tcl - 1;
			} else {		/* Set it as suggested point for next allocation */
				lclst = scl - 1;
			}
		}
	} else
#endif
	{
		scl = clst = stcl; ncl = 0;
		for (;;) {	/* Find a contiguous cluster block */
			n = get_fat(&fp->obj, clst);
			if (++clst >= fs->n_fatent) clst = 2;
			if (n == 1) {
				res = FR_INT_ERR; break;
			}
			if (n == 0xFFFFFFFF) {
				res = FR_DISK_ERR; break;
			}
			if (n == 0) {	/* Is it a free cluster? */
				if (++ncl == tcl) break;	/* Break if a contiguous cluster block is found */
			} else {
				scl = clst; ncl = 0;		/* Not a free cluster */
			}
			if (clst == stcl) {		/* No contiguous cluster? */
				res = FR_DENIED; break;
			}
		}
		if (res == FR_OK) {	/* A contiguous free area is found */
			if (opt) {		/* Allocate it now */
				for (clst = scl, n = tcl; n; clst++, n--) {	/* Create a cluster chain on the FAT */
					res = put_fat(fs, clst, (n == 1) ? 0xFFFFFFFF : clst + 1);
					if (res != FR_OK) break;
					lclst = clst;
				}
			} else {		/* Set it as suggested point for next allocation */
				lclst = scl - 1;
			}
		}
	}

	if (res == FR_OK) {
		fs->last_clst = lclst;		/* Set suggested start cluster to start next */
		if (opt) {	/* Is it allocated now? */
			fp->obj.sclust = scl;		/* Update object allocation information */
			fp->obj.objsize = fsz;
			if (FF_FS_EXFAT) fp->obj.stat = 2;	/* Set status 'contiguous chain' */
			fp->flag |= FA_MODIFIED;
			if (fs->free_clst <= fs->n_fatent - 2) {	/* Update FSINFO */
				fs->free_clst -= tcl;
				fs->fsi_flag |= 1;
			}
		}
	}

	LEAVE_FF(fs, res);
}

#endif /* FF_USE_EXPAND && !FF_FS_READONLY */



#if FF_USE_FORWARD
/*-----------------------------------------------------------------------*/
/* Forward Data to the Stream Directly                                   */
/*-----------------------------------------------------------------------*/

FRESULT f_forward (
	FIL* fp, 						/* Pointer to the file object */
	UINT (*func)(const BYTE*,UINT),	/* Pointer to the streaming function */
	UINT btf,						/* Number of bytes to forward */
	UINT* bf						/* Pointer to number of bytes forwarded */
)
{
	FRESULT res;
	FATFS *fs;
	DWORD clst;
	LBA_t sect;
	FSIZE_t remain;
	UINT rcnt, csect;
	BYTE *dbuf;


	*bf = 0;	/* Clear transfer byte counter */
	res = validate(&fp->obj, &fs);		/* Check validity of the file object */
	if (res != FR_OK || (res = (FRESULT)fp->err) != FR_OK) LEAVE_FF(fs, res);
	if (!(fp->flag & FA_READ)) LEAVE_FF(fs, FR_DENIED);	/* Check access mode */

	remain = fp->obj.objsize - fp->fptr;
	if (btf > remain) btf = (UINT)remain;			/* Truncate btf by remaining bytes */

	for ( ; btf > 0 && (*func)(0, 0); fp->fptr += rcnt, *bf += rcnt, btf -= rcnt) {	/* Repeat until all data transferred or stream goes busy */
		csect = (UINT)(fp->fptr / SS(fs) & (fs->csize - 1));	/* Sector offset in the cluster */
		if (fp->fptr % SS(fs) == 0) {				/* On the sector boundary? */
			if (csect == 0) {						/* On the cluster boundary? */
				clst = (fp->fptr == 0) ?			/* On the top of the file? */
					fp->obj.sclust : get_fat(&fp->obj, fp->clust);
				if (clst <= 1) ABORT(fs, FR_INT_ERR);
				if (clst == 0xFFFFFFFF) ABORT(fs, FR_DISK_ERR);
				fp->clust = clst;					/* Update current cluster */
			}
		}
		sect = clst2sect(fs, fp->clust);			/* Get current data sector */
		if (sect == 0) ABORT(fs, FR_INT_ERR);
		sect += csect;
#if FF_FS_TINY
		if (move_window(fs, sect) != FR_OK) ABORT(fs, FR_DISK_ERR);	/* Move sector window to the file data */
		dbuf = fs->win;
#else
		if (fp->sect != sect) {		/* Fill sector cache with file data */
#if !FF_FS_READONLY
			if (fp->flag & FA_DIRTY) {		/* Write-back dirty sector cache */
				if (disk_write(fs->pdrv, fp->buf, fp->sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);
				fp->flag &= (BYTE)~FA_DIRTY;
			}
#endif
			if (disk_read(fs->pdrv, fp->buf, sect, 1) != RES_OK) ABORT(fs, FR_DISK_ERR);
		}
		dbuf = fp->buf;
#endif
		fp->sect = sect;
		rcnt = SS(fs) - (UINT)fp->fptr % SS(fs);	/* Number of bytes remains in the sector */
		if (rcnt > btf) rcnt = btf;					/* Clip it by btr if needed */
		rcnt = (*func)(dbuf + ((UINT)fp->fptr % SS(fs)), rcnt);	/* Forward the file data */
		if (rcnt == 0) ABORT(fs, FR_INT_ERR);
	}

	LEAVE_FF(fs, FR_OK);
}
#endif /* FF_USE_FORWARD */



//#if !FF_FS_READONLY && FF_USE_MKFS  //wfeng
/*-----------------------------------------------------------------------*/
/* Create FAT/exFAT volume (with sub-functions)                          */
/*-----------------------------------------------------------------------*/

#define N_SEC_TRACK 63			/* Sectors per track for determination of drive CHS */
#define	GPT_ALIGN	0x100000	/* Alignment of partitions in GPT [byte] (>=128KB) */
#define GPT_ITEMS	128			/* Number of GPT table size (>=128, sector aligned) */


/* Create partitions on the physical drive in format of MBR or GPT */

static FRESULT create_partition (
	BYTE drv,			/* Physical drive number */
	const LBA_t plst[],	/* Partition list */
	BYTE sys,			/* System ID for each partition (for only MBR) */
	BYTE *buf			/* Working buffer for a sector */
)
{
	UINT i, cy;
	LBA_t sz_drv;
	DWORD sz_drv32, nxt_alloc32, sz_part32;
	BYTE *pte;
	BYTE hd, n_hd, sc, n_sc;

	/* Get physical drive size */
	if (disk_ioctl(drv, GET_SECTOR_COUNT, &sz_drv) != RES_OK) return FR_DISK_ERR;

#if FF_LBA64
	if (sz_drv >= FF_MIN_GPT) {	/* Create partitions in GPT format */
		WORD ss;
		UINT sz_ptbl, pi, si, ofs;
		DWORD bcc, rnd, align;
		QWORD nxt_alloc, sz_part, sz_pool, top_bpt;
		static const BYTE gpt_mbr[16] = {0x00, 0x00, 0x02, 0x00, 0xEE, 0xFE, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};

#if FF_MAX_SS != FF_MIN_SS
		if (disk_ioctl(drv, GET_SECTOR_SIZE, &ss) != RES_OK) return FR_DISK_ERR;	/* Get sector size */
		if (ss > FF_MAX_SS || ss < FF_MIN_SS || (ss & (ss - 1))) return FR_DISK_ERR;
#else
		ss = FF_MAX_SS;
#endif
		rnd = (DWORD)sz_drv + GET_FATTIME();	/* Random seed */
		align = GPT_ALIGN / ss;				/* Partition alignment for GPT [sector] */
		sz_ptbl = GPT_ITEMS * SZ_GPTE / ss;	/* Size of partition table [sector] */
		top_bpt = sz_drv - sz_ptbl - 1;		/* Backup partition table start sector */
		nxt_alloc = 2 + sz_ptbl;			/* First allocatable sector */
		sz_pool = top_bpt - nxt_alloc;		/* Size of allocatable area */
		bcc = 0xFFFFFFFF; sz_part = 1;
		pi = si = 0;	/* partition table index, size table index */
		do {
			if (pi * SZ_GPTE % ss == 0) memset(buf, 0, ss);	/* Clean the buffer if needed */
			if (sz_part != 0) {				/* Is the size table not termintated? */
				nxt_alloc = (nxt_alloc + align - 1) & ((QWORD)0 - align);	/* Align partition start */
				sz_part = plst[si++];		/* Get a partition size */
				if (sz_part <= 100) {		/* Is the size in percentage? */
					sz_part = sz_pool * sz_part / 100;
					sz_part = (sz_part + align - 1) & ((QWORD)0 - align);	/* Align partition end (only if in percentage) */
				}
				if (nxt_alloc + sz_part > top_bpt) {	/* Clip the size at end of the pool */
					sz_part = (nxt_alloc < top_bpt) ? top_bpt - nxt_alloc : 0;
				}
			}
			if (sz_part != 0) {				/* Add a partition? */
				ofs = pi * SZ_GPTE % ss;
				memcpy(buf + ofs + GPTE_PtGuid, GUID_MS_Basic, 16);	/* Set partition GUID (Microsoft Basic Data) */
				rnd = make_rand(rnd, buf + ofs + GPTE_UpGuid, 16);	/* Set unique partition GUID */
				st_qword(buf + ofs + GPTE_FstLba, nxt_alloc);		/* Set partition start sector */
				st_qword(buf + ofs + GPTE_LstLba, nxt_alloc + sz_part - 1);	/* Set partition end sector */
				nxt_alloc += sz_part;								/* Next allocatable sector */
			}
			if ((pi + 1) * SZ_GPTE % ss == 0) {		/* Write the buffer if it is filled up */
				for (i = 0; i < ss; bcc = crc32(bcc, buf[i++])) ;	/* Calculate table check sum */
//				memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
//				if (disk_write1(drv, (BYTE *)(0xA0001000), 2 + pi * SZ_GPTE / ss, 1 )!= RES_OK)   return FR_DISK_ERR;
//				memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
				if (disk_write1(drv, buf, 2 + pi * SZ_GPTE / ss, 1) != RES_OK) return FR_DISK_ERR;		/* Write to primary table */
//				memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
//				if (disk_write1(drv, (BYTE *)(0xA0001000), top_bpt + pi * SZ_GPTE / ss, 1 )!= RES_OK)  return FR_DISK_ERR;
//				memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
				if (disk_write1(drv, buf, top_bpt + pi * SZ_GPTE / ss, 1) != RES_OK) return FR_DISK_ERR;	/* Write to secondary table */
			}
		} while (++pi < GPT_ITEMS);

		/* Create primary GPT header */
		memset(buf, 0, ss);
		memcpy(buf + GPTH_Sign, "EFI PART" "\0\0\1\0" "\x5C\0\0", 16);	/* Signature, version (1.0) and size (92) */
		st_dword(buf + GPTH_PtBcc, ~bcc);			/* Table check sum */
		st_qword(buf + GPTH_CurLba, 1);				/* LBA of this header */
		st_qword(buf + GPTH_BakLba, sz_drv - 1);	/* LBA of secondary header */
		st_qword(buf + GPTH_FstLba, 2 + sz_ptbl);	/* LBA of first allocatable sector */
		st_qword(buf + GPTH_LstLba, top_bpt - 1);	/* LBA of last allocatable sector */
		st_dword(buf + GPTH_PteSize, SZ_GPTE);		/* Size of a table entry */
		st_dword(buf + GPTH_PtNum, GPT_ITEMS);		/* Number of table entries */
		st_dword(buf + GPTH_PtOfs, 2);				/* LBA of this table */
		rnd = make_rand(rnd, buf + GPTH_DskGuid, 16);	/* Disk GUID */
		for (i = 0, bcc= 0xFFFFFFFF; i < 92; bcc = crc32(bcc, buf[i++])) ;	/* Calculate header check sum */
		st_dword(buf + GPTH_Bcc, ~bcc);				/* Header check sum */
		if (disk_write(drv, buf, 1, 1) != RES_OK) return FR_DISK_ERR;

		/* Create secondary GPT header */
		st_qword(buf + GPTH_CurLba, sz_drv - 1);	/* LBA of this header */
		st_qword(buf + GPTH_BakLba, 1);				/* LBA of primary header */
		st_qword(buf + GPTH_PtOfs, top_bpt);		/* LBA of this table */
		st_dword(buf + GPTH_Bcc, 0);
		for (i = 0, bcc= 0xFFFFFFFF; i < 92; bcc = crc32(bcc, buf[i++])) ;	/* Calculate header check sum */
		st_dword(buf + GPTH_Bcc, ~bcc);				/* Header check sum */
		if (disk_write(drv, buf, sz_drv - 1, 1) != RES_OK) return FR_DISK_ERR;

		/* Create protective MBR */
		memset(buf, 0, ss);
		memcpy(buf + MBR_Table, gpt_mbr, 16);		/* Create a GPT partition */
		st_word(buf + BS_55AA, 0xAA55);
		if (disk_write1(drv, buf, 0, 1) != RES_OK) return FR_DISK_ERR;//9.3

	} else
#endif
	{	/* Create partitions in MBR format */
		sz_drv32 = (DWORD)sz_drv;
		n_sc = N_SEC_TRACK;				/* Determine drive CHS without any consideration of the drive geometry */
		for (n_hd = 8; n_hd != 0 && sz_drv32 / n_hd / n_sc > 1024; n_hd *= 2) ;
		if (n_hd == 0) n_hd = 255;		/* Number of heads needs to be <256 */

		memset(buf, 0, FF_MAX_SS);		/* Clear MBR */
		pte = buf + MBR_Table;	/* Partition table in the MBR */
		for (i = 0, nxt_alloc32 = n_sc; i < 4 && nxt_alloc32 != 0 && nxt_alloc32 < sz_drv32; i++, nxt_alloc32 += sz_part32) {
			sz_part32 = (DWORD)plst[i];	/* Get partition size */
			if (sz_part32 <= 100) sz_part32 = (sz_part32 == 100) ? sz_drv32 : sz_drv32 / 100 * sz_part32;	/* Size in percentage? */
			if (nxt_alloc32 + sz_part32 > sz_drv32 || nxt_alloc32 + sz_part32 < nxt_alloc32) sz_part32 = sz_drv32 - nxt_alloc32;	/* Clip at drive size */
			if (sz_part32 == 0) break;	/* End of table or no sector to allocate? */

			st_dword(pte + PTE_StLba, nxt_alloc32);	/* Start LBA */
			st_dword(pte + PTE_SizLba, sz_part32);	/* Number of sectors */
			pte[PTE_System] = sys;					/* System type */

			cy = (UINT)(nxt_alloc32 / n_sc / n_hd);	/* Start cylinder */
			hd = (BYTE)(nxt_alloc32 / n_sc % n_hd);	/* Start head */
			sc = (BYTE)(nxt_alloc32 % n_sc + 1);	/* Start sector */
			pte[PTE_StHead] = hd;
			pte[PTE_StSec] = (BYTE)((cy >> 2 & 0xC0) | sc);
			pte[PTE_StCyl] = (BYTE)cy;

			cy = (UINT)((nxt_alloc32 + sz_part32 - 1) / n_sc / n_hd);	/* End cylinder */
			hd = (BYTE)((nxt_alloc32 + sz_part32 - 1) / n_sc % n_hd);	/* End head */
			sc = (BYTE)((nxt_alloc32 + sz_part32 - 1) % n_sc + 1);		/* End sector */
			pte[PTE_EdHead] = hd;
			pte[PTE_EdSec] = (BYTE)((cy >> 2 & 0xC0) | sc);
			pte[PTE_EdCyl] = (BYTE)cy;

			pte += SZ_PTE;		/* Next entry */
		}

		st_word(buf + BS_55AA, 0xAA55);		/* MBR signature */
		memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
		if (disk_write1(drv, (BYTE *)(0xA0001000), 0, 1) != RES_OK) return FR_DISK_ERR;	/* Write it to the MBR *///9.3
		memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
	}

	return FR_OK;
}


FRESULT f_mkfs (
	const TCHAR* path,		/* Logical drive number */
	const MKFS_PARM* opt,	/* Format options */
	void* work,				/* Pointer to working buffer (null: use len bytes of heap memory) */
	UINT len				/* Size of working buffer [byte] */
)
{
	static const WORD cst[] = {1, 4, 16, 64, 256, 512, 0};	/* Cluster size boundary for FAT volume (4Ks unit) */
	static const WORD cst32[] = {1, 2, 4, 8, 16, 32, 0};	/* Cluster size boundary for FAT32 volume (128Ks unit) */
//	static const MKFS_PARM defopt = {0x04, 2,512*8, 0, 1048576};	/* Default parameter */
	static const MKFS_PARM defopt = {0x04, 2,512*8, 0, 16777216};	/* Default parameter */
//	static const MKFS_PARM defopt = {0x04, 2,512*6, 0, 12582912};	/* Default parameter */
//	static const MKFS_PARM defopt = {FM_ANY, 0, 0,0};
	BYTE fsopt, fsty, sys, pdrv, ipart;
	BYTE *buf;
	BYTE *pte;
	WORD ss;	/* Sector size */
	DWORD sz_buf, sz_blk, n_clst, pau, nsect, n, vsn;
//	LBA_t sz_vol, b_vol, b_fat, b_data;		/* Size of volume, Base LBA of volume, fat, data *///lyh 11.28
	LBA_t b_vol, b_fat, b_data;
	QWORD sz_vol;
	LBA_t sect, lba[2];
	DWORD sz_rsv, sz_fat, sz_dir, sz_au;	/* Size of reserved, fat, dir, data, cluster */
	UINT n_fat, n_root, i;					/* Index, Number of FATs and Number of roor dir entries */
	int vol;
	DSTATUS ds;
	FRESULT res;


	/* Check mounted drive and clear work area */
	vol = get_ldnumber(&path);					/* Get target logical drive */
	if (vol < 0) return FR_INVALID_DRIVE;
	if (FatFs[vol]) FatFs[vol]->fs_type = 0;	/* Clear the fs object if mounted */
	pdrv = LD2PD(vol);		/* Hosting physical drive */
	ipart = LD2PT(vol);		/* Hosting partition (0:create as new, 1..:existing partition) */

	/* Initialize the hosting physical drive */
	ds = disk_initialize(pdrv);
	if (ds & STA_NOINIT) return FR_NOT_READY;
	if (ds & STA_PROTECT) return FR_WRITE_PROTECTED;

	/* Get physical drive parameters (sz_drv, sz_blk and ss) */
	if (!opt) opt = &defopt;	/* Use default parameter if it is not given */
	sz_blk = opt->align;
	if (sz_blk == 0) disk_ioctl(pdrv, GET_BLOCK_SIZE, &sz_blk);					/* Block size from the paramter or lower layer */
 	xil_printf("\n\n\n##############111 sz_blk=%lu##############\n\n\n",  sz_blk);
	if (sz_blk == 0 || sz_blk > 0x8000 || (sz_blk & (sz_blk - 1))) sz_blk = 1;	/* Use default if the block size is invalid */
 	xil_printf("\n\n\n##############222 sz_blk=%d##############\n\n\n",  sz_blk);
 	#if FF_MAX_SS != FF_MIN_SS
	if (disk_ioctl(pdrv, GET_SECTOR_SIZE, &ss) != RES_OK) return FR_DISK_ERR;
	if (ss > FF_MAX_SS || ss < FF_MIN_SS || (ss & (ss - 1))) return FR_DISK_ERR;
#else
	ss = FF_MAX_SS;
#endif
	/* Options for FAT sub-type and FAT parameters */
	fsopt = opt->fmt & (FM_ANY | FM_SFD);
	n_fat = (opt->n_fat >= 1 && opt->n_fat <= 2) ? opt->n_fat : 1;
	n_root = (opt->n_root >= 1 && opt->n_root <= 32768 && (opt->n_root % (ss / SZDIRE)) == 0) ? opt->n_root : 512;
	sz_au = (opt->au_size <= 0x1000000 && (opt->au_size & (opt->au_size - 1)) == 0) ? opt->au_size : 0;
	sz_au /= ss;	/* Byte --> Sector */

	/* Get working buffer */
	sz_buf = len / ss;		/* Size of working buffer [sector] */
	if (sz_buf == 0) return FR_NOT_ENOUGH_CORE;
	buf = (BYTE*)work;		/* Working buffer */
#if FF_USE_LFN == 3
	if (!buf) buf = ff_memalloc(sz_buf * ss);	/* Use heap memory for working buffer */
#endif
	if (!buf) return FR_NOT_ENOUGH_CORE;
	/* Determine where the volume to be located (b_vol, sz_vol) */
	b_vol = sz_vol = 0;
	if (FF_MULTI_PARTITION && ipart != 0) {	/* Is the volume associated with any specific partition? */
		/* Get partition location from the existing partition table */
//		if (disk_read(pdrv,(BYTE *)(0xA0001000), 0, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);	/* Load MBR */
		if (disk_read2(pdrv,(BYTE *)(0xA0001000), 0, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);	/* Load MBR *///9.3
		memcpy(buf,0xA0001000,SECTORSIZE*1);
		memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);

		if (ld_word(buf + BS_55AA) != 0xAA55) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Check if MBR is valid */
#if FF_LBA64
		if (buf[MBR_Table + PTE_System] == 0xEE) {	/* GPT protective MBR? */
			DWORD n_ent, ofs;
			QWORD pt_lba;
			xil_printf("wfeng: fun = %s, line = %d\n", __func__, __LINE__);
			/* Get the partition location from GPT */
			if (disk_read2(pdrv, (BYTE *)(0xA0001000), 1, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3	/* Load GPT header sector (next to MBR) */
			xil_printf("wfeng: fun = %s, line = %d\n", __func__, __LINE__);
			memcpy(buf,0xA0001000,SECTORSIZE*1);
			if (!test_gpt_header(buf)) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Check if GPT header is valid */
			n_ent = ld_dword(buf + GPTH_PtNum);		/* Number of entries */
			pt_lba = ld_qword(buf + GPTH_PtOfs);	/* Table start sector */
			ofs = i = 0;
			while (n_ent) {		/* Find MS Basic partition with order of ipart */
				if (ofs == 0 && disk_read2(pdrv, buf, pt_lba++, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3	/* Get PT sector */
//				memcpy(buf,0x80000000,SECTORSIZE*1);
				if (!memcmp(buf + ofs + GPTE_PtGuid, GUID_MS_Basic, 16) && ++i == ipart) {	/* MS basic data partition? */
					b_vol = ld_qword(buf + ofs + GPTE_FstLba);
					sz_vol = ld_qword(buf + ofs + GPTE_LstLba) - b_vol + 1;
					break;
				}
				n_ent--; ofs = (ofs + SZ_GPTE) % ss;	/* Next entry */
			}
			if (n_ent == 0) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Partition not found */
			fsopt |= 0x80;	/* Partitioning is in GPT */
		} else
#endif
		{	/* Get the partition location from MBR partition table */
			pte = buf + (MBR_Table + (ipart - 1) * SZ_PTE);
			if (ipart > 4 || pte[PTE_System] == 0) LEAVE_MKFS(FR_MKFS_ABORTED);	/* No partition? */
			b_vol = ld_dword(pte + PTE_StLba);		/* Get volume start sector */
			sz_vol = ld_dword(pte + PTE_SizLba);	/* Get volume size */
		}
	} else {	/* The volume is associated with a physical drive */
		if (disk_ioctl(pdrv, GET_SECTOR_COUNT, &sz_vol) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);
//		sz_vol=1073741824;
//		sz_vol=268492800;
		if (!(fsopt & FM_SFD)) {	/* To be partitioned? */
			/* Create a single-partition on the drive in this function */
#if  FF_LBA64
			if (sz_vol >= FF_MIN_GPT) {	/* Which partition type to create, MBR or GPT? */
				fsopt |= 0x80;		/* Partitioning is in GPT */
				b_vol = GPT_ALIGN / ss; sz_vol -= b_vol + GPT_ITEMS * SZ_GPTE / ss + 1;	/* Estimated partition offset and size */
			} else
#endif
			{	/* Partitioning is in MBR */
				if (sz_vol > N_SEC_TRACK) {
					b_vol = N_SEC_TRACK; sz_vol -= b_vol;	/* Estimated partition offset and size */
				}
			}
		}
	}
	if (sz_vol < 128) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Check if volume size is >=128s */
	/* Now start to create an FAT volume at b_vol and sz_vol */

	do {	/* Pre-determine the FAT type */
		if (FF_FS_EXFAT && (fsopt & FM_EXFAT)) {	/* exFAT possible? */
			if ((fsopt & FM_ANY) == FM_EXFAT || sz_vol >= 0x4000000 || sz_au > 128) {	/* exFAT only, vol >= 64MS or sz_au > 128S ? */
				fsty = FS_EXFAT; break;
			}
		}
#if  FF_LBA64
		if (sz_vol >= 0x100000000) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Too large volume for FAT/FAT32 */
#endif
		if (sz_au > 128) sz_au = 128;	/* Invalid AU for FAT/FAT32? */
		if (fsopt & FM_FAT32) {	/* FAT32 possible? */
			if (!(fsopt & FM_FAT)) {	/* no-FAT? */
				fsty = FS_FAT32; break;
			}
		}
		if (!(fsopt & FM_FAT)) LEAVE_MKFS(FR_INVALID_PARAMETER);	/* no-FAT? */
		fsty = FS_FAT16;
	} while (0);
	vsn = (DWORD)sz_vol + GET_FATTIME();	/* VSN generated from current time and partitiion size */

#if FF_FS_EXFAT
	if (fsty == FS_EXFAT) {	/* Create an exFAT volume */
		DWORD szb_bit, szb_case, sum, nbit, clu, clen[3];
		WCHAR ch, si;
		UINT j, st;
		if (sz_vol < 0x1000) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Too small volume for exFAT? */
#if FF_USE_TRIM
		lba[0] = b_vol; lba[1] = b_vol + sz_vol - 1;	/* Inform storage device that the volume area may be erased */
		disk_ioctl(pdrv, CTRL_TRIM, lba);
#endif
		/* Determine FAT location, data location and number of clusters */
		if (sz_au == 0) {	/* AU auto-selection */
			sz_au = 8;
			if (sz_vol >= 0x80000) sz_au = 64;		/* >= 512Ks */
			if (sz_vol >= 0x4000000) sz_au = 256;	/* >= 64Ms */
		}

		b_fat = b_vol + 32;										/* FAT start at offset 32 */
		sz_fat = (DWORD)((sz_vol / sz_au + 2) * 4 + ss - 1) / ss;	/* Number of FAT sectors */
		b_data = (b_fat + sz_fat + sz_blk - 1) & ~((LBA_t)sz_blk - 1);	/* Align data area to the erase block boundary */
		if (b_data - b_vol >= sz_vol / 2) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Too small volume? */
		n_clst = (DWORD)((sz_vol - (b_data - b_vol)) / sz_au);	/* Number of clusters */
		if (n_clst <16) LEAVE_MKFS(FR_MKFS_ABORTED);			/* Too few clusters? */
		if (n_clst > MAX_EXFAT) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Too many clusters? */

		szb_bit = (n_clst + 7) / 8;								/* Size of allocation bitmap */
		clen[0] = (szb_bit + sz_au * ss - 1) / (sz_au * ss);	/* Number of allocation bitmap clusters */

		/* Create a compressed up-case table */
		sect = b_data + sz_au * clen[0];	/* Table start sector */
		sum = 0;							/* Table checksum to be stored in the 82 entry */
		st = 0; si = 0; i = 0; j = 0; szb_case = 0;
		do {
			switch (st) {
			case 0:
				ch = (WCHAR)ff_wtoupper(si);	/* Get an up-case char */
				if (ch != si) {
					si++; break;		/* Store the up-case char if exist */
				}
				for (j = 1; (WCHAR)(si + j) && (WCHAR)(si + j) == ff_wtoupper((WCHAR)(si + j)); j++) ;	/* Get run length of no-case block */
				if (j >= 128) {
					ch = 0xFFFF; st = 2; break;	/* Compress the no-case block if run is >= 128 chars */
				}
				st = 1;			/* Do not compress short run */
				/* FALLTHROUGH */
			case 1:
				ch = si++;		/* Fill the short run */
				if (--j == 0) st = 0;
				break;

			default:
				ch = (WCHAR)j; si += (WCHAR)j;	/* Number of chars to skip */
				st = 0;
			}
			sum = xsum32(buf[i + 0] = (BYTE)ch, sum);	/* Put it into the write buffer */
			sum = xsum32(buf[i + 1] = (BYTE)(ch >> 8), sum);
			i += 2; szb_case += 2;
			if (si == 0 || i == sz_buf * ss) {		/* Write buffered data when buffer full or end of process */
				n = (i + ss - 1) / ss;
				memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*n);
//				Xil_L1DCacheFlush(); //8.20 add
//				if (disk_write(pdrv, (BYTE *)(0xA0001000), sect, n) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);
				if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect, n) != RES_OK) LEAVE_MKFS(FR_DISK_ERR); //9.3
				xil_printf("%s %d\r\n", __FUNCTION__, __LINE__);
				memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
				sect += n; i = 0;
			}
		} while (si);
		clen[1] = (szb_case + sz_au * ss - 1) / (sz_au * ss);	/* Number of up-case table clusters */
		clen[2] = 1;	/* Number of root dir clusters */
		xil_printf("%s %d\r\n", __FUNCTION__, __LINE__);
		/* Initialize the allocation bitmap */
		sect = b_data; nsect = (szb_bit + ss - 1) / ss;	/* Start of bitmap and number of bitmap sectors */
		nbit = clen[0] + clen[1] + clen[2];				/* Number of clusters in-use by system (bitmap, up-case and root-dir) */
		do {
			memset(buf, 0, sz_buf * ss);				/* Initialize bitmap buffer */
			for (i = 0; nbit != 0 && i / 8 < sz_buf * ss; buf[i / 8] |= 1 << (i % 8), i++, nbit--) ;	/* Mark used clusters */
			n = (nsect > sz_buf) ? sz_buf : nsect;		/* Write the buffered data */
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*n);
//			Xil_L1DCacheFlush(); //8.20 add
			if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect, n) != RES_OK) LEAVE_MKFS(FR_DISK_ERR); //9.3
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*n);
			sect += n; nsect -= n;
		} while (nsect);

		/* Initialize the FAT */
		sect = b_fat; nsect = sz_fat;	/* Start of FAT and number of FAT sectors */
		j = nbit = clu = 0;
		do {
			memset(buf, 0, sz_buf * ss); i = 0;	/* Clear work area and reset write offset */
			if (clu == 0) {	/* Initialize FAT [0] and FAT[1] */
				st_dword(buf + i, 0xFFFFFFF8); i += 4; clu++;
				st_dword(buf + i, 0xFFFFFFFF); i += 4; clu++;
			}
			do {			/* Create chains of bitmap, up-case and root dir */
				while (nbit != 0 && i < sz_buf * ss) {	/* Create a chain */
					st_dword(buf + i, (nbit > 1) ? clu + 1 : 0xFFFFFFFF);
					i += 4; clu++; nbit--;
				}
				if (nbit == 0 && j < 3) nbit = clen[j++];	/* Get next chain length */
			} while (nbit != 0 && i < sz_buf * ss);
			n = (nsect > sz_buf) ? sz_buf : nsect;	/* Write the buffered data */
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*n);
//			Xil_L1DCacheFlush(); //8.20 add
			if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect, n) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3
			sect += n; nsect -= n;
		} while (nsect);
		xil_printf("%s %d\r\n", __FUNCTION__, __LINE__);
		/* Initialize the root directory */
		memset(buf, 0, sz_buf * ss);
		buf[SZDIRE * 0 + 0] = ET_VLABEL;				/* Volume label entry (no label) */
		buf[SZDIRE * 1 + 0] = ET_BITMAP;				/* Bitmap entry */
		st_dword(buf + SZDIRE * 1 + 20, 2);				/*  cluster */
		st_dword(buf + SZDIRE * 1 + 24, szb_bit);		/*  size */
		buf[SZDIRE * 2 + 0] = ET_UPCASE;				/* Up-case table entry */
		st_dword(buf + SZDIRE * 2 + 4, sum);			/*  sum */
		st_dword(buf + SZDIRE * 2 + 20, 2 + clen[0]);	/*  cluster */
		st_dword(buf + SZDIRE * 2 + 24, szb_case);		/*  size */
		sect = b_data + sz_au * (clen[0] + clen[1]); nsect = sz_au;	/* Start of the root directory and number of sectors */
		do {	/* Fill root directory sectors */
			n = (nsect > sz_buf) ? sz_buf : nsect;
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*n);
//			Xil_L1DCacheFlush(); //8.20 add
			if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect, n) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*n);
			memset(buf, 0, ss);	/* Rest of entries are filled with zero */
			sect += n; nsect -= n;
		} while (nsect);

		/* Create two set of the exFAT VBR blocks */
		sect = b_vol;
		for (n = 0; n < 2; n++) {
			/* Main record (+0) */
			memset(buf, 0, ss);
			memcpy(buf + BS_JmpBoot, "\xEB\x76\x90" "EXFAT   ", 11);	/* Boot jump code (x86), OEM name */
			st_qword(buf + BPB_VolOfsEx, b_vol);					/* Volume offset in the physical drive [sector] */
			st_qword(buf + BPB_TotSecEx, sz_vol);					/* Volume size [sector] */
			st_dword(buf + BPB_FatOfsEx, (DWORD)(b_fat - b_vol));	/* FAT offset [sector] */
			st_dword(buf + BPB_FatSzEx, sz_fat);					/* FAT size [sector] */
			st_dword(buf + BPB_DataOfsEx, (DWORD)(b_data - b_vol));	/* Data offset [sector] */
			st_dword(buf + BPB_NumClusEx, n_clst);					/* Number of clusters */
			st_dword(buf + BPB_RootClusEx, 2 + clen[0] + clen[1]);	/* Root dir cluster # */
			st_dword(buf + BPB_VolIDEx, vsn);						/* VSN */
			st_word(buf + BPB_FSVerEx, 0x100);						/* Filesystem version (1.00) */
			for (buf[BPB_BytsPerSecEx] = 0, i = ss; i >>= 1; buf[BPB_BytsPerSecEx]++) ;	/* Log2 of sector size [byte] */
			for (buf[BPB_SecPerClusEx] = 0, i = sz_au; i >>= 1; buf[BPB_SecPerClusEx]++) ;	/* Log2 of cluster size [sector] */
			buf[BPB_NumFATsEx] = 1;					/* Number of FATs */
			buf[BPB_DrvNumEx] = 0x80;				/* Drive number (for int13) */
			st_word(buf + BS_BootCodeEx, 0xFEEB);	/* Boot code (x86) */
			st_word(buf + BS_55AA, 0xAA55);			/* Signature (placed here regardless of sector size) */
			for (i = sum = 0; i < ss; i++) {		/* VBR checksum */
				if (i != BPB_VolFlagEx && i != BPB_VolFlagEx + 1 && i != BPB_PercInUseEx) sum = xsum32(buf[i], sum);
			}
			xil_printf("%s %d\r\n", __FUNCTION__, __LINE__);
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
//			Xil_L1DCacheFlush(); //8.20 add
			if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect++, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
			/* Extended bootstrap record (+1..+8) */
			memset(buf, 0, ss);
			st_word(buf + ss - 2, 0xAA55);	/* Signature (placed at end of sector) */
			for (j = 1; j < 9; j++) {
				for (i = 0; i < ss; sum = xsum32(buf[i++], sum)) ;	/* VBR checksum */
				memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
//				Xil_L1DCacheFlush(); //8.20 add
				if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect++, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3
				memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
			}
			xil_printf("%s %d\r\n", __FUNCTION__, __LINE__);
			/* OEM/Reserved record (+9..+10) */
			memset(buf, 0, ss);
			for ( ; j < 11; j++) {
				for (i = 0; i < ss; sum = xsum32(buf[i++], sum)) ;	/* VBR checksum */
				memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
//				Xil_L1DCacheFlush(); //8.20 add
				if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect++, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3
			}
			/* Sum record (+11) */
			for (i = 0; i < ss; i += 4) st_dword(buf + i, sum);		/* Fill with checksum value */
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
			if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect++, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
		}

	} else
#endif	/* FF_FS_EXFAT */
	{	/* Create an FAT/FAT32 volume */
		do {
			pau = sz_au;
			/* Pre-determine number of clusters and FAT sub-type */
			if (fsty == FS_FAT32) {	/* FAT32 volume */
				if (pau == 0) {	/* AU auto-selection */
					n = (DWORD)sz_vol / 0x20000;	/* Volume size in unit of 128KS */
					for (i = 0, pau = 1; cst32[i] && cst32[i] <= n; i++, pau <<= 1) ;	/* Get from table */
				}
				n_clst = (DWORD)sz_vol / pau;	/* Number of clusters */
				sz_fat = (n_clst * 4 + 8 + ss - 1) / ss;	/* FAT size [sector] */
				sz_rsv = 32;	/* Number of reserved sectors */
				sz_dir = 0;		/* No static directory */
				if (n_clst <= MAX_FAT16 || n_clst > MAX_FAT32) LEAVE_MKFS(FR_MKFS_ABORTED);
			} else {				/* FAT volume */
				if (pau == 0) {	/* au auto-selection */
					n = (DWORD)sz_vol / 0x1000;	/* Volume size in unit of 4KS */
					for (i = 0, pau = 1; cst[i] && cst[i] <= n; i++, pau <<= 1) ;	/* Get from table */
				}
				n_clst = (DWORD)sz_vol / pau;
				if (n_clst > MAX_FAT12) {
					n = n_clst * 2 + 4;		/* FAT size [byte] */
				} else {
					fsty = FS_FAT12;
					n = (n_clst * 3 + 1) / 2 + 3;	/* FAT size [byte] */
				}
				sz_fat = (n + ss - 1) / ss;		/* FAT size [sector] */
				sz_rsv = 1;						/* Number of reserved sectors */
				sz_dir = (DWORD)n_root * SZDIRE / ss;	/* Root dir size [sector] */
			}
			b_fat = b_vol + sz_rsv;						/* FAT base */
			b_data = b_fat + sz_fat * n_fat + sz_dir;	/* Data base */

			/* Align data area to erase block boundary (for flash memory media) */
			n = (DWORD)(((b_data + sz_blk - 1) & ~(sz_blk - 1)) - b_data);	/* Sectors to next nearest from current data base */
			if (fsty == FS_FAT32) {		/* FAT32: Move FAT */
				sz_rsv += n; b_fat += n;
			} else {					/* FAT: Expand FAT */
				if (n % n_fat) {	/* Adjust fractional error if needed */
					n--; sz_rsv++; b_fat++;
				}
				sz_fat += n / n_fat;
			}

			/* Determine number of clusters and final check of validity of the FAT sub-type */
			if (sz_vol < b_data + pau * 16 - b_vol) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Too small volume? */
			n_clst = ((DWORD)sz_vol - sz_rsv - sz_fat * n_fat - sz_dir) / pau;
			if (fsty == FS_FAT32) {
				if (n_clst <= MAX_FAT16) {	/* Too few clusters for FAT32? */
					if (sz_au == 0 && (sz_au = pau / 2) != 0) continue;	/* Adjust cluster size and retry */
					LEAVE_MKFS(FR_MKFS_ABORTED);
				}
			}
			if (fsty == FS_FAT16) {
				if (n_clst > MAX_FAT16) {	/* Too many clusters for FAT16 */
					if (sz_au == 0 && (pau * 2) <= 64) {
						sz_au = pau * 2; continue;	/* Adjust cluster size and retry */
					}
					if ((fsopt & FM_FAT32)) {
						fsty = FS_FAT32; continue;	/* Switch type to FAT32 and retry */
					}
					if (sz_au == 0 && (sz_au = pau * 2) <= 128) continue;	/* Adjust cluster size and retry */
					LEAVE_MKFS(FR_MKFS_ABORTED);
				}
				if  (n_clst <= MAX_FAT12) {	/* Too few clusters for FAT16 */
					if (sz_au == 0 && (sz_au = pau * 2) <= 128) continue;	/* Adjust cluster size and retry */
					LEAVE_MKFS(FR_MKFS_ABORTED);
				}
			}
			if (fsty == FS_FAT12 && n_clst > MAX_FAT12) LEAVE_MKFS(FR_MKFS_ABORTED);	/* Too many clusters for FAT12 */

			/* Ok, it is the valid cluster configuration */
			break;
		} while (1);

#if FF_USE_TRIM
		lba[0] = b_vol; lba[1] = b_vol + sz_vol - 1;	/* Inform storage device that the volume area may be erased */
		disk_ioctl(pdrv, CTRL_TRIM, lba);
#endif
		/* Create FAT VBR */
		memset(buf, 0, ss);
		memcpy(buf + BS_JmpBoot, "\xEB\xFE\x90" "MSDOS5.0", 11);	/* Boot jump code (x86), OEM name */
		st_word(buf + BPB_BytsPerSec, ss);				/* Sector size [byte] */
		buf[BPB_SecPerClus] = (BYTE)pau;				/* Cluster size [sector] */
		st_word(buf + BPB_RsvdSecCnt, (WORD)sz_rsv);	/* Size of reserved area */
		buf[BPB_NumFATs] = (BYTE)n_fat;					/* Number of FATs */
		st_word(buf + BPB_RootEntCnt, (WORD)((fsty == FS_FAT32) ? 0 : n_root));	/* Number of root directory entries */
		if (sz_vol < 0x10000) {
			st_word(buf + BPB_TotSec16, (WORD)sz_vol);	/* Volume size in 16-bit LBA */
		} else {
			st_dword(buf + BPB_TotSec32, (DWORD)sz_vol);	/* Volume size in 32-bit LBA */
		}
		buf[BPB_Media] = 0xF8;							/* Media descriptor byte */
		st_word(buf + BPB_SecPerTrk, 63);				/* Number of sectors per track (for int13) */
		st_word(buf + BPB_NumHeads, 255);				/* Number of heads (for int13) */
		st_dword(buf + BPB_HiddSec, (DWORD)b_vol);		/* Volume offset in the physical drive [sector] */
		if (fsty == FS_FAT32) {
			st_dword(buf + BS_VolID32, vsn);			/* VSN */
			st_dword(buf + BPB_FATSz32, sz_fat);		/* FAT size [sector] */
			st_dword(buf + BPB_RootClus32, 2);			/* Root directory cluster # (2) */
			st_word(buf + BPB_FSInfo32, 1);				/* Offset of FSINFO sector (VBR + 1) */
			st_word(buf + BPB_BkBootSec32, 6);			/* Offset of backup VBR (VBR + 6) */
			buf[BS_DrvNum32] = 0x80;					/* Drive number (for int13) */
			buf[BS_BootSig32] = 0x29;					/* Extended boot signature */
			memcpy(buf + BS_VolLab32, "NO NAME    " "FAT32   ", 19);	/* Volume label, FAT signature */
		} else {
			st_dword(buf + BS_VolID, vsn);				/* VSN */
			st_word(buf + BPB_FATSz16, (WORD)sz_fat);	/* FAT size [sector] */
			buf[BS_DrvNum] = 0x80;						/* Drive number (for int13) */
			buf[BS_BootSig] = 0x29;						/* Extended boot signature */
			memcpy(buf + BS_VolLab, "NO NAME    " "FAT     ", 19);	/* Volume label, FAT signature */
		}

		st_word(buf + BS_55AA, 0xAA55);					/* Signature (offset is fixed here regardless of sector size) */
		memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
//		Xil_L1DCacheFlush(); //8.20 add
		if (disk_write1(pdrv, (BYTE *)(0xA0001000), b_vol, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3	/* Write it to the VBR sector */
		memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);

		/* Create FSINFO record if needed */
		if (fsty == FS_FAT32) {
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
			disk_write1(pdrv, (BYTE *)(0xA0001000), b_vol + 6, 1);	//9.3	/* Write backup VBR (VBR + 6) */
			memset(buf, 0, ss);
			st_dword(buf + FSI_LeadSig, 0x41615252);
			st_dword(buf + FSI_StrucSig, 0x61417272);
			st_dword(buf + FSI_Free_Count, n_clst - 1);	/* Number of free clusters */
			st_dword(buf + FSI_Nxt_Free, 2);			/* Last allocated cluster# */
			st_word(buf + BS_55AA, 0xAA55);
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
//			Xil_L1DCacheFlush(); //8.20 add
			disk_write1(pdrv, (BYTE *)(0xA0001000), b_vol + 7, 1);		//9.3/* Write backup FSINFO (VBR + 7) */
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
			
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
//			Xil_L1DCacheFlush(); //8.20 add
			disk_write1(pdrv, (BYTE *)(0xA0001000), b_vol + 1, 1);		//9.3/* Write original FSINFO (VBR + 1) */
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
		}

		/* Initialize FAT area */
		memset(buf, 0, sz_buf * ss);
		sect = b_fat;		/* FAT start sector */
		for (i = 0; i < n_fat; i++) {			/* Initialize FATs each */
			if (fsty == FS_FAT32) {
				st_dword(buf + 0, 0xFFFFFFF8);	/* FAT[0] */
				st_dword(buf + 4, 0xFFFFFFFF);	/* FAT[1] */
				st_dword(buf + 8, 0x0FFFFFFF);	/* FAT[2] (root directory) */
			} else {
				st_dword(buf + 0, (fsty == FS_FAT12) ? 0xFFFFF8 : 0xFFFFFFF8);	/* FAT[0] and FAT[1] */
			}
			nsect = sz_fat;		/* Number of FAT sectors */
			do {	/* Fill FAT sectors */
				n = (nsect > sz_buf) ? sz_buf : nsect;
				memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*n);
//				Xil_L1DCacheFlush(); //8.20 add
				if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect, (UINT)n) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3
				memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
				memset(buf, 0, ss);	/* Rest of FAT all are cleared */
				sect += n; nsect -= n;
			} while (nsect);
		}

		/* Initialize root directory (fill with zero) */
		nsect = (fsty == FS_FAT32) ? pau : sz_dir;	/* Number of root directory sectors */
		do {
			n = (nsect > sz_buf) ? sz_buf : nsect;
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*n);
//			Xil_L1DCacheFlush(); //8.20 add
			if (disk_write1(pdrv, (BYTE *)(0xA0001000), sect, (UINT)n) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*n);
			sect += n; nsect -= n;
		} while (nsect);
	}

	/* A FAT volume has been created here */

	/* Determine system ID in the MBR partition table */
	if (FF_FS_EXFAT && fsty == FS_EXFAT) {
		sys = 0x07;		/* exFAT */
	} else if (fsty == FS_FAT32) {
		sys = 0x0C;		/* FAT32X */
	} else if (sz_vol >= 0x10000) {
		sys = 0x06;		/* FAT12/16 (large) */
	} else if (fsty == FS_FAT16) {
		sys = 0x04;		/* FAT16 */
	} else {
		sys = 0x01;		/* FAT12 */
	}
	xil_printf("%s %d\r\n", __FUNCTION__, __LINE__);
	/* Update partition information */
	if (FF_MULTI_PARTITION && ipart != 0) {	/* Volume is in the existing partition */
		if (!FF_LBA64 || !(fsopt & 0x80)) {	/* Is the partition in MBR? */
			/* Update system ID in the partition table */

			if (disk_read2(pdrv, (BYTE *)(0xA0001000), 0, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);	//9.3/* Read the MBR */
//			Xil_L1DCacheFlush(); //8.20 add
			memcpy(buf,0xA0001000,SECTORSIZE*1);
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
			buf[MBR_Table + (ipart - 1) * SZ_PTE + PTE_System] = sys;			/* Set system ID */
			memcpy((BYTE *)(0xA0001000),buf,SECTORSIZE*1);
//			Xil_L1DCacheFlush(); //8.20 add
			if (disk_write1(pdrv, (BYTE *)(0xA0001000), 0, 1) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);//9.3	/* Write it back to the MBR */
			memset((BYTE *)(0xA0001000),0,SECTORSIZE*1);
		}
	} else {								/* Volume as a new single partition */
		if (!(fsopt & FM_SFD)) {			/* Create partition table if not in SFD format */
			lba[0] = sz_vol; lba[1] = 0;
			res = create_partition(pdrv, lba, sys, buf);
			if (res != FR_OK) LEAVE_MKFS(res);
			xil_printf("%s %d\r\n", __FUNCTION__, __LINE__);
		}
	}

	if (disk_ioctl(pdrv, CTRL_SYNC, 0) != RES_OK) LEAVE_MKFS(FR_DISK_ERR);
	LEAVE_MKFS(FR_OK);
}




#if FF_MULTI_PARTITION
/*-----------------------------------------------------------------------*/
/* Create Partition Table on the Physical Drive                          */
/*-----------------------------------------------------------------------*/

FRESULT f_fdisk (
	BYTE pdrv,			/* Physical drive number */
	const LBA_t ptbl[],	/* Pointer to the size table for each partitions */
	void* work			/* Pointer to the working buffer (null: use heap memory) */
)
{
	BYTE *buf = (BYTE*)work;
	DSTATUS stat;
	FRESULT res;


	/* Initialize the physical drive */
	stat = disk_initialize(pdrv);
	if (stat & STA_NOINIT) return FR_NOT_READY;
	if (stat & STA_PROTECT) return FR_WRITE_PROTECTED;

#if FF_USE_LFN == 3
	if (!buf) buf = ff_memalloc(FF_MAX_SS);	/* Use heap memory for working buffer */
#endif
	if (!buf) return FR_NOT_ENOUGH_CORE;

	res = create_partition(pdrv, ptbl, 0x07, buf);	/* Create partitions (system ID is temporary setting and determined by f_mkfs) */

	LEAVE_MKFS(res);
}

#endif /* FF_MULTI_PARTITION */
//#endif /* !FF_FS_READONLY && FF_USE_MKFS */  //wfeng




#if FF_USE_STRFUNC
#if FF_USE_LFN && FF_LFN_UNICODE && (FF_STRF_ENCODE < 0 || FF_STRF_ENCODE > 3)
#error Wrong FF_STRF_ENCODE setting
#endif
/*-----------------------------------------------------------------------*/
/* Get a String from the File                                            */
/*-----------------------------------------------------------------------*/

TCHAR* f_gets (
	TCHAR* buff,	/* Pointer to the buffer to store read string */
	int len,		/* Size of string buffer (items) */
	FIL* fp			/* Pointer to the file object */
)
{
	int nc = 0;
	TCHAR *p = buff;
	BYTE s[4];
	UINT rc;
	DWORD dc;
#if FF_USE_LFN && FF_LFN_UNICODE && FF_STRF_ENCODE <= 2
	WCHAR wc;
#endif
#if FF_USE_LFN && FF_LFN_UNICODE && FF_STRF_ENCODE == 3
	UINT ct;
#endif

#if FF_USE_LFN && FF_LFN_UNICODE			/* With code conversion (Unicode API) */
	/* Make a room for the character and terminator  */
	if (FF_LFN_UNICODE == 1) len -= (FF_STRF_ENCODE == 0) ? 1 : 2;
	if (FF_LFN_UNICODE == 2) len -= (FF_STRF_ENCODE == 0) ? 3 : 4;
	if (FF_LFN_UNICODE == 3) len -= 1;
	while (nc < len) {
#if FF_STRF_ENCODE == 0				/* Read a character in ANSI/OEM */
		f_read(fp, s, 1, &rc);		/* Get a code unit */
		if (rc != 1) break;			/* EOF? */
		wc = s[0];
		if (dbc_1st((BYTE)wc)) {	/* DBC 1st byte? */
			f_read(fp, s, 1, &rc);	/* Get 2nd byte */
			if (rc != 1 || !dbc_2nd(s[0])) continue;	/* Wrong code? */
			wc = wc << 8 | s[0];
		}
		dc = ff_oem2uni(wc, CODEPAGE);	/* Convert ANSI/OEM into Unicode */
		if (dc == 0) continue;		/* Conversion error? */
#elif FF_STRF_ENCODE == 1 || FF_STRF_ENCODE == 2 	/* Read a character in UTF-16LE/BE */
		f_read(fp, s, 2, &rc);		/* Get a code unit */
		if (rc != 2) break;			/* EOF? */
		dc = (FF_STRF_ENCODE == 1) ? ld_word(s) : s[0] << 8 | s[1];
		if (IsSurrogateL(dc)) continue;	/* Broken surrogate pair? */
		if (IsSurrogateH(dc)) {		/* High surrogate? */
			f_read(fp, s, 2, &rc);	/* Get low surrogate */
			if (rc != 2) break;		/* EOF? */
			wc = (FF_STRF_ENCODE == 1) ? ld_word(s) : s[0] << 8 | s[1];
			if (!IsSurrogateL(wc)) continue;	/* Broken surrogate pair? */
			dc = ((dc & 0x3FF) + 0x40) << 10 | (wc & 0x3FF);	/* Merge surrogate pair */
		}
#else	/* Read a character in UTF-8 */
		f_read(fp, s, 1, &rc);		/* Get a code unit */
		if (rc != 1) break;			/* EOF? */
		dc = s[0];
		if (dc >= 0x80) {			/* Multi-byte sequence? */
			ct = 0;
			if ((dc & 0xE0) == 0xC0) {	/* 2-byte sequence? */
				dc &= 0x1F; ct = 1;
			}
			if ((dc & 0xF0) == 0xE0) {	/* 3-byte sequence? */
				dc &= 0x0F; ct = 2;
			}
			if ((dc & 0xF8) == 0xF0) {	/* 4-byte sequence? */
				dc &= 0x07; ct = 3;
			}
			if (ct == 0) continue;
			f_read(fp, s, ct, &rc);	/* Get trailing bytes */
			if (rc != ct) break;
			rc = 0;
			do {	/* Merge the byte sequence */
				if ((s[rc] & 0xC0) != 0x80) break;
				dc = dc << 6 | (s[rc] & 0x3F);
			} while (++rc < ct);
			if (rc != ct || dc < 0x80 || IsSurrogate(dc) || dc >= 0x110000) continue;	/* Wrong encoding? */
		}
#endif
		/* A code point is avaialble in dc to be output */

		if (FF_USE_STRFUNC == 2 && dc == '\r') continue;	/* Strip \r off if needed */
#if FF_LFN_UNICODE == 1	|| FF_LFN_UNICODE == 3	/* Output it in UTF-16/32 encoding */
		if (FF_LFN_UNICODE == 1 && dc >= 0x10000) {	/* Out of BMP at UTF-16? */
			*p++ = (TCHAR)(0xD800 | ((dc >> 10) - 0x40)); nc++;	/* Make and output high surrogate */
			dc = 0xDC00 | (dc & 0x3FF);		/* Make low surrogate */
		}
		*p++ = (TCHAR)dc; nc++;
		if (dc == '\n') break;	/* End of line? */
#elif FF_LFN_UNICODE == 2		/* Output it in UTF-8 encoding */
		if (dc < 0x80) {	/* Single byte? */
			*p++ = (TCHAR)dc;
			nc++;
			if (dc == '\n') break;	/* End of line? */
		} else if (dc < 0x800) {	/* 2-byte sequence? */
			*p++ = (TCHAR)(0xC0 | (dc >> 6 & 0x1F));
			*p++ = (TCHAR)(0x80 | (dc >> 0 & 0x3F));
			nc += 2;
		} else if (dc < 0x10000) {	/* 3-byte sequence? */
			*p++ = (TCHAR)(0xE0 | (dc >> 12 & 0x0F));
			*p++ = (TCHAR)(0x80 | (dc >> 6 & 0x3F));
			*p++ = (TCHAR)(0x80 | (dc >> 0 & 0x3F));
			nc += 3;
		} else {					/* 4-byte sequence */
			*p++ = (TCHAR)(0xF0 | (dc >> 18 & 0x07));
			*p++ = (TCHAR)(0x80 | (dc >> 12 & 0x3F));
			*p++ = (TCHAR)(0x80 | (dc >> 6 & 0x3F));
			*p++ = (TCHAR)(0x80 | (dc >> 0 & 0x3F));
			nc += 4;
		}
#endif
	}

#else			/* Byte-by-byte read without any conversion (ANSI/OEM API) */
	len -= 1;	/* Make a room for the terminator */
	while (nc < len) {
		f_read(fp, s, 1, &rc);	/* Get a byte */
		if (rc != 1) break;		/* EOF? */
		dc = s[0];
		if (FF_USE_STRFUNC == 2 && dc == '\r') continue;
		*p++ = (TCHAR)dc; nc++;
		if (dc == '\n') break;
	}
#endif

	*p = 0;		/* Terminate the string */
	return nc ? buff : 0;	/* When no data read due to EOF or error, return with error. */
}




#if !FF_FS_READONLY
#include <stdarg.h>
#define SZ_PUTC_BUF	64
#define SZ_NUM_BUF	32

/*-----------------------------------------------------------------------*/
/* Put a Character to the File (with sub-functions)                      */
/*-----------------------------------------------------------------------*/

/* Output buffer and work area */

typedef struct {
	FIL *fp;		/* Ptr to the writing file */
	int idx, nchr;	/* Write index of buf[] (-1:error), number of encoding units written */
#if FF_USE_LFN && FF_LFN_UNICODE == 1
	WCHAR hs;
#elif FF_USE_LFN && FF_LFN_UNICODE == 2
	BYTE bs[4];
	UINT wi, ct;
#endif
	BYTE buf[SZ_PUTC_BUF];	/* Write buffer */
} putbuff;


/* Buffered file write with code conversion */

static void putc_bfd (putbuff* pb, TCHAR c)
{
	UINT n;
	int i, nc;
#if FF_USE_LFN && FF_LFN_UNICODE
	WCHAR hs, wc;
#if FF_LFN_UNICODE == 2
	DWORD dc;
	const TCHAR* tp;
#endif
#endif

	if (FF_USE_STRFUNC == 2 && c == '\n') {	 /* LF -> CRLF conversion */
		putc_bfd(pb, '\r');
	}

	i = pb->idx;			/* Write index of pb->buf[] */
	if (i < 0) return;		/* In write error? */
	nc = pb->nchr;			/* Write unit counter */

#if FF_USE_LFN && FF_LFN_UNICODE
#if FF_LFN_UNICODE == 1		/* UTF-16 input */
	if (IsSurrogateH(c)) {	/* Is this a high-surrogate? */
		pb->hs = c; return;	/* Save it for next */
	}
	hs = pb->hs; pb->hs = 0;
	if (hs != 0) {			/* Is there a leading high-surrogate? */
		if (!IsSurrogateL(c)) hs = 0;	/* Discard high-surrogate if not a surrogate pair */
	} else {
		if (IsSurrogateL(c)) return;	/* Discard stray low-surrogate */
	}
	wc = c;
#elif FF_LFN_UNICODE == 2	/* UTF-8 input */
	for (;;) {
		if (pb->ct == 0) {	/* Out of multi-byte sequence? */
			pb->bs[pb->wi = 0] = (BYTE)c;	/* Save 1st byte */
			if ((BYTE)c < 0x80) break;					/* Single byte code? */
			if (((BYTE)c & 0xE0) == 0xC0) pb->ct = 1;	/* 2-byte sequence? */
			if (((BYTE)c & 0xF0) == 0xE0) pb->ct = 2;	/* 3-byte sequence? */
			if (((BYTE)c & 0xF8) == 0xF0) pb->ct = 3;	/* 4-byte sequence? */
			return;										/* Wrong leading byte (discard it) */
		} else {				/* In the multi-byte sequence */
			if (((BYTE)c & 0xC0) != 0x80) {	/* Broken sequence? */
				pb->ct = 0; continue;		/* Discard the sequense */
			}
			pb->bs[++pb->wi] = (BYTE)c;	/* Save the trailing byte */
			if (--pb->ct == 0) break;	/* End of the sequence? */
			return;
		}
	}
	tp = (const TCHAR*)pb->bs;
	dc = tchar2uni(&tp);			/* UTF-8 ==> UTF-16 */
	if (dc == 0xFFFFFFFF) return;	/* Wrong code? */
	hs = (WCHAR)(dc >> 16);
	wc = (WCHAR)dc;
#elif FF_LFN_UNICODE == 3	/* UTF-32 input */
	if (IsSurrogate(c) || c >= 0x110000) return;	/* Discard invalid code */
	if (c >= 0x10000) {		/* Out of BMP? */
		hs = (WCHAR)(0xD800 | ((c >> 10) - 0x40)); 	/* Make high surrogate */
		wc = 0xDC00 | (c & 0x3FF);					/* Make low surrogate */
	} else {
		hs = 0;
		wc = (WCHAR)c;
	}
#endif
	/* A code point in UTF-16 is available in hs and wc */

#if FF_STRF_ENCODE == 1		/* Write a code point in UTF-16LE */
	if (hs != 0) {	/* Surrogate pair? */
		st_word(&pb->buf[i], hs);
		i += 2;
		nc++;
	}
	st_word(&pb->buf[i], wc);
	i += 2;
#elif FF_STRF_ENCODE == 2	/* Write a code point in UTF-16BE */
	if (hs != 0) {	/* Surrogate pair? */
		pb->buf[i++] = (BYTE)(hs >> 8);
		pb->buf[i++] = (BYTE)hs;
		nc++;
	}
	pb->buf[i++] = (BYTE)(wc >> 8);
	pb->buf[i++] = (BYTE)wc;
#elif FF_STRF_ENCODE == 3	/* Write a code point in UTF-8 */
	if (hs != 0) {	/* 4-byte sequence? */
		nc += 3;
		hs = (hs & 0x3FF) + 0x40;
		pb->buf[i++] = (BYTE)(0xF0 | hs >> 8);
		pb->buf[i++] = (BYTE)(0x80 | (hs >> 2 & 0x3F));
		pb->buf[i++] = (BYTE)(0x80 | (hs & 3) << 4 | (wc >> 6 & 0x0F));
		pb->buf[i++] = (BYTE)(0x80 | (wc & 0x3F));
	} else {
		if (wc < 0x80) {	/* Single byte? */
			pb->buf[i++] = (BYTE)wc;
		} else {
			if (wc < 0x800) {	/* 2-byte sequence? */
				nc += 1;
				pb->buf[i++] = (BYTE)(0xC0 | wc >> 6);
			} else {			/* 3-byte sequence */
				nc += 2;
				pb->buf[i++] = (BYTE)(0xE0 | wc >> 12);
				pb->buf[i++] = (BYTE)(0x80 | (wc >> 6 & 0x3F));
			}
			pb->buf[i++] = (BYTE)(0x80 | (wc & 0x3F));
		}
	}
#else						/* Write a code point in ANSI/OEM */
	if (hs != 0) return;
	wc = ff_uni2oem(wc, CODEPAGE);	/* UTF-16 ==> ANSI/OEM */
	if (wc == 0) return;
	if (wc >= 0x100) {
		pb->buf[i++] = (BYTE)(wc >> 8); nc++;
	}
	pb->buf[i++] = (BYTE)wc;
#endif

#else							/* ANSI/OEM input (without re-encoding) */
	pb->buf[i++] = (BYTE)c;
#endif

	if (i >= (int)(sizeof pb->buf) - 4) {	/* Write buffered characters to the file */
		f_write(pb->fp, pb->buf, (UINT)i, &n);
		i = (n == (UINT)i) ? 0 : -1;
	}
	pb->idx = i;
	pb->nchr = nc + 1;
}


/* Flush remaining characters in the buffer */

static int putc_flush (putbuff* pb)
{
	UINT nw;

	if (   pb->idx >= 0	/* Flush buffered characters to the file */
		&& f_write(pb->fp, pb->buf, (UINT)pb->idx, &nw) == FR_OK
		&& (UINT)pb->idx == nw) return pb->nchr;
	return -1;
}


/* Initialize write buffer */

static void putc_init (putbuff* pb, FIL* fp)
{
	memset(pb, 0, sizeof (putbuff));
	pb->fp = fp;
}



int f_putc (
	TCHAR c,	/* A character to be output */
	FIL* fp		/* Pointer to the file object */
)
{
	putbuff pb;


	putc_init(&pb, fp);
	putc_bfd(&pb, c);	/* Put the character */
	return putc_flush(&pb);
}




/*-----------------------------------------------------------------------*/
/* Put a String to the File                                              */
/*-----------------------------------------------------------------------*/

int f_puts (
	const TCHAR* str,	/* Pointer to the string to be output */
	FIL* fp				/* Pointer to the file object */
)
{
	putbuff pb;


	putc_init(&pb, fp);
	while (*str) putc_bfd(&pb, *str++);		/* Put the string */
	return putc_flush(&pb);
}




/*-----------------------------------------------------------------------*/
/* Put a Formatted String to the File (with sub-functions)               */
/*-----------------------------------------------------------------------*/
#if FF_PRINT_FLOAT && FF_INTDEF == 2
#include <math.h>

static int ilog10 (double n)	/* Calculate log10(n) in integer output */
{
	int rv = 0;

	while (n >= 10) {	/* Decimate digit in right shift */
		if (n >= 100000) {
			n /= 100000; rv += 5;
		} else {
			n /= 10; rv++;
		}
	}
	while (n < 1) {		/* Decimate digit in left shift */
		if (n < 0.00001) {
			n *= 100000; rv -= 5;
		} else {
			n *= 10; rv--;
		}
	}
	return rv;
}


static double i10x (int n)	/* Calculate 10^n in integer input */
{
	double rv = 1;

	while (n > 0) {		/* Left shift */
		if (n >= 5) {
			rv *= 100000; n -= 5;
		} else {
			rv *= 10; n--;
		}
	}
	while (n < 0) {		/* Right shift */
		if (n <= -5) {
			rv /= 100000; n += 5;
		} else {
			rv /= 10; n++;
		}
	}
	return rv;
}


static void ftoa (
	char* buf,	/* Buffer to output the floating point string */
	double val,	/* Value to output */
	int prec,	/* Number of fractional digits */
	TCHAR fmt	/* Notation */
)
{
	int d;
	int e = 0, m = 0;
	char sign = 0;
	double w;
	const char *er = 0;
	const char ds = FF_PRINT_FLOAT == 2 ? ',' : '.';


	if (isnan(val)) {			/* Not a number? */
		er = "NaN";
	} else {
		if (prec < 0) prec = 6;	/* Default precision? (6 fractional digits) */
		if (val < 0) {			/* Negative? */
			val = 0 - val; sign = '-';
		} else {
			sign = '+';
		}
		if (isinf(val)) {		/* Infinite? */
			er = "INF";
		} else {
			if (fmt == 'f') {	/* Decimal notation? */
				val += i10x(0 - prec) / 2;	/* Round (nearest) */
				m = ilog10(val);
				if (m < 0) m = 0;
				if (m + prec + 3 >= SZ_NUM_BUF) er = "OV";	/* Buffer overflow? */
			} else {			/* E notation */
				if (val != 0) {		/* Not a true zero? */
					val += i10x(ilog10(val) - prec) / 2;	/* Round (nearest) */
					e = ilog10(val);
					if (e > 99 || prec + 7 >= SZ_NUM_BUF) {	/* Buffer overflow or E > +99? */
						er = "OV";
					} else {
						if (e < -99) e = -99;
						val /= i10x(e);	/* Normalize */
					}
				}
			}
		}
		if (!er) {	/* Not error condition */
			if (sign == '-') *buf++ = sign;	/* Add a - if negative value */
			do {				/* Put decimal number */
				if (m == -1) *buf++ = ds;	/* Insert a decimal separator when get into fractional part */
				w = i10x(m);				/* Snip the highest digit d */
				d = (int)(val / w); val -= d * w;
				*buf++ = (char)('0' + d);	/* Put the digit */
			} while (--m >= -prec);			/* Output all digits specified by prec */
			if (fmt != 'f') {	/* Put exponent if needed */
				*buf++ = (char)fmt;
				if (e < 0) {
					e = 0 - e; *buf++ = '-';
				} else {
					*buf++ = '+';
				}
				*buf++ = (char)('0' + e / 10);
				*buf++ = (char)('0' + e % 10);
			}
		}
	}
	if (er) {	/* Error condition */
		if (sign) *buf++ = sign;		/* Add sign if needed */
		do {		/* Put error symbol */
			*buf++ = *er++;
		} while (*er);
	}
	*buf = 0;	/* Term */
}
#endif	/* FF_PRINT_FLOAT && FF_INTDEF == 2 */



int f_printf (
	FIL* fp,			/* Pointer to the file object */
	const TCHAR* fmt,	/* Pointer to the format string */
	...					/* Optional arguments... */
)
{
	va_list arp;
	putbuff pb;
	UINT i, j, w, f, r;
	int prec;
#if FF_PRINT_LLI && FF_INTDEF == 2
	QWORD v;
#else
	DWORD v;
#endif
	TCHAR *tp;
	TCHAR tc, pad;
	TCHAR nul = 0;
	char d, str[SZ_NUM_BUF];


	putc_init(&pb, fp);

	va_start(arp, fmt);

	for (;;) {
		tc = *fmt++;
		if (tc == 0) break;			/* End of format string */
		if (tc != '%') {			/* Not an escape character (pass-through) */
			putc_bfd(&pb, tc);
			continue;
		}
		f = w = 0; pad = ' '; prec = -1;	/* Initialize parms */
		tc = *fmt++;
		if (tc == '0') {			/* Flag: '0' padded */
			pad = '0'; tc = *fmt++;
		} else if (tc == '-') {		/* Flag: Left aligned */
			f = 2; tc = *fmt++;
		}
		if (tc == '*') {			/* Minimum width from an argument */
			w = va_arg(arp, int);
			tc = *fmt++;
		} else {
			while (IsDigit(tc)) {	/* Minimum width */
				w = w * 10 + tc - '0';
				tc = *fmt++;
			}
		}
		if (tc == '.') {			/* Precision */
			tc = *fmt++;
			if (tc == '*') {		/* Precision from an argument */
				prec = va_arg(arp, int);
				tc = *fmt++;
			} else {
				prec = 0;
				while (IsDigit(tc)) {	/* Precision */
					prec = prec * 10 + tc - '0';
					tc = *fmt++;
				}
			}
		}
		if (tc == 'l') {			/* Size: long int */
			f |= 4; tc = *fmt++;
#if FF_PRINT_LLI && FF_INTDEF == 2
			if (tc == 'l') {		/* Size: long long int */
				f |= 8; tc = *fmt++;
			}
#endif
		}
		if (tc == 0) break;			/* End of format string */
		switch (tc) {				/* Atgument type is... */
		case 'b':					/* Unsigned binary */
			r = 2; break;

		case 'o':					/* Unsigned octal */
			r = 8; break;

		case 'd':					/* Signed decimal */
		case 'u': 					/* Unsigned decimal */
			r = 10; break;

		case 'x':					/* Unsigned hexadecimal (lower case) */
		case 'X': 					/* Unsigned hexadecimal (upper case) */
			r = 16; break;

		case 'c':					/* Character */
			putc_bfd(&pb, (TCHAR)va_arg(arp, int));
			continue;

		case 's':					/* String */
			tp = va_arg(arp, TCHAR*);	/* Get a pointer argument */
			if (!tp) tp = &nul;		/* Null ptr generates a null string */
			for (j = 0; tp[j]; j++) ;	/* j = tcslen(tp) */
			if (prec >= 0 && j > (UINT)prec) j = prec;	/* Limited length of string body */
			for ( ; !(f & 2) && j < w; j++) putc_bfd(&pb, pad);	/* Left pads */
			while (*tp && prec--) putc_bfd(&pb, *tp++);	/* Body */
			while (j++ < w) putc_bfd(&pb, ' ');			/* Right pads */
			continue;
#if FF_PRINT_FLOAT && FF_INTDEF == 2
		case 'f':					/* Floating point (decimal) */
		case 'e':					/* Floating point (e) */
		case 'E':					/* Floating point (E) */
			ftoa(str, va_arg(arp, double), prec, tc);	/* Make a floating point string */
			for (j = strlen(str); !(f & 2) && j < w; j++) putc_bfd(&pb, pad);	/* Left pads */
			for (i = 0; str[i]; putc_bfd(&pb, str[i++])) ;	/* Body */
			while (j++ < w) putc_bfd(&pb, ' ');	/* Right pads */
			continue;
#endif
		default:					/* Unknown type (pass-through) */
			putc_bfd(&pb, tc); continue;
		}

		/* Get an integer argument and put it in numeral */
#if FF_PRINT_LLI && FF_INTDEF == 2
		if (f & 8) {		/* long long argument? */
			v = (QWORD)va_arg(arp, long long);
		} else if (f & 4) {	/* long argument? */
			v = (tc == 'd') ? (QWORD)(long long)va_arg(arp, long) : (QWORD)va_arg(arp, unsigned long);
		} else {			/* int/short/char argument */
			v = (tc == 'd') ? (QWORD)(long long)va_arg(arp, int) : (QWORD)va_arg(arp, unsigned int);
		}
		if (tc == 'd' && (v & 0x8000000000000000)) {	/* Negative value? */
			v = 0 - v; f |= 1;
		}
#else
		if (f & 4) {	/* long argument? */
			v = (DWORD)va_arg(arp, long);
		} else {		/* int/short/char argument */
			v = (tc == 'd') ? (DWORD)(long)va_arg(arp, int) : (DWORD)va_arg(arp, unsigned int);
		}
		if (tc == 'd' && (v & 0x80000000)) {	/* Negative value? */
			v = 0 - v; f |= 1;
		}
#endif
		i = 0;
		do {	/* Make an integer number string */
			d = (char)(v % r); v /= r;
			if (d > 9) d += (tc == 'x') ? 0x27 : 0x07;
			str[i++] = d + '0';
		} while (v && i < SZ_NUM_BUF);
		if (f & 1) str[i++] = '-';	/* Sign */
		/* Write it */
		for (j = i; !(f & 2) && j < w; j++) {	/* Left pads */
			putc_bfd(&pb, pad);
		}
		do {				/* Body */
			putc_bfd(&pb, (TCHAR)str[--i]);
		} while (i);
		while (j++ < w) {	/* Right pads */
			putc_bfd(&pb, ' ');
		}
	}

	va_end(arp);

	return putc_flush(&pb);
}

#endif /* !FF_FS_READONLY */
#endif /* FF_USE_STRFUNC */



#if FF_CODE_PAGE == 0
/*-----------------------------------------------------------------------*/
/* Set Active Codepage for the Path Name                                 */
/*-----------------------------------------------------------------------*/

FRESULT f_setcp (
	WORD cp		/* Value to be set as active code page */
)
{
	static const WORD       validcp[22] = {  437,   720,   737,   771,   775,   850,   852,   855,   857,   860,   861,   862,   863,   864,   865,   866,   869,   932,   936,   949,   950, 0};
	static const BYTE *const tables[22] = {Ct437, Ct720, Ct737, Ct771, Ct775, Ct850, Ct852, Ct855, Ct857, Ct860, Ct861, Ct862, Ct863, Ct864, Ct865, Ct866, Ct869, Dc932, Dc936, Dc949, Dc950, 0};
	UINT i;


	for (i = 0; validcp[i] != 0 && validcp[i] != cp; i++) ;	/* Find the code page */
	if (validcp[i] != cp) return FR_INVALID_PARAMETER;		/* Not found? */

	CodePage = cp;
	if (cp >= 900) {	/* DBCS */
		ExCvt = 0;
		DbcTbl = tables[i];
	} else {			/* SBCS */
		ExCvt = tables[i];
		DbcTbl = 0;
	}
	return FR_OK;
}
#endif	/* FF_CODE_PAGE == 0 */


/* copy file */
FRESULT my_fcopy(TCHAR *psrc,TCHAR *pdst,u8 fwmode)
{
	FRESULT res;
	FIL *fsrc;// 闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊椤掑鏅悷婊冪箻楠炴垿濮�閵堝懐鐤�濡炪倖妫佸Λ鍕償婵犲洦鈷戦柛锔诲幖椤ｅ吋绻濋姀鈽呰�跨�殿喖鎲＄粭鐔兼晸娴犲钃熼柕濞炬櫆閸嬪嫰鏌ｉ幋鐑嗙劷闁糕晛鍚礳闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎婵炲樊浜濋ˉ鍫熺箾閹寸偞鐨戦柣锝夌畺濮婅櫣鎹勯妸銉︾亞濠碘槅鍋勭�氼喗绔熼弴銏╂晣闁绘鏁搁獮鎾绘⒑缂佹ê濮夐柛搴涘�濆畷鎰板垂椤愵偅顔旈梺缁樺姌鐏忔瑦绂掗姀銈嗙厱闁哄喛鎷风�癸拷閹间礁钃熼柣鏃傚帶缁�鍐煛鐏炶鍔氱�殿喕鍗冲铏规嫚閳ヨ櫕鐝紓浣虹帛缁诲牓鎮伴鎾呮嫹閿濆骸鏋熼柡鍛矒閺岋綁鏁愰崨鏉款伃濡ょ姷鍋涢悧鎾愁潖缂佹ɑ濯撮柛娑橈龚绾拷闂備胶顭堢花娲磹閺囶澁缍栭煫鍥ㄥ搸娴滃綊鏌熼悜妯诲碍濞寸姴銈稿铏规嫬鎼粹剝鍣藉ù鐘崇闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎闁惧繗顫夊畷澶愭煏婵炲灝鍔滈柣婵勫灲濮婃椽鎮烽弶鎸庮唨闂佺懓鍤栭幏锟�
	FIL *fdst;// fwmode闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柤纰卞墻濡茬兘姊绘担鍛婃儓缂佸绶氬畷銏＄鐎ｎ亞锛涢梺璺ㄥ枔婵敻鎮¤箛鎿冪唵閻犺櫣鍎らˉ鐐寸箾閸涱厽鍤囬柡宀嬬秮椤㈡﹢鎮ゆ担鍦澒闂備礁鎼張顒勬儎椤栫偛鏄ラ柛鏇ㄥ灠缁�鍐煥閺冨洦纭堕柡鍡橆殜濮婄粯鎷呴搹鐟扮濠殿喖锕ら…宄扮暦閵忥綆妯勯梺璇″枟閿氶柣锝囧厴瀹曞爼鏌ㄧ�ｎ亶浼撻梺鑽ゅ枑閻熴儳锟芥凹鍘剧划鍫ユ晸閽樺鏀介柣鎰皺濠�鎾煕閺冿拷閸ㄦ寧淇婄�涙鐟归柨鐔剁矙瀵偊骞樼紒妯绘闂佽法鍣﹂幏锟� 0:婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柟闂寸绾惧鏌ｉ幇顒佹儓闁搞劌鍊块弻娑㈩敃閿濆棛顦ョ紓浣哄С閸楁娊寮诲☉妯锋斀闁告洦鍋勬慨銏ゆ⒑濞茶骞楅柟鐟版喘瀵鏁愭径濠勵吅濠电姴鐏氶崝鏍礊濡ゅ懏鈷戦悹鎭掑妼閺嬫瑦淇婇銏狀伃妤犵偛锕ら～婊堟晸娴犲违濞撴熬鎷风�殿喗鎸虫慨锟介柍鈺佸暞閻濇洟姊绘担钘壭撻柨姘亜閿旇鐏＄紒鏃傚枛瀹曞崬鈽夊▎灞惧濠电偠鎻徊浠嬪箟閿熺姴绠氶柛顐犲劜閸嬶綁鏌涢妷銏℃珔濞寸姾浜敓鍊燁潐濞叉﹢鏁冮姀銈呮槬闁跨喓濮寸壕鍏肩節婵犲繑瀚圭紓浣介哺缁挸顫忔繝姘＜婵﹩鍓ㄩ幏閿嬵槹鎼达絿鐒兼繛鎾寸啲閹烽攱顨ラ悙瀵稿⒌妞ゃ垺娲熼弫鍌炴寠婢跺缍嶉梻鍌欒兌绾爼宕滃┑瀣啒閻庯綆鍠栭悙濠囨煏婵炲灝鍔撮柛銈冨�濆娲传閸曞灚效闂佹悶鍔庨弫璇茬暦閻㈢绠ｉ柨鏃囆掗幏娲⒑閸涘﹦鈽夐柨鏇樺�栭幈銊╂晸娴犲鈷戦柛婵嗗閸ｈ櫣绱掔拠鑼ⅵ濠碘剝鎸冲畷銊э拷娑櫭敓钘夘煼閺屻倝骞侀幒鎴濆Б闂佸憡鐟ュΛ婵嗩潖閾忓湱纾兼俊顖濆吹椤︺儵姊虹粙鍖″伐婵狅拷闁秵鏅搁柤鎭掑劤閸熸煡鏌熼崙銈嗗 1:闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊瑜忛弳锕傛煟閵忋埄鐒剧紒鎰殜閺岀喖鏌囬敃锟介崝鎺撶箾瀹割喕绨婚柛鎰舵嫹婵＄偑鍊ら崜锕傚礈濮樿京鐭欓柟杈剧畱閻撯�愁熆鐠哄ソ锟犳偄閼姐倗鏉搁梺鍝勬川閸嬫稒淇婇搹鍦＝濞达綀娅ｇ敮娑氱磼鐠囪尙澧曢柣锝囧厴楠炲棝鏌囬敂鍙晠姊绘担渚劸妞ゆ垵鎳愮划鏃堟偡闁附缍庨梺鎯х箰濠�杈╁閸忛棿绻嗘い鏍ㄧ箓閸氬綊鏌涘▎蹇旑棦婵﹨娅ｅ☉鐢稿椽娴ｅ憡鐤傜紓鍌欐祰妞寸煤濠婂牆绀嗛柟鐑樻尵缁★拷濠殿喗锕╅崜娑㈩敊婵犲倵鏀介幒鎶藉磹閹剧粯鍤勯柛顐ｆ礀閸屻劑鏌熼梻瀵稿妽闁抽攱鍨圭槐鎺旓拷锝庡亜椤曟粍绻濋敓浠嬪箥椤旂偓锛忛梺鍝勵槼濞夋洘鏅ラ梻浣筋嚃閸ㄤ即鎳熼婵堜簷濠电偠鎻紞锟芥繛鍜冪秮椤㈡瑩寮撮姀鈾�鎷虹紓渚囧灡濞叉﹢锝炴繝鍥ㄧ厱婵☆垰鍚嬪▍鏇㈡煥閻旇袚闁绘棏鍓熼獮蹇涙晸閿燂拷
	bw=0;
	br=0;
	u8 *fbuf=0;
	uint64_t Size=0;
//	fsrc=(FIL*)malloc(sizeof(FIL));//闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸婂潡鏌ㄩ弴鐐诧拷褰掑磿閹寸姵鍠愰柣妤�鐗嗙粭鎺楁煕閵娿儱锟藉骞夐幖浣瑰亱闁割偅绻勯悷鏌ユ⒑缁嬫鍎涘ù婊庝邯瀵鈽夐姀鐘栥劍銇勯弮鍌氬付闁抽攱甯″鐑樻姜閹殿噮妲銈嗗灥濡繃淇婇悽绋跨妞ゆ牗姘ㄩ濠囨⒑閻熸壆鎽犵紒璇茬У缁傛帡鎳栭埡鍐紳婵炴挻鑹鹃敃銉э拷姘秺濮婃椽宕ㄦ繝鍌毿曢梺鍝ュУ椤ㄥ﹪骞冮敓鐘插嵆闁绘棁娅ｉ鏇㈡⒑閻熸壆鎽犵紒璇插�块幊婊呮喆閸曞灚顔旈梺缁樺姌閹活亪鎳撻崸妤佺厸鐎癸拷閿熶粙宕伴弽褜鍤曟い鎺戝鍥撮梺绯曞墲椤ㄥ繑瀵奸敓锟�
	fsrc=(FIL*)wjq_malloc_m(sizeof(FIL));//闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸婂潡鏌ㄩ弴鐐诧拷褰掑磿閹寸姵鍠愰柣妤�鐗嗙粭鎺楁煕閵娿儱锟藉骞夐幖浣瑰亱闁割偅绻勯悷鏌ユ⒑缁嬫鍎涘ù婊庝邯瀵鈽夐姀鐘栥劍銇勯弮鍌氬付闁抽攱甯″鐑樻姜閹殿噮妲銈嗗灥濡繃淇婇悽绋跨妞ゆ牗姘ㄩ濠囨⒑閻熸壆鎽犵紒璇茬У缁傛帡鎳栭埡鍐紳婵炴挻鑹鹃敃銉э拷姘秺濮婃椽宕ㄦ繝鍌毿曢梺鍝ュУ椤ㄥ﹪骞冮敓鐘插嵆闁绘棁娅ｉ鏇㈡⒑閻熸壆鎽犵紒璇插�块幊婊呮喆閸曞灚顔旈梺缁樺姌閹活亪鎳撻崸妤佺厸鐎癸拷閿熶粙宕伴弽褜鍤曟い鎺戝鍥撮梺绯曞墲椤ㄥ繑瀵奸敓锟�
//	fdst=(FIL*)malloc(sizeof(FIL));
	fdst=(FIL*)wjq_malloc_m(sizeof(FIL));
//	fbuf=(u8*)malloc(4096);
//	fbuf=(u8*)wjq_malloc_m(4096);  // 3.25闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柛鎰紦閻㈠姊绘担绋挎毐闁圭⒈鍋婇獮濠冩償閿濆洨锛滈梺鍐叉惈閹冲繘鍩涢幋鐐簻闁硅櫣鍋炵�氬湱绱撴担鍓叉Ч闁圭鍟块锝夊川婵犲嫮鎳濋梺璺ㄥ枍缁瑥顕ｆ繝姘櫜濠㈣泛锕﹂悿锟芥俊鐐�栧濠氬储瑜庢穱濠偯洪鍛嫼缂傚倷鐒﹁摫閻忓浚鍙冮弻娑欑節閸屾稑浠撮悗娈垮枛椤攱淇婇幖浣哥厸闁稿本鐭花浠嬫⒒娴ｄ警鐒鹃柡鍫墰缁瑩骞嬮敂缁樻櫆闂佽法鍣﹂幏锟� by lyh
	fbuf=(u8*)(0x80000000);		   // 3.25闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柛鎰紦閻㈠姊绘担绋挎毐闁圭⒈鍋婇獮濠冩償閿濆洨锛滈梺鍐叉惈閹冲繘鍩涢幋鐐簻闁硅櫣鍋炵�氬湱绱撴担鍓叉Ч闁圭鍟块锝夊川婵犲嫮鎳濋梺璺ㄥ枍缁瑥顕ｆ繝姘╅柍鍝勫�告禍鐐烘⒑缁嬫寧婀扮紒瀣灴椤㈡棃鏁撻敓锟�  by lyh
	if(fsrc==NULL||fdst==NULL||fbuf==NULL)
		res= FR_INVALID_PARAMETER;//
	else
	{
		 if(fwmode==0)
			 fwmode=FA_CREATE_NEW;     //婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柟闂寸绾惧鏌ｉ幇顒佹儓闁搞劌鍊块弻娑㈩敃閿濆棛顦ョ紓浣哄С閸楁娊寮诲☉妯锋斀闁告洦鍋勬慨銏ゆ⒑濞茶骞楅柟鐟版喘瀵鏁愭径濠勵吅濠电姴鐏氶崝鏍礊濡ゅ懏鈷戦悹鎭掑妼閺嬫瑦淇婇銏狀伃妤犵偛锕ら～婊堟晸娴犲违濞撴熬鎷风�殿喗鎸虫慨锟介柍鈺佸暞閻濇洟姊绘担钘壭撻柨姘亜閿旇鐏＄紒鏃傚枛瀹曞崬鈽夊▎灞惧濠电偠鎻紞锟藉┑顔哄�楀☉鐢稿醇閺囩喓鍘遍梺鎸庣箓缁绘帡鎮鹃崹顐闁绘劘灏欑粻濠氭煛娴ｈ宕岄柡浣规崌閺佹捇鏁撻敓锟�
		 else
			 fwmode=FA_CREATE_ALWAYS;   //闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊瑜忛弳锕傛煟閵忋埄鐒剧紒鎰殜閺岀喖鏌囬敃锟介崝鎺撶箾瀹割喕绨婚柛鎰舵嫹婵＄偑鍊ら崜锕傚礈濮樿京鐭欓柟杈剧畱閻撯�愁熆鐠哄ソ锟犳偄閼姐倗鏉搁梺鍝勫枦閹风兘鏌曢崶銊х疄闁哄备鍓濋幏鍛喆閸曨偆锛撻梻浣芥〃閻掞箓骞戦崶顒�鏋侀柟鍓х帛閺呮悂鏌ㄩ悤鍌涘
	     res=f_open(fsrc,(const TCHAR*)psrc,FA_READ|FA_OPEN_EXISTING); //闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙缂佺姷濞�閺岀喖宕滆鐢盯鏌涙繝鍛厫闁逛究鍔岃灒闁圭娴烽妴鎰磽娴ｅ搫小闁告濞婂璇测槈濡攱鏂�闂佸憡娲﹂崑鍕叏閺囩儐娓婚柕鍫濋娴滄繃绻涢懠顒�鏋涚�殿喖顭烽幃銏ゅ川婵犲嫮肖闂備礁鎲￠幐鍡涘川椤旂瓔鍟呴梻鍌氬�烽悞锕�顪冮崸妤�鍌ㄥù鐘差儍閿熻棄鍟村畷鍗炩槈濡粣绠撻弻娑㈠即閵娿儲鐏撻梺姹囧�ч幏鐑芥⒒娴ｇ瓔娼愰柛搴㈠▕椤㈡岸顢橀姀鐘栄囨煃閸濆嫭鍣洪柍閿嬪灴閺岀喖鎳栭埡浣风捕闂佽法鍠曟慨銈夊垂閸喚鏆﹂悷娆忓椤╃兘鎮楅敐搴濇捣闁硅姤娲熷铏规崉閵娿儲鐏佹繝娈垮枛椤曨厽绔熼弴銏犵闁稿繒鍘у鍨攽椤旂瓔娈旀俊顐ｎ殜閻涱喖顫滈敓浠嬪蓟閿濆绠婚柡澶嬪灩娴犳挳姊虹�圭媭娼愰柛銊ユ健楠炲啫鈻庨幘宕囩厬婵犮垼鍩栫粙鎾愁啅濠靛鈷掑ù锝囧劋閸わ拷闂佹悶鍊栭悧鐘荤嵁韫囨稒鏅搁柨鐕傛嫹
	     if(res==0)
	     {
	    	   Size=fsrc->obj.objsize;
	    	   res=f_open(fdst,(const TCHAR*)pdst,FA_WRITE|fwmode);
			   if(res==0)
			   {
					while(res==0)
				   {
//						res=f_read1(fsrc,fbuf,4096,(UINT*)&br);
						res=f_read1(fsrc,fbuf,0x100000,(UINT*)&br);
//						if(res||br==0)
						if(res)
						{
							xil_printf("Read failed! Res=%d\r\n",res);
							break;
						}

						Size-=br;
						res=f_write1(fdst,fbuf,(UINT)br,(UINT*)&bw);
//						if(res||bw<br)
						if(res)
						{

							xil_printf("Write failed! Res=%d\r\n",res);
							break;
						}
						if(Size<=0)
						{
							xil_printf("here");
							break;
						}
				   }		//	while
				   f_close(fsrc);
				   f_close(fdst);
			   }
	     }
	}
		 wjq_free_m(fsrc);
		 wjq_free_m(fdst);
//		 wjq_free_m(fbuf);
		 return res;
}

// 闂傚倸鍊搁崐宄懊归崶顒夋晪鐟滃秹婀侀梺缁樺灱濡嫰寮告笟锟介弻娑樷槈濮楀牊鏁惧┑鐐叉噽婵灚绌辨繝鍥ч柛娑卞枛濞咃繝姊虹捄銊ユ灆婵☆偄瀚板畷顖炲级閹寸姵娈鹃梺闈浥堥弲娑氱棯瑜旈弻鐔猴拷鐢殿焾娴狅妇鎮敐澶嬧拺閻犲洤寮堕幑锝嗙箾閸涱偄鐏叉鐐茬箻閹粓鎳為妷褍寮抽梻浣虹帛閺屻劍鏅舵惔銊﹀剹婵炲棙鍔﹀▓浠嬫煟閹邦厽缍戦柣蹇擃嚟閿熷�燁潐濞叉粓宕伴弽顓滐拷浣糕槈閵忊剝娅滈梺绯曞墲钃遍柣婵愬亜閳规垿鎮╅幇浣告櫛闂佸摜濮甸〃濠囧灳閿曞倸閱囬柣鏂捐濞茬顪冮妶鍡楃瑨閻庢凹鍙冨畷鎴澪熷Ч鍥︾盎闂佸搫鍟崐鐟扳枍閺囩姷纾奸柣妯垮吹閻ｆ椽鏌″畝锟介崰鎾绘晸閻ｅ本鏆╂い顓炵墛缁傛帡鏁冮崒娑橈拷鍫曠叓閸ラ鍒版鐐搭殜閺屾洟宕惰椤忣厽顨ラ悙宸剰闁宠鍨垮畷鍫曞Ω閿曪拷閿熺晫鍏樺缁樻媴閸濄儻绱炵紓渚囧櫘閸ㄥ爼鐛幋锕�鐐婃い鎺戝�哥粊锕傛煟鎼搭垳绉甸柛鐘愁殜瀵彃鈹戠�ｎ偆鍙嗛梺缁樻⒒缁垶藟婢舵劖鎳氶柣鎰摠閸欏繑淇婇妶鍜佸剱閻庢艾缍婂娲传閸曨剚鎷遍梺鐑╂櫓閸ㄨ鲸绌辨繝鍥ㄥ�荤紒娑橆儐閺咁剟姊虹紒妯哄闁诡垰鐭傞弫鎾绘寠婢跺睗銏°亜椤忓嫬鏆ｅ┑鈥崇埣瀹曞崬螖閿熶粙锝為幋婵冩斀闁宠棄妫楁禍婊堟倵濮橆偄宓嗛柛銊╃畺閺佸倿鎮欓锟界壕顖炴⒑闂堟侗鐓紒鐘冲灴椤㈡挸鈽夐姀锛勫幗闂佺粯鏌ㄩ幗婊堝箠閸愵喗鍊垫慨妯煎帶婢у瓨銇勯姀鈩冾棃闁轰焦鎹囬弫鎾绘晸閿燂拷
u8* get_src_dname(BYTE* dpfn)
{
//        u16 temp=0;

        while(*dpfn!=0){
                dpfn++;
//                temp++;
        }
      //  if(temp<4){return 0;}
        while((*dpfn!=0x5c)&&(*dpfn!=0x2f)){dpfn--;}        // 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘炬嫹妤犵偞鐗犻、鏇氱秴闁搞儺鍓﹂弫鍐煥閺囶亝瀚归梺姹囧�楅崑鎾舵崲濞戙垹绠ｆ繛鍡楃箳娴犻箖姊洪崫鍕櫤闁诡喖鍊垮濠氭晲婢跺娅滈梺鍛婄♁濠㈡﹢顢旈銏♀拺闁告繂瀚烽崕蹇涙⒑鐢喚绉�殿喖顭烽弫鎰板川閸屾稒鈷愰柟宄版噽缁瑩骞愭惔銏犳畼闂傚倸鍊风粈渚�骞栭锕�瀚夋い鎺戝閸庡孩銇勯弽顐户鐎规挷绶氶弻鐔兼倻濮楀棙鐣剁紓浣哄Т椤兘骞冨Δ鍛仺婵炲牐娉曢崝鎼佹⒑閹肩偛锟芥牜鏁垾鎰佹綎缂備焦蓱婵挳鏌ら幁鎺戝姢闁靛棗锕娲传閵夈儛锝嗙箾閸欏鑰挎鐐茬墦婵℃悂鍩℃担鍕撳洦鐓曢柕澶涚到婵¤姤绻涢崼鐔哥凡闁宠鍨堕獮濠囨煕婵犲啯绀嬫鐐诧攻閹棃鍩嶉幑顒�娲ら拑鐔兼煏婢舵稑顩柛妯圭矙濮婃椽宕崟顐ｆ濠电偠顕滅粻鎾汇�侀弮鍫熷亹闁汇垻鏁搁敍婊堟⒑缂佹﹩鐒炬繛鍛礋閸╂盯骞囬悧鍫㈠帾闂佹悶鍎滈崘鍙ョ磾婵°倗濮烽崑娑㈩敄婢舵劕鏋侀柟鐗堟緲楠炪垺绻涢崱妤冣枌闁圭兘鏀辩换婵嬪磼閵堝棗鐦滈梻渚�娼ч悧鍡涘箠閹邦喚涓嶉柟娈垮櫙閹烽鎲撮崟顒�顦╅梺鍛婃尵閸犳牕鐣峰ú顏勎ㄩ柨鏇嫹缂佸墎鍋ら弻鐔兼焽閿曪拷婢х増銇勯弮锟介幑鍥ь潖濞差亜宸濆┑鐘插暙椤︹晠姊洪崨濠冨鞍闁荤啿鏅犻妴渚�寮崼鐔告闂佽法鍣﹂幏锟�"\"闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙缂佺姷濞�閺岀喖宕滆鐢盯鏌涚�ｃ劌锟芥繈寮婚弴鐔虹闁绘劦鍓氶悵鏇㈡⒑缁嬫鍎忔い鎴濐樀瀵鏁愭径濠勭杸濡炪倖姊婚崢褎淇婂ú顏呪拺闁告繂瀚崳娲煙椤旂厧锟藉灝顕ｆ繝姘櫢闁绘灏欓敍婊冣攽閳藉棗鐏ｉ悘蹇嬪姂楠炲繘鎮滈挊澶婂敤濡炪倖鍔﹂崜姘憋拷姘愁潐閹便劌螣閻撳簼澹曢柣搴㈢啲閹凤拷"/"婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柛娑橈攻閸欏繐霉閸忓吋缍戦柛銊ュ�搁埞鎴﹀磼濮橆剦妫岄梺杞扮閿曨亪寮婚悢鍏煎亱闁割偆鍠撻崙锛勭磽娴ｅ搫顎岄柛銊ョ埣瀵濡搁埡鍌氫簽闂佺鏈粙鎴︻敂閿燂拷
        return ++dpfn;
}
//闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎婵炲樊浜濋ˉ鍫熺箾閹寸偞鐨戦柣锝夌畺濮婅櫣鎹勯妸銉︾亞濠碘槅鍋勭�氼喗绔熼弴銏╂晣闁绘鏁搁獮鎾绘⒑缂佹ê濮夐柛搴涘�濋崺娑㈠箣閿旂晫鍘炬繝娈垮枟閸旀洟鏁撻懞銉︾鐎殿喚顭堥埥澶愬閿涘嫬骞堥梺璇插嚱缂嶅棙绂嶅畡閭﹀晠闁靛鏅涚涵锟介梺鍛婎殘閸嬫劙寮ㄦ禒瀣厽婵☆垵娅ｉ敍宥嗐亜閿濆棛鍙�闁哄矉缍侀獮妯硷拷娑欘焽椤︿即姊洪崫鍕伇闁哥姵鐗犻獮鏍亹閹烘挸浠俊顐︻暒閻掞箓宕熼崘顔解拺閻犲洦褰冮銏ゆ煟閺冩垵澧存鐐茬箻閺佹捇鏁撻敓锟�
//闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊椤掑鏅悷婊冪箻楠炴垿濮�閵堝懐鐤�濡炪倖妫佸Λ鍕償婵犲洦鈷戦柛锔诲幖椤ｅ吋绻濋姀鈽呰�跨�殿喖鎲＄粭鐔兼晸娴犲钃熼柕濞炬櫆閸嬪嫰鏌ｉ幋鐑嗙劷闁糕晛鍚礳闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎婵炲樊浜濋ˉ鍫熺箾閹寸偞鐨戦柣锝夌畺濮婅櫣鎹勯妸銉︾亞濠碘槅鍋勭�氼喗绔熼弴銏╂晣闁绘鏁搁獮鎾绘⒑缂佹ê濮夐柛搴涘�濋崺娑㈠箣閿旇棄浠梺璇″幗鐢帗淇婇崗鑲╃闁告侗鍠栨慨宥夋煛瀹�锟介崰鏍х暦濞嗘挸围闁糕剝顨忔导锟�,copy闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极瀹ュ绀嬫い鎺嶇劍椤斿洭姊绘担铏瑰笡闁告梹鐗滅划濠囧箻椤旂厧鍤戦梺鍝勫暙閻楀﹪鎮″▎鎰╀簻闁规崘娉涙禍濂告煥閻旂粯顥夌紒渚垮姂濮婂宕掑顒婃嫹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎婵炲樊浜濋ˉ鍫熺箾閹寸偞鐨戦柣锝夌畺濮婅櫣鎹勯妸銉︾亞濠碘槅鍋勭�氼喗绔熼弴銏╂晣闁绘鏁搁獮鎾绘⒑缂佹ê濮夐柛搴涘�濋崺娑㈠箣閿旇棄浠梺璇″幗鐢帗淇婇崗鑲╃闁告侗鍠栨慨宥夋煛瀹�锟介崰鏍х暦濞嗘挸围闁糕剝顨忔导锟�
// fwmode闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柤纰卞墻濡茬兘姊绘担鍛婃儓缂佸绶氬畷銏＄鐎ｎ亞锛涢梺璺ㄥ枔婵敻鎮¤箛鎿冪唵閻犺櫣鍎らˉ鐐寸箾閸涱厽鍤囬柡宀嬬秮椤㈡﹢鎮ゆ担鍦澒闂備礁鎼張顒勬儎椤栫偛鏄ラ柛鏇ㄥ灠缁�鍐煥閺冨洦纭堕柡鍡橆殜濮婄粯鎷呴搹鐟扮濠殿喖锕ら…宄扮暦閵忥綆妯勯梺璇″枟閿氶柣锝囧厴瀹曞爼鏌ㄧ�ｎ亶浼撻梺鑽ゅ枑閻熴儳锟芥凹鍘剧划鍫ユ晸閽樺鏀介柣鎰皺濠�鎾煕閺冿拷閸ㄦ寧淇婄�涙鐟归柨鐔剁矙瀵偊骞樼紒妯绘闂佽法鍣﹂幏锟� 0:婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柟闂寸绾惧鏌ｉ幇顒佹儓闁搞劌鍊块弻娑㈩敃閿濆棛顦ョ紓浣哄С閸楁娊寮诲☉妯锋斀闁告洦鍋勬慨銏ゆ⒑濞茶骞楅柟鐟版喘瀵鏁愭径濠勵吅濠电姴鐏氶崝鏍礊濡ゅ懏鈷戦悹鎭掑妼閺嬫瑦淇婇銏狀伃妤犵偛锕ら～婊堟晸娴犲违濞撴熬鎷风�殿喗鎸虫慨锟介柍鈺佸暞閻濇洟姊绘担钘壭撻柨姘亜閿旇鐏＄紒鏃傚枛瀹曞崬鈽夊▎灞惧濠电偠鎻徊浠嬪箟閿熺姴绠氶柛顐犲劜閸嬶綁鏌涢妷銏℃珔濞寸姾浜敓鍊燁潐濞叉﹢鏁冮姀銈呮槬闁跨喓濮寸壕鍏肩節婵犲繑瀚圭紓浣介哺缁挸顫忔繝姘＜婵﹩鍓ㄩ幏閿嬵槹鎼达絿鐒兼繛鎾寸啲閹烽攱顨ラ悙瀵稿⒌妞ゃ垺娲熼弫鍌炴寠婢跺缍嶉梻鍌欒兌绾爼宕滃┑瀣啒閻庯綆鍠栭悙濠囨煏婵炲灝鍔撮柛銈冨�濆娲传閸曞灚效闂佹悶鍔庨弫璇茬暦閻㈢绠ｉ柨鏃囆掗幏娲⒑閸涘﹦鈽夐柨鏇樺�栭幈銊╂晸娴犲鈷戦柛婵嗗閸ｈ櫣绱掔拠鑼ⅵ濠碘剝鎸冲畷銊э拷娑櫭敓钘夘煼閺屻倝骞侀幒鎴濆Б闂佸憡鐟ュΛ婵嗩潖閾忓湱纾兼俊顖濆吹椤︺儵姊虹粙鍖″伐婵狅拷闁秵鏅搁柤鎭掑劤閸熸煡鏌熼崙銈嗗 1:闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊瑜忛弳锕傛煟閵忋埄鐒剧紒鎰殜閺岀喖鏌囬敃锟介崝鎺撶箾瀹割喕绨婚柛鎰舵嫹婵＄偑鍊ら崜锕傚礈濮樿京鐭欓柟杈剧畱閻撯�愁熆鐠哄ソ锟犳偄閼姐倗鏉搁梺鍝勬川閸嬫稒淇婇搹鍦＝濞达綀娅ｇ敮娑氱磼鐠囪尙澧曢柣锝囧厴楠炲棝鏌囬敂鍙晠姊绘担渚劸妞ゆ垵鎳愮划鏃堟偡闁附缍庨梺鎯х箰濠�杈╁閸忛棿绻嗘い鏍ㄧ箓閸氬綊鏌涘▎蹇旑棦婵﹨娅ｅ☉鐢稿椽娴ｅ憡鐤傜紓鍌欐祰妞寸煤濠婂牆绀嗛柟鐑樻尵缁★拷濠殿喗锕╅崜娑㈩敊婵犲倵鏀介幒鎶藉磹閹剧粯鍤勯柛顐ｆ礀閸屻劑鏌熼梻瀵稿妽闁抽攱鍨圭槐鎺旓拷锝庡亜椤曟粍绻濋敓浠嬪箥椤旂偓锛忛梺鍝勵槼濞夋洘鏅ラ梻浣筋嚃閸ㄤ即鎳熼婵堜簷濠电偠鎻紞锟芥繛鍜冪秮椤㈡瑩寮撮姀鈾�鎷虹紓渚囧灡濞叉﹢锝炴繝鍥ㄧ厱婵☆垰鍚嬪▍鏇㈡煥閻旇袚闁绘棏鍓熼獮蹇涙晸閿燂拷
FRESULT my_dcopy(TCHAR *psrc,TCHAR *pdst,u8 fwmode)
{
        FRESULT res;
        DIR *srcdir=0;                         // 濠电姷鏁告慨鐑藉极閸涘﹥鍙忛柣鎴ｆ閺嬩線鏌涘☉姗堟敾闁告瑥绻掗敓钘夌畭閸庨亶藝椤栨粎鐭嗛悗锝庡亖娴滄粓鏌熼幍铏珔闁绘帞鍎ょ换娑㈠礂閸忚偐顦ㄧ紓浣虹帛缁诲牓骞冩禒瀣棃婵炴垶顨堥幑鏇㈡煟鎼淬埄鍟忛柛鐘崇洴瀹曟椽寮介鐐殿槴婵犵數濮撮崯浼淬�呴悜鑺ュ�甸柨婵嗗嚱閹风兘顢橀妸褏鏆ら梺鍝勭灱閸犳牠鐛澶樻晩缁炬媽椴稿В澶愭⒒娴ｅ憡鎯堥柟鍐茬箻楠炲啴宕掗悙鑼舵憰闂侀潧艌閺呮粓宕戦崱娑欑厱閻忕偛澧介埥澶嬨亜韫囥儲瀚�
        FILINFO finfo;                         // 闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎婵炲樊浜濋ˉ鍫熺箾閹存瑥鐏�规洦浜炵槐鎾存媴娴犲鎽靛┑鐐跺皺閸犳牕鐣峰ú顏呭�风�瑰壊鍠栭幃鎴炵節閵忥絾纭炬い鎴濇喘瀹曘垽骞樼紒妯锋嫼闁诲骸婀辨慨鐢稿Υ閸愵亞纾奸柨鐔诲Г缁楃喖鏁撻挊澶樺殨闁规儼妫勯崡鎶芥煟濡吋鏆╅柨娑欑矒濮婅櫣鎲撮崟顐ょシ濡炪倖鍨靛Λ娑㈡晸閼恒儳鍟查柟鍑ゆ嫹
        u8* fn=0;                             // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾惧綊鏌熼梻瀵割槮缁炬崘顕ч埞鎴︽偐閸欏鎮欑紓浣哄閸ㄥ爼寮婚敐澶婄闁挎繂鎲涢幘缁樼厽闁规儳顕幊鍛磼鏉堛劌绗ч柨鐔告灮缂嶅棙绂嶉悙瀵割浄闁靛緵棰佺盎闂佺懓鎼鍛存倶閺屻儲鐓涚�癸拷鐎ｎ剛蓱闂佽鍨卞Λ鍐�佸▎鎾崇闁兼祴鏅欓柇顖炴⒒閸屾艾锟界煤閵堝＆鍥偨缁嬭儻鎽曢梺鎸庣箓閹叉﹢鎮㈤崗鐓庝簵闁硅偐琛ラ敓鑺ュ墯閻庤京绱撻崒娆掑厡闁惧繐閰ｅ畷锝夊礃椤忓棔绗夐梺鍝勭▉閸樺ジ鎷戦悢鍏肩厽闁哄啫鍊甸幏锟犳煛娴ｅ壊鍎旈柡灞剧洴閸╁嫰宕楅悪锟芥禍顏堛�侀弮鍫熸櫢闁跨噦鎷�
        u8* dstpathname=0;                // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙缁炬儳娼￠弻锝夊閵忊晝鍔搁梺姹囧�濈粻鏍蓟瀹ュ浼犻柛鏇ㄥ墮濞咃絿绱撴担鐟板妞ゃ劌妫欑粚杈ㄧ節閸ヮ灛褔鏌涘☉鍗炴灈婵炲懌鍊濆铏圭矙濞嗘儳鍓板銈忓閺佽顕ｆ繝姘╅柕澶堝灪閺傦拷闂備胶纭跺褔寮插鍛噮婵犵數濮烽。钘壩ｉ崨鏉戠；闁告稑鐡ㄩ弲婵嬫煏韫囧锟芥洟鎷戦悢鍝ョ闁瑰瓨鐟ラ悘鈺呭船椤栨凹娓婚柕鍫濇婢ч亶鏌涚�ｎ剙浠辨い銏℃尭椤撳ジ宕担鐟扮槣闂備線娼ч悧鍡椢涘Δ浣瑰弿閻忕偛褰炵换鍡樸亜閹扳晛鐏╂い蹇ｅ弮閺屽秹濡烽婊呮殼閻庤娲滈…鍫ｇ亙闂佽法鍠撻弲顐ゅ垝閸儱閱囨繝闈涘閹风兘骞掗幋顓熷兊濡炪倖甯婄粈渚�藝閳哄懏鈷戦弶鐐村鐠愪即鏌涢妸銊︾【妞ゎ偄绻樺畷顐﹀礉閸婄喐顏犻柟椋庡█楠炴捇骞掗弮鎴濇櫏闂傚倸鍊烽懗鍫曗�﹂崼顫嫹濞戞帗娅嗙紒缁樼♁缁绘繈宕堕妷顖涘濞达絽澹婂鈺呮偣鏉炴壆绉块柕濞炬櫆閻撳啴鏌涘┑鍡楊仼闁跨喓鏅幊鎾诲煝瀹ュ顫呴柕鍫濇閹锋椽鏌ｉ悩鍏呰埅闁告柨鑻埢宥夊箛閻楀牏鍘甸梺鍛婂灟閸婃牜锟芥熬鎷�+闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎婵炲樊浜濋ˉ鍫熺箾閹寸偞鐨戦柣銈呭濮婅櫣绮欓崠鈩冩暰濠电偛寮剁划鎾荤嵁婢舵劕绠绘い鏃囧Г濞呭洭姊虹粙鎸庢拱缂佸鎹囧畷锝夊幢濞戞瑢鎷虹紓鍌欑劍钃辩紒锟介敓浠嬫⒑缁嬪尅宸ユ繝锟介柆宥嗘櫢闁兼亽鍎抽崯鏌ユ煙閸戙倖瀚�
        u8* srcpathname=0;                // 濠电姷鏁告慨鐑藉极閸涘﹥鍙忛柣鎴ｆ閺嬩線鏌涘☉姗堟敾闁告瑥绻掗敓钘夌畭閸庨亶藝椤栨粎鐭嗛悗锝庡亖娴滄粓鏌熼幍铏珔闁绘帞鍎ょ换娑㈠礂閸忕⒈妫冨┑顔硷功缁垶骞忛崨鏉戝窛濠电姴鍟崜鍨繆閻愵亜锟芥牠宕归悽绋跨疇婵☆垵娅ｉ弳锔姐亜閺嶎偄鍓遍柡浣哥У缁绘繃绻濋崒娑樻闂佺粯甯掑鈥愁潖濞差亜鎹舵い鎾跺仜婵″搫鈹戦纭峰姛闁硅櫕鎹囬幃楣冩煥鐎ｎ亞绐為梺褰掑亰閸橀箖宕㈤棃娑辨富闁靛牆妫欑亸鐢告煕閻樺弶鎹ｇ紒顕呭弮瀹曟帒顭ㄩ崨顖ょ床婵＄偑鍊栧Λ浣规叏閵堝洣鐒婇柨鏇炲�归悡娑氾拷鐧告嫹閻庯綆鍓涜ⅵ闂備浇顕栭崰鎺楀疾濠婂喚鐒介煫鍥ㄤ緱閺佸啯銇勯幇鈺佺仼闂婏箓姊婚崒姘拷鐑芥倿閿曞倸绠栭柛顐ｆ礀缁�澶岋拷骞垮劚濡盯鎮甸崼鏇熺厱闁斥晛鍟ㄦ禒婊堟煛鐎ｎ亪鍙勯柡灞炬礉缁犳稓锟斤綆浜烽幏鐑藉冀椤撶偟鏌ч梺褰掓？閻掞箓鎮￠妷鈺傜厽闁哄洨鍋涢敓钘夋贡閿熻姤鐔幏锟�+闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎婵炲樊浜濋ˉ鍫熺箾閹寸偞鐨戦柣銈呭濮婅櫣绮欓崠鈩冩暰濠电偛寮剁划鎾荤嵁婢舵劕绠绘い鏃囧Г濞呭洭姊虹粙鎸庢拱缂佸鎹囧畷锝夊幢濞戞瑢鎷虹紓鍌欑劍钃辩紒锟介敓浠嬫⒑缁嬪尅宸ユ繝锟介柆宥嗘櫢闁兼亽鍎抽崯鏌ユ煙閸戙倖瀚�
        u16 dstpathlen=0;                 // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙缁炬儳娼￠弻锝夊閵忊晝鍔搁梺姹囧�濈粻鏍蓟瀹ュ浼犻柛鏇ㄥ墮濞咃絿绱撴担鐟板妞ゃ劌妫欑粚杈ㄧ節閸ヮ灛褔鏌涘☉鍗炴灈婵炲懌鍊濆铏圭矙濞嗘儳鍓板銈忓閺佽顕ｆ繝姘╅柕澶堝灪閺傦拷闂備胶纭堕崜婵嬫晪濡炪倧鑵归弲鐘诲箖濡ゅ啯鍠嗛柛鏇ㄥ墰椤︺儱顪冮妶蹇曠窗闁告娅曟穱濠囨偨缁嬭法顦板銈嗙墬閼归箖宕妸鈺傗拺闂傚牊渚楅悡顓炩攽閳ヨ櫕鎼愰柍缁樻崌婵″爼宕堕埡鍐跨闯濠电偠鎻徊鍧楀箠閹惧瓨鍙忓鑸靛姈閻撴洟鎮楅敐鍐ㄥ闁跨喕濮ゅú鐔兼晲閻愬墎鐤�闁哄啫鍊婚惁鍫濃攽椤旀枻渚涢柛妯挎閳诲秹濮�閿涘嫮顔曢柣搴ｆ暩椤牆鐡俊鐐�栭崹鐢稿箠濡櫣鏆︾憸鐗堝笒绾惧吋绻涢幋鐐靛ⅶ缂併劌顭峰娲传閸曨偅娈梺绋匡功閺佸鐛箛娑欐櫢闁绘ê纾崢閬嶆⒑缂佹ê鐏ユ繛璇у閿熻姤鐔幏锟�
        u16 srcpathlen=0;                 // 濠电姷鏁告慨鐑藉极閸涘﹥鍙忛柣鎴ｆ閺嬩線鏌涘☉姗堟敾闁告瑥绻掗敓钘夌畭閸庨亶藝椤栨粎鐭嗛悗锝庡亖娴滄粓鏌熼幍铏珔闁绘帞鍎ょ换娑㈠礂閼测晜鍣板┑顔硷功缁垶骞忛崨顖涘枂闁告洍鏅欓幋鐑芥⒒娴ｅ憡鍟為惇澶岀磼椤旂晫鎳冮柣锝囧厴瀵挳濮�閻樻鍞寸紓鍌欑劍缁嬫垿顢栭崱娑樼柧妞ゅ繐鐗婇埛鎴︽⒒閸喍绶辨俊鍙夋尦閺岋繝宕ㄩ淇憋拷鎺旂磼椤旇偐澧㈤柨鐔告灮缂嶅棝宕戞担鍦洸婵犲﹤鐗婇悡娑氾拷骞垮劚閸燁偅淇婇崸妤佺厓闁告瑣鍎崇粣鏃堟煛瀹�瀣М闁轰礁鍊块幊鏍煛閸愬啯绮撳娲传閸曨厾浼囬梺鍝ュУ閻楃娀鐛繝鍌楁斀閻庯綆鍋勬禍閬嶆⒑閸撴彃浜濈紒璇插暣閺屻劑顢橀姀鈾�鎷绘繛杈剧悼閸庛倝宕甸敓浠嬫⒑閹肩偛锟芥牠鎮ч悩鑽ゅ祦闊洦绋掗弲鎼佹煥閻曞倹瀚�
//        double fileSizeKb=0.0;        // 婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柛娑橈攻閸欏繐霉閸忓吋缍戦柛銊ュ�块弻锝夊箻瀹曞洤鍝洪梺鍝勵儐閻楁鎹㈠☉銏犵闁绘劕顕▓銈夋⒑濞茶骞楅柟鐟版喘瀵鎮㈤搹鍦紲闂侀潧绻掓慨鐢告倶閸儲鈷戦柛婵嗗椤忋儵鏌涙惔鈥崇骇缂佸矁椴哥换婵嬪炊椤儸鍥ㄧ厱婵炴垵宕弸娑欑箾閸滃啰鎮肩紒杈ㄦ尰閹峰懘宕崟鎴墴閺屾稓锟斤綆鍋勬慨宥夋煛娴ｈ宕岄柟绋匡攻瀵板嫬鐣濋敓浠嬪汲濞戙垺鈷戠紒瀣閸炲霉濠婂骸澧撮柡浣规崌閹崇偤濡烽妷銉︾槗闂備礁鎽滄慨闈涱潩閵娾晛绀嗛柟鐑樺灍閺嬪酣鏌熼柇锕�鏋ら柣锕�鐗撳娲箹閻愭彃濮岄梺鍛婃煥闁帮絽鐣烽姀锛勵浄閻庯綆鍋�閹锋椽姊婚崒姘卞濞撴碍顨婇幃鐐淬偅閸愨晝鍘遍柟鍏肩暘閸斿骞夐悙顑句簻闁靛繆鍓濋ˉ鍫熴亜閵忊剝绀嬮柡浣瑰姍瀹曞爼鍩℃繝鍌涙珬闂傚倸鍊风粈渚�骞夐敓鐘冲仭闁靛鏁￠崶顒夋晬闁绘垵妫欓弲娑樷攽閻樿宸ラ柣妤�锕幃陇绠涘☉娆戝幈闂侀潧顧�缁茶姤淇婇悡搴樻斀妞ゆ棁鍋愯倴闂佽法鍠曟慨銈夘敊閺嶎厼绐楁俊銈呮噹缁犱即鏌熼幆鐗堫棄缂佺姵鐗楃换娑㈠幢濡粯鍎庨梺杞扮閸婂潡寮诲☉銏犵疀闁靛闄勯悵鏇㈡倵鐟欏嫭绀冨┑鐐诧工椤繒绱掑Ο璇差�撶紓浣圭☉椤戝懎鈻撻鐘电＝濞达綀娅ｇ敮娑㈡煕閺冿拷閻楃娀濡撮崘顔嘉ㄩ柕濞у懏婢戞繝鐢靛仦閸ㄥ爼鈥﹂崶顒夋晩闁糕剝绋掗埛鎴︽偣閹帒濡兼繛鍛姍閺岀喖宕欓妶鍡楊伓(KB)
//        double copySpeed=0.0;        // 婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柛娑橈攻閸欏繐霉閸忓吋缍戦柛銊ュ�块弻锝夊箻瀹曞洤鍝洪梺鍝勵儐閻楁鎹㈠☉銏犵闁绘劕顕▓銈夋⒑濞茶骞楅柟鐟版喘瀵鎮㈤搹鍦紲闂侀潧绻掓慨鐢告倶閸儲鈷戦柛婵嗗椤忋儵鏌涙惔鈥崇骇缂佸矁椴哥换婵嬪炊椤儸鍥ㄧ厱婵炴垵宕弸娑欑箾閸滃啰鎮肩紒杈ㄦ尰閹峰懘宕崟鎴墴閺屾稓锟斤綆鍋勬慨宥夋煛娴ｈ宕岄柟绋匡攻瀵板嫬鐣濋敓浠嬪汲濞戙垺鈷戠紒瀣閸炲霉濠婂骸澧撮柡浣规崌閹崇偤濡烽妷銉︾槗闂備礁鎽滄慨闈涱潩閵娾晛绀嗛柟鐑樺灍閺嬪酣鏌熼柇锕�鏋ら柣锕�鐗撳娲箹閻愭彃濮岄梺鍛婃煥闁帮絽鐣烽姀锛勵浄閻庯綆鍋�閹锋椽姊婚崒姘卞濞撴碍顨婇幃鐐淬偅閸愨晝鍘遍柟鍏肩暘閸斿骞夐悙顑句簻闁靛繆鍓濋ˉ鍫熴亜閵忊剝顥堢�规洏鍔戦、妤呭磼濠婂懏姣庨梻鍌氬�烽懗鍓佸垝椤栫偛绀夐柡宥庡厵娴滃綊鏌涢幇闈涙灍闁哄懏鎮傞弻锕�螣娓氼垱楔婵炲濮伴崹娲Φ閸曨垼鏁冮柕蹇嬪灮椤斿绱撴担铏瑰笡缂佽鍊块敐鐐测攽鐎ｅ灚鏅ｉ梺缁樻煥婢瑰﹥绂掕濮婂宕掑▎鎰偘濠电偛顦板ú鐔风暦閹惰姤鏅濋柛灞炬皑椤斿棝姊虹捄銊ユ珢闁瑰嚖鎷�(KB/sec)
//        float timeUsed=0.0;                // 婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柛娑橈攻閸欏繐霉閸忓吋缍戦柛銊ュ�块弻锝夊箻瀹曞洤鍝洪梺鍝勵儐閻楁鎹㈠☉銏犵闁绘劕顕▓銈夋⒑濞茶骞楅柟鐟版喘瀵鎮㈤搹鍦紲闂侀潧绻掓慨鐢告倶閸儲鈷戦柛婵嗗椤忋儵鏌涙惔鈥崇骇缂佸矁椴哥换婵嬪炊椤儸鍥ㄧ厱婵炴垵宕弸娑欑箾閸滃啰鎮肩紒杈ㄦ尰閹峰懘宕崟鎴墴閺屾稓锟斤綆鍋勬慨宥夋煛娴ｈ宕岄柟绋匡攻瀵板嫬鐣濋敓浠嬪汲濞戙垺鈷戠紒瀣閸炲霉濠婂骸澧撮柡浣规崌閹崇偤濡烽妷銉︾槗闂備礁鎽滄慨闈涱潩閵娾晛绀嗛柟鐑樺灍閺嬪酣鏌熼柇锕�鏋ら柣锕�鐗撳娲箹閻愭彃濮岄梺鍛婃煥闁帮絽鐣烽姀锛勵浄閻庯綆鍋�閹锋椽姊婚崒姘卞濞撴碍顨婇幃鐐淬偅閸愨晝鍘遍柟鍏肩暘閸斿骞夐悙顑句簻闁靛繆鍓濋ˉ鍫熴亜閵忊剝顥堢�规洏鍔戦、妤呭磼濠婂懏姣庨梻鍌氬�烽懗鍓佸垝椤栫偛绀夐柡宥庡厵娴滃綊鏌涢幇闈涙灍闁哄懏鎮傞弻锕�螣娓氼垱楔婵炲濮伴崹娲Φ閸曨垼鏁冮柕蹇嬪灮椤斿绱撴担铏瑰笡缂佽鍊块敐鐐测攽鐎ｅ灚鏅ｉ梺缁樻煥婢瑰﹥绂掕濮婂宕掑▎鎰偘濠电偛顦板ú鐔风暦閹惰姤鏅濋柛灞炬皑椤斿棝姊虹捄銊ユ珢闁瑰嚖鎷�(sec)
//        long lastTime;                        // 闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柤纰卞墻閸炲爼姊绘担鍛婂暈缂佸搫娼″畷鏇㈠箮閼恒儱鍓归梺瑙勫礃椤旀劙骞忔搴㈠枂闁告洦鍓涢ˇ銉モ攽閻愯尙婀撮柛鏃�鍨甸悾鐑藉灳閹颁焦鍍甸梺鐓庢憸閺佹悂宕㈤悽鐢电＝闁稿本鐟╁鐑芥煕閵娿儳绉虹�殿喚顭堥埥澶婎潩鏉堚晪绱叉俊鐐�栭崝鎴﹀垂缂佹ɑ娅忛梻鍌欐祰椤曟牠宕伴弽顐ょ濠电姴鍊婚弳锔姐亜閹板墎鐣辩紒锟界�ｎ偁浜滈柟鍝勭Ф椤︼箓鏌涢幘鑸垫毈婵﹦绮幏鍛存惞閻熸壆顐奸梻浣告贡閳峰牓宕戞繝鍥╁祦闊洦绋掗弲鎼佹煥閻曞倹瀚�(ms)
//        srcdir=(DIR*)malloc(sizeof(DIR));                // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸婂潡鏌ㄩ弴鐐诧拷褰掑磿閹寸姵鍠愰柣妤�鐗嗙粭鎺楁煕閵娿儱锟藉骞夐幖浣瑰亱闁割偅绻勯悷鏌ユ⒑缁嬫鍎涘ù婊庝邯瀵鈽夐姀鐘栥劍銇勯弮鍌氬付闁抽攱甯″鐑樻姜閹殿噮妲銈嗗灥椤﹂潧顕ｆ繝姘櫜濠㈣泛顑呮禍婊堟⒑閸忓吋鍊愭繛浣冲浂鏁傜紒鍌滃惖ir闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柤纰卞墻濡茬兘姊绘担鍛婃儓婵炲眰鍨藉畷褰掑捶椤撶姳绗夐梺缁橆焾椤曆呯不鐟欏嫮绠鹃柨婵嗛婢ь喖鈹戦垾鑼煓闁哄本绋撻敓鏂ょ祷閸斿矂鏁撻懞銉х疄鐎殿喖顭锋俊鎼佸煛閸屾矮绨介梻浣侯焾閺堫剛绮欓幋锔绘晜闁跨噦鎷�
//        srcpathname=malloc((FF_LFN_BUF+1)*2);        // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸婂潡鏌ㄩ弴鐐诧拷褰掑磿閹寸姵鍠愰柣妤�鐗嗙粭鎺楁煕閵娿儱锟藉骞夐幖浣瑰亱闁割偅绻勯悷鏌ユ⒑缁嬫鍎涘ù婊庝邯瀵鈽夐姀鐘栥劍銇勯弮鍌氬付闁抽攱甯″鐑樻姜閹殿噮妲銈嗗灥椤﹂潧顕ｆ繝姘╅柍鍝勫�告禍鐐烘⒑缁嬫寧婀扮紒瀣灴椤㈡棃鏁撻敓锟� srcpathname闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柤纰卞墻濡茬兘姊绘担鍛婃儓婵炲眰鍨藉畷褰掑捶椤撶姳绗夐梺缁橆焾椤曆呯不鐟欏嫮绠鹃柨婵嗛婢ь喖鈹戦垾鑼煓闁哄本绋撻敓鏂ょ祷閸斿矂鏁撻懞銉х疄鐎殿喖顭锋俊鎼佸煛閸屾矮绨介梻浣侯焾閺堫剛绮欓幋锔绘晜闁跨噦鎷�
//        dstpathname=malloc((FF_LFN_BUF+1)*2);        // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸婂潡鏌ㄩ弴鐐诧拷褰掑磿閹寸姵鍠愰柣妤�鐗嗙粭鎺楁煕閵娿儱锟藉骞夐幖浣瑰亱闁割偅绻勯悷鏌ユ⒑缁嬫鍎涘ù婊庝邯瀵鈽夐姀鐘栥劍銇勯弮鍌氬付闁抽攱甯″鐑樻姜閹殿噮妲銈嗗灥椤﹂潧顕ｆ繝姘櫜濠㈣泛顑呴敓钘夘煼閺屾盯濡烽姀鈩冪彟闂佸摜鍠庨敓鏂ゆ嫹pathname闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柤纰卞墻濡茬兘姊绘担鍛婃儓婵炲眰鍨藉畷褰掑捶椤撶姳绗夐梺缁橆焾椤曆呯不鐟欏嫮绠鹃柨婵嗛婢ь喖鈹戦垾鑼煓闁哄本绋撻敓鏂ょ祷閸斿矂鏁撻懞銉х疄鐎殿喖顭锋俊鎼佸煛閸屾矮绨介梻浣侯焾閺堫剛绮欓幋锔绘晜闁跨噦鎷�
        srcdir=(DIR*)wjq_malloc_m(sizeof(DIR));                // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸婂潡鏌ㄩ弴鐐诧拷褰掑磿閹寸姵鍠愰柣妤�鐗嗙粭鎺楁煕閵娿儱锟藉骞夐幖浣瑰亱闁割偅绻勯悷鏌ユ⒑缁嬫鍎涘ù婊庝邯瀵鈽夐姀鐘栥劍銇勯弮鍌氬付闁抽攱甯″鐑樻姜閹殿噮妲銈嗗灥椤﹂潧顕ｆ繝姘櫜濠㈣泛顑呮禍婊堟⒑閸忓吋鍊愭繛浣冲浂鏁傜紒鍌滃惖ir闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柤纰卞墻濡茬兘姊绘担鍛婃儓婵炲眰鍨藉畷褰掑捶椤撶姳绗夐梺缁橆焾椤曆呯不鐟欏嫮绠鹃柨婵嗛婢ь喖鈹戦垾鑼煓闁哄本绋撻敓鏂ょ祷閸斿矂鏁撻懞銉х疄鐎殿喖顭锋俊鎼佸煛閸屾矮绨介梻浣侯焾閺堫剛绮欓幋锔绘晜闁跨噦鎷�
        srcpathname=wjq_malloc_m((FF_LFN_BUF+1)*2);        // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸婂潡鏌ㄩ弴鐐诧拷褰掑磿閹寸姵鍠愰柣妤�鐗嗙粭鎺楁煕閵娿儱锟藉骞夐幖浣瑰亱闁割偅绻勯悷鏌ユ⒑缁嬫鍎涘ù婊庝邯瀵鈽夐姀鐘栥劍銇勯弮鍌氬付闁抽攱甯″鐑樻姜閹殿噮妲銈嗗灥椤﹂潧顕ｆ繝姘╅柍鍝勫�告禍鐐烘⒑缁嬫寧婀扮紒瀣灴椤㈡棃鏁撻敓锟� srcpathname闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柤纰卞墻濡茬兘姊绘担鍛婃儓婵炲眰鍨藉畷褰掑捶椤撶姳绗夐梺缁橆焾椤曆呯不鐟欏嫮绠鹃柨婵嗛婢ь喖鈹戦垾鑼煓闁哄本绋撻敓鏂ょ祷閸斿矂鏁撻懞銉х疄鐎殿喖顭锋俊鎼佸煛閸屾矮绨介梻浣侯焾閺堫剛绮欓幋锔绘晜闁跨噦鎷�
        dstpathname=wjq_malloc_m((FF_LFN_BUF+1)*2);        // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸婂潡鏌ㄩ弴鐐诧拷褰掑磿閹寸姵鍠愰柣妤�鐗嗙粭鎺楁煕閵娿儱锟藉骞夐幖浣瑰亱闁割偅绻勯悷鏌ユ⒑缁嬫鍎涘ù婊庝邯瀵鈽夐姀鐘栥劍銇勯弮鍌氬付闁抽攱甯″鐑樻姜閹殿噮妲銈嗗灥椤﹂潧顕ｆ繝姘櫜濠㈣泛顑呴敓钘夘煼閺屾盯濡烽姀鈩冪彟闂佸摜鍠庨敓鏂ゆ嫹pathname闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愰柤纰卞墻濡茬兘姊绘担鍛婃儓婵炲眰鍨藉畷褰掑捶椤撶姳绗夐梺缁橆焾椤曆呯不鐟欏嫮绠鹃柨婵嗛婢ь喖鈹戦垾鑼煓闁哄本绋撻敓鏂ょ祷閸斿矂鏁撻懞銉х疄鐎殿喖顭锋俊鎼佸煛閸屾矮绨介梻浣侯焾閺堫剛绮欓幋锔绘晜闁跨噦鎷�
        dstpathname[0]=0;
        srcpathname[0]=0;
        strcat((char*)srcpathname,(const char*)psrc);        // 婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柛娑橈攻閸欏繐霉閸忓吋缍戦柛銊ュ�块弻锝夊箻瀹曞洤鍝洪梺鍝勵儐閻楁鎹㈠☉銏犵闁绘劕顕▓銈夋⒑濞茶骞楅柟鐟版喘瀵鎮㈤搹鍦紲闂侀潧绻掓慨鐢告倶閸儲鈷戦柛婵嗗椤忋儵鏌涙惔鈥崇骇缂佸矁椴哥换婵嬪炊椤儸鍥ㄧ厱婵炴垵宕弸娑欑箾閸滃啰绉慨濠呮缁瑩鎳楅锝嗚晧闂備礁鎲″褰掑垂閸噮鍤曞┑鐘崇閺呮彃顭跨捄鐚存敾妞ゃ儲绻傞埞鎴︽倷閸欏妫ら梺绋款儐閹瑰洭骞冮崸妤�鐐婄憸澶愬绩娴犲鐓熼柟閭﹀幖缁插鏌熼钘夌仸闁靛洤瀚版俊鎼佸Ψ閿旂粯锟ラ梻浣烘嚀缁犲秹宕硅ぐ鎺戠厴闁瑰鍋熺弧锟介柟鑲╄ˉ閹筹綁顢旈崼鐔叉嫽婵炶揪绲介幉锟犲疮閻愬瓨鍙忓┑鐘插�荤粔娲煙椤斻劌娲﹂崑鎰拷鐟板閸犳牕鈻撻妸鈺傗拺鐟滅増甯楅敍鐔虹磼閿熻姤鎷呴搹鍦劶闂佸憡鍔﹂崰妤呮偂閸愵喗鐓曟繝闈涙椤忊晠鏌＄�ｃ劌锟芥牜鎹㈠☉銏犵骇闁瑰瓨绻嶆导鍐ㄢ攽椤旂》榫氭繛鍜冪秮楠炲繘鎮╃拠鑼紜閻庤娲栧ú锝夋偨鐠囨祴鏀介柣姗嗗枛閻忣噣鏌熼搹顐ｅ碍閾荤偞绻濋棃娑卞剰缂佺姵鐗犻弻鏇＄疀鐎ｎ亷鎷烽弴鐑嗗晠婵犻潧娲㈡禍婊堟煛瀹ュ啫鍔氶柨鐔诲Г閻楁粓鏁撻懞銉ㄥ缂傚秴锕ら～蹇旂節濮橆剟鍞堕梺缁樻閵嗭拷婵℃彃鐗忕槐鎾存媴闂堟稑顬堝銈庡幘閸忔ê顕ｆ繝姘亜闁绘挸娴烽ˇ鈺呮⒑闂堟稓澧曟俊顐ｎ殜椤㈡棃鏁撻敓锟�
        strcat((char*)dstpathname,(const char*)pdst);       // 婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柛娑橈攻閸欏繐霉閸忓吋缍戦柛銊ュ�块弻锝夊箻瀹曞洤鍝洪梺鍝勵儐閻楁鎹㈠☉銏犵闁绘劕顕▓銈夋⒑濞茶骞楅柟鐟版喘瀵鎮㈤搹鍦紲闂侀潧绻掓慨鐢告倶閸儲鈷戦柛婵嗗椤忋儵鏌涙惔鈥崇骇缂佸矁椴哥换婵嬪炊椤儸鍥ㄧ厱婵炴垵宕弸娑欑箾閸滃啰绉慨濠呮缁瑩鎳楅锝嗚晧闂備礁鎲″褰掑垂閸噮鍤曞┑鐘崇閺呮彃顭跨捄鐚存敾妞ゃ儲绻傞埞鎴︽倷閸欏妫ら梺绋款儐閹瑰洭骞冮崸妤�鐐婄憸澶愬绩娴犲鐓熼柟閭﹀幖缁插鏌熼钘夌仸闁靛洤瀚版俊鎼佸Ψ椤栨繂鎯堥柣搴㈩問閸犳牠鈥﹂悜钘夋瀬闁归偊鍘肩欢鐐测攽閻樻彃顏╂鐐村姇閳规垿鎮╅崹顐ｆ瘎婵犳鍠楅幐鍐茬暦閹邦垬浜归柟鐑樻尭閿熻棄澧庨敓钘夌畭閸庨亶藝娴兼潙鐓曢柟瀵稿Х绾捐棄霉閿濆牜鍤冮柣鎺曟椤潡鎮烽弶娆句紑缂備浇椴搁幐鎼侇敇婵傜绀嬫い鎾楀嫅婊勪繆閻愵亜锟芥牕煤閳哄啰绀婂〒姘炬嫹闁靛棔绀佽灃闁告侗鍘鹃ˇ鏉款渻閵堝棗濮傞柛濠冩礋閺佹捇鎮剧仦鎴掓濠殿喖锕ュ浠嬬嵁閹邦厽鍎熼柍鍨涙櫆鐎氫粙姊绘担鍝勫姦闁告挻绻傝灋闁告劑鍔庨弳锕傛煙鏉堝墽鐣遍幆鐔兼⒑閸愬弶鎯堥柛濠傤煼瀹曘垺绂掔�ｎ偀鎷虹紓鍌欑劍閿曗晠鎮為崜褏纾兼い鏇嫹缂佺姵鐗犻妴浣肝旈崨顔间簻闂佺绻楅崑鎰板储闁秵鈷戦梻鍫熶緱閻擃厾绱掗悩鍐茬伌閽樼喖鎮楅敐搴′簽缂佺娀绠栭弻娑㈠焺閸愩劌顫岄梺璇茬箲閻擄繝寮婚埄鍐╁閻熸瑥瀚壕鎶芥⒑鏉炴壆鍔嶉柟鐟版喘瀵偊骞樼紒妯绘闂佽法鍣﹂幏锟�
        res=f_opendir(srcdir,(const TCHAR*)psrc);             // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙缂佺姷濞�閺岀喖宕滆鐢盯鏌涙繝鍛厫闁逛究鍔岃灒闁圭娴烽妴鎰磽娴ｅ搫小闁告濞婂璇测槈濡攱鏂�闂佸憡娲﹂崑鍕叏閺囩儐娓婚柕鍫濋娴滄繃绻涢懠顒�鏋涚�殿喖顭烽幃銏ゆ偖鐎涙ê顏跺┑鐐村灦閻燁垶鎮為挊澶嗘斀闁炽儴娅曢崰姗�鏌″畝瀣瘈闁轰焦鎸荤粋鎺旓拷锝庡亝濞呭洭姊虹粙鎸庢拱缂佸鎹囧畷銏ゆ偨閸涘ň鎷绘繛鎾磋壘濞层倕顕ｇ捄銊х＜闁绘ê鍟块悘瀵革拷娈垮枟閹倿骞冮姀銈嗘優闁革富鍙忕槐鏌ユ⒒娴ｅ摜绉洪柛瀣躬瀹曪絾鎯旈埦锟介弸鏃�鎱ㄥΔ瀣闂佸搫鐬奸崰鏍嵁閹捐绠抽柟鐐綑閺嬫垿姊绘担鑺ャ�冪紒璁圭節瀹曟娊鏁愭径鍫嫹娴ｇ硶鏋庨柟鐐綑閻у嫭绻濋姀锝呯厫閻绱掗幉瀣
        if(res==FR_OK){                // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙缂佺姷濞�閺岀喖宕滆鐢盯鏌涙繝鍛厫闁逛究鍔岃灒闁圭娴烽妴鎰磽娴ｅ搫小闁告濞婂璇测槈濡攱鏂�闂佸憡娲﹂崑鍕叏閺囩儐娓婚柕鍫濋娴滄繃绻涢懠顒�鏋涚�殿喖顭烽幃銏ゅ川婵犲嫮肖濠德板�х徊浠嬪疮椤栫儐鏁佺�广儱顦伴埛鎴犵磼鐎ｎ亝鍋ユい搴㈩殜閹鈽夐幒鎾寸彋婵犵绱曢弫璇茬暦閻旂⒈鏁嶆慨妯夸含濞煎姊绘担瑙勫仩闁稿孩绮撳畷鎺戔槈濮橆厾绋佺紓鍌氬�搁崐鎼佸磹妞嬪海鐭嗗〒姘炬嫹閽樻繃銇勯弽銊ュ毈闁绘帊绮欓弻銊╂偄閸濆嫅銏ゆ煢閸愵亜鏋涢柡宀嬬秮瀵噣宕掑杈吇闂備胶鎳撻崲鏌ュ床閺屻儱鐓″璺号堥弸宥嗐亜閹炬鍊婚崙褰掓⒑闁稓鈹掗柛鏃�鍨甸悾鐑藉箚闁附啸闂備胶灏ㄩ幏鐑芥煠閹帒鍔樺ù婊勭矒閺岋繝宕堕埡浣锋勃濡炪們鍎抽崑銈夊箖濡わ拷椤繈鎮欓锟介锟�
                res=f_mkdir((const TCHAR*)dstpathname);

//                strcat((char*)dstpathname,(const char*)"/");   // 闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿垂妤ｅ啫绠涘ù锝呮贡缁嬩胶绱撻崒姘拷鐑芥倿閿曚焦鎳岄梻浣告啞閻熴儳鎹㈠锟藉濠氭偄閾忓湱锛滈梺闈涚箳婵敻鎮橀崼銉︹拺婵炶尪顕ч獮妤併亜閵娿儻韬�殿喛顕ч埥澶愬閻橀潧濮堕梻浣告啞閸旓附绂嶉弽顬綁宕煎┑鍐╂杸闂佸疇妫勫Λ妤佺濠靛瀚呴弶鍫氭櫇绾捐偐绱撴担璇＄劷缂佺姵鐗滅槐鎺旂磼濡偐鐤勯悗瑙勬礃鐢帡锝炲┑瀣拻閻庨潧鎲￠敍蹇旂節閻㈤潧啸闁轰焦鎮傚畷鎴︽偐鐠囪尙顔屽銈呯箰閻楀棛绮婚鐐寸叆闁绘洖鍊圭�氾拷

                strcat((char*)psrc,(const char*)"/");//11.24 LYH JIA
                fn=get_src_dname(psrc);
                if(fn==0){                // 闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极閹剧粯鍋愭い鏇炴鐎氬綊鏌涢幇銊︽珖缂佲槄鎷烽梻浣规偠閸庢粓宕ㄩ鐔稿暉闂傚倸鍊搁崐椋庢閿熺姴绀堟繛鍡樺灩閻捇鏌ｉ姀銏╃劸缁炬崘顕ч…鍧楁嚋闂堟稑顫嶉梺缁樻尪閸庤尙鎹㈠┑瀣棃婵炴垶鐟辩槐鐐测攽閳╁啫绲婚柟鑺ョ矌濡叉劙骞掑Δ浣镐杭闂佽法鍠嶇划娆忕暦瑜版帒閱囬柡鍥╁仩閹芥洟姊洪幐搴ｇ畵妞わ富鍨板ú鍧楁⒑绾懎顥嶉柟娲讳簽濡叉劙寮撮悢渚祫濡炪倖鐗楅崙鐟般�掓繝姘厪闁割偅绻勭粻鐑樸亜閹惧瓨銇濋柡宀�鍠栧畷娆撳Χ閸℃浼�
                        dstpathlen=strlen((const char*)dstpathname);
                        dstpathname[dstpathlen]=psrc[0];                 // 闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊瑜忛弳锕傛煕椤垵浜濋柛娆忕箻閺岀喖骞嗛弶鍟冩捇鏌涙繝鍌涘仴闁哄被鍔戝鎾敂閸涱収浼撳┑锛勫亼閸娿倝宕㈡總鍛婂�舵繝闈涳功娴滀粙姊绘担绋挎倯缂佷焦鎸冲鎻掆攽鐎ｅ骸娲、娑㈡倷閺夋埊鎷烽崹顐闁绘劘灏欐禒銏ゆ煕閺冿拷绾板秹濡甸崟顖涙櫆閻犲洩灏欐禒顖氣攽閻愭潙鐏╅柡浣割煼瀵偊骞樼�靛壊娴勯柣搴秵閸嬶拷闁归绮换娑欐綇閸撗冨煂闂佺濮ょ划宥囩矉閹烘顫呴幒铏濠婂牊鐓欓悗娑欘焽缁犳牠鏌涢悩鎰佺劷闁跨喎锟界噥娼愭繛鍙夌墱缁辩偞绻濋崶褎鐎梺鐟板⒔缁垶寮查幖浣圭叆闁绘洖鍊圭�氾拷
                        dstpathname[dstpathlen+1]=0;                          // 缂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾惧綊鏌熼梻瀵割槮缁炬儳缍婇弻锝夊箣閿濆憛鎾绘煕婵犲倹鍋ラ柡灞诲姂瀵挳鎮欑拠褎瀚归柛婵勫劤娑撳秴霉閻撳海鎽犻柛瀣剁秮閺屾盯濡烽幋婵嗩仱闁哄鐟╁铏圭磼濡櫣顑勬繝娈垮枔閸婃繃淇婇悽绋跨妞ゆ牗姘ㄩ悿锟介梻浣哥枃濡椼劎娆㈤妶澶婄鐎瑰嫭瀚堥弮鍫濈妞ゅ繐鍟伴悷婵嬫⒒娴ｅ憡鎯堥柛鐕佸亰閹勭節閸ャ劌浜楅梺闈涱槴閺呮粓鎮￠悢鍏肩厸闁搞儮鏅涙禒婊堟煥閻旂粯顥夋繝锟介柆宥嗘櫢闁兼亽鍎抽崯鏌ユ煙閸戙倖瀚�
                }else{
                        strcat((char*)dstpathname,(const char*)fn);                // 闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿垂妤ｅ啫绠涘ù锝呮贡缁嬩胶绱撻崒姘拷鐑芥倿閿曚焦鎳岄梻浣告啞閻熴儳鎹㈠锟藉濠氭晲婢跺娼婇梺闈涚箚閺呮繈宕濋幖浣光拺闁告稑锕ら悘鈺佲攽閻戝洦瀚归梻浣告惈閺堫剟鎯勯鐐靛祦闁搞儺鍓欐儫闂佹寧姊婚弲顐ャ亹閸ャ劋绻嗛柣鎰典簻閿熻姤鍔欏鎻掆攽鐎ｎ亞顦у┑顔筋殣閹烽攱顨ラ悙鎻掓殺闁靛洦鍔欓獮鎺楀箻閺夋垵濮冮梻鍌欐祰瀹曠敻宕伴幇顒夌唵婵☆垵顔婄换鍡樼箾瀹割喕绨奸柍閿嬪灩缁辨帞锟斤綆鍋掗崕銉╂煟閹垮啫寮柡宀�鍠栧畷娆撳Χ閸℃浼�
                }

				if(dstpathname[strlen((const char*)dstpathname)-1]==0x2f)
						if(dstpathname[strlen((const char*)dstpathname)-2]==0x2f)
						   dstpathname[strlen((const char*)dstpathname)-1]=0;
                res=f_mkdir((const TCHAR*)dstpathname);    // 婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柛娑橈攻閸欏繘鏌ｉ幋婵愭綗闁跨喕妫勯崐鍦矉閹烘棑鎷烽敐搴′簼婵炲懌鍨藉娲嚍閵夊喚浜棟妞ゆ牜鍋涘Ч鏌ユ⒑椤掞拷缁夌敻鎮￠妷鈺傜厽闁哄啫鍊荤敮娑欍亜閵夈儺妲虹紒杈ㄦ尭椤撳ジ宕崘顓炴儓婵°倗濮烽崑娑㈠疮椤愩儳浜介梺鑽ゅТ濞测晝浜稿▎鎴犵幓闁绘劗鍎ら埛鎴犳喐閻楀牆绗掑ù婊�鍗抽弻娑㈠箻閺夋垵鎽甸柦妯煎枑缁绘繈妫冨☉鍗炲壉闂佹娊鏀遍崹鍧楀蓟閻斿吋鍤冮柍杞版缁爼姊洪崨濠冣拻闁轰浇顕ч～蹇旂節濮橆剛顦板銈嗗姂閸╁嫭瀵奸崘顭戞富闁靛牆鍟悘顏呯箾閼碱剙鏋涙鐐村姈缁绘繈宕橀妸褏鐛繝纰樻閸ㄦ娊宕㈣瀵偊骞栨担鍏夋嫽婵炶揪绲介幉锟犲疮閻愮儤鐓欓柛婵勫劚閸樻挳鏌熼鎯т槐闁轰礁鍟村畷鎺戭潩椤掍礁鍔掗梻鍌欐祰濞夋洟宕板鍥у灊婵炲棗娴氬鏍ㄧ箾瀹割喕绨荤�瑰憡绻傞埞鎴︽偐閹绘帪鎷锋繝姘偍闁归偊鍠氱壕钘壝归敐鍕煓闁告繄鍎ょ换娑㈠矗婢跺瞼鐓�闁告浜堕弻鐔兼偋閸喓鍑＄紓浣哄У婵炲﹪寮婚敓鐘茬倞闁宠桨绲块妷鈺傜厸濠㈣泛顑嗛崐鎰叏婵犲懏顏犻柟鍙夋尦瀹曠喖顢曢妶搴⑿為梻鍌欒兌绾爼寮插鍫熷亱闁绘宕靛畵浣割熆鐠轰警鍎戦梻鍕閺屾稑鈽夊Ο鎴濈墦楠炲繐煤椤忓應鎷婚梺绋挎湰濮樸劍鏅堕幇鐗堢厸闁告侗鍨版禒杈ㄣ亜閵忊埗顏嗗弲濡炪倕绻愰幊鎰板储閻㈠憡鈷戦柛娑橈工閻忕喖鏌涙繝鍐⒈闁跨喕濮ら悢顒勫箯閿燂拷 闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊椤掑鏅悷婊冪箻楠炴垿濮�閵堝懐鐤�濡炪倖妫佸Λ鍕償婵犲洦鈷戠憸鐗堝笒娴滀即鏌涢…鎴濆缂佸倸绉归幃鐑芥焽閿旀儳鏁搁梺鑽ゅ█缂傛艾鈻嶉敐澶嬪�堕弶鍫氭櫇绾惧ジ鏌ｅΟ鎸庣彧闁绘挶鍎查妵鍕敇閻愭潙浠撮梺纭呮珪缁挸螞閸愩劉妲堟慨妤�妫欑紞瀣磽閸屾艾锟介娆㈤妶澶婄闁绘垼濮ら悡鏇㈡煃閳轰礁鏋ら柣鎺旀櫕缁辨帡鎮╅懡銈囨毇闂佸搫鐬奸崰鎾绘晸閻ｅ本鏆╂い顓炵墦瀹曟粓鏌嗗鍡欏幗闂佸湱鍎ゅ鐟扳枍閺囩姷纾奸弶鍫涘妼濞搭喗顨ラ悙宸Ш闁跨喐鏋荤紞鍡涘磻閸曨垼鏁傞柨鐕傛嫹 婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柛娑橈攻閸欏繘鏌ｉ幋婵愭綗闁跨喕妫勯崐鍦矉閹烘棑鎷烽敐搴′簼婵炲懌鍨藉娲嚍閵夊喚浜棟妞ゆ牜鍋涘Ч鏌ユ⒑椤掞拷缁夌敻鎮￠妷鈺傜厽闁哄啫鍊荤敮娑欍亜閵夈儺妲虹紒杈ㄦ尭椤撳ジ宕崘顓炴儓婵°倗濮烽崑娑㈠疮椤愩儳浜介梺鑽ゅТ濞测晝浜稿▎鎴犵幓闁绘劗鍎ら悡鐔煎箹閹碱厼鐏ｇ紒澶屾暬閺屾稖绠涢弮鎾癸拷璺拷娈垮枟閹倸顕ｆ禒瀣垫晣闁绘柨鍤栭幏鐑藉垂椤愵偅顔旈梺缁樺姌鐏忔瑦绂掗姀銈嗙厱闁哄喛鎷风�癸拷閹间礁钃熼柣鏂垮悑閹偞銇勯幇鈺佺仼妞ゎ偅甯掕灃闁绘﹢娼ф禒锔姐亜閵娿儻韬鐐插暣閸╋繝宕橀鍡床婵犵妲呴崹鎶藉储瑜旈悰顕�宕奸妷锔规嫽婵炶揪绲块幊鎾活敋濠婂牊鐓涢悘鐐额嚙婵倹顨ラ悙瀵稿⒌妞ゃ垺娲熼弫鎰板礋椤撶姷鏆伴梻鍌欒兌椤牏鎹㈤幇鏉胯Е閻庯綆鍠栭惌妤呯叓閸ャ劍鐓ｇ紒璇叉閵囧嫰寮介妸褏鐓犻梺缁樺笚閸庢娊鍩為幋锔绘晩闁绘挸鍑介幏閿嬬節濮橆厽娅㈤梺绋匡功閸ｃ儱顭囬幇顓犵闁告瑥顧�閼板潡鏌熼搹顐ょ畺闁靛牞缍佸畷姗�濡歌瀵劌鈹戦悩顔肩伇婵炲绋栭惂宀勬⒑缂佹ɑ鐓ラ柛姘儔瀹曠敻宕橀鐣屽帗闁哄鍋炴竟鍡欐嫻閻楀牅绻嗛柡灞诲劙閹茬偓鎱ㄦ繝鍌ょ吋鐎规洘甯掗埢搴ㄥ箣椤撶啘婊堟⒒娴ｅ憡璐￠柍宄扮墦瀹曟垶绻濋崒婊勬闂佸綊鍋婇崰妤呭窗閸℃稒鐓曢柡鍥ュ妼楠炴鎲告导瀵哥暫婵﹨娅ｉ崠鏍即閻愭祴鎷ら梻渚�娼уú锕傛儎椤栨凹鍤曢柟闂寸缁秹鏌涢銈呮灁闁告鏁婚弻鈩冨緞婵犲嫬顣烘繝鈷�鍌滅煓闁诡喚鍋撳蹇涘Ω閵堝洨鐣炬俊鐐�栭崝褏绱為崶顒佸殌闁秆勵殕閻撴盯鎮橀悙鎻掆挃婵炲弶娼欓埞鎴︽晬閸曨偄骞嬪銈冨灪閻╊垶骞冨▎鎾崇妞ゆ挶鍔嶇�氬湱锟藉箍鍎遍幏瀣�掓繝姘厪闁割偅绻冮ˉ婊冣攽椤斿吋婀板ǎ鍥э躬椤㈡洟濮�閻欙拷娴煎啴姊洪悙钘夊姷濠碘�虫喘楠炴垿宕熼姣尖晠鏌ㄩ弴顏呭濡炪倕瀛╅惄顖炲蓟閿濆鍋勯柛婵勫劜閸Ｑ囨煟鎼淬垹鍤柛鎾跺枛閵嗕線寮崼鐔告闂佽法鍣﹂幏锟�
                if(res==FR_EXIST){res=FR_OK;}
                while(res==FR_OK){                     // 闂傚倸鍊搁崐宄懊归崶顒夋晪鐟滃繘鏁撻懞銉р枔闁哄懐濞�閵嗕礁鈻庨幘鍐插敤濡炪倖鎸鹃崑銈呂涘畡閭︽富闁靛牆妫涙晶閬嶆煕鐎ｎ偆銆掔紒顔碱煼椤㈡稑顭ㄩ幇顓烆伓闂佽崵鍠愬姗�顢旈鍕电唵闁荤喖鍋婇崕鏃傦拷娈垮枔閸旀垿骞婇悙鍝勎ㄩ柨婵嗗閻╁酣姊绘担鍛婃儓闁哥噥鍋婂畷鎰版偨缁嬭法顔嗛梺璺ㄥ枔婵敻鎮￠弴銏犵閺夊牆澧界壕璺ㄧ磼閻樺磭鍙�闁哄本娲熷畷鎯邦槻妞ゅ浚鍙冮弻鈩冩媴缁嬪尅鎷烽崸妤�绠栭柛鎾楀倹鍕冮梺鑺ッˇ閬嶅传濡ゅ懏鈷戦悹鍥у级閸炲銇勯銏╂Ц閻撱倖淇婇婵囶仩闁哄棗妫濋弻鐔兼⒒鐎靛壊妲紓浣哄Х婵數鎹㈠┑鍥╃瘈闁稿本绮岄。娲⒑閹肩偛濡奸柛濠傜秺婵＄敻宕熼姘辩杸闂佸疇妗ㄧ欢銈夊箯閻ゎ垼妯勫Δ鐘靛仜缁绘﹢骞冨鍛┏閻庯綆鍋呭▍鎾寸節閻㈤潧浠︽繛鍏肩懄椤ㄣ儵宕妷褏顦繝鐢靛Т濞层倗绮婚弽顓熺厓闁告繂瀚崳娲煕婵犲嫮甯涘ǎ鍥э躬椤㈡稑顭ㄦ惔鈥冲Υ闂備浇娉曢崰鏇熸叏閵堝绀夋繛鍡楁禋濞兼牗绻涘顔荤凹妞ゃ儱鐗婄换娑㈠箣閻愬灚鍣у銈忚吂閺呯姴顫忓ú顏呭殥闁靛牆鎳忓В鎰版⒑閸濆嫭鍣藉┑顔芥尦椤㈡岸鏁愭径瀣闂侀潧鐗嗙�氼參宕熼崘顔解拺濞村吋鐟ч崚浼存煛閸偄澧柍缁樻崌瀵挳濮�閳撅拷閹锋椽鏌ｉ悩鍏呰埅闁告柨鐭傚绋库枎閹邦亞绠氬銈嗗姂閸ㄥ綊顢旈銏＄厱闁崇懓鐏濋悘鍙夘殽閻愭惌鐒介柟椋庡█閹崇娀顢楁径濠冨�涢梻鍌氬�烽懗鍓佸垝椤栫偛绀夋俊銈呮噷閿熻棄鍊圭粋鎺旓拷锝庝簻閸ゆ垿姊洪崫鍕檨闁跨喍绮欏銊︾鐎ｎ偆鍘藉┑鈽嗗灡椤戞瑩宕电�ｎ剨鎷风憴鍕仩闁稿骸寮剁粚杈ㄧ節閸ヨ埖鏅濋梺闈涚箞閸婃洖顕ｆ导瀛樺�甸悷娆忓缁�鍐煕閵娿儲鍋ョ�殿噮鍋婇獮妯肩磼濡粯顏熼梻浣芥硶閸ｏ箓骞忛敓锟�
                        res=f_readdir(srcdir,&finfo);                      // 闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊瑜忛弳锕傛煕椤垵浜濋柛娆忕箻閺屸剝寰勭�ｎ亝顔呭┑鐐叉▕娴滄粓鎮″☉銏＄厱婵犲鎷烽柣鎺炵畵瀵煡顢旈崼鐔蜂画濠电姴锕ょ�氼剟鎮橀弶鎴旀斀闁挎稑瀚弳顒侇殽閻愬弶鍠樼�殿喖澧庨幑鍕Ω閵夘垱瀚归柣鎰▕濞撳鏌曢崼婵囶棞缂佹鍊荤槐鎺楁晸閼恒儳鐟归柨鐔绘閻ｅ嘲顭ㄩ崼顐ｆ櫓缂佺偓濯芥ご鍝ワ拷闈涚焸濮婃椽妫冨☉姘暫濠碘槅鍋呴悷鈺勬＂闂佺硶鍓濈粙鎺楁偂閺囥垺鍊甸柨婵嗛娴滄粌鈹戦纰辨Ш缂佽鲸甯￠、娆撴嚍閵夘喗顥堥柣搴ゎ潐濞叉牜绱炴繝鍥ワ拷浣糕枎閹寸偛鏋傞梺鍛婃礀閻忔氨绱炲畝鍕拻闁稿本鐟чˇ锔界節閿熶粙鏌嗗鍛紱闂佽宕橀褏绮堥崼鐔稿弿婵☆垱瀵х涵鍓х棯閹勫仴闁哄瞼鍠撻敓鐣屾暩椤牊绂掕缁辨帡鎮╅懡銈囨毇闂佸搫鏈惄顖炪�侀弴銏犖ч柛娑卞枤閿熻棄顭峰铏规嫚閺屻儳宕繝纰橈拷铏窛婵″弶鍔欓獮鎺楀籍閹炬潙顏堕梺鎸庣箓缁ㄥジ骞夐悙顑跨箚妞ゆ牓鍊栫�氬綊姊婚崒娆愮グ婵℃ぜ鍔戦幃鐐烘晝閸屾氨顔夐梺鎼炲労閸撴瑧绮婚悩缁樼厽闁归偊鍓氶幆鍫ュ船椤栫偞鍋℃繝濠傚枤濡拷閻庢鍠楅幃鍌氼嚕閸婄噥妾ㄥ┑鐐存尭椤兘寮婚弴銏犻唶婵犻潧娲ゅ▍褏绱撴担鍝勑￠柛妤佸▕瀵鎮㈤悡搴ｎ槰闂佽偐鈷堥崜娑㈩敊閹烘鈷戦悹鍥ｏ拷铏亶濡炪們鍔岄敃顏堝Υ娴ｇ硶鏋庣�电増绻嗛～澶愬箚閺冨牊鏅柛鏇ㄥ帨閵娾晜鈷戦悹鍥ｏ拷铏彯婵炲瓨绮犳禍婊堟偩閻戣棄惟闁冲搫锕ラ弲鈺冪磼閻愵剚绶茬憸鏉款槺濡叉劙鏁撻敓锟�
                        if(res!=FR_OK||finfo.fname[0]==0){break;}         // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾惧綊鏌ｉ幋锝呅撻柛濠傛健閺屻劑寮敓浠嬪箯濠靛绠瀣捣缁犳梹绻涢幋鐐嗘垶寰勯崟顖涚厱閻庯絽澧庣弧锟介梺鍝勬湰濞叉鎹㈠☉銏″�锋い鎺嶈兌瑜扮喖姊绘担鑺ャ�冪紒锟芥笟锟介、鏍ㄥ緞閹邦剝鎽曢梺鍝勬储閸ㄥ綊鏌嬮崶銊х瘈闂傚牊绋掔粊鈺備繆椤愮姴锟芥洟鈥旈崘顔嘉ч柛灞剧♁閻濇洟姊虹紒妯绘儓缂佺粯绻傞锝嗙節濮橆儵鈺呮煃閸濆嫬锟藉憡绂嶉悙鐑樷拺缂佸瀵у﹢鎵磼鐎ｎ偄鐏存い銏℃閺佹捇鏁撻敓锟�/闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿极瀹ュ绀嬫い鎺嶇劍椤斿洭姊绘担铏瑰笡闁告梹娲熼幃娲Ω閵夈垺鐎洪梺缁樏崢鏍崲閸℃稒鐓忛柛顐ｇ箘缁犳煡鎮楀顒傜Ш婵﹥妞介獮鎰償閵忣澁绱梻浣规偠閸斿鍒掑▎鎾澄ュù锝囩《濡插牊鎱ㄥΔ锟藉Λ娑㈠矗閸℃稒鈷戦悹鎭掑妼閺嬪秶绱掗鐣屾噰妤犵偛鍟撮幃娆戯拷闈涙憸閻﹀牓姊洪幖鐐插姌闁告柨閰ｅ畷銏ゅ础閻愨晜鏂�闂佺粯鍔曞鍫曀夊鍛＜濠㈣泛顑嗙亸锔撅拷瑙勬礃缁诲牊淇婇懜闈涚窞閻庯綆鍓欓獮鍫ユ⒒娴ｈ櫣甯涙繛鍙夌墵瀹曟劙宕烽銊﹀婵鍋撶�氾拷 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾剧懓顪冪�ｎ亜顒㈡い鎰矙閺屻劑鎮㈤崫鍕戙垻鐥幆褜鐓奸柡宀�鍠栭獮鎴﹀箛闂堟稒顔勭紓鍌欒兌婵參宕归崼鏇炶摕闁挎繂顦粻锝夋煥濠靛棙鍟楅柟鍓х帛閻撶喖鏌熼幆褏鎽犵紒锟界�ｎ喗鐓涚�癸拷閿熶粙宕伴弽顓犲祦闁哄稁鍙庨弫鍥煟閹邦剙鎮侀柣銏狀煼濮婅櫣鎷犻幓鎺濆妷闂佺粯妫忛崜鐔肩嵁韫囨稒鏅搁柨鐕傛嫹
                        dstpathlen=strlen((const char*)dstpathname);        // 闂傚倸鍊搁崐宄懊归崶顒夋晪鐟滃秹婀侀梺缁樺灱濡嫰寮告笟锟介弻娑樷槈濮楀牊鏁惧┑鐐叉噽婵灚绌辨繝鍥ч柛娑卞枛濞咃繝姊虹捄銊ユ灆婵☆偄瀚板畷顖炲级閹寸姵娈鹃梺闈浥堥弲娑氱棯瑜旈弻鐔猴拷鐢殿焾娴狅妇鎮敐澶嬧拺閻犲洤寮堕幑锝嗙箾閸涱偄鐏叉鐐茬箻閹粓鎳為妷褍骞堥梻浣筋潐濠㈡ɑ鏅舵惔锝嗩潟闁绘鐗婇崣蹇涙偡濞嗗繐顏存繛鍫熺矋閹便劍绻濋崨顕呬哗闂佺懓寮堕幐鍐茬暦閻旂⒈鏁冮柕蹇曞閹达附鈷掑ù锝呮啞閹叉悂鏌涢悩鏌ヮ�楁い顓炴喘濡鹃亶鏌ｉ銏㈢暫婵﹥妞藉畷銊︾節閸曘劍顫嶉梻浣割吔閺夊灝顫囬梺璇″櫙缁绘繈骞冮姀銈呯闁兼祴鏅涚敮妤呮⒒娴ｅ憡鍟炵紒璇插�婚敓鑺ユ皑椤牓顢欒箛娑樜ㄩ柍鍝勫�婚崢鎼佹煟鎼搭垳绉甸柛鎾寸懇瀵鈽夐姀锛勫幐閻庣櫢鎷烽悗锝庡墰琚﹂柣搴㈩問閸犳洜鍒掑▎鎾崇畺濞寸姴顑呴崹鍌涖亜閹板灚绶氶弶鈺傦耿濮婂宕掑▎鎴М濠电媴鎷烽梺顒�绉寸粻鐘绘煙閹规劦鍟囬柟宄板槻椤繈顢曢姀鐘点偖闂備線娼уΛ鏃傜矆娓氾拷閸┿儲寰勬繝搴㈠缓闂佺硶鍓濋敋闁稿繐锕娲传閸曞灚笑闂佺粯顨呴崯鏉戭嚕閹绘巻鏀介柛鈩冪懄濞堝吋绻涢幘瀵稿暡闁圭兘鏀遍幈銊︾節閸曨厼绗￠梺鐟板槻閹虫ê鐣烽悜绛嬫晣闁绘棁顕ч崡鎶芥⒒閸屾瑧顦﹂柟璇х節瀵濡搁埡鍌氬壎婵犻潧鍊搁幉锟犲疾閹间焦鐓犻柟顓熷笒閸斻倝鏌ｉ幙鍐ㄧ仸闁哄本绋戣灃闁跨喍绮欏畷顖炲锤濡ゅ﹥鏅梺鎸庣箓椤︿即骞嗛悙娣簻闁规澘澧庨幃鑲╃磼婢跺﹦鍩ｆ慨濠冩そ濡啫鈽夋潏鈺佸綃缂傚倷鑳舵慨鐢稿垂閸喚鏆︽繝闈涱儏瀹告繈鎮楀☉娅辨岸骞忓ú顏呯厽闁绘ê鍘栭懜顏堟煕閺傝儻瀚伴柍璇茬Ч楠炲洭鎮ч崼銏犲箥闂備礁鎲￠崹顖炲磹閺嶎偓鎷峰鐐
                        srcpathlen=strlen((const char*)srcpathname);         // 闂傚倸鍊搁崐宄懊归崶顒夋晪鐟滃秹婀侀梺缁樺灱濡嫰寮告笟锟介弻娑樷槈濮楀牊鏁惧┑鐐叉噽婵灚绌辨繝鍥ч柛娑卞枛濞咃繝姊虹捄銊ユ灆婵☆偄瀚板畷顖炲级閹寸姵娈鹃梺闈浥堥弲娑氱棯瑜旈弻鐔猴拷鐢殿焾娴狅妇鎮敐澶嬧拻濞达絿鐡旈崵娆戠磼缂佹ê娴�规洘鍨块幃鈺傜瑹椤栨稒鐦為梻鍌氬�烽懗鍓佷焊閵娾晛绠柣鎴ｅГ閻撱儵鏌￠崶鈺佷粶闁跨喕妫勭紞濠囧箖閳ユ枼鏋庨柟鍓цˉ閹峰搫顪冮妶鍡樺蔼闁告柨閰ｉ幃楣冩焼瀹ュ棛鍘介棅顐㈡储閸庡磭绮旈锟介弻鈥崇暆鐎ｎ剛袦閻庢鍣崜鐔肩嵁閹邦厽鍎熼柍鈺佸枤娴犻亶姊婚崒娆愮グ婵炲娲熷畷浼村即閻愬秵鐩畷鐔碱敍濞戞﹫鎷烽懜鍨弿婵妫楁晶濠氭煟閺傛寧顥炲ǎ鍥э躬椤㈡稑鈹冮崠鈩冨閻庯綆鍠栫粻顖滐拷鐟板閸嬪﹤顭囬埡鍌樹簻闁规壋鏅涢悘鈺冪磼娓氬洤娅嶉柟顔筋殔閳绘捇宕归鐣屼粚婵犵數鍋涢幊蹇撁洪弽顓涳拷锕傚炊椤忓棛鏉稿┑鐐村灦椤倿鍩￠崨顔惧弳闂佸搫娴傛禍婵堬拷姘秺濮婃椽宕ㄦ繝鍐弳闂佺娅曢敋妞ゎ偄绻橀幖鍦喆閸曨偆锛忛梻渚�娼ч…鍫ュ磿閺屻儲鍋熼柕蹇嬪�栭埛鎴︽煟閻斿憡绶叉繛鍫氭櫊閺岀喖宕欓妶鍡楊伓
                        strcat((char*)srcpathname,(const char*)"/");        // 濠电姷鏁告慨鐑藉极閸涘﹥鍙忛柣鎴ｆ閺嬩線鏌涘☉姗堟敾闁告瑥绻掗敓钘夌畭閸庨亶藝椤栨粎鐭嗛悗锝庡亖娴滄粓鏌熼幍铏珔闁绘帞鍎ょ换娑㈠礂閼测晜鍣板┑顔硷功缁垶骞忛崨顖涘枂闁告洍鏅欓幋鐑芥⒒娴ｅ憡鍟為惇澶岀磼椤旂晫鎳冮柣锝囧厴瀵挳濮�閻樻鍞寸紓鍌欑劍缁嬫垿顢栭崱娑樼柧妞ゅ繐鐗婇埛鎴︽⒒閸喍绶辨俊鍙夋尦閺岋繝宕ㄩ淇憋拷鎺旂磼椤旇偐澧㈤柨鐔告灮缂嶅棝宕戞担鍦洸婵犲﹤鐗婇悡娆撴煙娴ｅ啯鐝繛鍛嚇閺岋綁骞掗弬鍨缂備胶绮粙鎺旂紦娴犲鈷愰柟閭﹀幖閺嬨倖绻濆▓鍨灈闁挎洏鍎遍—鍐寠婢跺本娈惧銈嗗姧缁犳垹绮堢�ｎ偁浜滈柟浼存涧婢ь垶鎮楀顒傜Ш闁哄本鐩弫鍌滄嫚閹绘帞顔愰梻浣规偠閸斿秶鎹㈤崟顖涙櫢闁芥ê顦遍悾顓㈡煕鎼淬劋鎲炬鐐茬箳閿熸枻缍嗛崰妤呭磹閸啔褰掓偐瀹割喖鍓遍梺缁樻尪閸庣敻寮婚敐澶婂嵆闁绘劘顕滈幏鐑藉捶椤撱劍瀚规慨妯煎亾鐎氾拷
                        strcat((char*)srcpathname,(const char*)finfo.fname);     // 濠电姷鏁告慨鐑藉极閸涘﹥鍙忛柣鎴ｆ閺嬩線鏌涘☉姗堟敾闁告瑥绻掗敓钘夌畭閸庨亶藝椤栨粎鐭嗛悗锝庡亖娴滄粓鏌熼幍铏珔闁绘帞鍎ょ换娑㈠礂閼测晜鍣板┑顔硷功缁垶骞忛崨顖涘枂闁告洍鏅欓幋鐑芥⒒娴ｅ憡鍟為惇澶岀磼椤旂晫鎳冮柣锝囧厴瀵挳濮�閻樻鍞寸紓鍌欑劍缁嬫垿顢栭崱娑樼柧妞ゅ繐鐗婇埛鎴︽⒒閸喍绶辨俊鍙夋尦閺岋繝宕ㄩ淇憋拷鎺旂磼椤旇偐澧㈤柨鐔告灮缂嶅棝宕戞担鍦洸婵犲﹤鐗婇悡娆撴煙娴ｅ啯鐝繛鍛嚇閺岋綁骞掗弬鍨缂備胶绮惄顖炲箠濠靛洤顕遍柡澶嬪灦閹虫瑧绱撻崒娆掑厡缂侇噮鍨堕幆鍕敍閻愰潧绁﹂柣搴秵閸犳宕愰悜鑺ョ厸濠㈣泛顑呴悘鈺傘亜閿濆棛鍙�婵﹦绮幏鍛存偡闁箑娈濇繝鐢靛仦瑜板啰鎹㈠Ο铏规殾闁归偊鍏橀弨浠嬫倵閿濆簼绨介柣锝嗘そ濮婃椽宕ㄦ繝鍕暤闁诲孩鐨滈崶褍鍤戦柟鍏肩暘閸斿秹鎮″▎鎾寸厽闁逛即娼ф晶顖滅磽瀹ュ棗鐏撮柡灞剧洴楠炴瑩宕橀妸锔句邯婵＄偑鍊ゆ禍婊堝疮鐎涙ü绻嗛柛顐ｆ礀楠炪垺鎱ㄥΔ锟藉Λ娆撳煕閺嶎厽鈷掑ù锝勮閻掔偓銇勯幋婵囶棦鐎规洘绻傝灃闁告劑鍔岄悘濠囨⒑閸濆嫬鏆欓柣妤�妫濋弻銊╁Χ閸℃洜绠氶梺闈涚墕鐎氼垶宕楀畝鍕厱婵☆垰鎼懜褰掓煃鐟欏嫬鐏存い銏＄懇瀵剟濡堕崟顓＄箲闂傚倷绀侀幉锟犲箰閼姐倗鐭欓柟杈鹃檮閸嬨倖銇勯幘鍗炵仾闁抽攱甯掗湁闁挎繂鎳忛幆鍫ユ煕閺冩捇妾ǎ鍥э躬楠炴捇骞掗幋顓濈磾婵°倗濮烽崑娑氭崲濮楋拷瀵偊骞樼紒妯绘闂佽法鍣﹂幏锟�
                        if(finfo.fattrib&0x10){                              //闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎闁惧繗顫夊畷澶愭煏婵炲灝鍔滈柣婵勫灲濮婃椽鎮烽弶鎸庮唨闂佺懓鍤栭幏锟�:0x20;闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊椤掑鏅悷婊冪箻閺佹捇鎳為妷褉鏋旈梺鍝勬噺缁诲嫰宕氶幒鎴旀瀻闁规儳纾濠傗攽鎺抽崐褔骞忔搴ｇ＜闁跨喕濮ゅ鍕拷锝傛櫇缁犳岸姊洪棃娑氬缂佺粯鍨归敓鑺ヨ壘缂嶅﹪寮婚敐澶婄闁告鍎戦幏宄扳攽鐎ｎ亣鎽曢梺缁樻椤ユ捇寮崇�ｎ喗鐓欑�瑰嫭澹嗛悞鐐箾閼规澘鐓愮紒缁樼〒閿熻姤绋掗…鍥儗婵犲嫮纾界�广儱鎷戦煬顒傦拷娈垮枛椤攱淇婇幖浣哥厸闁稿本鐭花浠嬫⒒娴ｄ警鐒鹃柡鍫墰缁瑩骞嬮敂缁樻櫆闂佽法鍣﹂幏锟�:0x10
                        		strcat((char*)dstpathname,(const char*)"/");
                        		strcat((char*)dstpathname,(const char*)finfo.fname);
                        		xil_printf("\r\ncopy folder %s to %s\r\n",srcpathname,dstpathname);
                                res=(FRESULT)my_dcopy(srcpathname,dstpathname,fwmode);         // 闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗霉閿濆牊顏犵紒锟芥繝鍌楁斀闁绘ê寮剁涵钘夘熆閼搁潧濮囩紒鐘差煼閹綊宕堕鍕暱闂佺濮ゅú妯兼崲濠靛顫呴柨婵嗘閵嗘劙姊哄ú璇插闁靛牊鎮傞獮鍡楃暆閸曨偄鑰垮┑掳鍊曢敃锕傚船閻㈠憡鈷戦柛蹇撳悑閸婃劖绻涙担鍐插閸欏繘鏌涢妷锝呭缂佽妫欓妵鍕箛閸撲胶肖闂佸吋婢樺锟犲蓟閿涘嫪娌柛鎾楀嫬鍨卞┑鐘殿暜缁辨洟宕楀锟介妴浣糕槈閵忊�筹拷鐑芥煙绾板崬寮块柟宄板槻椤撳ジ宕担鐟扮槣闂備線娼ч悧鍡椢涘Δ浣瑰弿閻忕偛褰炵换鍡樸亜閹扳晛鐏╂い蹇ｅ弮閺屽秹濡烽姘兼喘闂佸湱鎳撶�氱増淇婇幖浣规櫇闁跨喍绮欓、鎾斥槈閵忥紕鍘介梺缁樻煥閹芥粓骞婇崘顔藉�垫慨妯煎帶婢у瓨銇勯姀鈩冾棃闁轰焦鎹囬弫鎾绘晸閿燂拷
                        }else{
                                strcat((char*)dstpathname,(const char*)"/");          // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙缁炬儳娼￠弻锝夊閵忊晝鍔搁梺姹囧�濈粻鏍蓟瀹ュ浼犻柛鏇ㄥ墮濞咃絿绱撴担鐟板妞ゃ劌妫欑粚杈ㄧ節閸ヮ灛褔鏌涘☉鍗炴灈婵炲懌鍊濆铏圭矙濞嗘儳鍓板銈忓閺佽顕ｆ繝姘╅柕澶堝灪閺傦拷闂備胶纭堕崜婵嬫晪濡炪倧鑵归弲鐘诲箖濡ゅ啯鍠嗛柛鏇ㄥ墰椤︺儱顪冮妶蹇曠窗闁告娅曟穱濠囨偨缁嬭法顦板銈嗙墬閼归箖宕妸鈺傗拺闂傚牊渚楅悡顓炩攽閳ヨ櫕鎼愰柍缁樻崌婵″爼宕堕埡鍐跨闯濠电偠鎻徊鍧楀箠閹惧瓨鍙忓鑸靛姈閻撴洟鎮楅敐鍐ㄥ闁跨喕濮ょ换鍌烆敋閿濆洦瀚氭繛鏉戭儐椤秹姊洪棃娑氱濠殿喚鍏橀幆鍫ュ礋椤栨稈鎷虹紓浣割儐鐎笛冿耿閻楀牄浜滈柡鍥╁枑鐏忥箓鏌℃担鐟板鐎垫澘瀚敓鏂ょ秵閸撴瑩鐛幇鐗堚拺閻犲洦褰冮崵閬嶆煙椤戞儳鍔︾�规洜鍠栭、妤呭磼濮樿京袪闂傚倷娴囬褏锟芥稈鏅犻、娆撳冀椤撶偟鐛ラ梺鍝勭▉閸樹粙宕戞径濞炬斀闁稿本绮犻悞楣冩煛鐎ｂ晝绐旈柡宀�鍠栧畷婊嗩槾閻㈩垱鐩弻锟犲川椤旇棄锟芥劙鏌＄仦璇插闁诡喓鍊濆畷鎺戔槈濮楀棔绱� 11.24 ZHUSHI
                                strcat((char*)dstpathname,(const char*)finfo.fname);         // 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙缁炬儳娼￠弻锝夊閵忊晝鍔搁梺姹囧�濈粻鏍蓟瀹ュ浼犻柛鏇ㄥ墮濞咃絿绱撴担鐟板妞ゃ劌妫欑粚杈ㄧ節閸ヮ灛褔鏌涘☉鍗炴灈婵炲懌鍊濆铏圭矙濞嗘儳鍓板銈忓閺佽顕ｆ繝姘╅柕澶堝灪閺傦拷闂備胶纭堕崜婵嬫晪濡炪倧鑵归弲鐘诲箖濡ゅ啯鍠嗛柛鏇ㄥ墰椤︺儱顪冮妶蹇曠窗闁告娅曟穱濠囨偨缁嬭法顦板銈嗙墬閼归箖宕妸鈺傗拺闂傚牊渚楅悡顓炩攽閳ヨ櫕鎼愰柍缁樻崌婵″爼宕堕埡鍐跨闯濠电偠鎻徊鍧楀箠閹惧瓨鍙忓鑸靛姈閻撴洟鎮楅敐鍐ㄥ闁跨喕濮ょ换鍌烆敋閿濆洦瀚氭繛鏉戭儐椤秹姊洪棃娑氱濠殿喚鍏橀幆鍫ュ礋椤栨稈鎷虹紓浣割儐鐎笛冿耿閻楀牄浜滈柡鍥╁枑鐏忥箓鏌℃担鐟板鐎垫澘瀚敓鏂ょ秵閸撴瑩鐛幇鐗堚拺閻犲洦褰冮崵杈╃磽瀹ュ懏顥炵紒鍌氱Т椤劑宕煎┑鍥发闂備胶绮崝妤呭极閸濄儱顥氬┑鍌氭啞閻撴洟鎮橀悙鎻掆挃闁宠棄顦辩槐鎺戭渻閿曪拷濞诧箓鎮″▎鎾寸厽闁绘柨鎲＄欢鍙夈亜韫囷絽寮柡宀�鍠栭、娆撴偩瀹�锟介悡锟介梺鍙ョ串缂嶄線寮婚敐鍜佹僵妞ゆ帒鍊归幉濂告煟鎼淬垼澹樼紓宥咃躬瀵濡搁埡鍌氫簽闂佺鏈粙鎴︻敂閿燂拷
                                xil_printf("\r\ncopy file %s to %s ",srcpathname,dstpathname);
                                my_fcopy(srcpathname,dstpathname,fwmode);         // 闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗霉閿濆牊顏犵紒锟芥繝鍌楁斀闁绘ê寮剁涵钘夘熆閼搁潧濮囩紒鐘差煼閹綊宕堕鍕暱闂佺濮ゅú妯兼崲濠靛顫呴柨婵嗘閵嗘劙姊哄ú璇插闁靛牊鎮傞獮鍡楃暆閸曨偄鑰垮┑掳鍊曢敃锕傚船閻㈠憡鈷戦柛蹇撳悑閸婃劖绻涙担鍐插閸欏繘鏌涢妷锝呭缂佽妫欓妵鍕箛閸撲胶肖闂佸吋婢樺锟犲蓟閿涘嫪娌柛鎾楀嫬鍨卞┑鐘殿暜缁辨洟宕楀锟介妴浣糕槈閵忊�筹拷鐑芥煙绾板崬寮块柟宄板槻椤撳ジ宕担鐟扮槣闂備線娼ч悧鍡椢涘Δ浣瑰弿閻忕偛褰炵换鍡樸亜閹扳晛鐏╂い蹇ｅ弮閺屽秹濡烽姘兼喘闂佸湱鎳撶�氱増淇婇幖浣规櫇闁跨喍绮欓、鎾斥槈閵忥紕鍘介梺缁樻煥閹芥粓骞婇崘顔藉�垫慨妯煎帶婢у瓨銇勯姀鈩冾棃闁轰焦鎹囬弫鎾绘晸閿燂拷
                        }
                        srcpathname[srcpathlen]=0;              //  闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿垂妤ｅ啫绠涘ù锝呮贡缁嬩胶绱撻崒姘拷鐑芥倿閿曚焦鎳岄梻浣告啞閻熴儳鎹㈠锟藉濠氭偄閾忓湱锛滈梺闈涚箳婵敻鎮橀崼銉︹拺婵炶尪顕ч獮妤併亜閵娿儻韬�殿喛顕ч埥澶愬閻橀潧濮堕梻浣告啞閸旓附绂嶅┑瀣棷妞ゆ柨澧界壕濂告煟閹伴潧澧柛鏂诲�濋弻鏇㈠醇閻旂锟芥劗锟芥鍠栭…鐑藉箖閵忋倖鍋傞幖杈剧悼閺嗕即鏌ｉ悢鍝ョ煀缂佺粯锕㈤悰顔嘉旈崨顔间汗缂傚倷鐒﹂敋闁跨喕妫勯悥濂告偂椤愶箑鐐婇柕濠忕畱闂夊秴顪冮妶鍐ㄥ姢濠殿噣顥撳Σ鎰板箳閹惧绉堕梺闈涱焾閸庢娊鎮烽妸鈺傜叄缂備焦顭囨晶鐢告煙椤旂瓔娈滈柡浣瑰姈閹棃鍨鹃懠顒傛晨濠碉紕鍋戦崐鏇燁殽韫囨稑绠柨鐕傛嫹
                        dstpathname[dstpathlen]=0;              //  闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋涢ˇ鐢稿垂妤ｅ啫绠涘ù锝呮贡缁嬩胶绱撻崒姘拷鐑芥倿閿曚焦鎳岄梻浣告啞閻熴儳鎹㈠锟藉濠氭偄閾忓湱锛滈梺闈涚箳婵敻鎮橀崼銉︹拺婵炶尪顕ч獮妤併亜閵娿儻韬�殿喛顕ч埥澶愬閻橀潧濮堕梻浣告啞閸旓附绂嶅┑瀣棷妞ゆ柨澧界壕濂告煟閹伴潧澧柛鏂诲�濋弻鏇㈠醇閻旂锟芥劗锟芥鍠栭…鐑藉箖閵忋倖鍋傞幖杈剧悼閺嗕即鏌ｉ悢鍝ョ煀缂佺粯锕㈤悰顔嘉旈崨顔间汗缂傚倷鐒﹂敋闁跨喕妫勯悥濂告偂椤愶箑鐐婇柕濠忕畱闂夊秴顪冮妶鍐ㄥ姢濠殿噣顥撳Σ鎰板箳閹惧绉堕梺闈涱焾閸庢娊鎮烽妸鈺傜叄缂備焦顭囨晶鐢告煙椤旂瓔娈滈柡浣瑰姈閹棃鍨鹃懠顒傛晨濠碉紕鍋戦崐鏇燁殽韫囨稑绠柨鐕傛嫹
                }
        }
        xil_printf("\r\n\r\n ******** Copy files completed !!   ********\r\n\r\n\r\n");
        wjq_free_m(dstpathname);
        wjq_free_m(srcpathname);
        wjq_free_m(srcdir);
        return res;
}

////list all the file and sub_directory of the directory
//FRESULT scan_files(
//	char* path        /* Start node to be scanned (***also used as work area***) */
//)
//{
//		FRESULT res;
//		DIR dir;
//		UINT i;
//		static FILINFO fno;
//
//		res = f_opendir(&dir, path);                       /* Open the directory */
//		if (res == FR_OK) {
//			for (;;) {
//				res = f_readdir(&dir, &fno);                   /* Read a directory item */
//				if (res != FR_OK || fno.fname[0] == 0) break;  /* Break on error or end of dir */
//				if (fno.fattrib & AM_DIR) {                    /* It is a directory */
//					i = strlen(path);
//					sprintf(&path[i], "/%s", fno.fname);
//					res = scan_files(path);                    /* Enter the directory */
//					if (res != FR_OK) break;
//					xil_printf("directory name is:%s\n", path);
//					path[i] = 0;
//				}
//				else {                                       /* It is a file. */
//					xil_printf("file name is:%s/%s\n", path, fno.fname);
//				}
//			}
//			f_closedir(&dir);
//		}
//		return res;
//}

//闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙闁稿被鍔庨幉鎼佸籍閸垹绁﹂梺鍝勭▉閸欏酣寮崘顔界叆闁哄浂浜濈�氬湱绱掗幆褍鈷旈柟铏崌閸╃偤骞嬮敂钘変汗闁诲骸婀辨慨鎾夊┑鍫㈢＜闁绘劦鍓欓崝銈嗐亜椤撶姴鍘寸�殿喖顭锋俊鎼佸Ψ閵忊剝鏉搁梻浣虹《濡狙囧疾濠婂懐鎳呯紓鍌氬�搁崐椋庢閵堝绠柣鎴ｅГ閻撴洜锟界櫢鎷烽柨鐔剁矙瀹曟垿鎮欓悜妯轰簵闂婎偄娲﹂幖鈺呮偄閸℃稒鍋ｉ柧蹇曟嚀閸斿銇勯妷褍浠︾紒缁樼洴瀹曘劑顢橀悤浣癸骏闂備浇顕栭崳顕�宕伴弽顓炵厴闁瑰濯撮幏鐑芥晲鎼粹�茬爱闂佸綊鏀卞钘夘潖濞差亜鎹舵い鎾楀懎濮兼繝鐢靛仜椤曨參宕楀锟藉畷娲Ψ閿曪拷缁剁偤鏌熼柇锕�骞橀柛妯挎椤啴濡堕崱妯烘殫闂佺顑嗛惄顖炲极閹剧粯瀵犲璺哄閾忓酣姊烘导娆戞偧闁稿繑锕㈤獮鏍亹閹烘繃鏅濋梺闈涚箚閺呮稑鈻撴總鍛娾拺閻犲洦褰冮銏㈢磼鐎ｎ偄娴柡浣割儐缁绘稓锟界數顭堟牎濠碉紕鍋犲Λ鍕綖韫囨拋娲敂閸滀焦顥堟繝鐢靛仦閸ㄥ吋绂嶉鍕闁归棿鐒﹂埛鎴犵磼鐎ｎ亞浠㈡い鎺嬪灩閳规垿鎮欑拠褍浼愰梺浼欑悼閸忔﹢銆佸☉銏″�烽柤鑹板煐閹蹭即姊绘笟锟藉褔篓閿熻棄鈹戦垾铏枠鐎规洏鍨介幃浠嬫偨閻㈢绱抽梻浣侯焾閺堫剟鎮疯瀹曟繂顓兼径瀣弳濠殿喗顭堟禍顒傚閸忛棿绻嗛柕鍫濆閸斿秹鏌ｉ妸锕�鐏撮柡宀嬬秮婵＄兘顢欐繝姘粣婵＄偑鍊戦崹娲晝閵忊�茬箚闁归棿鐒﹂弲婵嬫煥閻斿墎鐭欐い銏℃閺佹捇鏁撻敓锟�
void List_TailInsert(LinkedList List,Node node)
{
	 Node *L;
//	 L = (Node *)malloc(sizeof(Node));

	 L = (Node *)wjq_malloc_m(sizeof(Node));
	 L->data= node.data;
	 Node *r=List;
	 while(r->next!=NULL)
	 {
		 r=r->next;
	 }
	 r->next=L;
	 r=L;
	 r->next=NULL;
}

// 闂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾剧懓顪冪�ｎ亝鎹ｉ柣顓炴闇夐柨婵嗙墛閵嗗啴鏌ｉ幒鎴含闁哄本绋戦埥澶娾枎閹邦喚鈻忕紓鍌欒兌婵參宕圭捄渚綎婵炲樊浜滈崹鍌涖亜閺囩偞鍣归柛鎾讳憾濮婃椽宕ㄦ繝鍕櫑缂備胶绮敃銏狀嚕婵犳艾惟闁靛鍨洪弬锟介梻浣虹《閸撴繈銆冭箛鏂款嚤闁跨喓鏅槐鎾诲磼濞嗘垵濡介梺鍛婃⒐閻楁洟锝炶箛鏇熷枂闁告洦鍘搁弨铏節閻㈤潧孝閻庢凹鍘鹃敓鑺ョ濮樸劑骞夊宀�鐤�婵炴垶鐟ユ禒濂告⒑濮瑰洤鐏い锝庡櫍楠炲繑顦版惔銏犳瀭闂佸憡娲﹂崜娑⑺囬妸鈺傚�甸柣褍鎲＄�氬綊姊鸿ぐ鎺擄紵缂侊拷娓氾拷瀵憡绗熼敓浠嬪蓟閻旂厧绀堢憸蹇曟暜濞戙垺鐓涢柛娑卞枟閸婃劙鏌＄仦璇插闁诡喓鍊濆畷鎺戔槈濮楀棔绱�
void DestroyList(LinkedList List)
{
	if (List == NULL)
	{
		return;
	}
	// 婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柟闂寸绾剧粯绻涢幋娆忕労闁轰礁顑嗛妵鍕箻鐠虹儤鐎鹃梺鍛婄懃缁绘﹢寮婚埄鍐ㄧ窞閻庯綆浜濋鍛存偡濠婂懎顣奸悽顖涱殜瀹曟劙鎳￠妶鍥╋紲濠电偞鍨堕敃鈺呭磿閹扮増鐓涢柛娑卞灠娴犺鲸鎱ㄦ繝鍐┿仢妤犵偞鐗犻幃娆撳箵閹烘埈娼欓梻鍌欑閹诧繝寮婚妸鈺傜厐闁挎繂顦弰銉╂煏韫囧锟芥洜鐚惧澶嬬厱妞ゆ劑鍊曢弸鏃堟煕濞嗗繑顥㈡慨濠呮缁辨帒螣濞茬粯鈷栨俊鐐�栧▔锕傚幢閳哄倹鐦ｇ紓鍌氬�搁崐鎼佸磹妞嬪海鐭嗗〒姘炬嫹妞ゃ垺鐗犲畷銊ヮ潰閵堝懏鍠橀柟顔荤矙楠炴牠鎮滈崶銊ヮ伓婵炴挻鐔幏椋庯拷娈垮櫘閸ｏ絽鐣烽悡搴樻斀闁糕剝鐟у畷鍝勨攽閿涘嫬浜奸柛濠冪墵瀵濡搁敂鑺ョ彿婵炲濮撮鍛ч弻銉︾厪闊洤顑呴敓鑺ョ墵閸╂盯骞掗幊銊ョ秺閺佹劙宕煎顒佹崌閺屾洟宕卞Δ锟介弳锝夋煛鐏炶锟芥鏁撻挊澶嬭础濠殿喗鎸抽幃锟犲箛閻楀牏鍘搁梺鍛婄〒婢ф娑垫ィ鍐╂嚉闁哄稁鍘介悡銉╂煟閺傚灝顣抽柣顓熺懇閺岀喖顢氶敓鐣岀不閺嵮呮殾鐟滅増甯╅弫鍐煏閸繃澶勯柛銈呯焸濮婄粯鎷呴懞銉с�婇梺鍝ュТ缁夊爼宕氶幒鎴旀瀻闁规崘娉涚粊锕傛⒑缁洖澧茬紒瀣灩缁牓宕橀埞澶哥盎闂佸搫鍟ú銈嗙鐟欏嫨浜滈柨鏃囧Г缁跺弶銇勯鍕殻濠碘�崇埣瀹曞崬螣閻撳骸姹插┑鐘殿暯閸撴繆銇愰崘顔藉亱闁糕剝绋戦悡姗�鏌熺�电顎撻柟椋庡厴閺佹劖鎯旈垾鑼晼闂備礁鎲＄湁缂侇喗鐟ラ～蹇斻偊鐟併倓姹楅梺鍦劋閸ㄦ娊宕版繝鍥ㄢ拺闁告縿鍎辨牎濡炪們鍔岄敃銈夋偩閻戣姤鍋ㄩ柛娑橈攻濞呫垽姊烘导娆戝埌闁活剝鍋愭竟鏇㈡寠婢规繂缍婇弫鎰板礋椤撶姷鍘梻浣告啞缁诲啫顪冩禒瀣摕婵炴垯鍨规儫闂侀潧锛忛崘顏勫箺濠德板�楁慨鐑藉磻濞戙垺鍋嬮柟鍓х節缁诲棙鎱ㄥ┑鍡欑劸婵＄虎浜楦裤亹閹烘繃顥栭梺绋跨箲閿曘垹顕ｉ锕�绠涙い鎾跺枎閸斿懘姊洪弬銉︽珔闁哥喓澧楃粋宥夘敂閸涱垳鐦堥梺姹囧灲濞佳勭濠婂牊鐓欓柧蹇ｅ亜婵秶锟借娲橀崹鎸庝繆閼搁潧绶炲┑鐘叉噺閹蹭即姊绘担鑺ョ《闁哥姵鎸婚幈銊╂偨缁嬭法鏌х紓浣割儐閿涙洝銇愰幒鎾充汗閻庣懓澹婇崰鏍礈闁秵鈷戦柛婵嗗閸ｆ椽鏌熼鐓庯拷鍨嚕婵犳艾惟闁冲搫鍊告禍鐐烘⒑缁嬫寧婀扮紒瀣灴椤㈡棃鏁撻敓锟�
	LinkedList curNode=List->next;
	while (curNode != NULL)
	{
		//闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙５闁跨喐鏋荤粻鎾崇暦婵傜顫呴柍銉ュ暱缁ㄣ儵姊绘担绛嬫綈濠㈢懓妫欓弲璺何旈崨顓狅紱闁诲函缍嗛崰妤呮偂閺囩喓绠鹃柟瀛樼箓閼稿綊鏌ｈ箛銉х？闁跨喎锟界噥娼愭繛鍙夌墪椤曪綁宕奸弴鐐电杽闂侀潧顭堥崕鍝勵焽閵娾晜鐓曢柍鈺佸枤濞堟梻绱掗悩闈涘妺缂佺粯绻傞埢鎾诲垂椤斿彞鐢婚梻浣烘嚀閹测剝绻涙繝鍥х畺闁跨喓濯弫鍐煥閺囶亝瀚归梺缁樺姇閿曪箓骞夐崨濠冨劅闁靛鍎抽澶愭⒑閹稿海绠撴い锔垮嵆閹繝鎮㈤崗鑲╁幗闂佸搫鍊圭�笛囧疮閻愮儤鍊堕煫鍥风到瀵噣鏌＄仦鐣屝ч柟绋匡攻瀵板嫬螣閻戔晜鐎板┑掳鍊楁慨鐑藉磻閻愮儤鍋￠柍杞拌兌閺嗭箓鏌ｉ弮鍌楁嫛闁轰礁妫濋弻銊╂偄閸撲胶鐓撳銈冨灪濮婂骞戦崟顓熷仒闁斥晛鍟弶鎼佹⒒娴ｈ櫣甯涢柛鏃�鐗曢…鍥р枎閹炬潙锟藉爼鏌ㄩ弴鐐诧拷褰掓偂濞嗘挻鍊堕煫鍥ㄦ⒒婢ь剚绻涢崨顓燁棤缂佽鲸甯″畷鎺戭潩濮ｆ鍥ㄧ厸濞达絿鎳撴慨宥囷拷瑙勬礋娴滆泛顕ｉ幘顔藉亹闁汇垹鐏氬В搴㈢節绾板纾块柛瀣灴瀹曟劙寮介鐐殿唶闂佸壊鍋呭ú鏍垂閸屾稓绠剧�瑰壊鍠曠花鑽ょ棯閹呯Ш闁哄矉缍侀獮瀣晲閸涘懏鎹囬弻锝夊箻鐎涙顦伴梺鍝勮閸旀垵顕ｉ锟藉畷鍓佹崉閻戞﹩鍞插┑掳鍊楁慨鐑藉磻閻愭亽锟藉啯绻濋崶褑鎽曢梺鎸庣箓椤︿即寮查弻銉︾厱婵炴垵宕銊╂煕閳哄啫浠辨慨濠傤煼瀹曟儼顧佹俊顖ゆ嫹闂備礁鎼悮顐﹀礉瀹�鍕厴闁硅揪绠戦獮銏′繆椤栨粌鍔嬫い蹇嬪�濆娲偂鎼达紕楠囬梺缁橆殘婵挳锝炶箛娑樹紶闁告洘鍤崶褏鍊為悷婊勭箞楠炲繘鎮块锝嗏枌婵°倗濮烽崑娑氭崲濮楋拷瀵偊骞樼紒妯绘闂佽法鍣﹂幏锟�
		LinkedList  nextNode = curNode->next;
		wjq_free_t(curNode);
		curNode = nextNode;
	}
	//闂傚倸鍊搁崐鎼佸磹閹间礁纾归柟闂寸绾惧綊鏌ｉ幋锝呅撻柛濠傛健閺屻劑寮村鑸殿�栨繛瀛樼矊缂嶅﹪寮诲☉銏犵疀闂傚牊绋掗悘宥夋⒑閸濆嫭鍣虹紒璇茬墦瀵寮撮悢椋庣獮闂佺硶鍓濊摫闁绘繃鏌ㄩ埞鎴﹀煡閸℃ぞ绨奸梺鎸庡哺濡焦寰勯幇顓犲弳濠电娀娼уΛ娆愬緞閸曨垱鐓曢柕鍫濈箲鐎氬湱绱撻崒姘拷椋庣矆娴ｈ娅犻幖娣妼绾惧鏌曢崼婵愭Ц缂佺姵鐗楁穱濠囧Χ閸涱喖娅ゅ銈冨劚閻楀﹦鎹㈠☉銏犵闁绘劕鐏氶崳顓㈡⒑閸濄儱校闁告梹娲熼崺鐐哄箣閿旇棄锟介锟界懓澹婇崰妤勫�撮梻鍌欑劍閹爼宕濈�ｎ剙鍨濇繛鍡楁禋閸ゆ洖鈹戦悩宕囶暡闁哄懏褰冮…璺ㄦ崉閻氭潙濮涢梺姹囧�ч幏鐑芥⒒閸屾瑧顦﹂柛姘儔楠炲啴宕掑鑲╁姺閻熸粍妫冮妴渚�寮崼鐔告闂佽法鍣﹂幏锟�
	wjq_free_t(List);
	//婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柛娑橈攻閸欏繐霉閸忓吋缍戦柛銊ュ�块弻锝夊箻瀹曞洤鍝洪梺鍝勵儐閻楁鎹㈠☉銏犵婵炲棗绻掗崝鎾⒑鏉炴壆顦︽い鎴濇婵＄敻宕熼姘鳖啋闁荤姾娅ｅú鍛村閵堝棛鍘遍梺闈涱煭婵″洨绮婚悙鐑樼厸閻忕偟鍋撶粈鍐磼缂佹娲撮柟顔界懇椤㈡鎷呴崫鍕ɑ闂傚倸鍊烽懗鍫曗�﹂崼銉︽櫇闁挎洖鍊哥粈鍌涙叏濡ゅ瀚瑰Δ鐘靛仜閸燁偊鎮鹃敓鐘茬闁惧浚鍋嗛敓钘夘煼濡懘顢曢姀鈥愁槱闂佺懓鐨烽弲婊呯矉閹烘挾闄勯柛娑樑堥幏鐑樼箾閺夋垵鎮戦柣鐔濆洦鍋╅弶鍫氭櫇绾剧晫锟藉箍鍎遍幏鎴濐啅閵夛负浜滄い鎰╁灮缁犱即鎮￠妶鍡愪簻闊洦鎸婚崳褰掓煟瑜嶇�氼厾鎹㈠┑瀣潊闁挎繂妫涢妴鎰版⒑閸忓吋銇熼柛銊ョ埣瀹曟椽宕ㄧ�涙鍔堕悗骞垮劚濡矂骞忛崫鍕ㄦ斀妞ゆ梻鍋撻崵锟藉┑鐐茬湴閸婃繈寮幘缁樺殟闁靛濡囬ˇ銉╂煣閼姐倕浠︾紒缁樼洴楠炲鎮欑捄渚闂備焦鎮堕崝宥囨崲閸愵喖绠為柕濞垮剻閻旂厧鍨傛い鏃�鍎崇敮鍧楁⒒娴ｅ憡鎯堥柟鍐茬箻楠炲啴宕掗悙鑼舵憰闂侀潧艌閺呮粓宕戦崱娑欑厱閻忕偛澧介埥澶嬨亜韫囥儲瀚�
	List = NULL;
}

////闁荤姳鐒﹀妯肩礊瀹ュ绠ユい鎰剁到娴煎酣鏌涢幒鎾愁棆婵炲牊鍨垮顒勫炊閿旂瓔鍋ㄩ梺鍝勫�稿ú锝呪枎閵忊�崇窞闁革富鍘惧▔銏ゆ煛鐎ｎ亜顏уǎ鍥э躬楠炰線鏁撻敓锟� 闂佸搫瀚晶浠嬪Φ濮樿埖鍎庢い鏃囧亹缁夊灝鈽夐幘鎰佸剱濠⒀冪Ч瀵灚寰勬繝鍌涙殽闁诲海娅㈤幏锟�
FRESULT record_struct_of_Dir_and_File(BYTE *path,LinkedList LinkList)
{
	FRESULT res;
	DIR dir;
	UINT i;
	static FILINFO fno;
	//char filename[1024]={0};
	char filename[256]={0};
	Node node;

	res = f_opendir(&dir, path);                       /* Open the directory */
	if (res == FR_OK) {
		for (;;) {
			memset(&node,0,sizeof(Node));
			res = f_readdir(&dir, &fno);                   /* Read a directory item */
			if (res != FR_OK || fno.fname[0] == 0) break;  /* Break on error or end of dir */
			if (fno.fattrib & AM_DIR) {                    /* It is a directory */
				i = strlen(path);
				sprintf(&path[i], "/%s", fno.fname);
#if 1   		// 婵炴垶鏌ㄩ鍛櫠閻樼粯鍋ㄩ柕濞垮劚琚熼梺璇″厸缁舵岸骞楅懖鈺傚仒闁靛鍎抽幗鐘绘煕鐏炶濡挎繛鍫熷灴瀵剛鎲撮崟顓滐拷濠囨煥濞戞鐏辩�规悂浜堕幃娆撴儌閸濄儳鐛ラ梺鍛婎殘婵兘寮妶澶婇唶闁糕剝鐟㈤弫鍕⒒閸屾繃褰х紒杈ㄧ箞瀹曘儲鎯旈姀锟犳闂佺儵鍋撻崝宀勫船鐎甸潻鎷峰☉娅虫垿鎯堝鍜冩嫹濞戞鎴﹀棘娓氾拷瀹曟繈濡搁敂鍏煎濞达綀顫夊▓鍫曟煙閻у憡瀚�
				//闂佺厧鎼崐濠氬磻閿濆洦灏庨悗锝庝悍閹风兘鏁撻敓锟�
				node.data.type=1;		//闂佸搫鍊稿ú锝呪枎閵忋倖鏅柨鐕傛嫹0闂佹寧绋戦張顒勫几閸愨晝顩烽悹鐑樹航娴犳岸鏌ㄥ☉铏1
				get_Dir_size(path,&node.data.size);
				strcpy(node.data.name,path);
//				node.data.ChangeTime1

				//闂佺厧鎼崐濠氬磻閿濆绀傞柕澶嗘櫆琚�
				List_TailInsert(LinkList,node);
#endif
				res = record_struct_of_Dir_and_File(path,LinkList);  /* Enter the directory */
				if (res != FR_OK) break;
//				printf("directory name is:%s\n", path);
				path[i] = 0;
			}
			else {                                       /* It is a file. */
//				printf("file name is:%s/%s\n", path, fno.fname);
				sprintf(filename,"%s/%s", path, fno.fname);
#if 1   		//婵炴垶鏌ㄩ鍛櫠閻樼粯鍋ㄩ柕濞垮劚琚熼梺璇″厸缁舵岸骞楅懖鈺傚仒闁靛鍎抽幗鐘绘煕鐏炶濡挎繛鍫熷灴瀵剛鎲撮崟顓滐拷濠囨煥濞戞鐏辩�规悂浜堕幃娆撴儌閸濄儳鐛ラ梺鍛婎殘婵兘寮妶澶婇唶闁糕剝鐟㈤弫鍕⒒閸屾繃褰х紒杈ㄧ箞瀹曘儲鎯旈姀锟犳闂佺儵鍋撻崝宀勫船鐎甸潻鎷峰☉娅虫垿鎯堝鍜冩嫹濞戞鎴﹀棘娓氾拷瀹曟繈濡搁敂鍏煎濞达綀顫夊▓鍫曟煙閻у憡瀚�
				//闂佺厧鎼崐濠氬磻閿濆洦灏庨悗锝庝悍閹风兘鏁撻敓锟�
				node.data.type=0;		//闂佸搫鍊稿ú锝呪枎閵忋倖鏅柨鐕傛嫹0闂佹寧绋戦張顒勫几閸愨晝顩烽悹鐑樹航娴犳岸鏌ㄥ☉铏1
				node.data.size=fno.fsize;
				strcpy(node.data.name,filename);
//				node.data.ChangeTime1

				//闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙闁稿被鍔庨幉鎼佸籍閸垹绁﹂梺鍝勭▉閸欏酣寮崘顔界叆闁哄浂浜濈�氬湱绱掗幆褍鈷旈柟铏崌閸╃偤骞嬮敂钘変汗闁诲骸婀辨慨鎾夊┑鍫㈢＜闁绘劦鍓欓崝銈嗐亜椤撶姴鍘寸�殿喖顭锋俊鎼佸Ψ閵忊剝鏉搁梻浣虹《濡狙囧疾濠婂懐鎳呯紓鍌氬�搁崐椋庢閵堝绠柣鎴ｅГ閻撴洜锟界櫢鎷烽柨鐔剁矙瀹曟垿鎮欓悜妯轰簵闂婎偄娲﹂幖鈺呮偄閸℃稒鍋ｉ柧蹇曟嚀閸斿銇勯妷褍浠︾紒缁樼洴瀹曘劑顢橀悤浣癸骏闂備浇顕栭崳顕�宕抽敐澶婃瀬闁瑰墽绮弲鎼佹煥閻曞倹瀚�
				List_TailInsert(LinkList,node);
#endif
			}
		}
		f_closedir(&dir);
	}
	return res;
}


//FRESULT record_struct_of_Dir_and_File(BYTE *path,LinkedList LinkList)
//{
//	FRESULT res;
//	DIR dir;
//	UINT i;
//	static FILINFO fno;
//	Node NODE;
//	char filename[1024]={0};
////	memset(&dir,0,sizeof(DIR));
//
//	res = f_opendir(&dir, path);                       /* Open the directory */
//	if (res == FR_OK) {
//		for (;;) {
//			memset(&NODE,0,sizeof(Node));
//			res = f_readdir(&dir, &fno);                   /* Read a directory item */
//			if (res != FR_OK || fno.fname[0] == 0) break;  /* Break on error or end of dir */
//			if (fno.fattrib & AM_DIR) {                    /* It is a directory */
//				i = strlen(path);
//				sprintf(&path[i], "/%s", fno.fname);
//#if 1   		// 婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柟闂寸绾惧鏌ｉ幇顒佹儓闁搞劌鍊块弻娑㈩敃閿濆棛顦ラ梺钘夊暟閸犳牠寮婚弴鐔虹闁绘劦鍓氶悵锕傛⒑鏉炴壆顦﹂悗姘嵆瀵鈽夊Ο閿嬵潔闂佸憡顨堥崑鐐烘倶瀹ュ應鏀介柣鎰级閸ｈ棄鈹戦悜鍥ㄥ闂備礁鎼惌澶屽緤閸婄喓浜介梻浣稿悑缁佹挳寮插☉姘辩當闁跨喓濮甸埛鎴犵磼鐎ｎ偒鍎ラ柛搴＄Ч閺屾盯寮敓浠嬪垂閸噮鍤曞┑鐘宠壘閸楁娊鏌ｉ弮鍥仩妞ゆ梹娲熷娲礈閼碱剙甯ラ梺鍝ュУ閻楁骞堥妸锔藉劅闁靛绠戞禒鈺佲攽椤旂煫顏勭暦椤掑嫬鍑犳繛鎴炵懄閸欏繐鈹戦悩鍙夊櫤妞ゅ繒濞�閺岀喐顦版惔鈾�鏋呴梺鎼炲姂缁犳牕鐣峰锟介獮鎾诲箳閺冩垵鏁圭紓鍌氬�搁崐鎼佸磹瀹勬噴褰掑炊椤掞拷閺勩儵鏌″畵顔兼噺濞堟洟姊鸿ぐ鎺擄紵闁煎疇娉涢悾鍨媴闁稓绠氶梺闈涚墕閹冲繘宕冲ú顏呯厱闁靛牆鎳庨弳锝夋煛鐏炵晫效鐎规洦鍋婂畷鐔碱敃椤掍礁顏堕梺鍛婄☉閿曪箓銆呴悜鑺ョ厵闁绘垶锕╁▓鏇㈡煃闁垮鐏存慨濠傤煼瀹曞ジ鎮㈤崜浣虹畳闂備胶绮敮锛勭不閺嶎厼钃熸繛鎴炵懄閸庣喖鏌曡箛鏇炐涢柡瀣懃铻栭柣姗�娼ф禒锔姐亜閵娿儻韬鐐插暣閸╋繝宕橀鍡床婵犵妲呴崹鎶藉储瑜旈悰顕�宕奸妷锔规嫼闁荤姴娲╃亸娆戠不閹惰姤鐓曢悗锝庡墮閳诲牊銇勯姀鈥蹭孩妞わ箑鍟胯彁闁搞儜宥堝惈濡ょ姷鍋為崝鏍箚閺冨牊鏅查柛銉ㄦ硾閺咁參姊婚崒娆戭槮濠㈢懓锕畷鎴﹀幢濞戞鐛ラ柟鍏肩暘閸斿秹宕愰崼鏇熷�甸柣銏犳啞娴溿倝鏌熷畡鏉挎Щ闁崇粯鎹囧畷褰掝敊閻ｅ苯钂嬮梻鍌欑閹诧繝骞愭繝姘剮妞ゆ牜鍋熷畵浣割熆閼搁潧濮囩紒鐘电帛閵囧嫰寮崶褌姹楀銈忛檮濠㈡﹢鈥旈崘顔嘉ч柛鈩兠棄宥囩磽娓氬洤娅欑紓宥勭窔閻涱喛绠涘☉娆戝弳闁诲函缍嗛崜娑㈡儊閸儲鈷戦柟鑲╁仜閸旀﹢鏌涢弬鍧楀弰鐎规洩缍佸畷鍗烆渻缂佹ɑ鏉搁梻浣虹帛閸旀牕顭囧▎鎾村�堕柨鏂款潟娴滄粍銇勯幘璺轰沪闁哥姵锕㈤弻鐔碱敊缂傚瓨鍨甸…鍥疀濞戞鍘搁柣搴秵閸嬪嫰顢旈崼鏇熺厽闁绘柨鎽滈幊鍐倵濮樼厧寮�规洘鍔欓獮鍥敄閻愬灚鍤�妞ゎ厹鍔戝畷姗�顢旈崟顓炲箺濠德板�楁慨鐑藉磻濞戙垹鐤い鎰剁畱閻撴繈骞栧ǎ顒�濡肩紒鐘差煼閺屸剝寰勭�ｎ亞浠存繝銏㈡嚀閸熸潙顫忕紒妯诲闁告稑锕ら弳鍫㈢磽娴ｅ憡鎯堟繛灏栵拷宕囨殾闁哄洢鍨圭粻顕�鏌ら幁鎺戝姎濞寸姵甯″娲濞戣鲸孝闂佸搫鎳忕划鎾诲春濞戙垹绠ｉ柨鏃傛櫕閸樺崬鈹戦悙鏉戠仸闁挎洍鏅犻幃锟狀敆娴ｈ櫣顔曢梺鍓插亞閸炲顢旈崼婵堝幋闂佺鎻�靛矂寮繝鍥ㄧ厵妞ゆ牕妫楅崯顐ょ不閿濆鐓熼幖娣焺閸熷繘鏌涢敐搴℃珝鐎规洘鍨剁换婵嬪礃瑜忕粻姘舵⒑閸忓吋鍊愭繛浣冲懏顐介柣鎰ゴ閺�浠嬫煟濡搫绾ч柟鍏煎姍閺屸剝鎷呴崫銉ㄥ┑顔硷功缁垶骞忛崨瀛樻優妤犵偛灏呴幏閿嬬節閸ャ劎鍘遍梺瑙勫劤椤曨厾绮婚悙鐑樼厵妞ゆ梹鍎抽崢鏉戔攽椤曞棙瀚归梻渚�娼ч悧鍡涘箠韫囨稒鍊垫い鎺戝閳锋垿鏌涘☉姗堟敾濠㈣泛瀚伴弻娑㈠Ω閳猴拷閹查箖鏌涢埡鍌滄创妤犵偞甯掕灃濞达絽鎼獮鍫ユ⒑鐠囪尙绠抽柛瀣♁閺呭爼鎮惧畝锟芥稉宥夋煛瀹ュ骸浜濋柛鐘冲姍閺岀喓鎹勯悮鏉戜紣闂佺娅曢崝妤佺珶閺囩喓闄勭紒瀣硶妤犲洭姊洪崜鎻掍簼缂佸鍨舵穱濠勬崉閵娧咃紲闂佺粯锕㈠褎绂掕閺屻劑鎮㈤崙銈嗗闁绘洑鐒︾紞鍫濃攽閻愭潙绲荤紒缁樏悾鐑藉即閵忕姾鎽曢梺闈涱槶閸庢娊鎮炬ィ鍐┾拺闁告繂瀚弳娆撴煟濡わ拷濡繈鏁愰悙鍝勫窛閻庢稒顭囬崣鍡涙⒑缂佹ɑ鐓ラ柟纰卞亝閻楀孩淇婇悙顏勶拷鏇狅拷娑掓櫊閹囨偐瀹割喗缍庣紓鍌欑劍钃卞┑顖涙尦閺屾稑鈹戦崱妤婁患婵犳鍣粻鎾愁潖閾忓湱鐭欐繛鍡樺劤閸撻亶姊洪崷顓熷殌婵炲眰鍊濋幃鎯х暋閹佃櫕鏂�闂佺硶鍓濋悷锕�鈻撻弴銏♀拺闁告稑锕ユ径鍕煕鐎ｎ亶妯�鐎规洘妞介幃娆撴倻濡厧骞楅梺纭呭閹活亞寰婃ィ鍐ㄦ辈妞ゆ帊鑳剁粻楣冩煟閹惧啿鐦ㄩ柣鎾冲悑椤ㄣ儵鎮欓懠顒傤唶闂佷紮缍囩换婵嬬嵁瀹ュ鎯炴い鎰靛亝缂嶅苯鈹戦悩鍨毄闁稿鐩獮濠囧箻閺傘儲鐎洪梺鍝勬储閸ㄥ綊宕归崒鐐寸厱鐟滃酣銆冮崨顖滀笉婵鍩栭悡鏇熴亜閹板墎鎮肩紒鐘劦閺岋綁骞橀崡鐐插Е闂佸搫鏈粙鎴︹�﹂妸鈺佺闁靛闄勯澶愭⒑鐠囨彃顒㈠ǎ鍥ㄦそ閿濈偞寰勭仦鎯у簥濠电偞鍨崹鍦不閿濆鐓熼柟瀛樼箖椤ユ瑧绱掓潏顭戞疁婵﹨娅ｅ☉鐢稿川椤斿吋閿紓鍌欒兌婵敻宕规担鍐罕婵犵妲呴崹杈ㄧ娴犲鏅搁柤鎭掑劚缁楁帗銇勯锝囩疄闁诡喗鐟╅、妤呮晸娴犲鏁傞柛顐ｆ礃閻撶喖骞栧ǎ顒�锟姐倕顭囬幇顓犵闁告瑥顦介悞浠嬫煙楠炲灝鐏茬�规洖銈搁幃銏ゅ礈娴ｈ櫣鏆伴梻鍌欑缂嶅﹤螞閸ф鍊块柨鏇炲�搁悿鐐節婵犲倻澧涢柣鎾存礋閻擃偊宕堕妸锔绢槬闁汇埄鍨甸崺鏍Φ閸曨喚鐤�婵﹩鍓涢崢顐ょ磽娴ｈ櫣甯涚紒瀣笒椤洩绠涘☉妯碱槶閻熸粌绻楅埅鎻掆攽閿涘嫬浜奸柛濞垮�濆畷鎴﹀礋椤栵拷閸ヮ剦鏁嶉柣鎰皺閸樻椽姊虹憴鍕妞ゆ泦鍥ㄧ厑闁搞儺鍓氶悡娑㈡煕閵夈垺娅呴柡瀣閺屾稑螣閸忓吋姣堝┑顔硷龚濞咃綁骞忛锝嗗劅闁炽儴娅曞▓鏌ユ⒑閸濄儱鏋旈柛瀣ㄥ�濋獮鍐ㄎ旈敓浠嬶綖濠靛鍊锋い鎺炴嫹妞ゅ骏鎷�
//				//闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙闁稿被鍔庨幉鎼佸籍閸垹绁﹂梺鍝勭▉閸欏酣寮崘顔界叆闁哄浂浜濈�氬湱绱掗幆褍鈷旈柟铏崌閸╃偤骞嬮敂钘変汗闁诲骸婀辨慨鎾夊┑鍫㈢＜闁绘劦鍓欓崝銈嗐亜椤撶姴鍘寸�殿喖顭锋俊鎼佸Ψ閵忊剝鏉搁梻浣虹《閸撴繈鏁嬪銈忚吂閺呯娀寮婚敐鍫㈢杸闁规儳澧庨鍥⒒娴ｇ绨荤紓宥勭窔閻涱噣宕橀妸搴㈡瀹曘劑顢欓懞銉у礁闂備礁婀遍崢褔鎮洪妸褎宕查柛鎰靛枛绾惧綊鏌ㄥ┑鍡╂Ч闁抽攱鍨归幉鎼佹偋閸繀鍒婂┑鈽嗗亝閸ㄥ潡寮诲☉婊呯杸闁哄啯鎹侀敓鍊熸硶閿熻姤顔栭崳顕�宕戞繝鍥╁祦婵☆垵鍋愮壕鍏间繆椤栨粎甯涙い蹇曞枛濮婄粯鎷呴懞銉с�婇梺闈╃秶缁犳捇鐛箛娑欐櫢闁跨噦鎷�
//				NODE.data.type=1;
//				get_Dir_size(path,&NODE.data.size);
//				strcpy(NODE.data.name,path);
////				node.data.ChangeTime1
//
//				//闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙闁稿被鍔庨幉鎼佸籍閸垹绁﹂梺鍝勭▉閸欏酣寮崘顔界叆闁哄浂浜濈�氬湱绱掗幆褍鈷旈柟铏崌閸╃偤骞嬮敂钘変汗闁诲骸婀辨慨鎾夊┑鍫㈢＜闁绘劦鍓欓崝銈嗐亜椤撶姴鍘寸�殿喖顭锋俊鎼佸Ψ閵忊剝鏉搁梻浣虹《濡狙囧疾濠婂懐鎳呯紓鍌氬�搁崐椋庢閵堝绠柣鎴ｅГ閻撴洜锟界櫢鎷烽柨鐔剁矙瀹曟垿鎮欓悜妯轰簵闂婎偄娲﹂幖鈺呮偄閸℃稒鍋ｉ柧蹇曟嚀閸斿銇勯妷褍浠︾紒缁樼洴瀹曘劑顢橀悤浣癸骏闂備浇顕栭崳顕�宕抽敐澶婃瀬闁瑰墽绮弲鎼佹煥閻曞倹瀚�
//				List_TailInsert(LinkList,NODE);
//#endif
////				res = record_struct_of_Dir_and_File(path,LinkList);  /* Enter the directory */
////				if (res != FR_OK) break;
////				printf("directory name is:%s\n", path);
//				path[i] = 0;
//			}
//			else {                                       /* It is a file. */
////				printf("file name is:%s/%s\n", path, fno.fname);
//				sprintf(filename,"%s/%s", path, fno.fname);
//#if 1   		//婵犵數濮烽弫鍛婃叏閻戣棄鏋侀柟闂寸绾惧鏌ｉ幇顒佹儓闁搞劌鍊块弻娑㈩敃閿濆棛顦ラ梺钘夊暟閸犳牠寮婚弴鐔虹闁绘劦鍓氶悵锕傛⒑鏉炴壆顦﹂悗姘嵆瀵鈽夊Ο閿嬵潔闂佸憡顨堥崑鐐烘倶瀹ュ應鏀介柣鎰级閸ｈ棄鈹戦悜鍥ㄥ闂備礁鎼惌澶屽緤閸婄喓浜介梻浣稿悑缁佹挳寮插☉姘辩當闁跨喓濮甸埛鎴犵磼鐎ｎ偒鍎ラ柛搴＄Ч閺屾盯寮敓浠嬪垂閸噮鍤曞┑鐘宠壘閸楁娊鏌ｉ弮鍥仩妞ゆ梹娲熷娲礈閼碱剙甯ラ梺鍝ュУ閻楁骞堥妸锔藉劅闁靛绠戞禒鈺佲攽椤旂煫顏勭暦椤掑嫬鍑犳繛鎴炵懄閸欏繐鈹戦悩鍙夊櫤妞ゅ繒濞�閺岀喐顦版惔鈾�鏋呴梺鎼炲姂缁犳牕鐣峰锟介獮鎾诲箳閺冩垵鏁圭紓鍌氬�搁崐鎼佸磹瀹勬噴褰掑炊椤掞拷閺勩儵鏌″畵顔兼噺濞堟洟姊鸿ぐ鎺擄紵闁煎疇娉涢悾鍨媴闁稓绠氶梺闈涚墕閹冲繘宕冲ú顏呯厱闁靛牆鎳庨弳锝夋煛鐏炵晫效鐎规洦鍋婂畷鐔碱敃椤掍礁顏堕梺鍛婄☉閿曪箓銆呴悜鑺ョ厵闁绘垶锕╁▓鏇㈡煃闁垮鐏存慨濠傤煼瀹曞ジ鎮㈤崜浣虹畳闂備胶绮敮锛勭不閺嶎厼钃熸繛鎴炵懄閸庣喖鏌曡箛鏇炐涢柡瀣懃铻栭柣姗�娼ф禒锔姐亜閵娿儻韬鐐插暣閸╋繝宕橀鍡床婵犵妲呴崹鎶藉储瑜旈悰顕�宕奸妷锔规嫼闁荤姴娲╃亸娆戠不閹惰姤鐓曢悗锝庡墮閳诲牊銇勯姀鈥蹭孩妞わ箑鍟胯彁闁搞儜宥堝惈濡ょ姷鍋為崝鏍箚閺冨牊鏅查柛銉ㄦ硾閺咁參姊婚崒娆戭槮濠㈢懓锕畷鎴﹀幢濞戞鐛ラ柟鍏肩暘閸斿秹宕愰崼鏇熷�甸柣銏犳啞娴溿倝鏌熷畡鏉挎Щ闁崇粯鎹囧畷褰掝敊閻ｅ苯钂嬮梻鍌欑閹诧繝骞愭繝姘剮妞ゆ牜鍋熷畵浣割熆閼搁潧濮囩紒鐘电帛閵囧嫰寮崶褌姹楀銈忛檮濠㈡﹢鈥旈崘顔嘉ч柛鈩兠棄宥囩磽娓氬洤娅欑紓宥勭窔閻涱喛绠涘☉娆戝弳闁诲函缍嗛崜娑㈡儊閸儲鈷戦柟鑲╁仜閸旀﹢鏌涢弬鍧楀弰鐎规洩缍佸畷鍗烆渻缂佹ɑ鏉搁梻浣虹帛閸旀牕顭囧▎鎾村�堕柨鏂款潟娴滄粍銇勯幘璺轰沪闁哥姵锕㈤弻鐔碱敊缂傚瓨鍨甸…鍥疀濞戞鍘搁柣搴秵閸嬪嫰顢旈崼鏇熺厽闁绘柨鎽滈幊鍐倵濮樼厧寮�规洘鍔欓獮鍥敄閻愬灚鍤�妞ゎ厹鍔戝畷姗�顢旈崟顓炲箺濠德板�楁慨鐑藉磻濞戙垹鐤い鎰剁畱閻撴繈骞栧ǎ顒�濡肩紒鐘差煼閺屸剝寰勭�ｎ亞浠存繝銏㈡嚀閸熸潙顫忕紒妯诲闁告稑锕ら弳鍫㈢磽娴ｅ憡鎯堟繛灏栵拷宕囨殾闁哄洢鍨圭粻顕�鏌ら幁鎺戝姎濞寸姵甯″娲濞戣鲸孝闂佸搫鎳忕划鎾诲春濞戙垹绠ｉ柨鏃傛櫕閸樺崬鈹戦悙鏉戠仸闁挎洍鏅犻幃锟狀敆娴ｈ櫣顔曢梺鍓插亞閸炲顢旈崼婵堝幋闂佺鎻�靛矂寮繝鍥ㄧ厵妞ゆ牕妫楅崯顐ょ不閿濆鐓熼幖娣焺閸熷繘鏌涢敐搴℃珝鐎规洘鍨剁换婵嬪礃瑜忕粻姘舵⒑閸忓吋鍊愭繛浣冲懏顐介柣鎰ゴ閺�浠嬫煟濡搫绾ч柟鍏煎姍閺屸剝鎷呴崫銉ㄥ┑顔硷功缁垶骞忛崨瀛樻優妤犵偛灏呴幏閿嬬節閸ャ劎鍘遍梺瑙勫劤椤曨厾绮婚悙鐑樼厵妞ゆ梹鍎抽崢鏉戔攽椤曞棙瀚归梻渚�娼ч悧鍡涘箠韫囨稒鍊垫い鎺戝閳锋垿鏌涘☉姗堟敾濠㈣泛瀚伴弻娑㈠Ω閳猴拷閹查箖鏌涢埡鍌滄创妤犵偞甯掕灃濞达絽鎼獮鍫ユ⒑鐠囪尙绠抽柛瀣♁閺呭爼鎮惧畝锟芥稉宥夋煛瀹ュ骸浜濋柛鐘冲姍閺岀喓鎹勯悮鏉戜紣闂佺娅曢崝妤佺珶閺囩喓闄勭紒瀣硶妤犲洭姊洪崜鎻掍簼缂佸鍨舵穱濠勬崉閵娧咃紲闂佺粯锕㈠褎绂掕閺屻劑鎮㈤崙銈嗗闁绘洑鐒︾紞鍫濃攽閻愭潙绲荤紒缁樏悾鐑藉即閵忕姾鎽曢梺闈涱槶閸庢娊鎮炬ィ鍐┾拺闁告繂瀚弳娆撴煟濡わ拷濡繈鏁愰悙鍝勫窛閻庢稒顭囬崣鍡涙⒑缂佹ɑ鐓ラ柟纰卞亝閻楀孩淇婇悙顏勶拷鏇狅拷娑掓櫊閹囨偐瀹割喗缍庣紓鍌欑劍钃卞┑顖涙尦閺屾稑鈹戦崱妤婁患婵犳鍣粻鎾愁潖閾忓湱鐭欐繛鍡樺劤閸撻亶姊洪崷顓熷殌婵炲眰鍊濋幃鎯х暋閹佃櫕鏂�闂佺硶鍓濋悷锕�鈻撻弴銏♀拺闁告稑锕ユ径鍕煕鐎ｎ亶妯�鐎规洘妞介幃娆撴倻濡厧骞楅梺纭呭閹活亞寰婃ィ鍐ㄦ辈妞ゆ帊鑳剁粻楣冩煟閹惧啿鐦ㄩ柣鎾冲悑椤ㄣ儵鎮欓懠顒傤唶闂佷紮缍囩换婵嬬嵁瀹ュ鎯炴い鎰靛亝缂嶅苯鈹戦悩鍨毄闁稿鐩獮濠囧箻閺傘儲鐎洪梺鍝勬储閸ㄥ綊宕归崒鐐寸厱鐟滃酣銆冮崨顖滀笉婵鍩栭悡鏇熴亜閹板墎鎮肩紒鐘劦閺岋綁骞橀崡鐐插Е闂佸搫鏈粙鎴︹�﹂妸鈺佺闁靛闄勯澶愭⒑鐠囨彃顒㈠ǎ鍥ㄦそ閿濈偞寰勭仦鎯у簥濠电偞鍨崹鍦不閿濆鐓熼柟瀛樼箖椤ユ瑧绱掓潏顭戞疁婵﹨娅ｅ☉鐢稿川椤斿吋閿紓鍌欒兌婵敻宕规担鍐罕婵犵妲呴崹杈ㄧ娴犲鏅搁柤鎭掑劚缁楁帗銇勯锝囩疄闁诡喗鐟╅、妤呮晸娴犲鏁傞柛顐ｆ礃閻撶喖骞栧ǎ顒�锟姐倕顭囬幇顓犵闁告瑥顦介悞浠嬫煙楠炲灝鐏茬�规洖銈搁幃銏ゅ礈娴ｈ櫣鏆伴梻鍌欑缂嶅﹤螞閸ф鍊块柨鏇炲�搁悿鐐節婵犲倻澧涢柣鎾存礋閻擃偊宕堕妸锔绢槬闁汇埄鍨甸崺鏍Φ閸曨喚鐤�婵﹩鍓涢崢顐ょ磽娴ｈ櫣甯涚紒瀣笒椤洩绠涘☉妯碱槶閻熸粌绻楅埅鎻掆攽閿涘嫬浜奸柛濞垮�濆畷鎴﹀礋椤栵拷閸ヮ剦鏁嶉柣鎰皺閸樻椽姊虹憴鍕妞ゆ泦鍥ㄧ厑闁搞儺鍓氶悡娑㈡煕閵夈垺娅呴柡瀣閺屾稑螣閸忓吋姣堝┑顔硷龚濞咃綁骞忛锝嗗劅闁炽儴娅曞▓鏌ユ⒑閸濄儱鏋旈柛瀣ㄥ�濋獮鍐ㄎ旈敓浠嬶綖濠靛鍊锋い鎺炴嫹妞ゅ骏鎷�
//				//闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸ゅ嫰鏌涢锝嗙闁稿被鍔庨幉鎼佸籍閸垹绁﹂梺鍝勭▉閸欏酣寮崘顔界叆闁哄浂浜濈�氬湱绱掗幆褍鈷旈柟铏崌閸╃偤骞嬮敂钘変汗闁诲骸婀辨慨鎾夊┑鍫㈢＜闁绘劦鍓欓崝銈嗐亜椤撶姴鍘寸�殿喖顭锋俊鎼佸Ψ閵忊剝鏉搁梻浣虹《閸撴繈鏁嬪銈忚吂閺呯娀寮婚敐鍫㈢杸闁规儳澧庨鍥⒒娴ｇ绨荤紓宥勭窔閻涱噣宕橀妸搴㈡瀹曘劑顢欓懞銉у礁闂備礁婀遍崢褔鎮洪妸褎宕查柛鎰靛枛绾惧綊鏌ㄥ┑鍡╂Ч闁抽攱鍨归幉鎼佹偋閸繀鍒婂┑鈽嗗亝閸ㄥ潡寮诲☉婊呯杸闁哄啯鎹侀敓鍊熸硶閿熻姤顔栭崳顕�宕戞繝鍥╁祦婵☆垵鍋愮壕鍏间繆椤栨粎甯涙い蹇曞枛濮婄粯鎷呴懞銉с�婇梺闈╃秶缁犳捇鐛箛娑欐櫢闁跨噦鎷�
//				NODE.data.type=0;		//闂傚倸鍊搁崐鎼佸磹閹间礁纾瑰瀣捣閻棗銆掑鐐濡ょ姷鍋為悧鐘汇�侀弴銏℃櫇闁跨喓鏅竟鏇㈠捶椤撶姷锛滈柣搴秵閸嬫挾妲愰埡鍌滅鐎瑰壊鍠曠花濂告煛閸涱喚鍙�闁哄本绋戦埥澶愬矗濡厧鍤梻浣筋嚙妤犳悂鈥﹀畡閭︽綎婵炲樊浜濋ˉ鍫熺箾閹寸偞鐨戦柣銈呭濮婅櫣绮欓崠鈩冩暰闂佺粯顨堟慨鎾敋閿濆钃熼柕澶樺枟閺呫垽姊洪崨濠冨闁告挻鐩畷锝夊幢濞戞瑢鎷虹紓鍌欑劍钃辩紒锟介敓浠嬫⒑缁嬪尅宸ユ繝锟介柆宥嗘櫢闁兼亽鍎抽崯鏌ユ煙閸戙倖瀚�0闂傚倸鍊搁崐鎼佸磹閹间礁纾归柣鎴ｅГ閸婂潡鏌ㄩ弮锟介幏婵嬪箯妞嬪海绠旀繛鎴炆戦崳浠嬫煟椤撶喓鎳囬柡宀�鍠愬蹇涘礈瑜忛弳鐘绘煟鎼淬垼澹樻い锔垮嵆婵＄敻宕熼姘鳖唺闂佺懓鐡ㄧ换宥嗙婵傚憡鈷戦柛娑橈工閻忊晛鈹戦悜鍥ㄥ闂備礁鎼張顒勬儎椤栫偟宓侀柛銉墮鎯熼梺鎸庢⒒閺咁偉銇愰崶銊ょ箚闁绘劦浜滈敓鑺ュ姍瀵彃鈹戠�ｎ亞顦у┑顔筋殣閹烽攱顨ラ悙鎻掓殺闁靛洦鍔欓獮鎺楀箻缁涜瀚圭紓浣姑肩换鍡樸亜閺嶃劎鐭ら柡锟芥导瀛樼厱闁宠桨鐒﹂崳铏圭磼缂佹銆掗柨鐔烘櫕閺佹悂鈥﹂崼鐔哄ⅰ闂佽娴峰▍銏ゅ箯閻戣姤鐓欓梻鍌氼嚟椤︼箓鏌﹂崘顏勬灈闁哄本娲樼换娑㈠垂椤旂厧顫庢繝纰樺墲瑜板啴鎮ч幘璇茶摕鐟滄垹绮诲☉銏℃櫜闁告侗鍓涢惄搴繆閻愵亜锟芥洘顨ヨ箛娑樼闁跨噦鎷�1
//				NODE.data.size=fno.fsize;
//				strcpy((char *)NODE.data.name,filename);
////				node.data.ChangeTime1
//
//				List_TailInsert(LinkList,NODE);
//#endif
//			}
//		}
//		f_closedir(&dir);
//	}
//	return res;
//}


FRESULT get_Dir_size(TCHAR *path,uint64_t*size)
{
	FRESULT res;
	DIR dir;
//	FIL file;
	FILINFO fno;
	int i=0;
	char filename[512]={0};

	res = f_opendir(&dir,path);                       /* Open the directory */
	if (res == FR_OK) {
		for (;;) {
			res = f_readdir(&dir, &fno);                   /* Read a directory item */
			if (res != FR_OK || fno.fname[0] == 0) break;  /* Break on error or end of dir */
			if (fno.fattrib & AM_DIR) {                    /* It is a directory */
				i = strlen(path);
				sprintf(&path[i], "/%s", fno.fname);

				res = get_Dir_size(path,size);  /* Enter the directory */
				if (res != FR_OK) break;
				// printf("directory name is:%s\n", path);
				path[i] = 0;
			}
			else {                                        /* It is a file. */
//				printf("file name is:%s/%s\n", path, fno.fname);
				sprintf(filename,"%s/%s", path, fno.fname);
#if  0
				f_open(&file,filename,FA_READ | FA_WRITE | FA_OPEN_ALWAYS);
				if (res != FR_OK) {
					xil_printf("f_open  Failed! res=%d\n", res);
//					return 0;
				}
				*size+=f_size(&file);
				f_close(&file);
#endif
#if  1
				*size+=fno.fsize;
#endif
			}
		}
		f_closedir(&dir);
	}
//    file_num=nfile;
//	dir_num=ndir;
	return res;
}

FRESULT Num_of_Dir_and_File (BYTE *path,DWORD *file_num,DWORD *dir_num,uint8_t mode)
{
    FRESULT res;
    DIR dir;
    static FILINFO fno;
    int i=0;

    res = f_opendir(&dir, path);                       /* Open the directory */
	if (res == FR_OK) {
		for (;;) {
			res = f_readdir(&dir, &fno);                   /* Read a directory item */
			if (res != FR_OK || fno.fname[0] == 0) break;  /* Break on error or end of dir */
			if (fno.fattrib & AM_DIR) {                    /* It is a directory */
				i = strlen(path);
				sprintf(&path[i], "/%s", fno.fname);
				if(!mode)
				{
					res = Num_of_Dir_and_File(path,file_num,dir_num,mode);  /* Enter the directory */
					if (res != FR_OK) break;
					// printf("directory name is:%s\n", path);
				}
				(*dir_num)++;
				path[i] = 0;
			}
			else {                                       /* It is a file. */
				// printf("file name is:%s/%s\n", path, fno.fname);
				(*file_num)++;
			}
		}
		f_closedir(&dir);
	}
//    file_num=nfile;
//	dir_num=ndir;
    return res;
}

void get_path_dname(BYTE* path,u8* des)
{
	 BYTE* temp=path;
	 while(*path!=0)
	 {
		 path++;
	 }
	 //  if(temp<4){return 0;}
	 while((*path!=0x5c)&&(*path!=0x2f))
	 {
		 path--;
		 if(*path=='\0')
		 {
			 des="";
			 return;
		 }
	 }
     memcpy(des,temp,path-temp);
}

// display state of the Storage: totalcap, usedcap, freecap, filenum
FRESULT Storage_state1(QWORD* totalcap,QWORD* usedcap,QWORD* freecap,DWORD* filenum)
{
	 FATFS *fs;
	 FRESULT res;
	 int file_num=0,dir_num=0;
	 QWORD free_clust=0, Free_Cap=0, Total_Cap=0,Used_Cap=0;
	 f_getfree("", &free_clust, &fs);
//	 xil_printf("fs->n_fatent=%u\r\n", fs->n_fatent);
//
////	 Total_Cap = (QWORD)((fs->n_fatent - 2) * fs->csize * 4096);
////	 Total_Cap = (((QWORD)(fs->n_fatent)) - 2 )* fs->csize * 4096*2;     // B
//	 Total_Cap = (((QWORD)(fs->n_fatent)) - 2)* fs->csize * 4096;     // B
//	 xil_printf("Total_Cap=%llu\r\n", Total_Cap);
//
//	 Free_Cap = free_clust * fs->csize*4096;             			// B
//	 xil_printf("Free_Cap=%llu\r\n", Free_Cap);
//
//	 Used_Cap = Total_Cap-Free_Cap;                    				// B
//	 xil_printf("Used_Cap=%llu\r\n", Used_Cap);

	 res=Num_of_Dir_and_File ("",&file_num,&dir_num,0);
	 if (res != FR_OK)
	 {
	 	  xil_printf("file_num get Failed! ret=%d\r\n", res);
//	 	  return -1;
	 }

//	 Total_Cap = (((QWORD)(fs->n_fatent)) - 2)* fs->csize * 4096;
	 Total_Cap = TOTAL_CAP;
	 get_Dir_size("0:",&Used_Cap);
	 Free_Cap= Total_Cap-Used_Cap-LOSS;
	 *totalcap=Total_Cap;
	 *usedcap=Used_Cap;
	 *freecap=Free_Cap;
	 *filenum=file_num+dir_num;
//	 xil_printf("Total_Cap=%llu  Free_Cap=%llu   Used_Cap=%llu    \r\n", Total_Cap,Free_Cap,Used_Cap);
     return FR_OK;
}

// display state of the Storage: WorkState,  WorkTemp,  Power  PowerUpNum
FRESULT Storage_state2(DWORD* workstate,DWORD* worktemp,DWORD* power,DWORD* powerupnum)
{
	 FATFS *Fs=&fs;
	 DWORD Work_State,Work_Temp,Power,PowerUpNum;
	 Work_State=0x1;
	 Work_Temp=55;
	 Power=33;
	 PowerUpNum=255;


	 *workstate=Work_State;
	 *worktemp=Work_Temp;
	 *power=Power;
	 *powerupnum=PowerUpNum;
      return 0;
}
