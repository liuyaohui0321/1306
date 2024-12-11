#ifndef __NHC_AMBA_H_
#define __NHC_AMBA_H_

#include <stdio.h>
#include <stdlib.h>


#define  NHC_NUM           4
#define  DDR_NUM           2
#define  U_BLK_SIZE        (2*1024*1024)        //2MB.
#define  DDR_BLK_NUM       (1024*1024*1024)/U_BLK_SIZE

#define  LEN_4             954368
extern uint8_t FLAG;
// NVMe Host IP Base Address


#define  NHC_BASE          0x44a70000  // NVMe1
#define  NHC2_BASE         0x44a20000  // NVMe2
#define  NHC3_BASE         0x44a40000  // NVMe3
#define  NHC4_BASE         0x44a50000  // NVMe4


#define  NHC5_BASE         0x44a40000  // NVMe5
#define  NHC6_BASE         0x44a50000  // NVMe6

//#define  NHC_BASE          0x44a70000  // NVMe1
//#define  NHC2_BASE         0x44a20000  // NVMe2
//#define  NHC3_BASE         0x44a30000  // NVMe3
//#define  NHC4_BASE         0x44a40000  // NVMe4
//
//
//#define  NHC5_BASE         0x44a40000  // NVMe5
//#define  NHC6_BASE         0x44a50000  // NVMe6


// REGION0: Registers
#define  NHC_IP_VS         0x0000
#define  NHC_NVME_VS       0x0004
#define  NHC_IP_CSR        0x0008
#define  NHC_NVME_CAP      0x000C
#define  NHC_LBA_MODE      0x0014
#define  NHC_LBA_SIZE      0x0018
#define  NHC_TIMEOUT_SET   0x0020
#define  NHC_QUEUE_CFG     0x0024
#define  NHC_CMD_STS       0x0028
#define  NHC_INTR_EN       0x0030
#define  NHC_INTR_MASK     0x0034
#define  NHC_INTR_STS      0x0038
#define  NHC_NVME_OCS      0x003C
#define  NHC_NVME_SGLS     0x0040
#define  NHC_PMON_ER       0x0E00
#define  NHC_PMON_CR       0x0E04
#define  NHC_PMON_WLBAC    0x0E10
#define  NHC_PMON_RLBAC    0x0E18
#define  NHC_PMON_WCYCLEC  0x0E20
#define  NHC_PMON_RCYCLEC  0x0E28
#define  NHC_DBG_LINK      0x0F00
#define  NHC_NODE_PCNT     0x0F04

// REGION1: MTR
#define  NHC_REGION_MTR    0x2000

// REGION2: MRR
#define  NHC_REGION_MRR    0x3000

// REGION3: QCMD
#define  NHC_REGION_QCMD   0x8000

// REGION3: QSTS
#define  NHC_REGION_QSTS   0xC000



// Function declaration
uint8_t nhc_init(uint8_t inst, uint32_t timeout_sec, uint32_t freq_MHz);
uint8_t nhc_queue_init(uint8_t inst, uint8_t depth, uint8_t mode);
//uint8_t nhc_queue_full(uint8_t inst);
uint8_t nhc_queue_full(void);
uint8_t nhc2_queue_full(void);
uint8_t nhc3_queue_full(void);
uint8_t nhc4_queue_full(void);
uint8_t nhc_queue_ept(uint8_t inst);
//uint8_t nhc2_queue_full(void);
uint8_t nhc_cmd_sub(uint8_t inst, uint32_t cmd_cdw[16]);
uint8_t nhc_cmd_sts(uint8_t inst);

uint8_t adm_startup(uint8_t inst);
uint8_t adm_shutdown(uint8_t inst);
uint8_t adm_shutdown_abrupt(uint8_t inst);

uint8_t io_flush(uint8_t nhc_num, uint32_t nsid);
uint8_t io_write(uint8_t nhc_num, uint32_t nsid, uint32_t addr, uint64_t slba, uint32_t nlba, uint32_t dsm);
uint8_t io_write1(uint8_t nhc_num, uint32_t nsid, uint32_t addr, uint64_t slba, uint32_t len,uint32_t nlba, uint32_t dsm);
uint8_t io_write2(uint8_t nhc_num, uint32_t nsid, uint32_t addr, uint64_t slba, uint32_t len, uint32_t dsm);
uint8_t io_read(uint8_t nhc_num, uint32_t nsid, uint32_t addr, uint64_t slba, uint32_t nlba, uint32_t dsm);
uint8_t io_read1(uint8_t nhc_num, uint32_t nsid, uint32_t addr, uint64_t slba, uint32_t nlba, uint32_t dsm);
uint8_t io_read2(uint8_t nhc_num, uint32_t nsid, uint32_t addr, uint64_t slba, uint32_t len, uint32_t dsm);
uint8_t io_dsm(uint8_t nhc_num, uint32_t nsid, uint32_t addr, uint32_t dsm);

void io_monitor_enable(uint8_t inst);
void io_monitor_disable(uint8_t inst);
void io_monitor_clear(uint8_t inst);
uint32_t io_monitor_wr(uint8_t inst, uint16_t cycle);
uint32_t io_monitor_rd(uint8_t inst, uint16_t cycle);

void nhc_sw_reset(uint8_t inst);
void pcie_hot_reset(uint8_t inst);

void send_axis_ack(uint8_t type,uint32_t addrt,uint32_t len,uint8_t sts);
void DiskInit();
uint64_t convert1ToMultipleOfSix(uint64_t num);
uint32_t convertToMultipleOfSix(uint32_t num);
#endif
