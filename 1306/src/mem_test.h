#ifndef __MEM_TEST_H_
#define __MEM_TEST_H_

#include <stdio.h>
#include <stdlib.h>

#define  MEM_DDR4_BASE          0x80000000
#define  DDR4_START_ADDR        0x80000000
#define  DDR4_END_ADDR          0xFFFFFFFF

#define  U_BLK_LBA_CNT          4096   //2048 lyh 10.17

uint8_t mem_data_clr(uint32_t *Addr, uint32_t Words);
uint8_t mem_data_gen(uint32_t *Addr, uint32_t Words, uint32_t Seed);
uint8_t mem_data_chk(uint32_t *Addr, uint32_t Words, uint32_t Seed);

uint8_t mem_dsm_gen(uint8_t nhc_num, uint32_t *Addr, uint32_t suba, uint32_t nuba, uint32_t attr);
uint32_t mem_data_sum(uint32_t *Addr, uint32_t Words);

#endif
