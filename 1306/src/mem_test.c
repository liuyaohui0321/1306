
#include "xil_printf.h"
//#include "xil_io.h"
#include "mem_test.h"

uint8_t mem_data_clr(uint32_t *Addr, uint32_t Words)
{
	uint32_t i;

	for(i=0; i<Words; i++)
	{
		*(Addr+i) = 0;
	}

	return 0x0;
}

// *********************************************************************************
// mem_data_gen: generate data pattern from one seed in a given memory space
// *********************************************************************************
uint8_t mem_data_gen(uint32_t *Addr, uint32_t Words, uint32_t Seed)
{
	uint32_t i;

	for(i=0; i<Words; i++)
	{
		*(Addr+i) = Seed;
		Seed++;
	}

	return 0x0;
}

// *********************************************************************************
// mem_dsm_gen: generate 4KB DSM Range page in a given memory space
// *********************************************************************************
uint8_t mem_dsm_gen(uint8_t nhc_num, uint32_t *Addr, uint32_t suba, uint32_t nuba, uint32_t attr)
{
	uint32_t i;

	uint32_t nlba = nuba*U_BLK_LBA_CNT/nhc_num;
	uint64_t slba = suba*U_BLK_LBA_CNT/nhc_num;
	// 1st Range
	*(Addr+4) = attr;
	*(Addr+5) = nlba;
	*(Addr+6) = slba & 0xFFFFFFFF;
	*(Addr+7) = slba >> 32;

	// 2nd-256th Range: not used
	for(i=8; i<1024; i++)
	{
		*(Addr+i) = i+4;
	}

	return 0x0;
}


// *********************************************************************************
// mem_data_chk: check data pattern from one seed in a given memory space
// *********************************************************************************
uint8_t mem_data_chk(uint32_t *Addr, uint32_t Words, uint32_t Seed)
{
	uint32_t i;
	uint32_t WordMem32;

	for(i=0; i<Words; i=i+1)
	{
		WordMem32 = *(Addr+i);

		if (WordMem32 != Seed) {
			return 0xFF;
		}
		Seed++;
	}

	return 0x0;
}


// *********************************************************************************
// mem_data_sum: sum of a given memory space
// *********************************************************************************
uint32_t mem_data_sum(uint32_t *Addr, uint32_t Words)
{
	uint32_t i;
	uint32_t WordMem32;
	uint32_t Sum = 0x0;

	for(i=0; i<Words; i=i+1)
	{
		WordMem32 = *(Addr+i);
		Sum = Sum + WordMem32;
	}

	return Sum;
}
