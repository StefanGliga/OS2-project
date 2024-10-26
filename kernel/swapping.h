//
// Created by stefangliga on 15/02/24.
//

#pragma once

#include "types.h"
#include "riscv.h"
#include "defs.h"

extern uint64 frame_access_info[4096];

uint64 static inline addr_to_ram_frame_idx(uchar* addr)
{
    if(addr < (uchar*)0x80000000)
        panic("addr_to_ram_frame_idx: addr < 0x80000000");
    return ((uint64)addr-0x80000000) >> 12;
}

void init_swapping();
int swapout();
int swapin(uint64* pte_entry);
void free_page_on_disk(pte_t* pte_entry);
void swapping_tick();
void trashing_tick();
