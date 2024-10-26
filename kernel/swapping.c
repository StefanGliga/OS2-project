//
// Created by stefangliga on 15/02/24.
//

#include "swapping.h"
#include "defs.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"

#define DISK_PAGE_GROUPS 128

uint64 frame_access_info[4096] = {};
uint32 disk_bitvector[DISK_PAGE_GROUPS] = {};
uint64 num_swapouts = 0;
//pte_t* gpte[4096] = {};

void init_swapping()
{
    // for(int i=0; i<4096; i++)
    // {
    //     frame_access_info[i] = 0;
    // }
    // for(int i=0; i<DISK_PAGE_GROUPS; i++)
    // {
    //     disk_bitvector[i] = 0;
    // }
}

unsigned static inline find_first_0bit(uint32 i)
{
    uint32 b = ~i & (i+1);   // this gives a 1 to the left of the trailing 1's
    b--;              // this gets us just the trailing 1's that need counting
    b = (b & 0x55555555) + ((b>>1) & 0x55555555);  // 2 bit sums of 1 bit numbers
    b = (b & 0x33333333) + ((b>>2) & 0x33333333);  // 4 bit sums of 2 bit numbers
    b = (b & 0x0f0f0f0f) + ((b>>4) & 0x0f0f0f0f);  // 8 bit sums of 4 bit numbers
    b = (b & 0x00ff00ff) + ((b>>8) & 0x00ff00ff);  // 16 bit sums of 8 bit numbers
    b = (b & 0x0000ffff) + ((b>>16) & 0x0000ffff); // sum of 16 bit numbers
    return b;
}

void pin_this_process()
{
    struct proc* p = myproc();
    acquire(&p->lock);
    p->pinned = 1;
    release(&p->lock);
}

void unpin_this_process()
{
    struct proc* p = myproc();
    acquire(&p->lock);  
    p->pinned = 0;
    release(&p->lock);
}

int get_free_page_on_disk()
{
    int i = -1;
    uint32 bits = 0;
    do
    {
        i++;
        bits = disk_bitvector[i];
    } while(bits == -1 && i<DISK_PAGE_GROUPS);
    if(i == DISK_PAGE_GROUPS)
        return -1;

    unsigned freeidx = find_first_0bit(bits);
    disk_bitvector[i] |= 1<<freeidx;
    return i*32 + freeidx;
}

void free_page_on_disk_internal(int idx)
{
    int i = idx / 32;
    int j = idx % 32;
    disk_bitvector[i] &= ~(1<<j);
}

int swapout_impl(uint64* pte_entry)
{
    // get the physical address of the page from the pte_entry
    pin_this_process();
    uint64 temp = *pte_entry;
    if ((PTE_FLAGS(temp) & PTE_V) == 0)
        panic("Swapping out an invalid page");
    uchar* page = (uchar*)PTE2PA(temp);

    uint64 frame_idx = addr_to_ram_frame_idx(page);
    frame_access_info[frame_idx] = 0;

   //printf("Swapping out page %p to disk block\n", page);

    int disk_block_idx = get_free_page_on_disk();
    if(disk_block_idx == -1)
        return -1;

    temp = (PTE_FLAGS(temp) & ~PTE_V) | PTE_S | BLK2PTE(disk_block_idx);
    *pte_entry = temp;

    disk_block_idx *= 4;
    write_block(disk_block_idx  , page       , 1);
    write_block(disk_block_idx+1, page+1024  , 1);
    write_block(disk_block_idx+2, page+1024*2ull, 1);
    write_block(disk_block_idx+3, page+1024*3ull, 1);

    kfree(page);

    //printf("Swapped out page %p to disk block %d\n", page, disk_block_idx/4);


    //printf("PTE for block %d is %p\n", disk_block_idx/4, pte_entry);
    //gpte[disk_block_idx/4] = pte_entry;
    unpin_this_process();

    return 0;
}

uint64* find_victim()
{
    uint64 min = 0xFFFFFFFFFFFFFFFF;
    int min_idx = -1;
    for(int i=0; i<4096; i++)
    {
        if (frame_access_info[i] == 0)
            continue;
        uint64 bits = frame_access_info[i] >> 24;
        if(bits < min)
        {
            min = bits;
            min_idx = i;
        }
    }
    if(min_idx == -1)
        return 0;
    uint64* pte_entry = (uint64*)(0x80000000 + (frame_access_info[min_idx] & ((1 << 24) - 1)));


    return pte_entry;
}

int swapout()
{
    num_swapouts++;
    uint64* pte_entry = find_victim();
    if(pte_entry == 0)
        return -1;
    return swapout_impl(pte_entry);
}

int swapin(uint64* pte_entry)
{
    if (PTE_FLAGS(*pte_entry) & PTE_V)
        return -1;

    pin_this_process();
    uint64 temp = *pte_entry;
    uint64 diskblk = PTE2BLK(temp);
    //printf("Swapping in frame from disk block %d\n", diskblk);

    uchar* frame = kalloc();
    if(frame == 0)
        return -1;

    temp = (PTE_FLAGS(temp) & ~PTE_S) | PTE_V | PA2PTE(frame);

    diskblk *= 4;
    read_block(diskblk  , frame       , 1);
    read_block(diskblk+1, frame+1024  , 1);
    read_block(diskblk+2, frame+1024*2ull, 1);
    read_block(diskblk+3, frame+1024*3ull, 1);

    free_page_on_disk_internal(diskblk/4);

    *pte_entry = temp;

    uint64 frame_idx = addr_to_ram_frame_idx(frame);
    frame_access_info[frame_idx] = (-1ull << 24) | (((uint64)pte_entry-0x80000000) & ((1<<24)-1));

    //printf("Swapped in frame %p from disk block %d\n", frame, diskblk/4);


    //printf("Swapped in block %d to pa %p\n", diskblk/4, frame);
    //printf("PTE for block %d is %p\n", diskblk/4, pte_entry);
    /* if (gpte[diskblk/4] != pte_entry)
    {
        printf("PTE mismatch: %p %p\n", gpte[diskblk/4], pte_entry);
        while(1);
    } */
    unpin_this_process();
    return 0;
}

void free_page_on_disk(pte_t* pte_entry)
{
    uint64 temp = *pte_entry;
    uint64 diskblk = PTE2BLK(temp);
    free_page_on_disk_internal(diskblk);
}

void swapping_tick()
{
    for(int i=0; i<4096; i++)
    {
        uint64 temp = frame_access_info[i];
        if(temp == 0)
            continue;
        pte_t* pte = (pte_t*)((temp & ((1<<24)-1)) + 0x80000000);

        temp = (temp & ((1 << 24) - 1)) | ((temp >> 1) & ~((1 << 24) - 1)) | (((*pte & PTE_A) >> 6) << 63);
        *pte &= ~PTE_A;
        frame_access_info[i] = temp;
    }
}

uint64 find_wss(pagetable_t pagetable)
{
    uint64 count = 0;
    for(int i=0; i<512; i++)
    {
        pte_t pte = pagetable[i];
        if((pte & PTE_V) == 0)
            continue;
        if((pte & (PTE_R | PTE_W | PTE_X)) == 0)
        {
            pagetable_t child = (pagetable_t)(PTE2PA(pte));
            count += find_wss(child);
        }
        else
        {
            if((pte & PTE_A) != 0 || (frame_access_info[addr_to_ram_frame_idx((uchar*)PTE2PA(pte))] >> 59) != 0)
                count++;
        }
    }
    return count;
}

void trashing_tick()
{
    // logic: iterate over all processes, and for each process
    // update the working set size of the process
    // then if the global counter of swaps is over a treshold
    // swap out the process with the largest working set size

    // additionally, if the global counter of swaps is low enough,
    // restore any swapped out processes

    for(int i = 0; i < NPROC; i++)
    {
        if(proc[i].state == UNUSED)
            continue;
        if(proc[i].state == ZOMBIE)
            continue;
        uint64 wss = find_wss(proc[i].pagetable);
        proc[i].wss = wss>proc[i].wss ? wss : (3*proc[i].wss/4);
    }

    if(num_swapouts > 128)
    {
        uint64 max_wss1 = 0, max_wss2 = 0;
        int max_wss_idx1 = -1;//, max_wss_idx2 = -1;
        for(int i = 0; i < NPROC; i++)
        {
            if(proc[i].state == UNUSED)
                continue;
            if(proc[i].state == ZOMBIE)
                continue;
            if(proc[i].state == TRASH)
                continue;
            if(proc[i].wss > max_wss1)
            {
                max_wss2 = max_wss1;
                //max_wss_idx2 = max_wss_idx1;
                max_wss1 = proc[i].wss;
                max_wss_idx1 = i;
            }
            else if(proc[i].wss > max_wss2)
            {
                max_wss2 = proc[i].wss;
                //max_wss_idx2 = i;
            }
        }

        //printf("DEBUG: Max WSSes: %d %d\n", max_wss1, max_wss2);

        // only trigger anti trashing if a lot of memory is being useds
        if(max_wss1 > 512 && max_wss2 > 24)
        {
            if(proc[max_wss_idx1].state == RUNNABLE)
                proc[max_wss_idx1].state = TRASH;
            else
                proc[max_wss_idx1].trashing = 1;
        }
    }
    if(num_swapouts < 4)
    {
        for(int i = 0; i < NPROC; i++)
        {
            if(proc[i].state == UNUSED)
                continue;
            if(proc[i].state == ZOMBIE)
                continue;
            if(proc[i].state == TRASH)
            {
                proc[i].state = RUNNABLE;
                break; // only unblock one process at a time
            }
        }
    }
    num_swapouts = 0;
}