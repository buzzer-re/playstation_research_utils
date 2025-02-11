#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "ps5/kernel.h"
#include "ps5/payload.h"
#include <sys/stat.h>

#include "../include/idt.h"
#include "../include/dmem.h"
#include "../freebsd-headers/sys/sysent.h"
#include "../freebsd-headers/sys/syscall.h"

#define IDT_OFFSET 0x64cdc80
#define SYSENT_VEC_OFFSET 0xd11d30

static uint64_t pmap_offset = 0;
struct flat_pmap kernel_pmap_store;
uint64_t dmap_base;


int init_pmap()
{
    payload_args_t* primitives = payload_get_args();
    if (!pmap_offset)
    {
        pmap_offset = guess_kernel_pmap_store_offset(primitives->kdata_base_addr);
        if (!pmap_offset)
        {
            printf("Unable to acquire PMAP offset!");
        }
        printf("Acquired PMAP offset at %#02lx\n", pmap_offset);
        kernel_copyout(primitives->kdata_base_addr + pmap_offset, &kernel_pmap_store, sizeof(kernel_pmap_store));
        dmap_base = kernel_pmap_store.pm_pml4 - kernel_pmap_store.pm_cr3;

        return 1;
    }

    return 0;
}


void dmap_copyout(uint64_t kaddr, void* uaddr, size_t len)
{
    if (!pmap_offset && !init_pmap())
    {
        printf("Failed to init dmap! aborting\n");
        return;
    }

    size_t page_end = 0;
    uint64_t paddr = vaddr_to_paddr(kaddr, dmap_base, kernel_pmap_store.pm_cr3, &page_end, 0);

    kernel_copyout(PADDR_TO_DMAP(paddr), uaddr, len);
}

void dmap_copyin(const void* uaddr, uint64_t kaddr, size_t len)
{
    if (!pmap_offset && !init_pmap())
    {
        printf("Failed to init dmap! aborting\n");
        return;
    }

    size_t page_end = 0;
    uint64_t paddr = vaddr_to_paddr(kaddr, dmap_base, kernel_pmap_store.pm_cr3, &page_end, 0);  
    printf("dmap_copyin => paddr %#02lx\n", paddr);

    kernel_copyin(uaddr, PADDR_TO_DMAP(paddr), len);
}

struct amd64tss {
	u_int32_t	tss_rsvd0;
	u_int64_t	tss_rsp0 __packed; 	/* kernel stack pointer ring 0 */
	u_int64_t	tss_rsp1 __packed; 	/* kernel stack pointer ring 1 */
	u_int64_t	tss_rsp2 __packed; 	/* kernel stack pointer ring 2 */
	u_int32_t	tss_rsvd1;
	u_int32_t	tss_rsvd2;
	u_int64_t	tss_ist1 __packed;	/* Interrupt stack table 1 */
	u_int64_t	tss_ist2 __packed;	/* Interrupt stack table 2 */
	u_int64_t	tss_ist3 __packed;	/* Interrupt stack table 3 */
	u_int64_t	tss_ist4 __packed;	/* Interrupt stack table 4 */
	u_int64_t	tss_ist5 __packed;	/* Interrupt stack table 5 */
	u_int64_t	tss_ist6 __packed;	/* Interrupt stack table 6 */
	u_int64_t	tss_ist7 __packed;	/* Interrupt stack table 7 */
	u_int32_t	tss_rsvd3;
	u_int32_t	tss_rsvd4;
	u_int16_t	tss_rsvd5;
	u_int16_t	tss_iobase;	/* io bitmap offset */
};


int main(int argc, char const *argv[])
{
    payload_args_t* args = payload_get_args();
    struct sysentvec sysentvec;
    // struct sysent* sv_table;
    // struct sysent kmalloc_syscall;

    // size_t alloc_size;
    uint8_t* sysentv_ptr = (uint8_t*) &sysentvec;

    dmap_copyout(args->kdata_base_addr + SYSENT_VEC_OFFSET, &sysentvec, sizeof(sysentvec));

        
    for (int i = 0; i < 20; ++i)
    {
        printf("%02x ", sysentv_ptr[i]);
    }

    // puts("");
    printf("sysentvec->sv_table = %p\nsysentvec->sv_size = %#02x\nsysentvec->sv_mask = %#02x\n", sysentvec.sv_table, sysentvec.sv_size, sysentvec.sv_mask);


    return 0;
}
