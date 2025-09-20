
#include <ps5kld/kernel.h>
#include <ps5kld/intrin.h>
#include <ps5kld/machine/idt.h>
#include <ps5kld/offsets/500.h>
#include <ps5kld/trap.h>
#include <sys/cpuset.h>

#define	APIC_LOCAL_INTS	240
#define	APIC_ERROR_INT	APIC_LOCAL_INTS
#define	APIC_THERMAL_INT (APIC_LOCAL_INTS + 1)
#define	APIC_CMC_INT	(APIC_LOCAL_INTS + 2)
#define	APIC_IPI_INTS	(APIC_LOCAL_INTS + 3)

#define	IPI_RENDEZVOUS	(APIC_IPI_INTS)		/* Inter-CPU rendezvous. */
#define	IPI_INVLTLB	(APIC_IPI_INTS + 1)	/* TLB Shootdown IPIs */
#define	IPI_INVLPG	(APIC_IPI_INTS + 2)
#define	IPI_INVLRNG	(APIC_IPI_INTS + 3)
#define	IPI_INVLCACHE	(APIC_IPI_INTS + 4)

extern void memcpy(uint64_t* dst, uint64_t* src, uint32_t size);
extern uint64_t int_handler();
extern uint64_t ipi_int_handler();


typedef struct __kproc_args
{
    uint64_t kdata_base;
    uint32_t fwver;
} kproc_args;


void handle_ipi_request(void* tf)
{

    // //
    // // Set dr1 to 0x1337 to verify
    // //
    // __writedr1(kfci_check);
    // __writedr7(0x401);
    int* p = NULL;
    *p = 10;
    __writemsr(0x80B, 0); // EOI
}


int kcfi_check_hook()
{
    return 0;
}

void handle_int(trap_frame_t* tf)
{
    kprintf("Int (%#02lx), cfi_check\n", tf->rip);
    // tf->rip = kcfi_check_hook;
}

#define IPI_VECTOR_ENTRY 0xF1


uint64_t get_dmem()
{
    return kernel_pmap->pm_pml4 - kernel_pmap->pm_cr3;
}


int module_start(kproc_args* args)
{    

    init_kernel(args->fwver);
    uint32_t apic_mask = 0;
    uint64_t dmem = get_dmem();
    uint64_t apic_base_addr = __readmsr(0x1B);
    volatile uint32_t* apic = dmem + apic_base_addr;
    apic_base_addr &= -4096;
    
    
    kprintf("Kernel base: %#02lx\n", get_kernel_base());
    kprintf("apic base addr: %#02lx\n", apic_base_addr);
    kprintf("dmem: %#02lx\n", dmem);

    
    kprintf("apic registers: %#02lx\n", apic);

    kprintf("read register: %x\n", apic[0xC0]);
    
    uint8_t idt[10];
    __sidt(&idt);
    
    idt_64* entry = ((IDTR*) idt)->base;
    idt_64* apic_init = &entry[APIC_LOCAL_INTS];
    idt_64* int1 = &entry[1];
    uint64_t handler = ipi_int_handler;
    memcpy(apic_init, int1, sizeof(idt_64));

    apic_init->offset_low    = handler & 0xFFFF;          
    apic_init->offset_middle = (handler >> 16) & 0xFFFF;
    apic_init->offset_high   = (handler >> 32) & 0xFFFFFFFF;

    // handler = int_handler;
    // int1->offset_low    = handler & 0xFFFF;          
    // int1->offset_middle = (handler >> 16) & 0xFFFF;
    // int1->offset_high   = (handler >> 32) & 0xFFFFFFFF;

    int cpuid = PCPU_GET(cpuid);
    kprintf("Sending IPI...\n");
    for (int i = 0; i < 16; ++i)
    {
        if (i != cpuid)
        {
            // Check the 
            // kprintf("Writing at apic registers (%x:%x)\n", apic[192], apic[196]);
            while ((apic[192] & 4096));
            
            // kprintf("Now pic registers (%x:%x)\n", apic[192], apic[196]);
            apic[196] = i << 24;
            apic[192] = 0x4001;
            // kprintf("Done\n");
        }
    }

    kprintf("Done\n");

    return 1;
}
