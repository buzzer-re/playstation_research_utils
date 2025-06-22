
#include <ps5kld/kernel.h>
#include <ps5kld/intrin.h>
#include <ps5kld/machine/idt.h>
#include <ps5kld/offsets/403.h>
#define _KERNEL
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <machine/cpufunc.h>
#include <sys/kthread.h>
#include <sys/pcpu.h>
#include <sys/cpuset.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <machine/specialreg.h>
#include "../include/trap.h"

typedef struct __kproc_args
{
    uint64_t kdata_base;
    uint32_t fwver;
} kproc_args;



int handle_int(trap_frame_t* frame)
{
    uint64_t kernel_base = get_kernel_base();
    kprintf("\n\n\nTRAP: Debug trap captured\nInfo:\n\n");

    kprintf("RIP: %#02lx\n", frame->rip);
    kprintf("RSP: %#02lx\n", frame->rsp);
    kprintf("Kernel Base: %#02lx\n", kernel_base);
    kprintf("Offset: %#02lx\n", frame->rip - kernel_base);
    kprintf("Resuming");

    // stepping out
    frame->rip = (uint64_t) (*(uint64_t*)frame->rsp);
    frame->rsp += 8;
   // while (1);
    return 0;
}

extern int int_handler();

void list_dr()
{
    uint64_t dr0 = __readdr0();

    // uint32_t cpu;
    // // CPU_FOREACH(cpu)
    // uint64_t cpuid = PCPU_GET(cpuid);
    // kprintf("Running on CPU %d\n", cpuid);
    kprintf("DR0: %lx\nDR1: %lx\nDR2: %lx\nDR3: %lx\nDR6: %lx\nDR7: %lx\n", 
        __readdr0(),
        __readdr1(),
        __readdr2(),
        __readdr3(),
        __readdr6(),
        __readdr7()
    );
}

int module_start(kproc_args* args)
{    
    init_kernel(args->fwver);
    kprintf("Kernel base: %#02lx\n", get_kernel_base());

    //
    // Acquire IDT address
    //
    uint8_t idt[10];
    __sidt(&idt);
    IDTR* idtr = (IDTR*) idt;

    // //
    // // Extract the necessary entry
    // //

    idt_64* entry = (idt_64*) idtr->base;
    idt_64* soft_bp = &entry[1]; // Trap 3 - Software Breakpoint

    kprintf("idt base: %#02llx\n", idtr->base);
    kprintf("int1 gate: %p\nOffset: %#02lx\n", UNPACK_HANDLER_ADDR(soft_bp), (UNPACK_HANDLER_ADDR(soft_bp)) - get_kernel_base());

    //
    // Swap the current gate to a custom one
    //
    uint64_t gate = (uint64_t) int_handler; // generic handler, that will  call `handle_int` (see int.s)
    soft_bp->offset_low     = (gate & 0xFFFF);
    soft_bp->offset_middle  = (gate >> 16 ) & 0xFFFF;
    soft_bp->offset_high    = (gate >> 32 ) & 0xFFFFFFFF;
    //
    // Testing 
    //
    // __asm__("int3");
    
    
    kprintf("ksmp_rendezvous is at %llx\n", ksmp_rendezvous);
    
    // // run_on_all_cores(hook_kcfi_check);
    kprintf("kcfi_check_offset: %#02lx\n", kcfi_check_offset);
    // kprintf("DR0: %lx\nDR7: %lx\n", get_kernel_base + kcfi_check_offset, __readdr7());
    // __writedr7(0x400);
    __writedr0(kcfi_check); // BELOW
    __writedr7(0x401); /// PIN ON EVERY CPU BEFORE DO THAT
    // ksmp_rendezvous(NULL, list_dr, NULL, NULL);
    uint64_t cpuid = PCPU_GET(cpuid);
    kprintf("int1 configured on cpu %d\n", cpuid);
    kcfi_check(0, 0);

    kprintf("goodbye\n");
    return 1;
}
