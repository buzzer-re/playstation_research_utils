
#include <ps5kld/kernel.h>
#include <ps5kld/intrin.h>
#include <ps5kld/machine/idt.h>
#define _KERNEL
#include <sys/param.h>
#include <sys/conf.h>
#include "../include/trap.h"

typedef struct __kproc_args
{
    uint64_t kdata_base;
    uint32_t fwver;
} kproc_args;



int handle_int(trap_frame_t* frame)
{
    uint64_t kernel_base = get_kernel_base();
    kprintf("\n\n\nTRAP: Software breakpoint captured\nInfo:\n\n");

    kprintf("RIP: %#02lx\n", frame->rip);
    kprintf("RSP: %#02lx\n", frame->rsp);
    kprintf("Kernel Base: %#02lx\n", kernel_base);
    kprintf("Offset: %#02lx\n", frame->rip - kernel_base);
    kprintf("Resuming");

    return 0;
}

extern int int_handler();


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

    //
    // Extract the necessary entry
    //

    idt_64* entry = (idt_64*) idtr->base;
    idt_64* soft_bp = &entry[3]; // Trap 3 - Software Breakpoint

    kprintf("idt base: %#02llx\n", idtr->base);
    kprintf("int3 gate: %p\n", UNPACK_HANDLER_ADDR(soft_bp));

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

    __asm__("int3");
   

    //
    kprintf("IDT gate 3 (soft breakpoint) is now hooked\n");
    //
    return 1;
}
