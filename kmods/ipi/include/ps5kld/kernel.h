#pragma once

#define _KERNEL
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/cpuset.h>
#include <machine/specialreg.h>
#include <stdint.h>


struct flat_pmap {                                                                                                   
    uint64_t mtx_name_ptr;
    uint64_t mtx_flags;
    uint64_t mtx_data;
    uint64_t mtx_lock;
    uint64_t pm_pml4;
    uint64_t pm_cr3;
}; 

uint64_t get_kernel_base();
void init_kernel(uint32_t fwver);


extern void(*kprintf)(char* fmt, ...);
extern void(*kipi_selected)(cpuset_t mask, unsigned long ipi);
extern void(*kipi_all_but_self)(unsigned long ipi_vector);
extern void(*lapic_eoi)();
extern void(*native_lapic_ipi_vectored)(uint32_t vector, int dest);
extern void(*kfci_check)();

extern uint64_t* kapic_ops;
extern int* cpu_apic_ids;
extern uint64_t justreturn;
extern struct flat_pmap* kernel_pmap;