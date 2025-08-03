#pragma once

#define _KERNEL
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/cpuset.h>
#include <machine/specialreg.h>
#include <stdint.h>

uint64_t get_kernel_base();
void init_kernel(uint32_t fwver);


extern void(*kprintf)(char* fmt, ...);
extern void(*kipi_selected)(cpuset_t mask, unsigned long ipi);
extern void(*kipi_all_but_self)(unsigned long ipi_vector);
extern uint64_t* kapic_ops;
extern int* cpu_apic_ids;
extern uint64_t justreturn;
