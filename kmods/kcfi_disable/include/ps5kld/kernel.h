#pragma once

#define _KERNEL
#include <sys/param.h>
#include <sys/conf.h>
#include <machine/specialreg.h>
#include <stdint.h>

uint64_t get_kernel_base();
void init_kernel(uint32_t fwver);


extern void(*kprintf)(char* fmt, ...);
extern struct cdev* (*kmake_dev)(struct	cdevsw	*cdevsw,  int  unit,  uid_t  uid,  gid_t  gid, int perms, const char *fmt, ...);
extern int (*kdestroy_dev)(struct cdev*);
extern int (*kcfi_check)(uint64_t, int);
extern void (*ksmp_rendezvous)( void (*a1)(uint64_t), void (*a2)(uint64_t), uint64_t a3, uint64_t a4);
