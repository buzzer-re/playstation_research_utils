#pragma once

#define _KERNEL
#include <sys/param.h>
#include <sys/conf.h>
#include <machine/specialreg.h>

uint64_t get_kernel_base();
void init_kernel(uint32_t fwver);


extern void(*kprintf)(char* fmt, ...);
extern struct cdev* (*kmake_dev)(struct	cdevsw	*cdevsw,  int  unit,  uid_t  uid,  gid_t  gid, int perms, const char *fmt, ...);
extern int (*kdestroy_dev)(struct cdev*);

