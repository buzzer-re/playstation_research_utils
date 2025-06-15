#include <ps5kld/kernel.h>
#include <ps5kld/firmware/500.h>

uint64_t kdata_address;
uint64_t kernel_base;
void (*kprintf)(char* fmt, ...) = NULL;
struct cdev* (*kmake_dev)(struct cdevsw	*cdevsw,  int  unit,  uid_t  uid,  gid_t  gid, int perms, const char *fmt, ...) = NULL;
int (*kdestroy_dev)(struct cdev*) = NULL;

uint64_t get_kernel_base()
{
    return rdmsr(MSR_LSTAR) - Xfast_syscall;
}

void init_kernel(uint32_t fwver)
{
    kernel_base = get_kernel_base();
    kprintf = kernel_base + kprintf_offset;
    kmake_dev = kernel_base + make_dev_offset;
    kdestroy_dev = kernel_base + destroy_dev_offset;
}

