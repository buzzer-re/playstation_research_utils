#include <ps5kld/kernel.h>
#include <ps5kld/offsets/403.h>

uint64_t kdata_address;
uint64_t kernel_base;
void (*kprintf)(char* fmt, ...) = NULL;
int (*kdestroy_dev)(struct cdev*) = NULL;
int (*kcfi_check)(uint64_t, int a2);
void (*ksmp_rendezvous)( void (*a1)(uint64_t), void (*a2)(uint64_t), uint64_t a3, uint64_t a4) = NULL;

uint64_t get_kernel_base()
{
    return rdmsr(MSR_LSTAR) - Xfast_syscall;
}

void init_kernel(uint32_t fwver)
{
    kernel_base = get_kernel_base();
    kprintf = kernel_base + kprintf_offset;
    kcfi_check = kernel_base + kcfi_check_offset;
    ksmp_rendezvous = kernel_base + smp_rendezvous_offset; 
}

