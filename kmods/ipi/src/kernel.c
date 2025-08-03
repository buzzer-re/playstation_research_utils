#include <ps5kld/kernel.h>
#include <ps5kld/offsets/500.h>

uint64_t kdata_address;
uint64_t kernel_base;
void (*kprintf)(char* fmt, ...) = NULL;
void (*kipi_selected)(cpuset_t mask, unsigned long ipi) = NULL;
void (*kipi_all_but_self)(unsigned long ipi_vector) = NULL;
uint64_t* kapic_ops = NULL;
int* cpu_apic_ids = NULL;
uint64_t justreturn = 0;


uint64_t get_kernel_base()
{
    return rdmsr(MSR_LSTAR) - Xfast_syscall;
}

void init_kernel(uint32_t fwver)
{
    kernel_base = get_kernel_base();
    kprintf = (void (*)(char *, ...)) kernel_base + kprintf_offset;
    kipi_selected = kernel_base + kipi_selected_offset;
    kipi_all_but_self = kernel_base + kipi_all_but_self_offset;
    kapic_ops = kernel_base + apic_ops_offset;
    cpu_apic_ids = kernel_base + cpu_apic_ids_offset;
    justreturn = kernel_base + justreturn_offset;
}

