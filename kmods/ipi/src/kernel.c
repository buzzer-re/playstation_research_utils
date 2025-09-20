#include <ps5kld/kernel.h>
#include <ps5kld/offsets/500.h>

uint64_t kdata_address;
uint64_t kernel_base;
void (*kprintf)(char* fmt, ...) = NULL;
void(*lapic_eoi)() = NULL;
void(*native_lapic_ipi_vectored)(uint32_t vector, int dest) = NULL;
void(*kfci_check)() = NULL;
uint64_t* kapic_ops = NULL;
int* cpu_apic_ids = NULL;
uint64_t justreturn = 0;
struct flat_pmap* kernel_pmap = 0;

uint64_t get_kernel_base()
{
    return rdmsr(MSR_LSTAR) - Xfast_syscall;
}

void init_kernel(uint32_t fwver)
{
    kernel_base = get_kernel_base();
    kprintf = (void (*)(char *, ...)) kernel_base + kprintf_offset;
    kapic_ops = kernel_base + apic_ops_offset;
    cpu_apic_ids = kernel_base + cpu_apic_ids_offset;
    justreturn = kernel_base + justreturn_offset;
    lapic_eoi = kernel_base + lapic_eoi_offset;
    // native_lapic_ipi_vectored = kernel_base + native_lapic_ipi_vectored_offset;
    kernel_pmap = kernel_base + kernel_pmap_offset;
    kfci_check = kernel_base + kcfi_check_offset;
}

