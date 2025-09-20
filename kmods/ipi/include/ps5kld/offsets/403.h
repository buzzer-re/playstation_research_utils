#pragma once

#define kernel_base_addr 0xFFFFFFFF80210000 

#define OFFSET(x) x - kernel_base_addr

#define Xfast_syscall 0x294218
#define kprintf_offset 0x28da78
#define apic_ops_offset OFFSET(0xFFFFFFFF81B44AC8)
#define cpu_apic_ids_offset OFFSET(0xFFFFFFFF83BCC870)
#define kcfi_check_offset OFFSET(0xFFFFFFFF8066A170)
#define justreturn_offset OFFSET(0xFFFFFFFF80440670)
#define lapic_eoi_offset OFFSET(0xFFFFFFFF804A43B8)
#define native_lapic_ipi_vectored_offset OFFSET(0xFFFFFFFF807667A0)
#define kernel_pmap_offset OFFSET(0xFFFFFFFF84067A78)