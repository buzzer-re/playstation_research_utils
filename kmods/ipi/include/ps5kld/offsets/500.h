#pragma once

#define kernel_base_addr 0xFFFFFFFF80210000 

#define OFFSET(x) x - kernel_base_addr

#define kprintf_offset OFFSET(0xFFFFFFFF804A74B0)
#define apic_ops_offset OFFSET(0xFFFFFFFF81C74130)
#define cpu_apic_ids_offset OFFSET(0xFFFFFFFF83D338C0)
#define kcfi_check_offset OFFSET(0xFFFFFFFF80677FB0)
#define Xfast_syscall 0x29d310
#define justreturn_offset OFFSET(0xFFFFFFFF8044AE40)
#define lapic_eoi_offset OFFSET(0xFFFFFFFF804AD1C0)
#define kernel_pmap_offset OFFSET(0xFFFFFFFF841E8A88)
