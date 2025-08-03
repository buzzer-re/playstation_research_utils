#pragma once

#define kernel_base_addr 0xFFFFFFFF80210000 

#define OFFSET(x) x - kernel_base_addr

#define kprintf_offset OFFSET(0xFFFFFFFF804A74B0)
#define kipi_selected_offset OFFSET(0xFFFFFFFF809E10B0)
#define kipi_all_but_self_offset OFFSET(0xFFFFFFFF809E1290)
#define apic_ops_offset OFFSET(0xFFFFFFFF81C74130)
#define cpu_apic_ids_offset OFFSET(0xFFFFFFFF83D338C0)
#define Xfast_syscall 0x29d310
#define justreturn_offset OFFSET(0xFFFFFFFF8044AE40)