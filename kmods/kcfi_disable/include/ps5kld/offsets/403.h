#pragma once

#define kernel_base_addr 0xFFFFFFFF80210000 

#define OFFSET(x) x - kernel_base_addr

#define Xfast_syscall 0x294218
#define kprintf_offset 0x28da78
#define kcfi_check_offset OFFSET(0xFFFFFFFF8066A170)
#define smp_rendezvous_offset OFFSET(0xFFFFFFFF80C7CA00)

