#include "r0gdb.h"
#include "offsets.h"

extern void* (*kernel_dynlib_dlsym)(int pid, unsigned int handle, const char* sym);
extern int (*f_usleep)(unsigned int usec);
extern int (*printf)(const char* fmt, ...);

#define sleepy_printf(fmt, ...) do { /*printf(fmt, ##__VA_ARGS__); f_usleep(100* 1000);*/ } while(0)


struct offset_table offsets;
extern uint64_t kdata_base;

#define OFFSET(x) offsets.x = kdata_base + x;
#define DEF(x, y) enum { x = (y) + 0 * sizeof(offsets.x) };

#define START_FW(fw) void set_offsets_ ## fw(void) {
#define END_FW() }

START_FW(250)
DEF(allproc, 0x2701c28) //data 0x4281C28
DEF(idt, 0x63acad0) //data 0x7F2CAD0
DEF(gdt_array, 0x63adc70) //data 0x7F2DC70
DEF(tss_array, 0x63af670) //data 0x7F2F670
DEF(pcpu_array, 0x63b1080) //data 0x7F31080
DEF(doreti_iret, -0x1976e6c) //data 0x209194
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x193779a) //data 0x248866
DEF(rdmsr_start, -0x197831a) //data 0x207CE6
DEF(wrmsr_ret, -0x19796ec) //data 0x206914
DEF(dr2gpr_start, -0x197e052) //data 0x201FAE
DEF(gpr2dr_1_start, -0x197dfdc) //data 0x202024
DEF(gpr2dr_2_start, -0x197dfbd) //data 0x202043
DEF(mov_cr3_rax, -0x137a662) //data 0x80599E
DEF(mov_rdi_cr3, -0x137a6d2) //data 0x80592E
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0x197e240) //data 0x201DC0
DEF(mprotect_fix_start, -0x18b7251) //data 0x2C8DAF
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x11d951d) //data 0x9A6AE3
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x12bc7dd) //data 0x8C3823
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x1689fac) //data 0x4F6054
DEF(sigaction_fix_end, -0x1689f60) //data 0x4F60A0
DEF(sysents, 0x166e00) //data 0x1CE6E00
DEF(sysents_ps4, 0x15e5e0) //data 0x1CDE5E0
DEF(sysentvec, 0xc40458) //data 0x27C0458
DEF(sysentvec_ps4, 0xc405d0) //data 0x27C05D0
DEF(sceSblServiceMailbox, -0x164bde0) //data 0x534220
DEF(sceSblAuthMgrSmIsLoadable2, -0x18540a0) //data 0x32BF60
DEF(mdbg_call_fix, -0x15ff8bd) //data 0x580743
DEF(syscall_before, -0x17b7e5f) //data 0x3C81A1
DEF(syscall_after, -0x17b7e3c) //data 0x3C81C4
DEF(malloc, -0x10adf60) //data 0xAD20A0
DEF(M_something, 0x1273630) //data 0x2DF3630
DEF(loadSelfSegment_epilogue, -0x1853852) //data 0x32C7AE
DEF(loadSelfSegment_watchpoint, -0x12bbdd8) //data 0x8C4228
DEF(loadSelfSegment_watchpoint_lr, -0x1853ab7) //data 0x32C549
DEF(decryptSelfBlock_watchpoint_lr, -0x185371a) //data 0x32C8E6
DEF(decryptSelfBlock_epilogue, -0x185365c) //data 0x32C9A4
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x1853205) //data 0x32CDFB
DEF(decryptMultipleSelfBlocks_epilogue, -0x1852d7c) //data 0x32D284
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x1853ce1) //data 0x32C31F
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x18538c6) //data 0x32C73A
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x18533dc) //data 0x32CC24
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x1852e36) //data 0x32CC24
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x185410e) //data 0x32BEF2
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x18f60c5) //data 0x289F3B
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x18f669c) //data 0x289964
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x18f6630) //data 0x2899D0
DEF(sceSblPfsSetKeys, -0x18f63a0) //data 0x289C60
DEF(sceSblServiceCryptAsync, -0x189a970) //data 0x2E5690
DEF(sceSblServiceCryptAsync_deref_singleton, -0x189a932) //data 0x2E56CE
DEF(copyin, -0x1937f30) //data 0x2480D0
DEF(copyout, -0x1937fd0) //data 0x248030
DEF(crypt_message_resolve, -0x1459840) //data 0x7267C0
DEF(justreturn, -0x1976fb0) //data 0x209050
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xcee628) //data 0x286E628
DEF(pop_all_iret, -0x1976ecb) //data 0x209135
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x1917aa8) //data 0x268558
DEF(kernel_pmap_store, 0x31338c8) //data 0x4CB38C8
DEF(crypt_singleton_array, 0x2d12390) //data 0x4892390
DEF(security_flags, 0x63e1274) //data 0x7F61274
DEF(targetid, 0x63e127d) //data 0x7F6127D
DEF(qa_flags, 0x63e1298) //data 0x7F61298
DEF(utoken, 0x63e1300) //data 0x7F61300
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(300)
DEF(allproc, 0x276dc58)
DEF(idt, 0x642dc80)
DEF(gdt_array, 0x642ee20)
DEF(tss_array, 0x6430820)
DEF(pcpu_array, 0x6432280)
DEF(doreti_iret, -0x9aefbc)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x96f79a)
DEF(rdmsr_start, -0x9b046a)
DEF(wrmsr_ret, -0x9b183c)
DEF(dr2gpr_start, -0x9b6513)
DEF(gpr2dr_1_start, -0x9b63fa)
DEF(gpr2dr_2_start, -0x9b6307)
DEF(mov_cr3_rax, -0x39099e)
DEF(mov_rdi_cr3, -0x390a0e)
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0x9b6700)
DEF(mprotect_fix_start, -0x8ee651)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2c92bd)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1dd21e)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6b549f)
DEF(sigaction_fix_end, -0x6b5449)
DEF(sysents, 0x16f720)
DEF(sysents_ps4, 0x167170)
DEF(sysentvec, 0xca0cd8)
DEF(sysentvec_ps4, 0xca0e50)
DEF(sceSblServiceMailbox, -0x675df0)
DEF(sceSblAuthMgrSmIsLoadable2, -0x88a540)
DEF(mdbg_call_fix, -0x626d49)
DEF(syscall_before, -0x7e91bf)
DEF(syscall_after, -0x7e919c)
DEF(malloc, -0xaa2a0)
DEF(M_something, 0x12d3d70)
DEF(loadSelfSegment_epilogue, -0x889e0d)
DEF(loadSelfSegment_watchpoint, -0x2c88a8)
DEF(loadSelfSegment_watchpoint_lr, -0x88a067)
DEF(decryptSelfBlock_watchpoint_lr, -0x889cca)
DEF(decryptSelfBlock_epilogue, -0x889c03)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x889595)
DEF(decryptMultipleSelfBlocks_epilogue, -0x889112)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x88a1bc)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x889e81)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x889954)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8891cc)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x88a5be)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x92d9b0)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x92df7b)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x92df05)
DEF(sceSblPfsSetKeys, -0x92dc60)
DEF(sceSblServiceCryptAsync, -0x8d1e30)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8d1df2)
DEF(copyin, -0x970050)
DEF(copyout, -0x970100)
DEF(crypt_message_resolve, -0x475790)
DEF(justreturn, -0x9af100)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xd4fe88)
DEF(pop_all_iret, -0x9af01b)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x94f570)
DEF(kernel_pmap_store, 0x31be218)
DEF(crypt_singleton_array, 0x2d99830)
DEF(security_flags, 0x6466474)
DEF(targetid, 0x646647d)
DEF(qa_flags, 0x6466498)
DEF(utoken, 0x6466500)
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(310)
DEF(allproc, 0x276dc58)
DEF(idt, 0x642dc80)
DEF(gdt_array, 0x642ee20)
DEF(tss_array, 0x6430820)
DEF(pcpu_array, 0x6432280)
DEF(doreti_iret, -0x9aefbc)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x96f79a)
DEF(rdmsr_start, -0x9b046a)
DEF(wrmsr_ret, -0x9b183c)
DEF(dr2gpr_start, -0x9b6513)
DEF(gpr2dr_1_start, -0x9b63fa)
DEF(gpr2dr_2_start, -0x9b6307)
DEF(mov_cr3_rax, -0x39095e)
DEF(mov_rdi_cr3, -0x3909ce)
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0x9b6700)
DEF(mprotect_fix_start, -0x8ee651)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2c927d)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1dd1de)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6b545f)
DEF(sigaction_fix_end, -0x6b5409)
DEF(sysents, 0x16f720)
DEF(sysents_ps4, 0x167170)
DEF(sysentvec, 0xca0cd8)
DEF(sysentvec_ps4, 0xca0e50)
DEF(sceSblServiceMailbox, -0x675db0)
DEF(sceSblAuthMgrSmIsLoadable2, -0x88a540)
DEF(mdbg_call_fix, -0x626d09)
DEF(syscall_before, -0x7e917f)
DEF(syscall_after, -0x7e915c)
DEF(malloc, -0xaa260)
DEF(M_something, 0x12d3d70)
DEF(loadSelfSegment_epilogue, -0x889dcd)
DEF(loadSelfSegment_watchpoint, -0x2c8868)
DEF(loadSelfSegment_watchpoint_lr, -0x88a027)
DEF(decryptSelfBlock_watchpoint_lr, -0x889c8a)
DEF(decryptSelfBlock_epilogue, -0x889bc3)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x889555)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8890d2)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x88a1bc)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x889e41)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x889914)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x88918c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x88a5be)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x92d9b0)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x92df7b)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x92df05)
DEF(sceSblPfsSetKeys, -0x92dc60)
DEF(sceSblServiceCryptAsync, -0x8d1e30)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8d1df2)
DEF(copyin, -0x970050)
DEF(copyout, -0x970100)
DEF(crypt_message_resolve, -0x475750)
DEF(justreturn, -0x9af100)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xd4fe88)
DEF(pop_all_iret, -0x9af01b)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x94f6b8)
DEF(kernel_pmap_store, 0x31be218)
DEF(crypt_singleton_array, 0x2d99830)
DEF(security_flags, 0x6466474)
DEF(targetid, 0x646647d)
DEF(qa_flags, 0x6466490)
DEF(utoken, 0x6466500)
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(320)
DEF(allproc, 0x276dc58)
DEF(idt, 0x642dc80)
DEF(gdt_array, 0x642ee20)
DEF(tss_array, 0x6430820)
DEF(pcpu_array, 0x6432280)
DEF(doreti_iret, -0x9aec7c)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x96f45a)
DEF(rdmsr_start, -0x9b012a)
DEF(wrmsr_ret, -0x9b14fc)
DEF(dr2gpr_start, -0x9b61d3)
DEF(gpr2dr_1_start, -0x9b60ba)
DEF(gpr2dr_2_start, -0x9b5fc7)
DEF(mov_cr3_rax, -0x39060e)
DEF(mov_rdi_cr3, -0x39067e)
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0x9b63c0)
DEF(mprotect_fix_start, -0x8ee311)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2c8f2d)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1dcd1e)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6b510f)
DEF(sigaction_fix_end, -0x6b50b9)
DEF(sysents, 0x16f720)
DEF(sysents_ps4, 0x167170)
DEF(sysentvec, 0xca0cd8)
DEF(sysentvec_ps4, 0xca0e50)
DEF(sceSblServiceMailbox, -0x675a60)
DEF(sceSblAuthMgrSmIsLoadable2, -0x88a200)
DEF(mdbg_call_fix, -0x6269b9)
DEF(syscall_before, -0x7e8e2f)
DEF(syscall_after, -0x7e8e0c)
DEF(malloc, -0xa9da0)
DEF(M_something, 0x12d3d70)
DEF(loadSelfSegment_epilogue, -0x889a7d)
DEF(loadSelfSegment_watchpoint, -0x2c8518)
DEF(loadSelfSegment_watchpoint_lr, -0x889cd7)
DEF(decryptSelfBlock_watchpoint_lr, -0x88993a)
DEF(decryptSelfBlock_epilogue, -0x889873)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x889205)
DEF(decryptMultipleSelfBlocks_epilogue, -0x888d82)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x889e7c)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x889af1)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8895c4)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x888e3c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x88a27e)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x92d670)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x92dc3b)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x92dbc5)
DEF(sceSblPfsSetKeys, -0x92d920)
DEF(sceSblServiceCryptAsync, -0x8d1af0)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8d1ab2)
DEF(copyin, -0x96fd10)
DEF(copyout, -0x96fdc0)
DEF(crypt_message_resolve, -0x475400)
DEF(justreturn, -0x9aedc0)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xd4fe88)
DEF(pop_all_iret, -0x9aecdb)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x94e7d0)
DEF(kernel_pmap_store, 0x31be218)
DEF(crypt_singleton_array, 0x2d99830)
DEF(security_flags, 0x6466474)
DEF(targetid, 0x646647d)
DEF(qa_flags, 0x6466498)
DEF(utoken, 0x6466500)
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(321)
DEF(allproc, 0x276dc58)
DEF(idt, 0x642dc80)
DEF(gdt_array, 0x642ee20)
DEF(tss_array, 0x6430820)
DEF(pcpu_array, 0x6432280)
DEF(doreti_iret, -0x9aec7c)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x96f45a)
DEF(rdmsr_start, -0x9b012a)
DEF(wrmsr_ret, -0x9b14fc)
DEF(dr2gpr_start, -0x9b61d3)
DEF(gpr2dr_1_start, -0x9b60ba)
DEF(gpr2dr_2_start, -0x9b5fc7)
DEF(mov_cr3_rax, -0x39060e)
DEF(mov_rdi_cr3, -0x39067e)
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0x9b63c0)
DEF(mprotect_fix_start, -0x8ee311)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2c8f2d)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1dcd1e)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6b510f)
DEF(sigaction_fix_end, -0x6b50b9)
DEF(sysents, 0x16f720)
DEF(sysents_ps4, 0x167170)
DEF(sysentvec, 0xca0cd8)
DEF(sysentvec_ps4, 0xca0e50)
DEF(sceSblServiceMailbox, -0x675a60)
DEF(sceSblAuthMgrSmIsLoadable2, -0x88a200)
DEF(mdbg_call_fix, -0x6269b9)
DEF(syscall_before, -0x7e8e2f)
DEF(syscall_after, -0x7e8e0c)
DEF(malloc, -0xa9da0)
DEF(M_something, 0x12d3d70)
DEF(loadSelfSegment_epilogue, -0x889a7d)
DEF(loadSelfSegment_watchpoint, -0x2c8518)
DEF(loadSelfSegment_watchpoint_lr, -0x889cd7)
DEF(decryptSelfBlock_watchpoint_lr, -0x88993a)
DEF(decryptSelfBlock_epilogue, -0x889873)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x889205)
DEF(decryptMultipleSelfBlocks_epilogue, -0x888d82)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x889e7c)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x889af1)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8895c4)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x888e3c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x88a27e)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x92d670)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x92dc3b)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x92dbc5)
DEF(sceSblPfsSetKeys, -0x92d920)
DEF(sceSblServiceCryptAsync, -0x8d1af0)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8d1ab2)
DEF(copyin, -0x96fd10)
DEF(copyout, -0x96fdc0)
DEF(crypt_message_resolve, -0x475400)
DEF(justreturn, -0x9aedc0)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xd4fe88)
DEF(pop_all_iret, -0x9aecdb)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x94e4d0)
DEF(kernel_pmap_store, 0x31be218)
DEF(crypt_singleton_array, 0x2d99830)
DEF(security_flags, 0x6466474)
DEF(targetid, 0x646647d)
DEF(qa_flags, 0x6466498)
DEF(utoken, 0x6466500)
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(400)
DEF(allproc, 0x27edcb8)
DEF(idt, 0x64cdc80)
DEF(gdt_array, 0x64cee30)
DEF(tss_array, 0x64d0830)
DEF(pcpu_array, 0x64d2280)
DEF(doreti_iret, -0x9cf84c)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x99002a)
DEF(rdmsr_start, -0x9d0cfa)
DEF(wrmsr_ret, -0x9d20cc)
DEF(dr2gpr_start, -0x9d6d93)
DEF(gpr2dr_1_start, -0x9d6c7a)
DEF(gpr2dr_2_start, -0x9d6b87)
DEF(mov_cr3_rax, -0x39707e)
DEF(mov_rdi_cr3, -0x3970ee)
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0x9d6f80)
DEF(mprotect_fix_start, -0x90ac61)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2cd3fd)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1df3ae)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6c2989)
DEF(sigaction_fix_end, -0x6c2933)
DEF(sysents, 0x1709c0)
DEF(sysents_ps4, 0x168410)
DEF(sysentvec, 0xd11bb8)
DEF(sysentvec_ps4, 0xd11d30)
DEF(sceSblServiceMailbox, -0x6824c0)
DEF(sceSblAuthMgrSmIsLoadable2, -0x8a5c40)
DEF(mdbg_call_fix, -0x631eb9)
DEF(syscall_before, -0x802311)
DEF(syscall_after, -0x8022ee)
DEF(malloc, -0xa9be0)
DEF(M_something, 0x1346080)
DEF(loadSelfSegment_epilogue, -0x8a54cd)
DEF(loadSelfSegment_watchpoint, -0x2cc9f8)
DEF(loadSelfSegment_watchpoint_lr, -0x8a5727)
DEF(decryptSelfBlock_watchpoint_lr, -0x8a538a)
DEF(decryptSelfBlock_epilogue, -0x8a52c3)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8a4c55)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8a47d2)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8a58bc)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8a5541)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8a5014)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8a488c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8a5cbe)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x94a7f0)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x94ada4)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x94ad2e)
DEF(sceSblPfsSetKeys, -0x94aaa0)
DEF(sceSblServiceCryptAsync, -0x8ed940)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8ed902)
DEF(copyin, -0x9908e0)
DEF(copyout, -0x990990)
DEF(crypt_message_resolve, -0x479e40)
DEF(justreturn, -0x9cf990)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xdc16e8)
DEF(pop_all_iret, -0x9cf8ab)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x96bc30)
DEF(kernel_pmap_store, 0x3257a78)
DEF(crypt_singleton_array, 0x2e31830)
DEF(security_flags, 0x6506474)
DEF(targetid, 0x650647d)
DEF(qa_flags, 0x6506498)
DEF(utoken, 0x6506500)
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(402)
DEF(allproc, 0x27edcb8)
DEF(idt, 0x64cdc80)
DEF(gdt_array, 0x64cee30)
DEF(tss_array, 0x64d0830)
DEF(pcpu_array, 0x64d2280)
DEF(doreti_iret, -0x9cf84c)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x99002a)
DEF(rdmsr_start, -0x9d0cfa)
DEF(wrmsr_ret, -0x9d20cc)
DEF(dr2gpr_start, -0x9d6d93)
DEF(gpr2dr_1_start, -0x9d6c7a)
DEF(gpr2dr_2_start, -0x9d6b87)
DEF(mov_cr3_rax, -0x39702e)
DEF(mov_rdi_cr3, -0x39709e)
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0x9d6f80)
DEF(mprotect_fix_start, -0x90ac61)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2cd3ad)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1df35e)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6c2989)
DEF(sigaction_fix_end, -0x6c2933)
DEF(sysents, 0x1709c0)
DEF(sysents_ps4, 0x168410)
DEF(sysentvec, 0xd11bb8)
DEF(sysentvec_ps4, 0xd11d30)
DEF(sceSblServiceMailbox, -0x6824c0)
DEF(sceSblAuthMgrSmIsLoadable2, -0x8a5c40)
DEF(mdbg_call_fix, -0x631e99)
DEF(syscall_before, -0x802311)
DEF(syscall_after, -0x8022ee)
DEF(malloc, -0xa9b90)
DEF(M_something, 0x1346080)
DEF(loadSelfSegment_epilogue, -0x8a54cd)
DEF(loadSelfSegment_watchpoint, -0x2cc9a8)
DEF(loadSelfSegment_watchpoint_lr, -0x8a5727)
DEF(decryptSelfBlock_watchpoint_lr, -0x8a538a)
DEF(decryptSelfBlock_epilogue, -0x8a52c3)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8a4c55)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8a47d2)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8a58bc)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8a5541)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8a5014)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8a488c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8a5cbe)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x94a7f0)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x94ada4)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x94ad2e)
DEF(sceSblPfsSetKeys, -0x94aaa0)
DEF(sceSblServiceCryptAsync, -0x8ed940)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8ed902)
DEF(copyin, -0x9908e0)
DEF(copyout, -0x990990)
DEF(crypt_message_resolve, -0x479df0)
DEF(justreturn, -0x9cf990)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xdc16e8)
DEF(pop_all_iret, -0x9cf8ab)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x96d208)
DEF(kernel_pmap_store, 0x3257a78)
DEF(crypt_singleton_array, 0x2e31830)
DEF(security_flags, 0x6505474)
DEF(targetid, 0x650547d)
DEF(qa_flags, 0x6505498)
DEF(utoken, 0x6505500)
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(403)
DEF(allproc, 0x27edcb8)
DEF(idt, 0x64cdc80)
DEF(gdt_array, 0x64cee30)
DEF(tss_array, 0x64d0830)
DEF(pcpu_array, 0x64d2280)
DEF(doreti_iret, -0x9cf84c)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x99002a /*-0x990a55*/)
DEF(rdmsr_start, -0x9d0cfa /*-0x9d6d02*/)
//DEF(rdmsr_end, -0x9d6cf9)
DEF(wrmsr_ret, -0x9d20cc)
DEF(dr2gpr_start, -0x9d6d93)
//DEF(dr2gpr_end, -0x9d6d7c)
DEF(gpr2dr_1_start, -0x9d6c7a)
//DEF(gpr2dr_1_end, -0x9d6c55)
DEF(gpr2dr_2_start, -0x9d6b87)
//DEF(gpr2dr_2_end, -0x9d6de9)
DEF(mov_cr3_rax, -0x396f9e)
DEF(mov_rdi_cr3, -0x39700e)
DEF(nop_ret, wrmsr_ret + 2 /*-0x28a3a0*/)
DEF(cpu_switch, -0x9d6f80)
DEF(mprotect_fix_start, -0x90ac61)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2cd31d)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1df2ce)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, -0x85a312)
DEF(aslr_fix_end, -0x85a2d2)

DEF(sigaction_fix_start, -0x6c2989)
DEF(sigaction_fix_end, -0x6c2933)
DEF(sysents, 0x1709c0)
DEF(sysents_ps4, 0x168410)
DEF(sysentvec, 0xd11bb8)
DEF(sysentvec_ps4, 0xd11d30)
DEF(sceSblServiceMailbox, -0x6824c0)
DEF(sceSblAuthMgrSmIsLoadable2, -0x8a5c40)
DEF(mdbg_call_fix, -0x631ea9)
DEF(syscall_before, -0x802311)
DEF(syscall_after, -0x8022ee)
DEF(malloc, -0xa9b00)
DEF(M_something, 0x1346080)
DEF(loadSelfSegment_epilogue, -0x8a54cd)
DEF(loadSelfSegment_watchpoint, -0x2cc918)
DEF(loadSelfSegment_watchpoint_lr, -0x8a5727)
//DEF(decryptSelfBlock_watchpoint, -0x2cc88e)
DEF(decryptSelfBlock_watchpoint_lr, -0x8a538a)
DEF(decryptSelfBlock_epilogue, -0x8a52c3)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8a4c55)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8a47d2)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8a58bc)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8a5541)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8a5014)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8a488c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8a5cbe)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x94a7f0)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x94ada4)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x94ad2e)
DEF(sceSblPfsSetKeys, -0x94aaa0)
//DEF(panic, -0x21020)
DEF(sceSblServiceCryptAsync, -0x8ed940)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8ed902)
DEF(copyin, -0x9908e0)
DEF(copyout, -0x990990)
DEF(crypt_message_resolve, -0x479d60)
DEF(justreturn, -0x9cf990)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xdc16e8)
DEF(pop_all_iret, -0x9cf8ab)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x96be70)
DEF(kernel_pmap_store, 0x3257a78)
DEF(crypt_singleton_array, 0x2e31830)
DEF(security_flags, 0x6506474)
DEF(targetid, 0x650647d)
DEF(qa_flags, 0x6506498)
DEF(utoken, 0x6506500)
DEF(kmem_alloc, -0xc1ed0)
DEF(kernel_vmmap, 0xd42b98)
DEF(kproc_create, -0x35ebf0)
DEF(kmem_alloc_rwx_fix, -0x70b963)
DEF(malloc_arena_fix_start, -0xa9ac2)
DEF(malloc_arena_fix_end, malloc_arena_fix_start+6)
#include "offset_list.txt"
END_FW()

START_FW(450)
DEF(allproc, 0x27edcb8)
DEF(idt, 0x64cdc80)
DEF(gdt_array, 0x64cee30)
DEF(tss_array, 0x64d0830)
DEF(pcpu_array, 0x64d2280)
DEF(doreti_iret, -0x9cf84c)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x99002a /*-0x990a55*/)
DEF(rdmsr_start, -0x9d0cfa /*-0x9d6d02*/)
//DEF(rdmsr_end, -0x9d6cf9)
DEF(wrmsr_ret, -0x9d20cc)
DEF(dr2gpr_start, -0x9d6d93)
//DEF(dr2gpr_end, -0x9d6d7c)
DEF(gpr2dr_1_start, -0x9d6c7a)
//DEF(gpr2dr_1_end, -0x9d6c55)
DEF(gpr2dr_2_start, -0x9d6b87)
//DEF(gpr2dr_2_end, -0x9d6de9)
DEF(mov_cr3_rax, -0x396e4e)
DEF(mov_rdi_cr3, -0x396ebe)
DEF(nop_ret, -0x396de1)
DEF(cpu_switch, -0x9d6f80)
DEF(mprotect_fix_start, -0x90ac61)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2cd16d)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1df11e)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6c2959)
DEF(sigaction_fix_end, -0x6c2903)
DEF(sysents, 0x1709c0)
DEF(sysents_ps4, 0x168410)
DEF(sysentvec, 0xd11bb8)
DEF(sysentvec_ps4, 0xd11d30)
DEF(sceSblServiceMailbox, -0x682490)
DEF(sceSblAuthMgrSmIsLoadable2, -0x8a5be0)
DEF(mdbg_call_fix, -0x631e79)
DEF(syscall_before, -0x8022e1)
DEF(syscall_after, -0x8022be)
DEF(malloc, -0xa9940)
DEF(M_something, 0x1346080)
DEF(loadSelfSegment_epilogue, -0x8a546d)
DEF(loadSelfSegment_watchpoint, -0x2cc768)
DEF(loadSelfSegment_watchpoint_lr, -0x8a56c7)
//DEF(decryptSelfBlock_watchpoint, -0x2cc6de)
DEF(decryptSelfBlock_watchpoint_lr, -0x8a532a)
DEF(decryptSelfBlock_epilogue, -0x8a5263)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8a4bf5)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8a4772)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8a585c)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8a54e1)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8a4fb4)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8a482c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8a5c5e)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x94a7f0)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x94ada4)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x94ad2e)
DEF(sceSblPfsSetKeys, -0x94aaa0)
//DEF(panic, -0x20e40)
DEF(sceSblServiceCryptAsync, -0x8ed930)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8ed8f2)
DEF(copyin, -0x9908e0)
DEF(copyout, -0x990990)
DEF(crypt_message_resolve, -0x479c30)
DEF(justreturn, -0x9cf990)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xdc16e8)
DEF(pop_all_iret, -0x9cf8ab)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x96db88)
DEF(kernel_pmap_store, 0x3257a78)
DEF(crypt_singleton_array, 0x2e31830)
DEF(security_flags, 0x6506474)
DEF(targetid, 0x650647d)
DEF(qa_flags, 0x6506498)
DEF(utoken, 0x6506500)
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(451)
DEF(allproc, 0x27edcb8)
DEF(idt, 0x64cdc80)
DEF(gdt_array, 0x64cee30)
DEF(tss_array, 0x64d0830)
DEF(pcpu_array, 0x64d2280)
DEF(doreti_iret, -0x9cf84c)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x99002a)
DEF(rdmsr_start, -0x9d0cfa)
//DEF(rdmsr_end, -0x9d6cf9)
DEF(wrmsr_ret, -0x9d20cc)
DEF(dr2gpr_start, -0x9d6d93)
//DEF(dr2gpr_end, -0x9d6d7c)
DEF(gpr2dr_1_start, -0x9d6c7a)
//DEF(gpr2dr_1_end, -0x9d6c55)
DEF(gpr2dr_2_start, -0x9d6b87)
//DEF(gpr2dr_2_end, -0x9d6de9)
DEF(mov_cr3_rax, -0x396aae)
DEF(mov_rdi_cr3, -0x396b1e)
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0x9d6f80)
DEF(mprotect_fix_start, -0x90ac61)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2ccdcd)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1ded7e)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6c2959)
DEF(sigaction_fix_end, -0x6c2903)
DEF(sysents, 0x1709c0)
DEF(sysents_ps4, 0x168410)
DEF(sysentvec, 0xd11bb8)
DEF(sysentvec_ps4, 0xd11d30)
DEF(sceSblServiceMailbox, -0x682490)
DEF(sceSblAuthMgrSmIsLoadable2, -0x8a5be0)
DEF(mdbg_call_fix, -0x631e79)
DEF(syscall_before, -0x8022e1)
DEF(syscall_after, -0x8022be)
DEF(malloc, -0xa9510)
DEF(M_something, 0x1346080)
DEF(loadSelfSegment_epilogue, -0x8a546d)
DEF(loadSelfSegment_watchpoint, -0x2cc3c8)
DEF(loadSelfSegment_watchpoint_lr, -0x8a56c7)
//DEF(decryptSelfBlock_watchpoint, -0x2cc33e)
DEF(decryptSelfBlock_watchpoint_lr, -0x8a532a)
DEF(decryptSelfBlock_epilogue, -0x8a5263)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8a4bf5)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8a4772)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8a585c)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8a54e1)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8a4fb4)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8a482c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8a5c5e)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x94a7f0)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x94ada4)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x94ad2e)
DEF(sceSblPfsSetKeys, -0x94aaa0)
//DEF(panic, -0x20a10)
DEF(sceSblServiceCryptAsync, -0x8ed930)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8ed8f2)
DEF(copyin, -0x9908e0)
DEF(copyout, -0x990990)
DEF(crypt_message_resolve, -0x479890)
DEF(justreturn, -0x9cf990)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xdc16e8)
DEF(pop_all_iret, -0x9cf8ab)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x96d488)
DEF(kernel_pmap_store, 0x3257a78)
DEF(crypt_singleton_array, 0x2e31830)
DEF(security_flags, 0x6506474)
DEF(targetid, 0x650647d)
DEF(qa_flags, 0x6506498)
DEF(utoken, 0x6506500)
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(500)
DEF(allproc, 0x291dd00) //data 0x355DD00
DEF(idt, 0x660dca0) //data 0x724DCA0
DEF(gdt_array, 0x660ee50) //data 0x724EE50
DEF(tss_array, 0x6610850) //data 0x7250850
DEF(pcpu_array, 0x6622680) //data 0x7262680
DEF(doreti_iret, -0xa04f93) //data 0x23B06D
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x9c576a) //data 0x27A896
DEF(rdmsr_start, -0xa0652a) //data 0x239AD6
DEF(wrmsr_ret, -0xa078fc) //data 0x238704
DEF(dr2gpr_start, -0xa0bf13) //data 0x2340ED
DEF(gpr2dr_1_start, -0xa0bdfa) //data 0x234206
DEF(gpr2dr_2_start, -0xa0bd07) //data 0x2342F9
DEF(mov_cr3_rax, -0x3a982e) //data 0x8967D2
DEF(mov_rdi_cr3, -0x3a989e) //data 0x896762
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0xa0c100) //data 0x233F00
DEF(mprotect_fix_start, -0x93efa2) //data 0x30105E
DEF(mprotect_fix_end, mprotect_fix_start+6)

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, -0x88c5aa)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6e7db0) //data 0x558250
DEF(sigaction_fix_end, -0x6e7d6e) //data 0x558292
DEF(sysents, 0x1b1ef0) //data 0xDF1EF0
DEF(sysents_ps4, 0x1a9940) //data 0xDE9940
DEF(sysentvec, 0xe00be8) //data 0x1A40BE8
DEF(sysentvec_ps4, 0xe00d60) //data 0x1A40D60
DEF(sceSblServiceMailbox, -0x6a5de0) //data 0x59A220
DEF(sceSblAuthMgrSmIsLoadable2, -0x8d90d0) //data 0x366F30
DEF(mdbg_call_fix, -0x650049) //data 0x5EFFB7
DEF(syscall_before, -0x8357e1) //data 0x40A81F
DEF(syscall_after, -0x8357be) //data 0x40A842
DEF(malloc, -0xb4df0) //data 0xB8B210
DEF(M_something, 0x14355a0) //data 0x20755A0
DEF(loadSelfSegment_epilogue, -0x8d898d) //data 0x367673
DEF(loadSelfSegment_watchpoint, -0x2dd358) //data 0x962CA8
DEF(loadSelfSegment_watchpoint_lr, -0x8d8be7) //data 0x367419
DEF(decryptSelfBlock_watchpoint_lr, -0x8d885f) //data 0x3677A1
DEF(decryptSelfBlock_epilogue, -0x8d87a2) //data 0x36785E
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8d8112) //data 0x367EEE //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8d8119) //data 0x367EE7 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8d7ee4) //data 0x36811C
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8d8d76) //data 0x36728A
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8d8a01) //data 0x3675FF
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8d8439) //data 0x367BC7
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8d7c58) //data 0x3683A8
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8d914e) //data 0x366EB2
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x97f430) //data 0x2C0BD0
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x97f9df) //data 0x2C0621
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x97f969) //data 0x2C0697
//DEF(sceSblPfsSetKeys, -0x97f6e0) //data 0x2C0920 // 403
DEF(sceSblPfsSetKeys, -0x9805e0) //data 0x2BFA20 // 550
DEF(sceSblServiceCryptAsync, -0x921ac0) //data 0x31E540
DEF(sceSblServiceCryptAsync_deref_singleton, -0x921a82) //data 0x31E57E
DEF(copyin, -0x9c6020) //data 0x279FE0
DEF(copyout, -0x9c60d0) //data 0x279F30
DEF(crypt_message_resolve, -0x48c080) //data 0x7B3F80
DEF(justreturn, -0xa051c0) //data 0x23AE40
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xeaf938) //data 0x1AEF938
DEF(pop_all_iret, -0xa04ff2) //data 0x23B00E
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x9a2d78) //data 0x29D288
DEF(kernel_pmap_store, 0x3398a88) //data 0x3FD8A88
DEF(crypt_singleton_array, 0x2f51830) //data 0x3B91830
DEF(security_flags, 0x66466ec) //data 0x72866EC
DEF(targetid, 0x66466f5) //data 0x72866F5
DEF(qa_flags, 0x6646710) //data 0x7286710
DEF(utoken, 0x6646778) //data 0x7286778
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(502)
DEF(allproc, 0x291dd00) //data 0x355DD00
DEF(idt, 0x660dca0) //data 0x724DCA0
DEF(gdt_array, 0x660ee50) //data 0x724EE50
DEF(tss_array, 0x6610850) //data 0x7250850
DEF(pcpu_array, 0x6622680) //data 0x7262680
DEF(doreti_iret, -0xa04f93) //data 0x23B06D
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x9c576a) //data 0x27A896
DEF(rdmsr_start, -0xa0652a) //data 0x239AD6
DEF(wrmsr_ret, -0xa078fc) //data 0x238704
DEF(dr2gpr_start, -0xa0bf13) //data 0x2340ED
DEF(gpr2dr_1_start, -0xa0bdfa) //data 0x234206
DEF(gpr2dr_2_start, -0xa0bd07) //data 0x2342F9
DEF(mov_cr3_rax, -0x3a982e) //data 0x8967D2
DEF(mov_rdi_cr3, -0x3a989e) //data 0x896762
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0xa0c100) //data 0x233F00
DEF(mprotect_fix_start, -0x93efa2) //data 0x30105E
DEF(mprotect_fix_end, mprotect_fix_start+6)

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, -0x88c5aa)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6e7db0) //data 0x558250
DEF(sigaction_fix_end, -0x6e7d6e) //data 0x558292
DEF(sysents, 0x1b1ef0) //data 0xDF1EF0
DEF(sysents_ps4, 0x1a9940) //data 0xDE9940
DEF(sysentvec, 0xe00be8) //data 0x1A40BE8
DEF(sysentvec_ps4, 0xe00d60) //data 0x1A40D60
DEF(sceSblServiceMailbox, -0x6a5de0) //data 0x59A220
DEF(sceSblAuthMgrSmIsLoadable2, -0x8d90d0) //data 0x366F30
DEF(mdbg_call_fix, -0x650049) //data 0x5EFFB7
DEF(syscall_before, -0x8357e1) //data 0x40A81F
DEF(syscall_after, -0x8357be) //data 0x40A842
DEF(malloc, -0xb4df0) //data 0xB8B210
DEF(M_something, 0x14355a0) //data 0x20755A0
DEF(loadSelfSegment_epilogue, -0x8d898d) //data 0x367673
DEF(loadSelfSegment_watchpoint, -0x2dd358) //data 0x962CA8
DEF(loadSelfSegment_watchpoint_lr, -0x8d8be7) //data 0x367419
DEF(decryptSelfBlock_watchpoint_lr, -0x8d885f) //data 0x3677A1
DEF(decryptSelfBlock_epilogue, -0x8d87a2) //data 0x36785E
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8d8112) //data 0x367EEE //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8d8119) //data 0x367EE7 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8d7ee4) //data 0x36811C
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8d8d76) //data 0x36728A
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8d8a01) //data 0x3675FF
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8d8439) //data 0x367BC7
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8d7c58) //data 0x3683A8
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8d914e) //data 0x366EB2
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x97f430) //data 0x2C0BD0
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x97f9df) //data 0x2C0621
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x97f969) //data 0x2C0697
//DEF(sceSblPfsSetKeys, -0x97f6e0) //data 0x2C0920 // 403
DEF(sceSblPfsSetKeys, -0x9805e0) //data 0x2BFA20 // 550
DEF(sceSblServiceCryptAsync, -0x921ac0) //data 0x31E540
DEF(sceSblServiceCryptAsync_deref_singleton, -0x921a82) //data 0x31E57E
DEF(copyin, -0x9c6020) //data 0x279FE0
DEF(copyout, -0x9c60d0) //data 0x279F30
DEF(crypt_message_resolve, -0x48c080) //data 0x7B3F80
DEF(justreturn, -0xa051c0) //data 0x23AE40
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xeaf938) //data 0x1AEF938
DEF(pop_all_iret, -0xa04ff2) //data 0x23B00E
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x9a33c8) //data 0x29CC38
DEF(kernel_pmap_store, 0x3398a88) //data 0x3FD8A88
DEF(crypt_singleton_array, 0x2f51830) //data 0x3B91830
DEF(security_flags, 0x66466ec) //data 0x72866EC
DEF(targetid, 0x66466f5) //data 0x72866F5
DEF(qa_flags, 0x6646710) //data 0x7286710
DEF(utoken, 0x6646778) //data 0x7286778
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(510)
DEF(allproc, 0x291dd00)
DEF(idt, 0x660dca0)
DEF(gdt_array, 0x660ee50)
DEF(tss_array, 0x6610850)
DEF(pcpu_array, 0x6622680)
DEF(doreti_iret, -0xa04f93)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x9c576a)
DEF(rdmsr_start, -0xa0652a)
DEF(wrmsr_ret, -0xa078fc)
DEF(dr2gpr_start, -0xa0bf13)
DEF(gpr2dr_1_start, -0xa0bdfa)
DEF(gpr2dr_2_start, -0xa0bd07)
DEF(mov_cr3_rax, -0x3a965e)
DEF(mov_rdi_cr3, -0x3a96ce)
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0xa0c100)
DEF(mprotect_fix_start, -0x93efa2)
DEF(mprotect_fix_end, mprotect_fix_start+6)

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6e7be0)
DEF(sigaction_fix_end, -0x6e7b9e)
DEF(sysents, 0x1b2040)
DEF(sysents_ps4, 0x1a9a90)
DEF(sysentvec, 0xe00be8)
DEF(sysentvec_ps4, 0xe00d60)
DEF(sceSblServiceMailbox, -0x6a5c10)
DEF(sceSblAuthMgrSmIsLoadable2, -0x8d90d0)
DEF(mdbg_call_fix, -0x64fe79)
DEF(syscall_before, -0x8357e1)
DEF(syscall_after, -0x8357be)
DEF(malloc, -0xb4ac0)
DEF(M_something, 0x14355a0)
DEF(loadSelfSegment_epilogue, -0x8d898d)
DEF(loadSelfSegment_watchpoint, -0x2dd108)
DEF(loadSelfSegment_watchpoint_lr, -0x8d8be7)
DEF(decryptSelfBlock_watchpoint_lr, -0x8d885f)
DEF(decryptSelfBlock_epilogue, -0x8d87a2)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8d8119)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8d7ee4)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8d8d76)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8d8A01)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8d8439)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8d7C58)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8d914E)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x97F430)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x97F9DF)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x97F969)
DEF(sceSblPfsSetKeys, -0x9805E0)
DEF(sceSblServiceCryptAsync, -0x921AC0)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x921A82)
DEF(copyin, -0x9c6020)
DEF(copyout, -0x9c60D0)
DEF(crypt_message_resolve, -0x48BEB0)
DEF(justreturn, -0xa051c0)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xeb0938)
DEF(pop_all_iret, -0xa04ff2)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x9a3e70)
DEF(kernel_pmap_store, 0x3398a88)
DEF(crypt_singleton_array, 0x2f51830)
DEF(security_flags, 0x66466EC)
DEF(targetid, 0x66466F5)
DEF(qa_flags, 0x6646710)
DEF(utoken, 0x6646778)
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(550)
DEF(allproc, 0x291dd00)
DEF(idt, 0x660dca0)
DEF(gdt_array, 0x660ee50)
DEF(tss_array, 0x6610850)
DEF(pcpu_array, 0x6622680)
DEF(doreti_iret, -0xa04fd3)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x9c57aa)
DEF(rdmsr_start, -0xa0656a)
DEF(wrmsr_ret, -0xa0793c)
DEF(dr2gpr_start, -0xa0bf53)
DEF(gpr2dr_1_start, -0xa0be3a)
DEF(gpr2dr_2_start, -0xa0bd47)
DEF(mov_cr3_rax, -0x3a886e)
DEF(mov_rdi_cr3, -0x3a88de)
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0xa0c140)
DEF(mprotect_fix_start, -0x93EFE2)
DEF(mprotect_fix_end, mprotect_fix_start+6)

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6e7b30)
DEF(sigaction_fix_end, -0x6e7aee)
DEF(sysents, 0x1b2210)
DEF(sysents_ps4, 0x1a9c60)
DEF(sysentvec, 0xe00be8)
DEF(sysentvec_ps4, 0xe00d60)
DEF(sceSblServiceMailbox, -0x6a5b60)
DEF(sceSblAuthMgrSmIsLoadable2, -0x8d9110)
DEF(mdbg_call_fix, -0x64fb79)
DEF(syscall_before, -0x835731)
DEF(syscall_after, -0x83570e)
DEF(malloc, -0xb3cd0)
DEF(M_something, 0x14355a0)
DEF(loadSelfSegment_epilogue, -0x8d89CD)
DEF(loadSelfSegment_watchpoint, -0x2dC318)
DEF(loadSelfSegment_watchpoint_lr, -0x8d8C27)
DEF(decryptSelfBlock_watchpoint_lr, -0x8d889F)
DEF(decryptSelfBlock_epilogue, -0x8d87E2)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8d8159)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8d7F24)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8d8DB6)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8d8A41)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8d8479)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8d7C98)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8d918E)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x97F470)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x97FA1F)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x97F9A9)
DEF(sceSblPfsSetKeys, -0x980620)
DEF(sceSblServiceCryptAsync, -0x921B00)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x921AC2)
DEF(copyin, -0x9c6060)
DEF(copyout, -0x9c6110)
DEF(crypt_message_resolve, -0x48B0C0)
DEF(justreturn, -0xa05200)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xeaf938)
DEF(pop_all_iret, -0xa05032)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x99fc70)
DEF(kernel_pmap_store, 0x3394a88)
DEF(crypt_singleton_array, 0x2f4d830)
DEF(security_flags, 0x66466EC)
DEF(targetid, 0x66466F5)
DEF(qa_flags, 0x6646710)
DEF(utoken, 0x6646778)
DEF(kernel_vmmap, 0)
DEF(kmem_alloc, -0xCC0C0)
DEF(kproc_create, -0x3714A0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(600)
DEF(allproc, 0x2869d20) //data 0x34C9D20
DEF(idt, 0x655dde0) //data 0x71BDDE0
DEF(gdt_array, 0x655f000) //data 0x71BF000
DEF(tss_array, 0x6560a00) //data 0x71C0A00
DEF(pcpu_array, 0x6572880) //data 0x71D2880
DEF(doreti_iret, -0xa1b813) //data 0x2447ED
DEF(add_rsp_iret, doreti_iret - 7) //data 0x2247E6
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //data 0x2247E3
DEF(rep_movsb_pop_rbp_ret, -0x9dbfea) //data 0x284016
DEF(rdmsr_start, -0xa1cdaa) //data 0x243256
DEF(wrmsr_ret, -0xa1e17c) //data 0x241E84
DEF(dr2gpr_start, -0xa22793) //data 0x23D86D
DEF(gpr2dr_1_start, -0xa2267a) //data 0x23D986
DEF(gpr2dr_2_start, -0xa22587) //data 0x23DA79
DEF(mov_cr3_rax, -0x3aa34e) //data 0x8B5CB2
DEF(mov_rdi_cr3, -0x3aa3be) //data 0x8B5C42
DEF(nop_ret, wrmsr_ret + 2) //data 0x241E86
DEF(cpu_switch, -0xa22980) //data 0x23D680
DEF(mprotect_fix_start, -0x9546d2) //data 0x30B92E
DEF(mprotect_fix_end, mprotect_fix_start+6) //data 0x30B934

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6f6b92) //data 0x56946E
DEF(sigaction_fix_end, -0x6f6b68) //data 0x569498
DEF(sysents, 0x1b49a0) //data 0xE149A0
DEF(sysents_ps4, 0x1ac3f0) //data 0xE0C3F0
DEF(sysentvec, 0xe210a8) //data 0x1A810A8
DEF(sysentvec_ps4, 0xe21220) //data 0x1A81220
DEF(sceSblServiceMailbox, -0x6b28c0) //data 0x5AD740
DEF(sceSblAuthMgrSmIsLoadable2, -0x8ed120) //data 0x372EE0
DEF(mdbg_call_fix, -0x65c2a9) //data 0x603D57
DEF(syscall_before, -0x844a71) //data 0x41B58F
DEF(syscall_after, -0x844a4e) //data 0x41B5B2
DEF(malloc, -0xaa4c0) //data 0xBB5B40
DEF(M_something, 0x1456690) //data 0x20B6690
DEF(loadSelfSegment_epilogue, -0x8ec9ed) //data 0x373613
DEF(loadSelfSegment_watchpoint, -0x2da988) //data 0x985678
DEF(loadSelfSegment_watchpoint_lr, -0x8ecc47) //data 0x3733B9
DEF(decryptSelfBlock_watchpoint_lr, -0x8ec8bf) //data 0x373741
DEF(decryptSelfBlock_epilogue, -0x8ec802) //data 0x3737FE
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8ec172) //data 0x373E8E //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8ec179) //data 0x373E87 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8ebf44) //data 0x3740BC
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8ecdd9) //data 0x373227
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8eca61) //data 0x37359F
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8ec499) //data 0x373B67
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8ebca8) //data 0x374358
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8ed19e) //data 0x372E62
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x995381) //data 0x2CAC7F
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x995931) //data 0x2CA6CF
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x9958bb) //data 0x2CA745
//DEF(sceSblPfsSetKeys, -0x995630) //data 0x2CA9D0 //403
DEF(sceSblPfsSetKeys, -0x996400) //data 0x2C9C00 //550
DEF(sceSblServiceCryptAsync, -0x936080) //data 0x329F80
DEF(sceSblServiceCryptAsync_deref_singleton, -0x936042) //data 0x329FBE
DEF(copyin, -0x9dc8a0) //data 0x283760
DEF(copyout, -0x9dc950) //data 0x2836B0
DEF(crypt_message_resolve, -0x490200) //data 0x7CFE00
DEF(justreturn, -0xa1ba40) //data 0x2445C0
DEF(justreturn_pop, justreturn+8) //data 0x2445C8
DEF(mini_syscore_header, 0xed2048) //data 0x1B32048
DEF(pop_all_iret, -0xa1b872) //data 0x24478E
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //data 0x244792
DEF(push_pop_all_iret, -0x9b99e0) //data 0x2A6620
DEF(kernel_pmap_store, 0x32e4358) //data 0x3F44358
DEF(crypt_singleton_array, 0x2e9d830) //data 0x3AFD830
DEF(security_flags, 0x65968ec) //data 0x71F68EC
DEF(targetid, 0x65968f5) //data 0x71F68F5
DEF(qa_flags, 0x6596910) //data 0x71F6910
DEF(utoken, 0x6596978) //data 0x71F6978
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(602)
DEF(allproc, 0x2869d20) //data 0x34C9D20
DEF(idt, 0x655dde0) //data 0x71BDDE0
DEF(gdt_array, 0x655f000) //data 0x71BF000
DEF(tss_array, 0x6560a00) //data 0x71C0A00
DEF(pcpu_array, 0x6572880) //data 0x71D2880
DEF(doreti_iret, -0xa1b813) //data 0x2447ED
DEF(add_rsp_iret, doreti_iret - 7) //data 0x2247E6
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //data 0x2247E3
DEF(rep_movsb_pop_rbp_ret, -0x9dbfea) //data 0x284016
DEF(rdmsr_start, -0xa1cdaa) //data 0x243256
DEF(wrmsr_ret, -0xa1e17c) //data 0x241E84
DEF(dr2gpr_start, -0xa22793) //data 0x23D86D
DEF(gpr2dr_1_start, -0xa2267a) //data 0x23D986
DEF(gpr2dr_2_start, -0xa22587) //data 0x23DA79
DEF(mov_cr3_rax, -0x3aa36e) //data 0x8B5C92
DEF(mov_rdi_cr3, -0x3aa3de) //data 0x8B5C22
DEF(nop_ret, wrmsr_ret + 2) //data 0x241E86
DEF(cpu_switch, -0xa22980) //data 0x23D680
DEF(mprotect_fix_start, -0x9546d2) //data 0x30B92E
DEF(mprotect_fix_end, mprotect_fix_start+6) //data 0x30B934

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6f6b92) //data 0x56946E
DEF(sigaction_fix_end, -0x6f6b68) //data 0x569498
DEF(sysents, 0x1b49f0) //data 0xE149F0
DEF(sysents_ps4, 0x1ac440) //data 0xE0C440
DEF(sysentvec, 0xe210a8) //data 0x1A810A8
DEF(sysentvec_ps4, 0xe21220) //data 0x1A81220
DEF(sceSblServiceMailbox, -0x6b28c0) //data 0x5AD740
DEF(sceSblAuthMgrSmIsLoadable2, -0x8ed120) //data 0x372EE0
DEF(mdbg_call_fix, -0x65c2c9) //data 0x603D37
DEF(syscall_before, -0x844a71) //data 0x41B58F
DEF(syscall_after, -0x844a4e) //data 0x41B5B2
DEF(malloc, -0xaa4e0) //data 0xBB5B20
DEF(M_something, 0x1456690) //data 0x20B6690
DEF(loadSelfSegment_epilogue, -0x8ec9ed) //data 0x373613
DEF(loadSelfSegment_watchpoint, -0x2da9a8) //data 0x985658
DEF(loadSelfSegment_watchpoint_lr, -0x8ecc47) //data 0x3733B9
DEF(decryptSelfBlock_watchpoint_lr, -0x8ec8bf) //data 0x373741
DEF(decryptSelfBlock_epilogue, -0x8ec802) //data 0x3737FE
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8ec172) //data 0x373E8E //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8ec179) //data 0x373E87 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8ebf44) //data 0x3740BC
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8ecdd9) //data 0x373227
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8eca61) //data 0x37359F
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8ec499) //data 0x373B67
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8ebca8) //data 0x374358
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8ed19e) //data 0x372E62
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x995381) //data 0x2CAC7F
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x995931) //data 0x2CA6CF
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x9958bb) //data 0x2CA745
//DEF(sceSblPfsSetKeys, -0x995630) //data 0x2CA9D0 //403
DEF(sceSblPfsSetKeys, -0x996400) //data 0x2C9C00 //550
DEF(sceSblServiceCryptAsync, -0x936080) //data 0x329F80
DEF(sceSblServiceCryptAsync_deref_singleton, -0x936042) //data 0x329FBE
DEF(copyin, -0x9dc8a0) //data 0x283760
DEF(copyout, -0x9dc950) //data 0x2836B0
DEF(crypt_message_resolve, -0x490220) //data 0x7CFDE0
DEF(justreturn, -0xa1ba40) //data 0x2445C0
DEF(justreturn_pop, justreturn+8) //data 0x2445C8
DEF(mini_syscore_header, 0xed2048) //data 0x1B32048
DEF(pop_all_iret, -0xa1b872) //data 0x24478E
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //data 0x244792
DEF(push_pop_all_iret, -0x9b9e20) //data 0x2A61E0
DEF(kernel_pmap_store, 0x32e4358) //data 0x3F44358
DEF(crypt_singleton_array, 0x2e9d830) //data 0x3AFD830
DEF(security_flags, 0x65968ec) //data 0x71F68EC
DEF(targetid, 0x65968f5) //data 0x71F68F5
DEF(qa_flags, 0x6596910) //data 0x71F6910
DEF(utoken, 0x6596978) //data 0x71F6978
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(650)
DEF(allproc, 0x2869d20) //data 0x34C9D20
DEF(idt, 0x655dde0) //data 0x71BDDE0
DEF(gdt_array, 0x655f000) //data 0x71BF000
DEF(tss_array, 0x6560a00) //data 0x71C0A00
DEF(pcpu_array, 0x6572880) //data 0x71D2880
DEF(doreti_iret, -0xa1b813) //data 0x2447ED
DEF(add_rsp_iret, doreti_iret - 7) //data 0x2247E6
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //data 0x2247E3
DEF(rep_movsb_pop_rbp_ret, -0x9dbfea) //data 0x284016
DEF(rdmsr_start, -0xa1cdaa) //data 0x243256
DEF(wrmsr_ret, -0xa1e17c) //data 0x241E84
DEF(dr2gpr_start, -0xa22793) //data 0x23D86D
DEF(gpr2dr_1_start, -0xa2267a) //data 0x23D986
DEF(gpr2dr_2_start, -0xa22587) //data 0x23DA79
DEF(mov_cr3_rax, -0x3aa0de) //data 0x8B5F22
DEF(mov_rdi_cr3, -0x3aa14e) //data 0x8B5EB2
DEF(nop_ret, wrmsr_ret + 2) //data 0x241E86
DEF(cpu_switch, -0xa22980) //data 0x23D680
DEF(mprotect_fix_start, -0x9546e2) //data 0x30B91E
DEF(mprotect_fix_end, mprotect_fix_start+6) //data 0x30B924

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6f6b12) //data 0x5694EE
DEF(sigaction_fix_end, -0x6f6ae8) //data 0x569518
DEF(sysents, 0x1b49f0) //data 0xE149F0
DEF(sysents_ps4, 0x1ac440) //data 0xE0C440
DEF(sysentvec, 0xe210a8) //data 0x1A810A8
DEF(sysentvec_ps4, 0xe21220) //data 0x1A81220
DEF(sceSblServiceMailbox, -0x6b2790) //data 0x5AD870
DEF(sceSblAuthMgrSmIsLoadable2, -0x8ed100) //data 0x372F00
DEF(mdbg_call_fix, -0x65c199) //data 0x603E67
DEF(syscall_before, -0x844a51) //data 0x41B5AF
DEF(syscall_after, -0x844a2e) //data 0x41B5D2
DEF(malloc, -0xa9d40) //data 0xBB62C0
DEF(M_something, 0x1456690) //data 0x20B6690
DEF(loadSelfSegment_epilogue, -0x8ec9cd) //data 0x373633
DEF(loadSelfSegment_watchpoint, -0x2da218) //data 0x985DE8
DEF(loadSelfSegment_watchpoint_lr, -0x8ecc27) //data 0x3733D9
DEF(decryptSelfBlock_watchpoint_lr, -0x8ec89f) //data 0x373761
DEF(decryptSelfBlock_epilogue, -0x8ec7e2) //data 0x37381E
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8ec152) //data 0x373EAE //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8ec159) //data 0x373EA7 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8ebf24) //data 0x3740DC
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8ecdb9) //data 0x373247
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8eca41) //data 0x3735BF
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8ec479) //data 0x373B87
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8ebc88) //data 0x374378
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8ed17e) //data 0x372E82
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x995381) //data 0x2CAC7F
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x995931) //data 0x2CA6CF
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x9958bb) //data 0x2CA745
//DEF(sceSblPfsSetKeys, -0x995630) //data 0x2CA9D0 //403
DEF(sceSblPfsSetKeys, -0x996400) //data 0x2C9C00 //550
DEF(sceSblServiceCryptAsync, -0x936090) //data 0x329F70
DEF(sceSblServiceCryptAsync_deref_singleton, -0x936052) //data 0x329FAE
DEF(copyin, -0x9dc8a0) //data 0x283760
DEF(copyout, -0x9dc950) //data 0x2836B0
DEF(crypt_message_resolve, -0x490060) //data 0x7CFFA0
DEF(justreturn, -0xa1ba40) //data 0x2445C0
DEF(justreturn_pop, justreturn+8) //data 0x2445C8
DEF(mini_syscore_header, 0xed2048) //data 0x1B32048
DEF(pop_all_iret, -0xa1b872) //data 0x24478E
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //data 0x244792
DEF(push_pop_all_iret, -0x9ba368) //data 0x2A5C98
DEF(kernel_pmap_store, 0x32e4358) //data 0x3F44358
DEF(crypt_singleton_array, 0x2e9d830) //data 0x3AFD830
DEF(security_flags, 0x65968ec) //data 0x71F68EC
DEF(targetid, 0x65968f5) //data 0x71F68F5
DEF(qa_flags, 0x6596910) //data 0x71F6910
DEF(utoken, 0x6596978) //data 0x71F6978
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(700)
DEF(allproc, 0x2859D50) //data 0x34A9D50
DEF(idt, 0x2E7FDF0) //data 0x3ACFDF0
DEF(gdt_array, 0x2E810B0) //data 0x3AD10B0
DEF(tss_array, 0x2E82AB0) //data 0x3AD2AB0
DEF(pcpu_array, 0x2E94A00) //data 0x3AE4A00
DEF(doreti_iret, -0xA0BA33) //data 0x2445CD
DEF(add_rsp_iret, doreti_iret - 7) //data 0x2445C6
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //data 0x2445C3
DEF(rep_movsb_pop_rbp_ret, -0x9CC1A6) //data 0x283E5A
DEF(rdmsr_start, -0xA0D16A) //data 0x242E96
DEF(wrmsr_ret, -0xA0E53C) //data 0x241AC4
DEF(dr2gpr_start, -0xA12B53) //data 0x23D4AD
DEF(gpr2dr_1_start, -0xA12A3A) //data 0x23D5C6
DEF(gpr2dr_2_start, -0xA12947) //data 0x23D6B9
DEF(mov_cr3_rax, -0x3B319E) //data 0x89CE62
DEF(mov_rdi_cr3, -0x3B320E) //data 0x89CDF2
DEF(nop_ret, wrmsr_ret + 2) //data 0x241AC6
DEF(cpu_switch, -0xA12D40) //data 0x23D2C0
DEF(mprotect_fix_start, -0x944F84) //data 0x30B07C
DEF(mprotect_fix_end, mprotect_fix_start+6) //data 0x30B082

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6F02DD) //data 0x55FD23
DEF(sigaction_fix_end, -0x6F02C2) //data 0x55FD3E
DEF(sysents, 0x1B7030) //data 0xE07030
DEF(sysents_ps4, 0x1AEA80) //data 0xDFEA80
DEF(sysentvec, 0xE21AB8) //data 0x1A71AB8
DEF(sysentvec_ps4, 0xE21C30) //data 0x1A71C30
DEF(sceSblServiceMailbox, -0x6AD700) //data 0x5A2900
DEF(sceSblAuthMgrSmIsLoadable2, -0x8DF590) //data 0x370A70
DEF(mdbg_call_fix, -0x6595A9) //data 0x5F6A57
DEF(syscall_before, -0x8375CF) //data 0x418A31
DEF(syscall_after, -0x8375AC) //data 0x418A54
DEF(malloc, -0xB6C60) //data 0xB993A0
DEF(M_something, 0x1457590) //data 0x20A7590
DEF(loadSelfSegment_epilogue, -0x8DEE99) //data 0x371167
DEF(loadSelfSegment_watchpoint, -0x2E30C8) //data 0x96CF38
DEF(loadSelfSegment_watchpoint_lr, -0x8DF0E7) //data 0x370F19
DEF(decryptSelfBlock_watchpoint_lr, -0x8DED6F) //data 0x371291
DEF(decryptSelfBlock_epilogue, -0x8DECB2) //data 0x37134E
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE632) //data 0x3719CE //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE639) //data 0x3719C7 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8DE404) //data 0x371BFC
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8DF276) //data 0x370D8A
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8DEF09) //data 0x3710F7
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8DE956) //data 0x3716AA
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8DE171) //data 0x371E8F
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8DF608) //data 0x3709F8
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x9852FD) //data 0x2CAD03
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x98589B) //data 0x2CA765
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x985828) //data 0x2CA7D8
//DEF(sceSblPfsSetKeys, -0x9855A0) //data 0x2CAA60 //403
DEF(sceSblPfsSetKeys, -0x986420) //data 0x2C9BE0 //550
DEF(sceSblServiceCryptAsync, -0x9271E0) //data 0x328E20
DEF(sceSblServiceCryptAsync_deref_singleton, -0x9271A2) //data 0x328E5E
DEF(copyin, -0x9CCA70) //data 0x283590
DEF(copyout, -0x9CCB20) //data 0x2834E0
DEF(crypt_message_resolve, -0x491BB0) //data 0x7BE450
DEF(justreturn, -0xA0BC60) //data 0x2443A0
DEF(justreturn_pop, justreturn+8) //data 0x2443A8
DEF(mini_syscore_header, 0xE7DD98) //data 0x1ACDD98
DEF(pop_all_iret, -0xA0BA92) //data 0x24456E
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //data 0x244572
DEF(push_pop_all_iret, -0x9AAFC8) //data 0x2A5038
DEF(kernel_pmap_store, 0x2E2C848) //data 0x3A7C848
DEF(crypt_singleton_array, 0x2D71830) //data 0x39C1830
DEF(security_flags, 0xAC8064) //data 0x1718064
DEF(targetid, 0xAC806D) //data 0x171806D
DEF(qa_flags, 0xAC8088) //data 0x1718088
DEF(utoken, 0xAC80F0) //data 0x17180F0
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(701)
DEF(allproc, 0x2859D50) //data 0x34A9D50
DEF(idt, 0x2E7FDF0) //data 0x3ACFDF0
DEF(gdt_array, 0x2E810B0) //data 0x3AD10B0
DEF(tss_array, 0x2E82AB0) //data 0x3AD2AB0
DEF(pcpu_array, 0x2E94A00) //data 0x3AE4A00
DEF(doreti_iret, -0xA0BA33) //data 0x2445CD
DEF(add_rsp_iret, doreti_iret - 7) //data 0x2445C6
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //data 0x2445C3
DEF(rep_movsb_pop_rbp_ret, -0x9CC1A6) //data 0x283E5A
DEF(rdmsr_start, -0xA0D16A) //data 0x242E96
DEF(wrmsr_ret, -0xA0E53C) //data 0x241AC4
DEF(dr2gpr_start, -0xA12B53) //data 0x23D4AD
DEF(gpr2dr_1_start, -0xA12A3A) //data 0x23D5C6
DEF(gpr2dr_2_start, -0xA12947) //data 0x23D6B9
DEF(mov_cr3_rax, -0x3B319E) //data 0x89CE62
DEF(mov_rdi_cr3, -0x3B320E) //data 0x89CDF2
DEF(nop_ret, wrmsr_ret + 2) //data 0x241AC6
DEF(cpu_switch, -0xA12D40) //data 0x23D2C0
DEF(mprotect_fix_start, -0x944F84) //data 0x30B07C
DEF(mprotect_fix_end, mprotect_fix_start+6) //data 0x30B082

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6F02DD) //data 0x55FD23
DEF(sigaction_fix_end, -0x6F02C2) //data 0x55FD3E
DEF(sysents, 0x1B7030) //data 0xE07030
DEF(sysents_ps4, 0x1AEA80) //data 0xDFEA80
DEF(sysentvec, 0xE21AB8) //data 0x1A71AB8
DEF(sysentvec_ps4, 0xE21C30) //data 0x1A71C30
DEF(sceSblServiceMailbox, -0x6AD700) //data 0x5A2900
DEF(sceSblAuthMgrSmIsLoadable2, -0x8DF590) //data 0x370A70
DEF(mdbg_call_fix, -0x6595A9) //data 0x5F6A57
DEF(syscall_before, -0x8375CF) //data 0x418A31
DEF(syscall_after, -0x8375AC) //data 0x418A54
DEF(malloc, -0xB6C60) //data 0xB993A0
DEF(M_something, 0x1457590) //data 0x20A7590
DEF(loadSelfSegment_epilogue, -0x8DEE99) //data 0x371167
DEF(loadSelfSegment_watchpoint, -0x2E30C8) //data 0x96CF38
DEF(loadSelfSegment_watchpoint_lr, -0x8DF0E7) //data 0x370F19
DEF(decryptSelfBlock_watchpoint_lr, -0x8DED6F) //data 0x371291
DEF(decryptSelfBlock_epilogue, -0x8DECB2) //data 0x37134E
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE632) //data 0x3719CE //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE639) //data 0x3719C7 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8DE404) //data 0x371BFC
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8DF276) //data 0x370D8A
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8DEF09) //data 0x3710F7
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8DE956) //data 0x3716AA
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8DE171) //data 0x371E8F
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8DF608) //data 0x3709F8
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x9852FD) //data 0x2CAD03
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x98589B) //data 0x2CA765
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x985828) //data 0x2CA7D8
//DEF(sceSblPfsSetKeys, -0x9855A0) //data 0x2CAA60 //403
DEF(sceSblPfsSetKeys, -0x986420) //data 0x2C9BE0 //550
DEF(sceSblServiceCryptAsync, -0x9271E0) //data 0x328E20
DEF(sceSblServiceCryptAsync_deref_singleton, -0x9271A2) //data 0x328E5E
DEF(copyin, -0x9CCA70) //data 0x283590
DEF(copyout, -0x9CCB20) //data 0x2834E0
DEF(crypt_message_resolve, -0x491BB0) //data 0x7BE450
DEF(justreturn, -0xA0BC60) //data 0x2443A0
DEF(justreturn_pop, justreturn+8) //data 0x2443A8
DEF(mini_syscore_header, 0xE7DD98) //data 0x1ACDD98
DEF(pop_all_iret, -0xA0BA92) //data 0x24456E
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //data 0x244572
DEF(push_pop_all_iret, -0x9A9310) //data 0x2A6CF0
DEF(kernel_pmap_store, 0x2E2C848) //data 0x3A7C848
DEF(crypt_singleton_array, 0x2D71830) //data 0x39C1830
DEF(security_flags, 0xAC8064) //data 0x1718064
DEF(targetid, 0xAC806D) //data 0x171806D
DEF(qa_flags, 0xAC8088) //data 0x1718088
DEF(utoken, 0xAC80F0) //data 0x17180F0
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(720)
DEF(allproc, 0x2859D50) //data 0x34A9D50
DEF(idt, 0x2E7FDF0) //data 0x3ACFDF0
DEF(gdt_array, 0x2E810D0) //data 0x3AD10D0
DEF(tss_array, 0x2E82AD0) //data 0x3AD2AD0
DEF(pcpu_array, 0x2E94A00) //data 0x3AE4A00
DEF(doreti_iret, -0xA0B7F3) //data 0x24480D
DEF(add_rsp_iret, doreti_iret - 7) //data 0x244806
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //data 0x244803
DEF(rep_movsb_pop_rbp_ret, -0x9CBF66) //data 0x28409A
DEF(rdmsr_start, -0xA0CF2A) //data 0x2430D6
DEF(wrmsr_ret, -0xA0E2FC) //data 0x241D04
DEF(dr2gpr_start, -0xA12913) //data 0x23D6ED
DEF(gpr2dr_1_start, -0xA127FA) //data 0x23D806
DEF(gpr2dr_2_start, -0xA12707) //data 0x23D8F9
DEF(mov_cr3_rax, -0x3B2E9E) //data 0x89D162
DEF(mov_rdi_cr3, -0x3B2F0E) //data 0x89D0F2
DEF(nop_ret, wrmsr_ret + 2) //data 0x241D04
DEF(cpu_switch, -0xA12B00) //data 0x23D500
DEF(mprotect_fix_start, -0x944D24) //data 0x30B2DC
DEF(mprotect_fix_end, mprotect_fix_start+6) //data 0x30B2E2

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6EFFDD) //data 0x560023
DEF(sigaction_fix_end, -0x6EFFC2) //data 0x56003E
DEF(sysents, 0x1B71A0) //data 0xE071A0
DEF(sysents_ps4, 0x1AEBF0) //data 0xDFEBF0
DEF(sysentvec, 0xE21B78) //data 0x1A71B78
DEF(sysentvec_ps4, 0xE21CF0) //data 0x1A71CF0
DEF(sceSblServiceMailbox, -0x6AD400) //data 0x5A2C00
DEF(sceSblAuthMgrSmIsLoadable2, -0x8DF330) //data 0x370CD0
DEF(mdbg_call_fix, -0x6592A9) //data 0x5F6D57
DEF(syscall_before, -0x8372CF) //data 0x418D31
DEF(syscall_after, -0x8372AC) //data 0x418D54
DEF(malloc, -0xB5C60) //data 0xB9A3A0
DEF(M_something, 0x1457650) //data 0x20A7650
DEF(loadSelfSegment_epilogue, -0x8DEC39) //data 0x3713C7
DEF(loadSelfSegment_watchpoint, -0x2E2DC8) //data 0x96D238
DEF(loadSelfSegment_watchpoint_lr, -0x8DEE87) //data 0x371179
DEF(decryptSelfBlock_watchpoint_lr, -0x8DEB0F) //data 0x3714F1
DEF(decryptSelfBlock_epilogue, -0x8DEA52) //data 0x3715AE
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE3D2) //data 0x371C2E //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE3D9) //data 0x371C27 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8DE1A4) //data 0x371E5C
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8DF016) //data 0x370FEA
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8DECA9) //data 0x371357
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8DE6F6) //data 0x37190A
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8DDF11) //data 0x3720EF
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8DF3A8) //data 0x370C58
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x98509D) //data 0x2CAF63
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x98563B) //data 0x2CA9C5
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x9855C8) //data 0x2CAA38
//DEF(sceSblPfsSetKeys, -0x985340) //data 0x2CACC0 //403
DEF(sceSblPfsSetKeys, -0x9861C0) //data 0x2C9E40 //550
DEF(sceSblServiceCryptAsync, -0x926F80) //data 0x329080
DEF(sceSblServiceCryptAsync_deref_singleton, -0x926F42) //data 0x3290BE
DEF(copyin, -0x9CC830) //data 0x2837D0
DEF(copyout, -0x9CC8E0) //data 0x283720
DEF(crypt_message_resolve, -0x4918B0) //data 0x7BE750
DEF(justreturn, -0xA0BA20) //data 0x2445E0
DEF(justreturn_pop, justreturn+8) //data 0x2445E8
DEF(mini_syscore_header, 0xE7DE58) //data 0x1ACDE58
DEF(pop_all_iret, -0xA0B852) //data 0x2447AE
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //data 0x2447B2
DEF(push_pop_all_iret, -0x9AAA88) //data 0x2A5578
DEF(kernel_pmap_store, 0x2E2C848) //data 0x3A7C848
DEF(crypt_singleton_array, 0x2D71830) //data 0x39C1830
DEF(security_flags, 0xAC8064) //data 0x1718064
DEF(targetid, 0xAC806D) //data 0x171806D
DEF(qa_flags, 0xAC8088) //data 0x1718088
DEF(utoken, 0xAC80F0) //data 0x17180F0
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(740)
DEF(allproc, 0x2859D50) //data 0x34A9D50
DEF(idt, 0x2E7FDF0) //data 0x3ACFDF0
DEF(gdt_array, 0x2E810D0) //data 0x3AD10D0
DEF(tss_array, 0x2E82AD0) //data 0x3AD2AD0
DEF(pcpu_array, 0x2E94A00) //data 0x3AE4A00
DEF(doreti_iret, -0xA0B7F3) //data 0x24480D
DEF(add_rsp_iret, doreti_iret - 7) //data 0x244806
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //data 0x244803
DEF(rep_movsb_pop_rbp_ret, -0x9CBF66) //data 0x28409A
DEF(rdmsr_start, -0xA0CF2A) //data 0x2430D6
DEF(wrmsr_ret, -0xA0E2FC) //data 0x241D04
DEF(dr2gpr_start, -0xA12913) //data 0x23D6ED
DEF(gpr2dr_1_start, -0xA127FA) //data 0x23D806
DEF(gpr2dr_2_start, -0xA12707) //data 0x23D8F9
DEF(mov_cr3_rax, -0x3B2E9E) //data 0x89D162
DEF(mov_rdi_cr3, -0x3B2F0E) //data 0x89D0F2
DEF(nop_ret, wrmsr_ret + 2) //data 0x241D04
DEF(cpu_switch, -0xA12B00) //data 0x23D500
DEF(mprotect_fix_start, -0x944D24) //data 0x30B2DC
DEF(mprotect_fix_end, mprotect_fix_start+6) //data 0x30B2E2

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6EFFDD) //data 0x560023
DEF(sigaction_fix_end, -0x6EFFC2) //data 0x56003E
DEF(sysents, 0x1B71A0) //data 0xE071A0
DEF(sysents_ps4, 0x1AEBF0) //data 0xDFEBF0
DEF(sysentvec, 0xE21B78) //data 0x1A71B78
DEF(sysentvec_ps4, 0xE21CF0) //data 0x1A71CF0
DEF(sceSblServiceMailbox, -0x6AD400) //data 0x5A2C00
DEF(sceSblAuthMgrSmIsLoadable2, -0x8DF330) //data 0x370CD0
DEF(mdbg_call_fix, -0x6592A9) //data 0x5F6D57
DEF(syscall_before, -0x8372CF) //data 0x418D31
DEF(syscall_after, -0x8372AC) //data 0x418D54
DEF(malloc, -0xB5C60) //data 0xB9A3A0
DEF(M_something, 0x1457650) //data 0x20A7650
DEF(loadSelfSegment_epilogue, -0x8DEC39) //data 0x3713C7
DEF(loadSelfSegment_watchpoint, -0x2E2DC8) //data 0x96D238
DEF(loadSelfSegment_watchpoint_lr, -0x8DEE87) //data 0x371179
DEF(decryptSelfBlock_watchpoint_lr, -0x8DEB0F) //data 0x3714F1
DEF(decryptSelfBlock_epilogue, -0x8DEA52) //data 0x3715AE
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE3D2) //data 0x371C2E //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE3D9) //data 0x371C27 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8DE1A4) //data 0x371E5C
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8DF016) //data 0x370FEA
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8DECA9) //data 0x371357
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8DE6F6) //data 0x37190A
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8DDF11) //data 0x3720EF
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8DF3A8) //data 0x370C58
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x98509D) //data 0x2CAF63
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x98563B) //data 0x2CA9C5
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x9855C8) //data 0x2CAA38
//DEF(sceSblPfsSetKeys, -0x985340) //data 0x2CACC0 //403
DEF(sceSblPfsSetKeys, -0x9861C0) //data 0x2C9E40 //550
DEF(sceSblServiceCryptAsync, -0x926F80) //data 0x329080
DEF(sceSblServiceCryptAsync_deref_singleton, -0x926F42) //data 0x3290BE
DEF(copyin, -0x9CC830) //data 0x2837D0
DEF(copyout, -0x9CC8E0) //data 0x283720
DEF(crypt_message_resolve, -0x4918B0) //data 0x7BE750
DEF(justreturn, -0xA0BA20) //data 0x2445E0
DEF(justreturn_pop, justreturn+8) //data 0x2445E8
DEF(mini_syscore_header, 0xE7DE58) //data 0x1ACDE58
DEF(pop_all_iret, -0xA0B852) //data 0x2447AE
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //data 0x2447B2
DEF(push_pop_all_iret, -0x9A0330) //data 0x2AFCD0
DEF(kernel_pmap_store, 0x2E2C848) //data 0x3A7C848
DEF(crypt_singleton_array, 0x2D71830) //data 0x39C1830
DEF(security_flags, 0xAC8064) //data 0x1718064
DEF(targetid, 0xAC806D) //data 0x171806D
DEF(qa_flags, 0xAC8088) //data 0x1718088
DEF(utoken, 0xAC80F0) //data 0x17180F0
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(760)
DEF(allproc, 0x2859D50) //data 0x34A9D50
DEF(idt, 0x2E7FDF0) //data 0x3ACFDF0
DEF(gdt_array, 0x2E810D0) //data 0x3AD10D0
DEF(tss_array, 0x2E82AD0) //data 0x3AD2AD0
DEF(pcpu_array, 0x2E94A00) //data 0x3AE4A00
DEF(doreti_iret, -0xA0B7F3) //data 0x24480D
DEF(add_rsp_iret, doreti_iret - 7) //data 0x244806
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //data 0x244803
DEF(rep_movsb_pop_rbp_ret, -0x9CBF66) //data 0x28409A
DEF(rdmsr_start, -0xA0CF2A) //data 0x2430D6
DEF(wrmsr_ret, -0xA0E2FC) //data 0x241D04
DEF(dr2gpr_start, -0xA12913) //data 0x23D6ED
DEF(gpr2dr_1_start, -0xA127FA) //data 0x23D806
DEF(gpr2dr_2_start, -0xA12707) //data 0x23D8F9
DEF(mov_cr3_rax, -0x3B2D5E) //data 0x89D2A2
DEF(mov_rdi_cr3, -0x3B2DCE) //data 0x89D232
DEF(nop_ret, wrmsr_ret + 2) //data 0x241D06
DEF(cpu_switch, -0xA12B00) //data 0x23D500
DEF(mprotect_fix_start, -0x944D14) //data 0x30B2EC
DEF(mprotect_fix_end, mprotect_fix_start+6) //data 0x30B2F2

DEF(mmap_self_fix_1_start, 0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, 0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6EFFCD) //data 0x560033
DEF(sigaction_fix_end, -0x6EFFB2) //data 0x56004E
DEF(sysents, 0x1B7260) //data 0xE07260
DEF(sysents_ps4, 0x1AECB0) //data 0xDFECB0
DEF(sysentvec, 0xE21B78) //data 0x1A71B78
DEF(sysentvec_ps4, 0xE21CF0) //data 0x1A71CF0
DEF(sceSblServiceMailbox, -0x6AD3F0) //data 0x5A2C10
DEF(sceSblAuthMgrSmIsLoadable2, -0x8DF320) //data 0x370CE0
DEF(mdbg_call_fix, -0x659169) //data 0x5F6E97
DEF(syscall_before, -0x8372BF) //data 0x418D41
DEF(syscall_after, -0x83729C) //data 0x418D64
DEF(malloc, -0xB5650) //data 0xB9A9B0
DEF(M_something, 0x1457650) //data 0x20A7650
DEF(loadSelfSegment_epilogue, -0x8DEC29) //data 0x3713D7
DEF(loadSelfSegment_watchpoint, -0x2E2C88) //data 0x96D378
DEF(loadSelfSegment_watchpoint_lr, -0x8DEE77) //data 0x371189
DEF(decryptSelfBlock_watchpoint_lr, -0x8DEAFF) //data 0x371501
DEF(decryptSelfBlock_epilogue, -0x8DEA42) //data 0x3715BE
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE3C2) //data 0x371C3E //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE3C9) //data 0x371C37 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8DE194) //data 0x371E6C
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8DF006) //data 0x370FFA
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8DEC99) //data 0x371367
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8DE6E6) //data 0x37191A
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8DDF01) //data 0x3720FF
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8DF398) //data 0x370C68
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x98508D) //data 0x2CAF73
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x98562B) //data 0x2CA9D5
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x9855B8) //data 0x2CAA48
//DEF(sceSblPfsSetKeys, -0x985330) //data 0x2CACD0 //403
DEF(sceSblPfsSetKeys, -0x9861B0) //data 0x2C9E50 //550
DEF(sceSblServiceCryptAsync, -0x926F70) //data 0x329090
DEF(sceSblServiceCryptAsync_deref_singleton, -0x926F32) //data 0x3290CE
DEF(copyin, -0x9CC830) //data 0x2837D0
DEF(copyout, -0x9CC8E0) //data 0x283720
DEF(crypt_message_resolve, -0x491770) //data 0x7BE890
DEF(justreturn, -0xA0BA20) //data 0x2445E0
DEF(justreturn_pop, justreturn+8) //data 0x2445E8
DEF(mini_syscore_header, 0xE7DE58) //data 0x1ACDE58
DEF(pop_all_iret, -0xA0B852) //data 0x2447AE
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //data 0x2447B2
DEF(push_pop_all_iret, -0x9A86E8) //data 0x2A7918
DEF(kernel_pmap_store, 0x2E2C848) //data 0x3A7C848
DEF(crypt_singleton_array, 0x2D71830) //data 0x39C1830
DEF(security_flags, 0xAC8064) //data 0x1718064
DEF(targetid, 0xAC806D) //data 0x171806D
DEF(qa_flags, 0xAC8088) //data 0x1718088
DEF(utoken, 0xAC80F0) //data 0x17180F0
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

START_FW(761)
DEF(allproc, 0x2859D50) //data 0x34A9D50
DEF(idt, 0x2E7FDF0) //data 0x3ACFDF0
DEF(gdt_array, 0x2E810D0) //data 0x3AD10D0
DEF(tss_array, 0x2E82AD0) //data 0x3AD2AD0
DEF(pcpu_array, 0x2E94A00) //data 0x3AE4A00
DEF(doreti_iret, -0xA0B7F3) //data 0x24480D
DEF(add_rsp_iret, doreti_iret - 7) //data 0x244806
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //data 0x244803
DEF(rep_movsb_pop_rbp_ret, -0x9CBF66) //data 0x28409A
DEF(rdmsr_start, -0xA0CF2A) //data 0x2430D6
DEF(wrmsr_ret, -0xA0E2FC) //data 0x241D04
DEF(dr2gpr_start, -0xA12913) //data 0x23D6ED
DEF(gpr2dr_1_start, -0xA127FA) //data 0x23D806
DEF(gpr2dr_2_start, -0xA12707) //data 0x23D8F9
DEF(mov_cr3_rax, -0x3B2D5E) //data 0x89D2A2
DEF(mov_rdi_cr3, -0x3B2DCE) //data 0x89D232
DEF(nop_ret, wrmsr_ret + 2) //data 0x241D06
DEF(cpu_switch, -0xA12B00) //data 0x23D500
DEF(mprotect_fix_start, -0x944D14) //data 0x30B2EC
DEF(mprotect_fix_end, mprotect_fix_start+6) //data 0x30B2F2

DEF(mmap_self_fix_1_start, -0x0)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x0)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)

DEF(aslr_fix_start, 0)
DEF(aslr_fix_end, aslr_fix_start+2)

DEF(sigaction_fix_start, -0x6EFFCD) //data 0x560033
DEF(sigaction_fix_end, -0x6EFFB2) //data 0x56004E
DEF(sysents, 0x1B7260) //data 0xE07260
DEF(sysents_ps4, 0x1AECB0) //data 0xDFECB0
DEF(sysentvec, 0xE21B78) //data 0x1A71B78
DEF(sysentvec_ps4, 0xE21CF0) //data 0x1A71CF0
DEF(sceSblServiceMailbox, -0x6AD3F0) //data 0x5A2C10
DEF(sceSblAuthMgrSmIsLoadable2, -0x8DF320) //data 0x370CE0
DEF(mdbg_call_fix, -0x659169) //data 0x5F6E97
DEF(syscall_before, -0x8372BF) //data 0x418D41
DEF(syscall_after, -0x83729C) //data 0x418D64
DEF(malloc, -0xB5650) //data 0xB9A9B0
DEF(M_something, 0x1457650) //data 0x20A7650
DEF(loadSelfSegment_epilogue, -0x8DEC29) //data 0x3713D7
DEF(loadSelfSegment_watchpoint, -0x2E2C88) //data 0x96D378
DEF(loadSelfSegment_watchpoint_lr, -0x8DEE77) //data 0x371189
DEF(decryptSelfBlock_watchpoint_lr, -0x8DEAFF) //data 0x371501
DEF(decryptSelfBlock_epilogue, -0x8DEA42) //data 0x3715BE
//DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE3C2) //data 0x371C3E //403
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8DE3C9) //data 0x371C37 //550
DEF(decryptMultipleSelfBlocks_epilogue, -0x8DE194) //data 0x371E6C
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8DF006) //data 0x370FFA
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8DEC99) //data 0x371367
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8DE6E6) //data 0x37191A
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8DDF01) //data 0x3720FF
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8DF398) //data 0x370C68
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x98508D) //data 0x2CAF73
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x98562B) //data 0x2CA9D5
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x9855B8) //data 0x2CAA48
//DEF(sceSblPfsSetKeys, -0x985330) //data 0x2CACD0 //403
DEF(sceSblPfsSetKeys, -0x9861B0) //data 0x2C9E50 //550
DEF(sceSblServiceCryptAsync, -0x926F70) //data 0x329090
DEF(sceSblServiceCryptAsync_deref_singleton, -0x926F32) //data 0x3290CE
DEF(copyin, -0x9CC830) //data 0x2837D0
DEF(copyout, -0x9CC8E0) //data 0x283720
DEF(crypt_message_resolve, -0x491770) //data 0x7BE890
DEF(justreturn, -0xA0BA20) //data 0x2445E0
DEF(justreturn_pop, justreturn+8) //data 0x2445E8
DEF(mini_syscore_header, 0xE7DE58) //data 0x1ACDE58
DEF(pop_all_iret, -0xA0B852) //data 0x2447AE
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //data 0x2447B2
DEF(push_pop_all_iret, -0x9A9750) //data 0x2A68B0
DEF(kernel_pmap_store, 0x2E2C848) //data 0x3A7C848
DEF(crypt_singleton_array, 0x2D71830) //data 0x39C1830
DEF(security_flags, 0xAC8064) //data 0x1718064
DEF(targetid, 0xAC806D) //data 0x171806D
DEF(qa_flags, 0xAC8088) //data 0x1718088
DEF(utoken, 0xAC80F0) //data 0x17180F0
DEF(kmem_alloc, 0);
DEF(kernel_vmmap, 0)
DEF(kproc_create, 0)
DEF(kmem_alloc_rwx_fix, 0)
DEF(malloc_arena_fix_start, 0)
DEF(malloc_arena_fix_end, 0)
#include "offset_list.txt"
END_FW()

void* dlsym(void*, const char*);

int set_offsets(void)
{
    uint32_t ver = r0gdb_get_fw_version() >> 16;
    switch(ver)
    {
#ifndef NO_BUILTIN_OFFSETS
    case 0x300: set_offsets_300(); break;
    case 0x310: set_offsets_310(); break;
    case 0x320: set_offsets_320(); break;
    case 0x321: set_offsets_321(); break;
    case 0x400: set_offsets_400(); break;
    case 0x402: set_offsets_402(); break;
    case 0x403: set_offsets_403(); break;
    case 0x450: set_offsets_450(); break;
    case 0x451: set_offsets_451(); break;
    case 0x500: set_offsets_500(); break;
    case 0x502: set_offsets_502(); break;
    case 0x510: set_offsets_510(); break;
    case 0x550: set_offsets_550(); break;
    case 0x600: set_offsets_600(); break;
    case 0x602: set_offsets_602(); break;
    case 0x650: set_offsets_650(); break;
    case 0x700: set_offsets_700(); break;
    case 0x701: set_offsets_701(); break;
    case 0x720: set_offsets_720(); break;
    case 0x740: set_offsets_740(); break;
    case 0x760: set_offsets_760(); break;
    case 0x761: set_offsets_761(); break;
#endif
    default: return -1;
    }
    return 0;
}