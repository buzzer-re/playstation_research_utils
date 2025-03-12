#include "r0gdb.h"
#include "offsets.h"

extern void* (*kernel_dynlib_dlsym)(int pid, unsigned int handle, const char* sym);
extern int (*f_usleep)(unsigned int usec);
extern int (*printf)(const char* fmt, ...);

#define sleepy_printf(fmt, ...) do { printf(fmt, ##__VA_ARGS__); f_usleep(100* 1000); } while(0)


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
#include "offset_list.txt"
END_FW()

void* dlsym(void*, const char*);

int set_offsets(void)
{
    uint32_t ver = r0gdb_get_fw_version() >> 16;

    sleepy_printf("set_offsets: ver=%x\n", ver);

    switch(ver)
    {
#ifndef NO_BUILTIN_OFFSETS
    case 0x250: set_offsets_250(); break;
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
#endif
    default: return -1;
    }
    return 0;
}
