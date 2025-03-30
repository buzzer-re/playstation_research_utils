#pragma once
#include <sys/types.h>

int try_handle_kernel_fix_trap(uint64_t* regs);
int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr);
void handle_kekcall_trap(uint64_t* regs, uint32_t trap);
