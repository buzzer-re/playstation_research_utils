#include <errno.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <machine/sysarch.h>
#include <string.h>
#include "kekcall.h"
#include "traps.h"
#include "utils.h"


extern char syscall_after[];
extern char doreti_iret[];
extern char nop_ret[];
extern char copyout[];
extern char copyin[];
extern char kmem_alloc[];
extern char kernel_vmmap[];
extern char malloc[];
extern char M_something[];
extern char kproc_create[];
extern char malloc_arena_fix_start[];
extern char malloc_arena_fix_end[];
extern char kmem_alloc_rwx_fix[];

extern struct sysent sysents[];

static uint64_t dbgregs_for_kfunction_fixes[6] = {
    (uint64_t)malloc_arena_fix_start, (uint64_t)kmem_alloc_rwx_fix,
    (uint64_t) 0, 0,
    0, 0x405,
};

#define PS5_PAGE_SIZE 0x4000
#define ROUND_PG(x) (((x) + (PS5_PAGE_SIZE - 1)) & ~(PS5_PAGE_SIZE - 1))


int try_handle_kernel_fix_trap(uint64_t* regs)
{
    if (regs[RIP] == (uint64_t) malloc_arena_fix_start)
    {
        // pretend that the system does not have memory backed, will make it ask for more
        regs[RIP] = (uint64_t) malloc_arena_fix_end;
        return 1;
    }
    else if (regs[RIP] == (uint64_t) kmem_alloc_rwx_fix)
    {
        regs[RCX] = 7; // rwx
        regs[RIP] += 5;
        return 1;
    }

    return 0;
}


int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr)
{
    if(nr == 1)
    {
        uint64_t stack_frame[12] = {
            (uint64_t)doreti_iret,
            (uint64_t)nop_ret, regs[CS], regs[EFLAGS], regs[RSP], regs[SS],
        };
        read_dbgregs(stack_frame+6);
        if(!get_pcb_dbregs())
        {
            stack_frame[6] = stack_frame[7] = stack_frame[8] = stack_frame[9] = 0;
            stack_frame[10] &= -16;
        }
        push_stack(regs, stack_frame, sizeof(stack_frame));
        kpoke64(regs[RDI]+td_retval, 0);
        regs[RDI] = regs[RSP] + 48;
        regs[RSI] = args[RDI];
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyout;
    }
    else if(nr == 2)
    {
        //
        // Copyin
        //
        uint64_t stack_frame[14] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 1), [12] = regs[RDI]};
        push_stack(regs, stack_frame, sizeof(stack_frame));
        regs[RDI] = args[RDI];
        regs[RSI] = regs[RSP] + 48;
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyin;
    }
    else if(nr == 3)
    {
        return rdmsr(args[RDI], &args[RAX]) ? 0 : EFAULT;
    }
    //nr 4 reserved for wrmsr
    else if(nr == 5)
    {
        uint64_t stack_frame[16] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 2)};
        stack_frame[6] = args[RDI];
        stack_frame[7] = args[RSI];
        stack_frame[14] = regs[RDI];
        push_stack(regs, stack_frame, sizeof(stack_frame));
        regs[RDI] = args[RDX];
        regs[RSI] = regs[RSP] + 64;
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyin;
    }
    else if (nr == 6)
    {
        //
        // malloc with rwx
        //
        kpoke64(regs[RDI]+td_retval, 0);
        regs[RDI] = args[RDI];
        regs[RSI] = (uint64_t) M_something;
        regs[RDX] = 0x1;
        regs[RIP] = (uint64_t) malloc;

        start_syscall_with_dbgregs(regs, dbgregs_for_kfunction_fixes);
    } 
    else if (nr == 7)
    {
        // kproc_create
        kpoke64(regs[RDI]+td_retval, 0);
        regs[RDI] = args[RDI];
        regs[RSI] = args[RSI];
        regs[RDX] = 0;
        regs[RCX] = 0;
        regs[R8] = 0;
        regs[R9] = 0;
        kpoke64(regs[RSP] + 0x10, args[RDX]);
        
        regs[RIP] = (uint64_t) kproc_create;

    }
    
    else if(nr == 0xffffffff)
    {
        args[RAX] = 0;
        return 0;
    }
    return ENOSYS;
}

void handle_kekcall_trap(uint64_t* regs, uint32_t trap)
{
    if(trap == 1)
    {
        uint64_t stack_frame[14];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        regs[RIP] = stack_frame[13];
        if((uint32_t)regs[RAX])
            return;
        kpoke64(stack_frame[11]+td_retval, 0);
        set_pcb_dbregs();
        write_dbgregs(stack_frame+5);
    }
    else if(trap == 2)
    {
        uint64_t stack_frame[15];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        if((uint32_t)regs[RAX])
        {
            pop_stack(regs, &regs[RIP], 8);
            return;
        }
        uint32_t pid = stack_frame[5];
        uint32_t sysc_no = stack_frame[6];
        int64_t proc = kpeek64(stack_frame[13]+td_proc);
        while(proc < -0x100000000)
            proc = kpeek64(proc+8);
        while(proc && (uint32_t)kpeek64(proc+p_pid) != pid)
            proc = kpeek64(proc);
        if(!proc)
        {
            regs[RAX] = ESRCH;
            pop_stack(regs, &regs[RIP], 8);
            return;
        }
        regs[RDI] = kpeek64(proc+16);
        uint64_t stack_frame_2[14] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 3), [6] = stack_frame[13], regs[RDI]};
        memcpy(stack_frame_2+8, stack_frame+7, 48);
        if(sysc_no == SYS_sysarch && (uint32_t)stack_frame[7] == AMD64_GET_FSBASE)
        {
            stack_frame_2[1] = MKTRAP(TRAP_KEKCALL, 4);
            stack_frame_2[8] = kpeek64(kpeek64(regs[RDI]+td_pcb)+pcb_fsbase);
            kpoke64(stack_frame[13]+td_retval, 0);
        }
        else
            kpoke64(regs[RDI]+td_retval, 0);
        push_stack(regs, stack_frame_2, sizeof(stack_frame_2));
        regs[RAX] = (uint64_t)&sysents[sysc_no];
        if(sysc_no == SYS_sysarch && (uint32_t)stack_frame[7] == AMD64_GET_FSBASE)
        {
            regs[RIP] = (uint64_t)copyout;
            regs[RDI] = regs[RSP] + 64;
            regs[RSI] = stack_frame[8];
            regs[RDX] = 8;
        }
        else
        {
            regs[RIP] = kpeek64((uint64_t)&sysents[sysc_no].sy_call);
            regs[RSI] = regs[RSP] + 64;
            handle_syscall(regs, 0);
        }
    }
    else if(trap == 3 || trap == 4)
    {
        uint64_t stack_frame[14];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        if(trap == 3 && !(uint32_t)regs[RAX])
            kpoke64(stack_frame[5]+td_retval, kpeek64(stack_frame[6]+td_retval));
        regs[RIP] = stack_frame[13];
    }
}
