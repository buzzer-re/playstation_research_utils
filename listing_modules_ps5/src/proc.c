#include "../include/proc.h"

struct proc* find_proc_by_name(const char* proc_name)
{

    uint64_t next = 0;
    kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uint64_t));
    struct proc* proc = (struct proc*) malloc(sizeof(struct proc));
    struct vmspace vmspace;

    do
    {
        kernel_copyout(next, (void*) proc, sizeof(struct proc));

        kernel_copyout((intptr_t) proc->p_vmspace, (void*) &vmspace, sizeof(vmspace));

        if (!strcmp(proc->p_comm, proc_name))
            return proc;

        kernel_copyout(next, &next, sizeof(uint64_t));

    } while (next);

    free(proc);
    return NULL;
}

struct proc* get_proc_by_pid(pid_t pid)
{
    uintptr_t next = 0;

    kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uintptr_t));
    struct proc* proc =  (struct proc*) malloc(sizeof(struct proc));
    do
    {
        kernel_copyout(next, proc, sizeof(struct proc));

        if (proc->pid == pid)
            return proc;

        kernel_copyout(next, &next, sizeof(uint64_t));

    } while (next);

    free(proc);
    return NULL;
}


//
// List process modules by using the sys_dynlib_get_info_ex syscall
//
void list_proc_modules(struct proc* proc)
{
    size_t num_handles = 0;
    syscall(SYS_dl_get_list, proc->pid, NULL, 0, &num_handles);
    
    if (num_handles)
    {
        uintptr_t* handles = (uintptr_t*) calloc(num_handles, sizeof(uintptr_t));
        syscall(SYS_dl_get_list, proc->pid, handles, num_handles, &num_handles);

        for (int i = 0; i < num_handles; ++i)
        {
            module_info_t mod_info;
            bzero(&mod_info, sizeof(mod_info));

            syscall(SYS_dl_get_info_2, proc->pid, 1, handles[i], &mod_info);

            printf("%s - %#lx\n", mod_info.filename, mod_info.unknown3);
        }
        
        free(handles);
    }
}






