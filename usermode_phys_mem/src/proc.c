#include "../include/proc.h"
#include <sys/sysctl.h>

uint32_t get_fw_version(void)
{
    int mib[2] = {1, 46};
    unsigned long size = sizeof(mib);
    unsigned int version = 0;
    sysctl(mib, 2, &version, &size, 0, 0);
    return version >> 16;
}


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


void list_all_proc_and_pid()
{

    uint64_t next = 0;
    kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uint64_t));
    struct proc* proc = (struct proc*) malloc(sizeof(struct proc));
    struct vmspace vmspace;

    do
    {
        kernel_copyout(next, (void*) proc, sizeof(struct proc));

        kernel_copyout((intptr_t) proc->p_vmspace, (void*) &vmspace, sizeof(vmspace));
        printf("%s - %d\n", proc->p_comm, proc->pid);

        kernel_copyout(next, &next, sizeof(uint64_t));

    } while (next);

    free(proc);
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

uint64_t proc_get_pmap(pid_t pid, struct flat_pmap* pmap)
{
    struct proc* proc = get_proc_by_pid(pid);

    if (!proc) return 0;

    struct vmspace vmspace;

    kernel_copyout((intptr_t) proc->p_vmspace, (void*) &vmspace, sizeof(vmspace));
    // the pmap seems to change between fw versions
    uint32_t fwver = get_fw_version();

    uint64_t pmap_offset = (fwver >= 0x700 ? 0x2E8 : 0x2E0);
    kernel_copyout((intptr_t) proc->p_vmspace + pmap_offset, pmap, sizeof(struct flat_pmap));


    return 0;
}

KernelData* proc_get_vmspace(struct proc* proc)
{
    KernelData* kernel_data = (KernelData*) malloc(sizeof(KernelData));

    struct vmspace* vmspace = (struct vmspace*) malloc(sizeof(struct vmspace));
    kernel_copyout((intptr_t) proc->p_vmspace, vmspace, sizeof(struct vmspace));

    kernel_data->kaddr = (uint64_t) proc->p_vmspace;
    kernel_data->uaddr = (void*) vmspace;

    return kernel_data;
}


KernelData* proc_get_next_entry(struct vm_map_entry* entry)
{
    KernelData* kernel_data = (KernelData*) malloc(sizeof(KernelData));
    struct vm_map_entry* next_entry = (struct vm_map_entry*) malloc(sizeof(struct vm_map_entry));

    kernel_copyout((intptr_t) entry->next, next_entry, sizeof(struct vm_map_entry));

    kernel_data->kaddr = (uint64_t) entry->next;
    kernel_data->uaddr = (void*) next_entry;

    return kernel_data;   
}

void proc_set_vm_entry_prot(uint64_t entry, uint16_t new_prot, uint16_t* old_prot)
{
    kernel_copyout(entry + VMSPACE_ENTRY_PROT, old_prot, sizeof(uint16_t));
    kernel_copyin(&new_prot, entry + VMSPACE_ENTRY_PROT, sizeof(uint16_t));
    kernel_copyin(&new_prot, entry + VMSPACE_ENTRY_MAX_PROT, sizeof(uint16_t));
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

            printf("%s - ", mod_info.filename);
            printf("%#02lx\n", mod_info.init);
        }
        
        free(handles);
    }
}


module_info_t* get_module_handle(pid_t pid, const char* module_name)
{
    size_t num_handles = 0;
    syscall(SYS_dl_get_list, pid, NULL, 0, &num_handles);
    
    if (num_handles)
    {
        uintptr_t* handles = (uintptr_t*) calloc(num_handles, sizeof(uintptr_t));
        syscall(SYS_dl_get_list, pid, handles, num_handles, &num_handles);

        module_info_t* mod_info = (module_info_t*) malloc(sizeof(module_info_t));
        
        for (int i = 0; i < num_handles; ++i)
        {
            bzero(mod_info, sizeof(module_info_t));
            syscall(SYS_dl_get_info_2, pid, 1, handles[i], mod_info);
            if (!strcmp(mod_info->filename, module_name))
            {
                return mod_info;
            }
        }
        
        free(handles);
        free(mod_info);
    }

    return NULL;
}






