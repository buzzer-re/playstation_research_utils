#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/proc.h"
#include "../include/ucred.h"
#include "../include/parasite.h"

#include "ps5/mdbg.h"

#include <dlfcn.h>

#define DUMP_SIZE 0x100


#define TARGET_SPRX "libicu.sprx"

int main(int argc, char const *argv[])
{
    set_ucred_to_debugger();

    struct proc* target_proc = find_proc_by_name("SceShellUI");

    if (target_proc)
    {

        write_parasite_loader(target_proc);
        free(target_proc);

        // void* handle = dlopen("libicu.sprx", RTLD_LAZY);

        // if (!handle)
        // {
        //     printf("Unable to load "TARGET_SPRX" inside the target!");
        //     free(myself);
        //     return 0;
        // }

        // // printf("SceShellUI pid %d\n", myself->pid);
        // list_proc_modules(myself);

        // module_info_t* lib_handle = get_module_handle(myself->pid, TARGET_SPRX);

        // if (!lib_handle)
        // {
        //     printf("Unable to find libmonosgen-2.0.sprx module information! exiting...\n");
        //     return 1;
        // }
        
        // uint64_t text_section = 0;
        
        // //
        // // Search .text
        // //
        // for (int i = 0; i < MODULE_INFO_MAX_SECTIONS; ++i)
        // {
        //     if (lib_handle->sections[i].prot & PROT_EXEC)
        //     {
        //         text_section = lib_handle->sections[i].vaddr;
        //         break;
        //     }
        // }

        // if (text_section)
        // {  
        //     func f = (func) text_section;
        //     unsigned char ret[] = {0x48, 0xc7, 0xc0, 0x0a, 0x00, 0x00, 0x00, 0xc3};           
        //     mdbg_copyin(myself->pid, ret, text_section, sizeof(ret));

        //     int r = f();

        //     printf("Done => %d\n", r);
        // }

        // free(lib_handle);
        // dlclose(handle);

    }   

    return 0;
}
