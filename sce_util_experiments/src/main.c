#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/proc.h"
#include "../include/ucred.h"
#include "ps5/mdbg.h"

#define DUMP_SIZE 0x100

int main(int argc, char const *argv[])
{
    set_ucred_to_debugger();

    struct proc* sce_shell_ui = find_proc_by_name("SceShellUI");

    if (sce_shell_ui)
    {
        printf("SceShellUI pid %d\n", sce_shell_ui->pid);
        list_proc_modules(sce_shell_ui);
        module_info_t* mono_handle = get_module_handle(sce_shell_ui->pid, "libmonosgen-2.0.sprx");

        if (!mono_handle)
        {
            printf("Unable to find libmonosgen-2.0.sprx module information! exiting...\n");
            return 1;
        }
        
        uint64_t text_section = 0;
        
        //
        // Search .text
        //
        for (int i = 0; i < MODULE_INFO_MAX_SECTIONS; ++i)
        {
            if (mono_handle->sections[i].prot & PROT_EXEC)
            {
                text_section = mono_handle->sections[i].vaddr;
                break;
            }
        }

        if (text_section)
        {
            uint8_t dump[DUMP_SIZE] = {0};
            printf("\n\nlibmonosgen-2.0.sprx .text => %#lx \nCheck on some tool the following dump:\n\n", text_section);
            // mono_class_get_method_from_name TODO: Improve this method search by checking the NID on the local file
            mdbg_copyout(sce_shell_ui->pid, text_section + 0x00000000000854E0 , dump, DUMP_SIZE); 
            
            puts("mono_class_get_method_from_name:\n");
            for (int i = 0; i < DUMP_SIZE; ++i)
            {
                printf("%02x ", dump[i]);
                if (i && (i % 16 == 0))
                    puts("");
            }
            puts("");
        }

        free(mono_handle);
    }   

    return 0;
}
