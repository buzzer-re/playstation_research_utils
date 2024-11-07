#include <stdio.h>
#include <sys/types.h>

#include "../include/proc.h"
#include "../include/ucred.h"


int main(int argc, char const *argv[])
{
    set_ucred_to_debugger();

    struct proc* sce_shell_ui = find_proc_by_name("SceShellUI");

    if (sce_shell_ui)
    {
        printf("SceShellUI pid %d\n", sce_shell_ui->pid);
        list_proc_modules(sce_shell_ui);
        //
        // Listing module
        //
    }   

    return 0;
}
