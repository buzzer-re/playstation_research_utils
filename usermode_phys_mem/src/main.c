#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ps5/kernel.h>

#include "../include/proc.h"
#include "../include/dmem.h"


int main(int argc, char const *argv[])
{
    struct flat_pmap proc_pmap;

    proc_get_pmap(getpid(), &proc_pmap);

    uint64_t dmap = proc_pmap.pm_pml4 - proc_pmap.pm_cr3; 
    printf("PID: %d\n", getpid());
    printf("Process CR3: %lx\n", proc_pmap.pm_cr3);
    printf("Procees DMAP: %lx\n", dmap);
    
    // testing
    uint64_t my_var = 10;
    printf("my_var: %lu\n", my_var);
    uint64_t phys_addr = vaddr_to_paddr((uint64_t) &my_var, dmap, proc_pmap.pm_cr3);

    printf("Phys addr: %#02lx\n", phys_addr);

    // Writing into phys
    uint64_t new_value = 0x100;
    kernel_copyin(&new_value, dmap + phys_addr, sizeof(new_value));

    printf("my_var => %lu\n", my_var);

    return 0;
}
