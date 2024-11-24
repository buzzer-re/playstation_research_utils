#include "../include/parasite.h"


int write_parasite_loader(struct proc* proc)
{
    module_info_t* eboot = get_module_handle(proc->pid, "eboot.bin");
    int status = true;

    if (!eboot)
    {
        // 
        // Oh god 
        //

        printf("Unable to find the eboot.bin! make sure that this is a valid PS5 application\n");
        return status;
    } 

    //
    // Search .text begin
    // 

    module_section_t* text_section = NULL;

    for (int i = 0; i < MODULE_INFO_MAX_SECTIONS; ++i)
    {
        if (eboot->sections[i].prot & PROT_EXEC)
        {
            text_section = &eboot->sections[i];
            break;
        }
    }

    if (!text_section)
    {
        printf("Unable to find .text section on eboot.bin! aborting...\n");
        status = false;
        goto clean;
    }

    printf(".text: addr: %lx size: %lu bytes prot: %d\n", text_section->vaddr, text_section->size, text_section->prot);

    uint8_t dump[0x100] = {0};
    
    mdbg_copyout(proc->pid, text_section->vaddr, dump, 0x100);

    for (int i = 0; i < 0x100; ++i)
    {
        printf("%02x ", dump[i]);
    }

    puts(" ");

clean:
    free(eboot);

    return status;
}