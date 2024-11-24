#pragma once

#include "../include/proc.h"
#include "ps5/mdbg.h"
#include <stdbool.h>


//
// TODO: Choose a better candidate
//
#define TARGET_SPRX "libicu.sprx"

int write_parasite_loader(struct proc* proc);
int launch_parasite();

// int write_shellcode(struct proc* proc, )