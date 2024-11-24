#include "../include/shellcode.h"


//
// The code to be inject on the .text of the target process
// it will start a unix socket and wait for the code to be injected into the target
// after received the target code, the socket will be closed and a shared object will be loaded into this process
// them, it will overwrite the shared library code with ours, when everything is ready we are going to execute the code into a different thread and hopefully not break the target app
//
void stager()
{

}