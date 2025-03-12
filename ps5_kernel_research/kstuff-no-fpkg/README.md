# Kernel research with Kstuff

This is a copy of [Kstuff](https://github.com/sleirsgoevy/ps4jb-payloads/tree/bd-jb/ps5-kstuff) [fork](https://github.com/ps5-payload-dev/kstuff) without the fpkg and fself support, which is intended for system debugging and study purposes only.

Currently:

1 - ASLR disabled for versions 5.0 and 4.03, achieved in the same way as the mprotect_fix patch.


## Build
Use the latest release from the [SDK](https://github.com/ps5-payload-dev/sdk):

`cd ps5-kstuff-ldr`
`make clean && make`

This will generate a file named `kstuff.elf`.


Todo:

1 - Rewrite the initial loader with well defined types
2 - Extend kstuff to support "modules" 
3 - Docs on how debug it with gdb