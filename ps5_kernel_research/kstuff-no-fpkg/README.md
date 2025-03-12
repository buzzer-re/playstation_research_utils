# Kernel research with Kstuff

This is a copy of [Kstuff](https://github.com/sleirsgoevy/ps4jb-payloads/tree/bd-jb/ps5-kstuff) [fork](https://github.com/ps5-payload-dev/kstuff) without the fpkg and fself support, which is intended for system debugging and study purposes only.

Currently:

- ASLR [disabled](https://github.com/buzzer-re/playstation_research_utils/blob/787054ada7b54f2e2cfabd96ee03d2bf53d83397/ps5_kernel_research/kstuff-no-fpkg/ps5-kstuff/uelf/syscall_fixes.c#L25) for versions 5.0 and 4.03, achieved in the same way as the mprotect_fix patch


## Build
Use the latest release from the [SDK](https://github.com/ps5-payload-dev/sdk):

`cd ps5-kstuff-ldr`
`make clean && make`

This will generate a file named `kstuff.elf`.

To learn more about kstuff working, refer to [OnOffsets.md](https://gist.github.com/sleirsgoevy/26c482553b9fa604dd9b8ba7dfe654d6)

Todo:

- Rewrite the initial loader with well defined types
- Extend kstuff to support "modules" 
- Docs on how debug it with gdb
