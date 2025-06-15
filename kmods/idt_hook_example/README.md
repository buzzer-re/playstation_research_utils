# IDT hook example


IDT hook example, hooking int 3 gate (Software Breakpoint).

Supported fw:
- 4.03 (kldload on branch master/dev)
- 5.0  (kldload dev)

Offets used:

- kprintf (logging)
- Xfast_syscall (get kernel base)

[kldload](https://github.com/buzzer-re/PS5_kldload)
[kldload-dev](https://github.com/buzzer-re/PS5_kldload/tree/dev?tab=readme-ov-file#using-the-dev-branch)