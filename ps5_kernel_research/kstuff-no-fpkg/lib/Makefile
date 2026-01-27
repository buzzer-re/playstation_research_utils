UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    CROSS_CC ?= x86_64-elf-gcc
    CROSS_LD ?= x86_64-elf-ld
    NOSTDINC :=
else
    CROSS_CC ?= gcc
    CROSS_LD ?= ld
    NOSTDINC := -nostdinc
endif

all: lib.a lib-ps5.a lib-elf.a lib-elf-ps5.a

clean:
	rm -f lib.a lib-*.a *.o syscalls.asm syscalls-ps5.asm

dl.o: dl.c
	$(CROSS_CC) -std=gnu11 -c -isystem ../freebsd-headers $(NOSTDINC) -fno-stack-protector dl.c -o dl.o -fPIE -ffreestanding

crt-elf-c.o: crt-elf-c.c
	$(CROSS_CC) -std=gnu11 -c -isystem ../freebsd-headers $(NOSTDINC) -fno-stack-protector -O3 crt-elf-c.c -o crt-elf-c.o -fPIE -ffreestanding

crt.o: crt.asm
	yasm -f elf64 crt.asm

crt-elf.o: crt-elf.asm
	yasm -f elf64 crt-elf.asm

rfork.o: rfork.asm
	yasm -f elf64 rfork.asm

syscalls.o: syscalls.asm
	yasm -f elf64 syscalls.asm

syscalls.asm: syscalls.py syscalls.txt
	python3 syscalls.py > syscalls.asm

syscalls-ps5.o: syscalls-ps5.asm
	yasm -f elf64 syscalls-ps5.asm

syscalls-ps5.asm: syscalls-ps5.py
	python3 syscalls-ps5.py > syscalls-ps5.asm

lib.a: crt.o rfork.o dl.o syscalls.o
	$(CROSS_LD) -r crt.o rfork.o dl.o syscalls.o -o lib.a

lib-ps5.a: crt.o dl.o syscalls-ps5.o
	$(CROSS_LD) -r crt.o dl.o syscalls-ps5.o -o lib-ps5.a

lib-elf.a: crt-elf.o crt-elf-c.o dl.o syscalls.o
	$(CROSS_LD) -r crt-elf.o crt-elf-c.o dl.o syscalls.o -o lib-elf.a

lib-elf-ps5.a: crt-elf.o crt-elf-c.o dl.o syscalls-ps5.o
	$(CROSS_LD) -r crt-elf.o crt-elf-c.o dl.o syscalls-ps5.o -o lib-elf-ps5.a
