#pragma once

typedef unsigned long  uint64_t;
typedef unsigned int uint32_t;
#define X86_CR0_WP (1 << 16)
// MSRs



#define DEFINE_DR_RW(N) \
static inline __attribute__((always_inline)) uint64_t __readdr##N(void) { \
    uint64_t val; \
    __asm__ volatile("movq %%dr" #N ", %0" : "=r"(val) :: "memory"); \
    return val; \
} \
static inline __attribute__((always_inline)) void __writedr##N(uint64_t val) { \
    __asm__ volatile("movq %0, %%dr" #N :: "r"(val) : "memory"); \
} \

DEFINE_DR_RW(0)
DEFINE_DR_RW(1)
DEFINE_DR_RW(2)
DEFINE_DR_RW(3)
DEFINE_DR_RW(6)
DEFINE_DR_RW(7)

//
// This intrinsics code make use of the GAS syntax, which the whole FreeBSD uses, it will make our compilation less error-prone (trust me)
//

static inline __attribute__((always_inline)) uint64_t __readmsr(unsigned long __register) {
    unsigned long __edx;
    unsigned long __eax;
    __asm__ volatile("wrmsr"
            : "=d"(__edx), "=a"(__eax)
            : "c"(__register));
    return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

static inline __attribute__((always_inline)) void __writemsr(unsigned long __register, uint64_t __value) {
    unsigned long __edx = (unsigned long)(__value >> 32);
    unsigned long __eax = (unsigned long)(__value & 0xFFFFFFFF);
    __asm__ volatile("wrmsr"
            :
            : "c"(__register), "d"(__edx), "a"(__eax));
}


static inline __attribute__((always_inline)) uint64_t __readcr0(void) {
    uint64_t cr0;
    __asm__ volatile("movq %%cr0, %0"
                    : "=r"(cr0)
                    :
                    : "memory");
  return cr0;
}

static inline __attribute__((always_inline)) uint64_t __readcr3(void) {
    uint64_t cr3;
    __asm__ volatile("movq %%cr3, %0"
                    : "=r"(cr3)
                    :
                    : "memory");
  return cr3;
}

static inline __attribute__((always_inline)) uint64_t __readcr4(void) {
    uint64_t cr4;
    __asm__ volatile("movq %%cr4, %0"
                    : "=r"(cr4)
                    :
                    : "memory");
  return cr4;
}




static inline __attribute__((always_inline)) void __writecr0(uint64_t cr0) {
    __asm__ volatile("movq %0, %%cr0"
                    :
                    : "r"(cr0)
                    : "memory");
}

static inline __attribute__((always_inline)) void __writecr4(uint64_t cr4) {
    __asm__ volatile("movq %0, %%cr4"
                    :
                    : "r"(cr4)
                    : "memory");
}

static inline __attribute__((always_inline)) void __sidt(uint64_t* idtr) {
    __asm__ volatile("sidt %0" :: "m"(*idtr));
}



// static inline __attribute__((always_inline)) uint64_t read_rflags(void)
// {
//     uint64_t	rf;

//     __asm__ volatile("pushfq; popq %0" : "=r" (rf));
//     return (rf);
// }

// static inline __attribute__((always_inline)) void write_rflags(uint64_t rf)
// {
//     __asm__ volatile("pushq %0;  popfq" : : "r" (rf));
// }

// static inline __attribute__((always_inline)) void disable_intr(void)
// {
//     __asm__ volatile("cli" : : : "memory");
// }

// static inline __attribute__((always_inline)) uint64_t intr_disable(void)
// {
//     uint64_t rflags;

//     rflags = read_rflags();
//     disable_intr();
//     return (rflags);
// }

// static inline __attribute__((always_inline)) void intr_restore(uint64_t rflags)
// {
//     write_rflags(rflags);
// }