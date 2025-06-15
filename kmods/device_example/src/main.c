
#include <ps5kld/kernel.h>
#include <ps5kld/intrin.h>
#include <ps5kld/machine/idt.h>
#define _KERNEL
#include <sys/param.h>
#include <sys/conf.h>
       

#define devkit_maybe_check_1 0x9cf1f8
#define devkit_maybe_check_2 0x6646817
#define idt_offset 0x660dca0
#define doireti_iretq -0xa04f93


typedef struct __kproc_args
{
    uint64_t kdata_base;
    uint32_t fwver;
} kproc_args;


// Example implementations
static int
mydev_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
    kprintf("mydev_open called\n");
    //  __asm__("int3");
    // while(1);
    return 0;
}

static int
mydev_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
    kprintf("mydev_close called\n");
    //  __asm__("int3");
    // while(1);
    return 0;
}

static int
mydev_write(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
    kprintf("mydev_write called\n");
    //  __asm__("int3");
    // while(1);
    return 0;
}

static int
mydev_read(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
    kprintf("mydev_read called\n");
    //  __asm__("int3");
    // while(1);
    return 0;
}


void *memset(void *dest, int value, size_t size) {
    unsigned char *ptr = (unsigned char *)dest;
    while (size--) {
        *ptr++ = (unsigned char)value;
    }
    return dest;
}



typedef struct __attribute__((__packed__)) __trap_frame
{
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
   // uint64_t error_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t eflags;
    uint64_t rsp;
    uint64_t ss;
} trap_frame_t;



int handle_int(trap_frame_t* frame)
{
    uint64_t kernel_base = get_kernel_base();
    // kprintf("int3 at %p - %#02lx\n", frame->rip, frame->rip - kernel_base);
    kprintf("Called handle_int!\n");

    // while(1);
    return 0;
}

extern int int_handler();


int module_start(kproc_args* args)
{    
    init_kernel(args->fwver);
    kprintf("Kernel base: %#02lx\n", get_kernel_base());
    kprintf("Creating device\n");

    static struct cdevsw device_sw = {
        .d_version = D_VERSION,
        .d_flags =  0,
        .d_open = mydev_open,
        .d_close = mydev_close,
        .d_read = mydev_read,
        .d_write = mydev_write,
        .d_ioctl = mydev_open,
        .d_poll = mydev_open,
        .d_mmap = mydev_open,
        .d_strategy = mydev_open,
        .d_name = "b_device"
    };

    struct cdev* dummy_device = kmake_dev(&device_sw, 0, 0, 0, 0666, "b_device");

    // kprintf("Done, hijacking idt...\n");

    // kdestroy_dev(dummy_device);

    //
    // prepare idt hook
    //

    uint8_t idt[10];
    __sidt(&idt);
    
    IDTR* idtr = (IDTR*) idt;
    idt_64* entry = (idt_64*) idtr->base;
    idt_64* ud = &entry[3];

    kprintf("int1 at: %p\n", UNPACK_HANDLER_ADDR(ud));
    kprintf("idt base: %#02llx\n", idtr->base);
    kprintf("ud handler: %p\n", UNPACK_HANDLER_ADDR(ud));

    uint64_t gate = (uint64_t) int_handler;
    ud->offset_low     = (gate & 0xFFFF);
    ud->offset_middle  = (gate >> 16 ) & 0xFFFF;
    ud->offset_high    = (gate >> 32 ) & 0xFFFFFFFF;

    // // kprintf("Hooking kcfi_check_fail...\n");

    // // uint64_t dr7;
    // // __writedr0(args->kdata_base-0x7d8050);          // Set DR0
    // // dr7 = __readdr7();                   // Read current DR7

    // // dr7 |= 0x1;                          // Enable local breakpoint on DR0
    // // dr7 &= ~(0xf << 16);                // Clear LENn and RWn for DR0
    // // dr7 |= (0x3 << 18);                 // Set RW0 = 11 (read/write), LEN0 = 00 (1 byte)

    // // __writedr7(dr7);                     // Write back to DR7


    // // // uint32_t* devkit_maybe_check_1_addr = args->kdata_base + devkit_maybe_check_1;
    // uint8_t* devkit_maybe_check_2_addr = args->kdata_base + devkit_maybe_check_2;

    // // // *devkit_maybe_check_1_addr = 4;
    // *devkit_maybe_check_2_addr = 1;

    // kprintf("Done\n");

   

    return 1;
}
