
#include <ps5kld/kernel.h>
#include <ps5kld/intrin.h>
#include <ps5kld/machine/idt.h>
#include <ps5kld/offsets/500.h>
#include <sys/cpuset.h>

extern void memcpy(uint64_t* dst, uint64_t* src, uint32_t size);
extern uint64_t int_handler;

#define IPI_VECTOR_ENTRY 0xF1

typedef struct __kproc_args
{
    uint64_t kdata_base;
    uint32_t fwver;
} kproc_args;

struct apic_ops
{
  void (*create)(unsigned int, int);
  void (*init)(unsigned __int64);
  void (*xapic_mode)(void);
  void (*setup)(int);
  void (*dump)(const char *);
  void (*disable)(void);
  void (*eoi)(void);
  int (*id)(void);
  int (*intr_pending)(unsigned int);
  void (*set_logical_id)(unsigned int, unsigned int, unsigned int);
  unsigned int (*cpuid)(unsigned int);
  unsigned int (*alloc_vector)(unsigned int, unsigned int);
  unsigned int (*alloc_vectors)(unsigned int, unsigned int *, unsigned int, unsigned int);
  void (*enable_vector)(unsigned int, unsigned int);
  void (*disable_vector)(unsigned int, unsigned int);
  void (*free_vector)(unsigned int, unsigned int, unsigned int);
  int (*enable_pmc)(void);
  void (*disable_pmc)(void);
  void (*reenable_pmc)(void);
  void (*enable_cmc)(void);
  void (*ipi_raw)(int, unsigned int);
  void (*ipi_vectored)(unsigned int, int);
  int (*ipi_wait)(int);
  int (*ipi_alloc)(void *ipifunc);
  void (*ipi_free)(int vector);
  int (*set_lvt_mask)(unsigned int, unsigned int, unsigned __int8);
  int (*set_lvt_mode)(unsigned int, unsigned int, unsigned int);
  int (*set_lvt_polarity)(unsigned int, unsigned int, unsigned int);
  int (*set_lvt_triggermode)(unsigned int, unsigned int, unsigned int);
};


void handle_int(void* tf)
{
    // kprintf("Hello from IPI handler\n");
    // while(1);
    struct apic_ops* apic_ops = kapic_ops;
    apic_ops->eoi();
}
#define	APIC_LOCAL_INTS	240
#define	APIC_ERROR_INT	APIC_LOCAL_INTS
#define	APIC_THERMAL_INT (APIC_LOCAL_INTS + 1)
#define	APIC_CMC_INT	(APIC_LOCAL_INTS + 2)
#define	APIC_IPI_INTS	(APIC_LOCAL_INTS + 3)

#define	IPI_RENDEZVOUS	(APIC_IPI_INTS)		/* Inter-CPU rendezvous. */
#define	IPI_INVLTLB	(APIC_IPI_INTS + 1)	/* TLB Shootdown IPIs */
#define	IPI_INVLPG	(APIC_IPI_INTS + 2)
#define	IPI_INVLRNG	(APIC_IPI_INTS + 3)
#define	IPI_INVLCACHE	(APIC_IPI_INTS + 4)
int module_start(kproc_args* args)
{    
    init_kernel(args->fwver);
    kprintf("Kernel base: %#02lx\n", get_kernel_base());


    uint32_t apic_mask = 0;

    // for (uint32_t i = 0; i < 16; ++i)
    {
        apic_mask |= (1 << cpu_apic_ids[PCPU_GET(cpuid)]);
    }
    
    uint8_t idt[10];
    __sidt(&idt);
    IDTR* idtr = (IDTR*) idt;
    
    
    idt_64* entry = (idt_64*) idtr->base;
    idt_64* ipi_handler = &entry[IPI_VECTOR_ENTRY];
    idt_64* invlcache_entry = &entry[IPI_INVLCACHE];
    // memcpy(ipi_handler, invlcache_entry)
    kprintf("IPI_INVLCACHE handler: %lx\n", UNPACK_HANDLER_ADDR(invlcache_entry));
    uint64_t handler = int_handler;
    ipi_handler->offset_low    = handler & 0xFFFF;
    ipi_handler->selector      = 0x8;  
    ipi_handler->ist_index     = 0;                         
    ipi_handler->type          = 0xE;                 
    ipi_handler->dpl           = 0;                         
    ipi_handler->present       = 1;                          
    ipi_handler->offset_middle = (handler >> 16) & 0xFFFF;
    ipi_handler->offset_high   = (handler >> 32) & 0xFFFFFFFF;


    kprintf("Mask: %d\nregistered IPI handler (int_handler)", apic_mask);

    kprintf("Sending IPI...\n");

    struct apic_ops* apic_ops = (struct apic_ops*) kapic_ops;


    apic_ops->ipi_vectored(IPI_VECTOR_ENTRY, apic_mask);
    kprintf("Done\n");

    return 1;
}
