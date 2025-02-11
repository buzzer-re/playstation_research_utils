#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ps5/kernel.h"
#include "ps5/payload.h"

struct flat_pmap {
  uint64_t mtx_name_ptr;
  uint64_t mtx_flags;
  uint64_t mtx_data;
  uint64_t mtx_lock;
  uint64_t pm_pml4;
  uint64_t pm_cr3;
};

const size_t CMD_BUF_SIZE = 0x100;
const size_t DUMP_BUF_SIZE = 0x100000;  // 1Mb
const size_t PMAP_LOOKUP_PREFIX =
    0x4000000;  // 64Mb, should be multiple of DUMP_BUF_SIZE
enum Errors {
  ERR_LOG_SOCK = 1,
  ERR_LOG_CONNECT,
  ERR_PMAP_OFFSET_GUESS,
  ERR_DUMPER_BUF_MALLOC,
  ERR_DUMPER_SOCK,
  ERR_DUMPER_SETSOCKOPT,
  ERR_DUMPER_BIND,
  ERR_DUMPER_LISTEN,
  ERR_DUMPER_CMD_READ,
  ERR_DUMP_COPYOUT,
  ERR_DUMP_WRITE,
  ERR_PADDR_NEGATIVE,
  ERR_VADDR_NOT_PRESENT,
  ERR_VADDR_NO_LEAF,
};
struct page_level {
  int from;
  int to;
  size_t size;
  int sign_ext;
  int leaf;
};

const struct page_level LEVELS[] = {
    {.from = 39, .to = 47, .size = 1ULL << 39, .sign_ext = 1, .leaf = 0},
    {.from = 30, .to = 38, .size = 1ULL << 30, .sign_ext = 0, .leaf = 0},
    {.from = 21, .to = 29, .size = 1ULL << 21, .sign_ext = 0, .leaf = 0},
    {.from = 12, .to = 20, .size = 1ULL << 12, .sign_ext = 0, .leaf = 1},
};

enum pde_shift {
  PDE_PRESENT = 0,
  PDE_RW,
  PDE_USER,
  PDE_WRITE_THROUGH,
  PDE_CACHE_DISABLE,
  PDE_ACCESSED,
  PDE_DIRTY,
  PDE_PS,
  PDE_GLOBAL,
  PDE_PROTECTION_KEY = 59,
  PDE_EXECUTE_DISABLE = 63
};

const size_t PDE_PRESENT_MASK = 1;
const size_t PDE_RW_MASK = 1;
const size_t PDE_USER_MASK = 1;
const size_t PDE_WRITE_THROUGH_MASK = 1;
const size_t PDE_CACHE_DISABLE_MASK = 1;
const size_t PDE_ACCESSED_MASK = 1;
const size_t PDE_DIRTY_MASK = 1;
const size_t PDE_PS_MASK = 1;
const size_t PDE_GLOBAL_MASK = 1;
const size_t PDE_PROTECTION_KEY_MASK = 0xF;
const size_t PDE_EXECUTE_DISABLE_MASK = 1;

#define PDE_FIELD(pde, name) (((pde) >> PDE_##name) & PDE_##name##_MASK)

const size_t PDE_ADDR_MASK = 0xffffffffff800ULL;  // bits [12, 51]

#define PADDR_TO_DMAP(paddr) ((paddr) + dmap_base)
ssize_t guess_kernel_pmap_store_offset(size_t kdata_base) {
  char *kdata;
  ssize_t result = -1;
  ssize_t offset;
  struct flat_pmap pmap;

  kdata = malloc(DUMP_BUF_SIZE);
  if (kdata == NULL) {
    result = -ERR_DUMPER_BUF_MALLOC;
    goto guess_offset_out;
  }
  for (offset = 0; offset + sizeof(struct flat_pmap) < 0x4000000; ++offset) {
    if ((offset % DUMP_BUF_SIZE) == 0) {
      // get next chunk of kdata
      kernel_copyout(kdata_base + offset, kdata, DUMP_BUF_SIZE);
    }
    memcpy(&pmap, kdata + (offset % DUMP_BUF_SIZE), sizeof(pmap));
    if (pmap.mtx_flags == 0x1430000 && pmap.mtx_data == 0x0 &&
        pmap.mtx_lock == 0x4 && pmap.pm_pml4 != 0 &&
        (pmap.pm_pml4 & 0xFFFFFFFFULL) == pmap.pm_cr3) {
      result = offset;
      // last one is the best, so continue the search
    }
  }
guess_offset_out:
  if (kdata != NULL) {
    free(kdata);
  }
  return result;
}


#define LOG_PDE 1;
ssize_t vaddr_to_paddr(size_t vaddr, size_t dmap_base, size_t cr3,
                       size_t *page_end, int log_sock) {
  ssize_t paddr = cr3;
  uint64_t pd[512];
  const struct page_level *level;
#ifdef LOG_PDE
  char printbuf[512];
#endif

  for (size_t level_idx = 0; level_idx < 4; ++level_idx) {
    level = LEVELS + level_idx;
    if (paddr < 0) {
      // something is wrong
      return -ERR_PADDR_NEGATIVE;
    }
    kernel_copyout(PADDR_TO_DMAP(paddr), &pd, sizeof(pd));
    int idx_bits = (level->to - level->from) + 1;
    size_t idx_mask = (1ULL << idx_bits) - 1ULL;
    size_t idx = (vaddr >> level->from) & idx_mask;

    uint64_t pde = pd[idx];
    paddr = pde & PDE_ADDR_MASK;
    size_t leaf = level->leaf || PDE_FIELD(pde, PS);
#ifdef LOG_PDE
    sprintf(
        printbuf,
        "[+] level %#02lx, idx %#02lx, paddr %#02lx, leaf %#02lx\n"
        "    present %#02lx, rw %#02lx, user %#02lx, write_through %#02lx, cache_disable %#02lx,\n"
        "    accessed %#02lx, dirty %#02lx, ps %#02lx, global %#02lx, protection_key %#02lx,\n"
        "    execute_disable %#02lx\n",
        level_idx, idx, paddr, leaf, PDE_FIELD(pde, PRESENT),
        PDE_FIELD(pde, RW), PDE_FIELD(pde, USER), PDE_FIELD(pde, WRITE_THROUGH),
        PDE_FIELD(pde, CACHE_DISABLE), PDE_FIELD(pde, ACCESSED),
        PDE_FIELD(pde, DIRTY), PDE_FIELD(pde, PS), PDE_FIELD(pde, GLOBAL),
        PDE_FIELD(pde, PROTECTION_KEY), PDE_FIELD(pde, EXECUTE_DISABLE));
   // printf("%s\n", printbuf);
#endif

    if (!PDE_FIELD(pde, PRESENT)) {
      // something is wrong
      return -ERR_VADDR_NOT_PRESENT;
    }

    if (leaf) {
      *page_end = paddr + level->size;
      return paddr | (vaddr & (level->size - 1));
    }
  }
  return -ERR_VADDR_NO_LEAF;
}