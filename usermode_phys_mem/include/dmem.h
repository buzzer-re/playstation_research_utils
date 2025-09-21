#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ps5/kernel.h"
#include "ps5/payload.h"



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


//
// A simplified version of the https://github.com/cheburek3000/meme_dumper/blob/main/source/main.c implementation
//
ssize_t vaddr_to_paddr(uint64_t vaddr, size_t dmap_base, size_t cr3) {
  ssize_t paddr = cr3;
  uint64_t pd[512];
  const struct page_level *level;


  for (size_t level_idx = 0; level_idx < 4; ++level_idx) {
    level = LEVELS + level_idx;
    if (paddr < 0) {
      // something is wrong
      return 0;
    }
    kernel_copyout(PADDR_TO_DMAP(paddr), &pd, sizeof(pd));
    int idx_bits = (level->to - level->from) + 1;
    size_t idx_mask = (1ULL << idx_bits) - 1ULL;
    size_t idx = (vaddr >> level->from) & idx_mask;

    uint64_t pde = pd[idx];
    paddr = pde & PDE_ADDR_MASK;
    size_t leaf = level->leaf || PDE_FIELD(pde, PS);

    if (!PDE_FIELD(pde, PRESENT)) {
      // something is wrong
      return 0;
    }

    if (leaf) {
      return paddr | (vaddr & (level->size - 1));
    }
  }
  return 0;
}