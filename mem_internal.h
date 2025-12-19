// -----------------------------------------------------------
// mem_internal.c
// -----------------------------------------------------------
#ifndef MEM_INTERNAL_H
#define MEM_INTERNAL_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// --- Configuration & Macros ---
#define WORD_SIZE (8)
#define HEADER_SIZE (offsetof(struct block, payload))
#define MAGIC_NUMBER 0xed

#define SET_BIT(x, n) ((x) |= (UINT64_C(1) << (n)))
#define CLEAR_BIT(x, n) ((x) &= ~(UINT64_C(1) << (n)))
#define GET_BIT(x, n) (((x) & (UINT64_C(1) << (n))) != 0)

#define FLAG_LIVE 0
#define FLAG_MARK 1

#define kB (1024)
#define MB (kB * kB)
#define GB (MB * kB)

#ifndef POOL_SIZE_IN_MB
#define POOL_SIZE_IN_MB (512)
#endif
#define POOL_SIZE (POOL_SIZE_IN_MB * MB)

#ifndef __clang__
#define _Nonnull
#define _Nullable
#define constructor(x) __constructor__
#endif

// --- Data Structures ---
typedef struct
{
  uint64_t block_size;
  uint32_t next_offset;
  uint8_t magic_number;
  uint8_t flags;
} header;

typedef struct block
{
  header head;
  uint8_t payload;
} block;

struct memory_pool
{
  void *head;
  void *prehead;
  uintptr_t current_break;
  uint64_t max_size;
  uint64_t available_size;
};

// --- Shared Globals ---
extern struct memory_pool pool;
extern pthread_mutex_t pool_mutex;
extern pthread_mutex_t free_list_mutex;
extern pthread_mutex_t mark_queue_mutex;
extern pthread_mutex_t threads_mutex;
extern block *free_list;
extern block *mark_queue;
extern volatile void *init_stack_ptr;

// --- Inline Bit Manipulation Helpers ---

static inline bool block_is_live(const block *blk)
{
  return GET_BIT(blk->head.flags, FLAG_LIVE);
}
static inline bool block_is_marked(const block *blk)
{
  return GET_BIT(blk->head.flags, FLAG_MARK);
}

static inline void block_mark_live(block *blk)
{
  SET_BIT(blk->head.flags, FLAG_LIVE);
}
static inline void block_mark_marked(block *blk)
{
  SET_BIT(blk->head.flags, FLAG_MARK);
}

static inline void block_clear_live(block *blk)
{
  CLEAR_BIT(blk->head.flags, FLAG_LIVE);
}
static inline void block_clear_marked(block *blk)
{
  CLEAR_BIT(blk->head.flags, FLAG_MARK);
}

static inline bool block_is_free(const block *blk)
{
  return !block_is_live(blk);
}
static inline void block_mark_free(block *blk) { block_clear_live(blk); }
static inline void block_clear_free(block *blk) { block_mark_live(blk); }

// --- Internal Helper Prototypes ---
uint64_t align_size(uint64_t size);
block *block_get_next_block(block *blk);
bool block_set_next_block(block *blk, block *next);
void add_to_free_list(block *free_block);
block *create_block(uint64_t size);
block *fit_block(block *best_fit, uint64_t size);
void coalesce();
bool is_valid_block_address(uintptr_t address);
void scan_for_garbage(void);
void platform_get_stack_bounds(void **start, void **end);
void *platform_get_memory(uint64_t size);
block *get_best_fit_block(uint64_t size);
bool mark_queue_push(block *blk);
block *mark_queue_pop();
void initialize_stack_ptr();
bool linkedlist_push(block **list, block *blk);
block *linkedlist_pop(block **list);
void claim_block(block *free_block);

#endif
// -----------------------------------------------------------
