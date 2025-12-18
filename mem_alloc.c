// -----------------------------------------------------------
// mem_alloc.c
// -----------------------------------------------------------
#include "mem_internal.h"
#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t last_scan_size;
volatile void *init_stack_ptr;

// --- Allocation API ---
void *allocate(uint64_t size) {

#ifdef DEBUG
  printf("%s: %" PRIu64 "\n", __FUNCTION__, size);
#endif

  if (init_stack_ptr == NULL) {
    initialize_stack_ptr();
  }

  if (last_scan_size != pool.available_size) {
    float ratio = (float)pool.available_size / pool.max_size;
#if 0
    if (fabsf(ratio - .25f) <= 1e-6 || fabsf(ratio - .5f) <= 1e-6 ||
        fabsf(ratio - .75f) <= 1e-6 || fabsf(ratio - 1.f) <= 1e-6)
#else
    if (fabsf(ratio - .5f) <= 1e-6 || fabsf(ratio - .75f) <= 1e-6 ||
        fabsf(ratio - .875f) <= 1e-6 || fabsf(ratio - 1.f) <= 1e-6)
#endif
    {
      last_scan_size = pool.available_size;
      scan_for_garbage();
    }
  }

  uint64_t aligned_size = align_size(size);
  block *blk = get_best_fit_block(aligned_size);

  if (!blk || blk->head.magic_number != MAGIC_NUMBER) {
    blk = create_block(aligned_size);
  } else {
    assert(blk->head.magic_number == MAGIC_NUMBER);
  }

  if (!blk)
    return NULL;

  blk->head.flags = 0;
  block_mark_live(blk);

  block_set_next_block(blk, NULL);

#ifdef DEBUG
  printf("%s %p\n", __FUNCTION__, (void *)((uintptr_t)blk + HEADER_SIZE));
#endif

  return (void *)((uintptr_t)blk + HEADER_SIZE);
}

bool claim(void *ptr) {

  if (!ptr)
    return false;

  pthread_mutex_lock(&pool_mutex);
  if (ptr < (void *)((uintptr_t)pool.head + HEADER_SIZE) ||
      (uintptr_t)ptr >= pool.current_break) {
    pthread_mutex_unlock(&pool_mutex);
    return false;
  }
  pthread_mutex_unlock(&pool_mutex);

  block *free_block = (block *)(((uintptr_t)ptr) - HEADER_SIZE);

#ifdef DEBUG
  printf("%s: %" PRIu64 " %p\n", __FUNCTION__, free_block->head.block_size,
         ptr);
#endif

  claim_block(free_block);
  return true;
}

void *reallocate(void *old_ptr, uint64_t new_size) {

  if (!old_ptr)
    return NULL;

  block *old_block = (block *)(((uintptr_t)old_ptr) - HEADER_SIZE);

#ifdef DEBUG
  printf("%s: %" PRIu64 " %p\n", __FUNCTION__, old_block->head.block_size,
         old_ptr);
#endif

  assert(old_block->head.magic_number == MAGIC_NUMBER);
  if (old_block->head.magic_number != MAGIC_NUMBER) {
    abort();
    return NULL;
  }
  if (old_block->head.block_size == align_size(new_size))
    return old_ptr;

  void *new_ptr = allocate(new_size);
  if (!new_ptr)
    return NULL;

  block *new_block = (block *)(((uintptr_t)new_ptr) - HEADER_SIZE);

  uint64_t copy_size = (old_block->head.block_size < new_block->head.block_size)
                           ? old_block->head.block_size
                           : new_block->head.block_size;

  memcpy(new_ptr, old_ptr, copy_size);
  claim(old_ptr);

  return new_ptr;
}

// --- Thread Creation Helper ---

int create_thread(pthread_t *_Nonnull thread_ptr,
                  pthread_attr_t const *_Nullable thread_attr,
                  void *_Nonnull (*_Nonnull start_routine)(void *_Nonnull),
                  void *_Nullable input) {
  void *thread_stack;
  size_t thread_stack_size;
  bool stack_is_set = true;

  if (thread_attr) {
    pthread_attr_getstack(thread_attr, &thread_stack, &thread_stack_size);
    if (thread_stack && thread_stack > pool.head &&
        (uintptr_t)thread_stack < pool.current_break) {
      stack_is_set = true;
    }
  }

  if (!stack_is_set) {
    thread_stack_size = PTHREAD_STACK_MIN + 1 * MB;
    thread_stack = allocate(thread_stack_size);
    thread_attr = allocate(sizeof(*thread_attr));
    if (!thread_attr) {
      return -1;
    }
    pthread_attr_init((pthread_attr_t *)thread_attr);
    pthread_attr_setstack((pthread_attr_t *)thread_attr, thread_stack,
                          thread_stack_size);
  }

  return pthread_create(thread_ptr, thread_attr, start_routine, input);
}

// --- Malloc Overrides ---
#ifdef CAN_REPLACE_MALLOC
void *malloc(size_t size) { return allocate(size); }
void *calloc(size_t count, size_t unit_size) {
  if (!count || !unit_size)
    return NULL;
  uint64_t size = count * unit_size;
  /* check mul overflow */
  if (unit_size != size / count)
    return NULL;
  void *ptr = malloc(size);
  if (!ptr)
    return NULL;
  memset(ptr, 0, size);
  return ptr;
}

void free(void *ptr) { claim(ptr); }

void *realloc(void *ptr, size_t new_size) { return reallocate(ptr, new_size); }
#endif

// -----------------------------------------------------------
