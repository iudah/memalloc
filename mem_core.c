// -----------------------------------------------------------
// mem_core.c
// -----------------------------------------------------------
#include "mem_internal.h"
#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef DEBUG
#include <stdio.h>
#endif

#define BLOCK_AT(offset) ((block *)((uintptr_t)pool.head + (offset)))

struct memory_pool pool;
pthread_mutex_t pool_mutex;
pthread_mutex_t free_list_mutex;
pthread_mutex_t mark_queue_mutex;
pthread_mutex_t threads_mutex;

block *free_list;

// --- Math Helpers ---
uint64_t align_size(uint64_t size) {
  if (size == 0)
    return WORD_SIZE;
  return (size + (WORD_SIZE - 1)) & ~(WORD_SIZE - 1);
}

// --- Block & List Manipulation ---
block *block_get_next_block(block *blk) {
  if (!blk)
    return NULL;
  block *nxt_blk =
      blk && blk->head.next_offset ? BLOCK_AT(blk->head.next_offset) : NULL;

  if (nxt_blk == blk) {
    // This block is pointing back to itself
    return NULL;
  }

  return nxt_blk;
}

bool block_set_next_block(block *blk, block *next) {
  if (!blk || blk == next)
    return false;
  if (!next) {
    blk->head.next_offset = 0;
  } else {
    blk->head.next_offset = (uintptr_t)next - (uintptr_t)pool.head;
  }
  return true;
}

bool linkedlist_push(block **list, block *blk) {
  if (!blk || !list)
    return false;
  block_set_next_block(blk, *list);
  *list = blk;
  return true;
}

block *linkedlist_pop(block **list) {
  if (!list)
    return NULL;
  block *blk = *list;
  if (!blk)
    return NULL;
  *list = block_get_next_block(blk);
  block_set_next_block(blk, NULL);
  return blk;
}

// --- Specific List Helpers ---
bool freelist_push(block *blk) {

#ifdef DEBUG
  assert(!block_is_live(blk));
#endif

  block_set_next_block(blk, NULL);
  block_mark_free(blk);
  return linkedlist_push(&free_list, blk);
}

block *freelist_pop() { return linkedlist_pop(&free_list); }

bool mark_queue_push(block *blk) {
#ifdef DEBUG
  assert(block_is_live(blk));
  assert(!block_is_scanned(blk));
#endif

  return linkedlist_push(&mark_queue, blk);
}

block *mark_queue_pop() { return linkedlist_pop(&mark_queue); }

block *fit_block(block *best_fit, uint64_t size) {
  if (!best_fit) {
    return NULL;
  }

  auto extra_payload_min = align_size(WORD_SIZE);

  if (best_fit->head.block_size <= (size + HEADER_SIZE + extra_payload_min)) {
    best_fit->head.flags = 0;
    block_mark_live(best_fit);
    block_set_next_block(best_fit, NULL);
    return best_fit;
  }

  uint64_t extra_size = best_fit->head.block_size - size - HEADER_SIZE;

  // Split
  block *extra = (block *)((uintptr_t)best_fit + HEADER_SIZE + size);
  extra->head.block_size = extra_size;
  extra->head.magic_number = MAGIC_NUMBER;

  extra->head.flags = 0;
  block_mark_free(extra);
  block_set_next_block(extra, NULL);
  add_to_free_list(extra);

  best_fit->head.block_size = size;
  best_fit->head.flags = 0;
  block_mark_live(best_fit);
  block_set_next_block(best_fit, NULL);

  return best_fit;
}

// --- Best Fit Logic ---
block *get_best_fit_block(uint64_t size) {
  pthread_mutex_lock(&free_list_mutex);

  block *best = NULL, *best_prev = NULL;
  block *prev = NULL, *cur = free_list;

  while (cur) {
    if (!is_valid_block_address((uintptr_t)cur))
      break;
    if (cur->head.magic_number != MAGIC_NUMBER)
      break;

    if (cur->head.block_size >= size &&
        (!best || cur->head.block_size < best->head.block_size)) {
      best = cur;
      best_prev = prev;
      if (cur->head.block_size == size)
        break; // exact fit early-exit
    }
    prev = cur;
    cur = block_get_next_block(cur);
  }

  if (best) {
    if (best_prev)
      block_set_next_block(best_prev, block_get_next_block(best));
    else
      free_list = block_get_next_block(best);
  }

  pthread_mutex_unlock(&free_list_mutex);

  return fit_block(best, size);
}

bool is_valid_block_address(uintptr_t address) {
  return address <= pool.current_break &&
         (address + sizeof(struct block)) <= pool.current_break;
}

block *create_block(uint64_t size) {
  const uint64_t aligned_payload = align_size(size);
  const uint64_t total = HEADER_SIZE + aligned_payload;

  pthread_mutex_lock(&pool_mutex);

  uintptr_t end = (uintptr_t)pool.prehead + pool.max_size;
  if (pool.current_break + total > end) {
    pthread_mutex_unlock(&pool_mutex);
    return NULL; // OOM
  }

  block *block = (struct block *)pool.current_break;
  block->head.block_size = aligned_payload; // payload size

  block->head.magic_number = MAGIC_NUMBER;

  pool.current_break += total;
  pool.available_size -= total;

  pthread_mutex_unlock(&pool_mutex);

  block->head.flags = 0;
  block_mark_live(block);
  block_set_next_block(block, NULL);

  return block;
}

static void recompute_available_size() {
  uint64_t avail = 0;
  uintptr_t cur = (uintptr_t)pool.head;
  while (cur < pool.current_break) {
    block *b = (block *)cur;
    uint64_t total = HEADER_SIZE + b->head.block_size;
    if (!block_is_live(b))
      avail += total;
    cur += total;
  }
  pool.available_size = avail;
}

void coalesce() {
  pthread_mutex_lock(&pool_mutex);
  pthread_mutex_lock(&free_list_mutex);

  // Clear list to rebuild it completely
  free_list = NULL;

  uintptr_t current = (uintptr_t)pool.head;

  while (current < pool.current_break) {
    block *cur_blk = (block *)current;

    // Ensure block size is valid to prevent infinite loops
    if (cur_blk->head.block_size == 0 &&
        (current + HEADER_SIZE < pool.current_break)) {
      // Force advance if we hit a zero-size block (corruption defense)
      current += HEADER_SIZE;
      continue;
    }

    // Calculate where the NEXT block currently starts
    uintptr_t next = current + HEADER_SIZE + cur_blk->head.block_size;

    if (!block_is_live(cur_blk)) {
      // Merge forward while next is also free
      while (next < pool.current_break) {

        // Ensure the header we are about to read fits in memory
        if (next + HEADER_SIZE > pool.current_break) {
          break;
        }

        block *nxt_blk = (block *)next;
        if (block_is_live(nxt_blk))
          break; // Stop if next block is in use

        // The space we gain is the next block's header + its payload
        uint64_t size_gained = HEADER_SIZE + nxt_blk->head.block_size;
        uint64_t new_payload_size = cur_blk->head.block_size + size_gained;

        // CRITICAL BOUNDARY CHECK
        // Address of Header + Header Size + New Payload Size must be <= Break
        if ((uintptr_t)cur_blk + HEADER_SIZE + new_payload_size >
            pool.current_break) {
          break; // Prevent overflow
        }

        // Execute Merge
        block_set_next_block(nxt_blk, NULL);
        cur_blk->head.block_size = new_payload_size;

        // Advance 'next' to the block AFTER the one we just consumed
        next += size_gained;
      }

      // Prepare for insertion into free list
      cur_blk->head.flags = 0;
#ifdef DEBUG
      assert(!block_is_live(cur_blk));
#endif
      add_to_free_list(cur_blk);
    }

    // Advance current to the start of the next distinct block
    current = next;
  }

  recompute_available_size();

  pthread_mutex_unlock(&free_list_mutex);
  pthread_mutex_unlock(&pool_mutex);
}

// The "Unsafe" version assumes the caller ALREADY holds the lock.
// This prevent deadlock where allocate calls get_best_fit which calls fit_block
// which tries to lock again.
void add_to_free_list_unsafe(block *free_block) { freelist_push(free_block); }

// The public version handles the lock
void add_to_free_list(block *free_block) {

#ifdef DEBUG
  printf("\n%s: %" PRIu64 " %p\n", __FUNCTION__, free_block->head.block_size,
         (void *)((uintptr_t)free_block + HEADER_SIZE));
#endif

  // assert(free_block->head.block_size <= 62335);
  // if (free_block->head.block_size > 62335) {
  //   abort();
  //   return;
  // }
  assert(free_block->head.magic_number == MAGIC_NUMBER);
  if (free_block->head.magic_number != MAGIC_NUMBER) {
    abort();
    return;
  }
  pthread_mutex_lock(&free_list_mutex);
  add_to_free_list_unsafe(free_block);
  pthread_mutex_unlock(&free_list_mutex);
}

// -----------------------------------------------------------
