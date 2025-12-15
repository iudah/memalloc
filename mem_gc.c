// -----------------------------------------------------------
// mem_gc.c
// -----------------------------------------------------------
#include "mem_internal.h"
#include <bits/pthread_types.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

// --- Global Scan State ---
block *mark_queue;

// --- Scanning Helper ---
void scan_memory_section(void *start, void *end) {
  // Ensure we start aligned
  uintptr_t current = (uintptr_t)start;
  if (current % sizeof(void *) != 0) {
    current += sizeof(void *) - (current % sizeof(void *));
  }

  uintptr_t end_addr = (uintptr_t)end;

  while (current < end_addr) {
    if (current + sizeof(void *) > end_addr)
      break;

    // Now safe to dereference
    void *potential_ptr = *(void **)current;

    if (potential_ptr > pool.head &&
        (uintptr_t)potential_ptr <= pool.current_break &&
        ((uintptr_t)potential_ptr + WORD_SIZE) <= pool.current_break) {

      block *blk = (struct block *)((uintptr_t)potential_ptr - HEADER_SIZE);

      if (blk->head.magic_number == MAGIC_NUMBER &&
          block_is_live((block *)blk) && !block_is_marked((block *)blk)) {

        block_mark_marked((block *)blk);

        pthread_mutex_lock(&mark_queue_mutex);
        mark_queue_push((block *)blk);
        pthread_mutex_unlock(&mark_queue_mutex);
      }
    }

    current += sizeof(void *);
  }
}

void claim_block(block *free_block) {
  if (block_is_live(free_block) &&
      free_block->head.magic_number == MAGIC_NUMBER)
    add_to_free_list(free_block);
}

// --- Main GC Driver ---
void scan_for_garbage() {
// Scan Globals (BSS/Data)
#ifdef _WIN32
  scan_memory_section(_bss_start, _bss_end);
  scan_memory_section(_data_start, _data_end);
#else
  extern char _etext, _edata, _end;
  scan_memory_section(&_etext, &_edata);
  scan_memory_section(&_edata, &_end);
#endif

  // Scan Stack
  void *start, *end;

  platform_get_stack_bounds(&start, &end);
  scan_memory_section(start, end);

  // Mark Phase
  pthread_mutex_lock(&pool_mutex);

  block *sweep_list = NULL;

  while (true) {
    pthread_mutex_lock(&mark_queue_mutex);
    block *current_blk = mark_queue_pop();
    pthread_mutex_unlock(&mark_queue_mutex);

    if (!current_blk)
      break;

    if (current_blk->head.magic_number == MAGIC_NUMBER &&
        block_is_live(current_blk)) {

      void *payload_start = (void *)&current_blk->payload;
      void *payload_end = (void *)((uintptr_t)&current_blk->payload +
                                   current_blk->head.block_size);

      scan_memory_section(payload_start, payload_end);
      block_mark_scanned(current_blk);

      linkedlist_push(&sweep_list, current_blk);
    }
  }

  // Sweep Phase
  uintptr_t current_address = (uintptr_t)pool.head;
  while (current_address <= pool.current_break &&
         (current_address + sizeof(struct block)) <= pool.current_break) {

    block *current_block = (block *)current_address;
    uintptr_t next_address =
        current_address + HEADER_SIZE + current_block->head.block_size;

    if (current_block->head.magic_number == MAGIC_NUMBER &&
        block_is_live(current_block)) {

      // If it's LIVE but NOT MARKED, it is Garbage!
      if (!block_is_marked(current_block)) {
        claim_block(current_block); // Free it
      } else {
        block_clear_marked(current_block); // Keep it, clear flag for next GC
      }
      block_clear_scanned(current_block);
    }
    current_address = next_address;
  }

  pthread_mutex_unlock(&pool_mutex);
  coalesce();

  // put windows aside for now
  // some windows stuff to consider
  // https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++
}

// -----------------------------------------------------------
