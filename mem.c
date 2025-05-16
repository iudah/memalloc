#include <math.h>
#include <memory.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define WORD_SIZE (8)
#define kB (1024)
#define MB (kB * kB)
#define GB (MB * kB)

#ifndef POOL_SIZE_IN_MB
#define POOL_SIZE_IN_MB (512)
#endif
#define POOL_SIZE (POOL_SIZE_IN_MB * MB)

#define MINIMUM_BLOCK_SIZE (sizeof(struct block))
#define HEADER_SIZE (sizeof(header))

typedef struct {
  uint64_t block_size;
  bool live;
  bool mark;
} header;

typedef struct block {
  header head;
  struct block *next_block;
} block;

struct {
  void *head;
  void *prehead;
  void *current_break;
  uint64_t max_size;
  uint64_t available_size;
} pool;

// struct threads {
//   pthread_t *ids;
//   uint16_t count;
//   uint16_t limit;
// } threads;

pthread_mutex_t pool_mutex;
pthread_mutex_t free_list_mutex;
pthread_mutex_t threads_mutex;

block *free_list;

void *allocate(uint64_t size);
void *reallocate(void *old_ptr, uint64_t new_size);
void scan_for_garbage();

void *get_memory_pool(uint64_t pool_size) {
  void *pool = mmap(0, pool_size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (pool == (void *)-1) {
    return nullptr;
  }

  return pool;
}

void return_memory_pool(void *pool, uint64_t pool_size) {
  munmap(pool, pool_size);
}

bool initialize_pool() {
  if (pool.max_size != 0)
    return true;

  pthread_mutex_lock(&pool_mutex);

  pool.available_size = pool.max_size = POOL_SIZE;
  pool.current_break = pool.head = pool.prehead = get_memory_pool(POOL_SIZE);

  pthread_mutex_unlock(&pool_mutex);

  if (!pool.head) {
    return false;
  }

  return true;
}

bool deinitialize_pool() {
  if (pool.max_size == 0)
    return true;

  pthread_mutex_lock(&pool_mutex);

  pool.available_size = pool.max_size = 0;
  return_memory_pool(pool.prehead, pool.max_size);

  pthread_mutex_unlock(&pool_mutex);

  return true;
}

bool constructed = false;
// bool fully_constructed = false;
pthread_t temp;
static void __attribute__((constructor)) initialize_memalloc() {
  if (!constructed) {
    constructed = true;

    pthread_mutex_init(&pool_mutex, NULL);
    pthread_mutex_init(&free_list_mutex, NULL);
    pthread_mutex_init(&threads_mutex, NULL);

    initialize_pool();

    return;
  }

  // if (!fully_constructed) {
  //   // threads.ids = &temp;
  //   // threads.limit = 8;
  //   // threads.ids = allocate(8 * sizeof(pthread_t));
  //   // threads.ids[0] = temp;

  //   fully_constructed = true;
  // }
}

static void __attribute__((destructor)) deinitialize_memalloc() {
  // if (fully_constructed) {
  //   fully_constructed = false;
  //   return;
  // }

  if (constructed) {
    deinitialize_pool();

    pthread_mutex_destroy(&threads_mutex);
    pthread_mutex_destroy(&free_list_mutex);
    pthread_mutex_destroy(&pool_mutex);
    constructed = false;
  }
}

static inline uint16_t min_u16(uint16_t a, uint16_t b) { return a < b ? a : b; }

// void add_thread_id(pthread_t id) {
//   pthread_mutex_lock(&threads_mutex);

//   for (uint16_t i = 0; i < threads.count; i++) {
//     if (pthread_equal(id, threads.ids[i])) {
//       pthread_mutex_unlock(&threads_mutex);
//       return;
//     }
//   }

//   threads.ids[threads.count++] = id;

//   if (threads.count == threads.limit) {
//     if (threads.limit > UINT16_MAX) return;
//     uint64_t new_limit = min_u16(threads.limit * 2, UINT16_MAX);

//     // pthread_mutex_unlock(&threads_mutex);
//     void *tmp = reallocate(threads.ids, new_limit * sizeof(pthread_t));
//     // pthread_mutex_lock(&threads_mutex);

//     if (!tmp) return;
//     threads.ids = tmp;
//     threads.limit = new_limit;
//   }

//   pthread_mutex_unlock(&threads_mutex);
// }

uint64_t align_size(uint64_t size) {
  return (size + (WORD_SIZE - 1)) & ~(WORD_SIZE - 1);
}

block *create_block(uint64_t size) {
  uint64_t aligned_size = align_size(size + HEADER_SIZE);

  pthread_mutex_lock(&pool_mutex);

  block *block = pool.current_break;
  block->head.block_size = size;
  block->head.live = true;
  block->head.mark = false;

  pool.current_break += aligned_size;
  pool.available_size -= aligned_size;

  pthread_mutex_unlock(&pool_mutex);

  return block;
}

void add_to_free_list(block *free_block) {
  if (!free_block->head.live)
    return;

  pthread_mutex_lock(&free_list_mutex);

  free_block->next_block = free_list;
  free_list = free_block;
  free_list->head.live = false;
  free_list->head.mark = false;

  pthread_mutex_unlock(&free_list_mutex);
}

block *fit_block(block *best_fit, uint64_t size) {
  if (!best_fit) {
    return nullptr;
  }

  if (best_fit->head.block_size == size ||
      (best_fit->head.block_size - size) < MINIMUM_BLOCK_SIZE) {
    return best_fit;
  }

  block *extra_block = (block *)(((char *)best_fit) + HEADER_SIZE + size);
  extra_block->head.block_size = best_fit->head.block_size - HEADER_SIZE - size;
  extra_block->head.live = true;

  best_fit->head.block_size = size;

  add_to_free_list(extra_block);
  best_fit->head.live = true;
  best_fit->head.mark = false;
  return best_fit;
}

block *get_best_fit_block(uint64_t size) {
  if (!free_list) {
    return nullptr;
  }

  pthread_mutex_lock(&free_list_mutex);

  block *best_fit = nullptr;
  block *prev_block = nullptr;
  block *current_block = free_list;

  while (current_block != nullptr) {
    if (current_block->head.block_size >= size &&
        (best_fit == nullptr ||
         current_block->head.block_size < best_fit->head.block_size)) {
      best_fit = current_block;
    }
    if (best_fit && best_fit->head.block_size == size) {
      break;
    }
    if (current_block->next_block != NULL) {
      prev_block = current_block;
    }
    current_block = current_block->next_block;
  }

  if (best_fit != nullptr) {
    if (prev_block != nullptr) {
      prev_block->next_block = best_fit->next_block;
    } else {
      free_list = best_fit->next_block;
    }
  }

  best_fit->head.live = true;

  pthread_mutex_unlock(&free_list_mutex);

  return fit_block(best_fit, size);
}

void *allocate(uint64_t size) {
  if (!constructed) {
    initialize_memalloc();
  }
  // if (!fully_constructed) {
  //   void *ptr = pool.head;
  //   uint64_t aligned_size = align_size(size);
  //   pool.head = ((char *)pool.head) + aligned_size;
  //   pool.available_size -= aligned_size;
  //   return ptr;
  // }

  // add_thread_id(pthread_self());

  uint64_t aligned_size = align_size(size);
  block *block = get_best_fit_block(aligned_size);
  if (!block) {
    block = create_block(aligned_size);
  }
  if (!block) {
    return nullptr;
  }

  float ratio = (float)pool.max_size / pool.available_size;
  if (fabsf(ratio - 4.f) <= 1e-6 || fabsf(ratio - 2.f) <= 1e-6 ||
      fabsf(ratio - 4.f / 3) <= 1e-6 || fabsf(ratio - 4 / 3.9f) <= 1e-6)
    scan_for_garbage();

  return ((char *)block) + sizeof(header);
}

void claim_block(block *free_block) {
  if (free_block->head.live)
    add_to_free_list(free_block);
}

void coalesce() {
  pthread_mutex_lock(&free_list_mutex);

  free_list = nullptr;

  pthread_mutex_lock(&pool_mutex);

  block *current_block = pool.head;
  while ((void *)current_block < pool.current_break) {
    block *next_block = (block *)(((char *)current_block) + HEADER_SIZE +
                                  current_block->head.block_size);

    if (current_block->head.live) {
      current_block = next_block;
      continue;
    }

    if (next_block->head.live) {
      current_block->next_block = free_list;
      free_list = current_block;
      current_block = (block *)(((char *)next_block) + HEADER_SIZE +
                                next_block->head.block_size);
      continue;
    }

    current_block->head.block_size += next_block->head.block_size + HEADER_SIZE;
  }
  pthread_mutex_unlock(&pool_mutex);

  if (!current_block->head.live && current_block != free_list) {
    current_block->next_block = free_list;
    free_list = current_block;
  }
  pthread_mutex_unlock(&free_list_mutex);
}

bool claim(void *ptr) {
  if (!ptr)
    return false;

  pthread_mutex_lock(&pool_mutex);

  if (ptr < pool.head || ptr > pool.current_break) {
    pthread_mutex_unlock(&pool_mutex);
    return false;
  }
  pthread_mutex_unlock(&pool_mutex);

  block *free_block = (block *)(((char *)ptr) - HEADER_SIZE);

  claim_block(free_block);

  return true;
}

static inline uint64_t min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }

void *reallocate(void *old_ptr, uint64_t new_size) {
  if (!old_ptr)
    return nullptr;

  block *old_block = (block *)(((char *)old_ptr) - HEADER_SIZE);
  if (old_block->head.block_size == align_size(new_size))
    return old_ptr;

  void *new_ptr = allocate(new_size);
  if (!new_ptr) {
    return nullptr;
  }

  block *new_block = (block *)(((char *)new_ptr) - HEADER_SIZE);

  memcpy(new_ptr, old_ptr,
         min_u64(old_block->head.block_size, new_block->head.block_size));

  return new_ptr;
}

void scan_memory_section(void *start, void *end) {
  void **location = start;
  while (location < (void **)end) {
    if (*(void **)location > pool.head &&
        *(void **)location < pool.current_break) {
      block *block = (void *)(((char *)*(void **)location) - HEADER_SIZE);
      if (block->head.live) {
        block->head.mark = true;
        // printf("%p\n", &block->next_block);
      };
    }

    location++;
  }
}

void scan_for_garbage() {
  extern char _etext, _edata, _end;

  // check all memory locations such as bss,stack, etc for any likely block
  // allocation if any found mark them
  scan_memory_section(&_edata, &_etext);
  scan_memory_section(&_end, &_edata);
  //   for (uint16_t i = 0; i < threads.count; i++) {
  //     void *stack_base;
  //     size_t stack_size;
  //     pthread_attr_t attribute;
  //     pthread_getattr_np(threads.ids[i], &attribute);
  //     pthread_attr_getstack(&attribute, &stack_base, &stack_size);
  //     // pthread_suspend(threads.id[i]);

  //     void *start = (char *)stack_base
  // #ifndef __arm__
  //                   - stack_size
  // #endif
  //         ;

  //     void *end = (char *)stack_base
  // #ifdef __arm__
  //                 + stack_size
  // #endif
  //         ;

  //     scan_memory_section(start, end);
  //   }

  // check the memory live blocks for block allocations if found mark as well
  pthread_mutex_lock(&pool_mutex);
  block *current_block = pool.head;
  while ((void *)current_block < pool.current_break) {
    block *next_block = (block *)(((char *)current_block) + HEADER_SIZE +
                                  current_block->head.block_size);

    if (current_block->head.live && current_block->head.mark) {
      scan_memory_section(&current_block->next_block, next_block);
    }
    current_block = next_block;
  }

  // begin sweep
  current_block = pool.head;
  while ((void *)current_block < pool.current_break) {
    block *next_block = (block *)(((char *)current_block) + HEADER_SIZE +
                                  current_block->head.block_size);

    if (current_block->head.live) {
      if (!current_block->head.mark) {
        // printf("~%p\n", &current_block->next_block);
        claim_block(current_block);
      } else {
        current_block->head.mark = false;
      }
    }
    current_block = next_block;
  }
  pthread_mutex_unlock(&pool_mutex);

  coalesce();

  // put windows aside for now
  // some windows stuff to consider
  // https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++
}

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
        thread_stack < pool.current_break) {
      stack_is_set = true;
    }
  }

  if (!stack_is_set) {
    thread_stack_size = PTHREAD_STACK_MIN + 1 * MB;
    thread_stack = allocate(thread_stack_size);
    thread_attr = allocate(sizeof(*thread_ptr));
    if (!thread_attr) {
      pthread_attr_init((pthread_attr_t *)thread_attr);
    }
    pthread_attr_setstack((pthread_attr_t *)thread_attr, thread_stack,
                          thread_stack_size);
  }

  return pthread_create(thread_ptr, thread_attr, start_routine, input);
}

// Unable to get malloc to work with library
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
