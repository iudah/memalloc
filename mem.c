#include "mem.h"
#include <math.h>
#include <memory.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <sys/mman.h>
#else
#include <windows.h>
#include <winnt.h>
#endif

#define WORD_SIZE (8)
#define kB (1024)
#define MB (kB * kB)
#define GB (MB * kB)

#ifndef POOL_SIZE_IN_MB
#define POOL_SIZE_IN_MB (512)
#endif
#define POOL_SIZE (POOL_SIZE_IN_MB * MB)

#define MINIMUM_BLOCK_SIZE (sizeof(struct block))
#define HEADER_SIZE (offsetof(struct block, next_block))

#define MAGIC_NUMBER 0xabadc0de

typedef struct {
  uint64_t block_size;
  uint32_t magic_number;
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
  uintptr_t current_break;
  uint64_t max_size;
  uint64_t available_size;
} pool;

pthread_mutex_t pool_mutex;
pthread_mutex_t free_list_mutex;
pthread_mutex_t threads_mutex;

block *free_list;

void *allocate(uint64_t size);
void *reallocate(void *old_ptr, uint64_t new_size);
void scan_for_garbage();

#ifdef _WIN32
// Allocate anonymous shared memory using system paging file
void *win_mmap_anon(size_t size) {
  HANDLE hMap = CreateFileMapping(
      INVALID_HANDLE_VALUE, // Use the system paging file (anonymous)
      NULL,                 // Default security
      PAGE_READWRITE,       // Read/write access
      (DWORD)((size >> 32) & 0xFFFFFFFF), // High-order DWORD of size
      (DWORD)(size & 0xFFFFFFFF),         // Low-order DWORD of size
      NULL // No name = not shared between processes
  );

  if (hMap == NULL) {
    fprintf(stderr, "CreateFileMapping failed with error %lu\n",
            GetLastError());
    return NULL;
  }

  void *addr = MapViewOfFile(hMap,                // Handle to map object
                             FILE_MAP_ALL_ACCESS, // Read/write access
                             0, 0,                // Offset
                             size                 // Number of bytes to map
  );

  CloseHandle(hMap); // We can close the handle; the mapping stays valid

  if (addr == NULL) {
    fprintf(stderr, "MapViewOfFile failed with error %lu\n", GetLastError());
  }

  return addr;
}

void munmap(void *addr, size_t size) {
  if (!UnmapViewOfFile(addr)) {
    fprintf(stderr, "UnmapViewOfFile failed with error %lu\n", GetLastError());
  }
}
#endif

void *get_memory_pool(uint64_t pool_size) {
#ifndef _WIN32
  void *pool = mmap(0, pool_size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#else
  void *pool = win_mmap_anon(pool_size);
#endif
  if (pool == (void *)-1) {
    return NULL;
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
  pool.head = pool.prehead = get_memory_pool(POOL_SIZE);
  pool.current_break = (uintptr_t)pool.head;

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

jmp_buf jmp_buffer;
void stack_base_signal(int signal) { longjmp(jmp_buffer, 50); }
int main();
bool constructed = false;
volatile static void *init_stack_ptr;
static void __attribute__((constructor(101))) initialize_memalloc() {
  if (!constructed) {

    constructed = true;

    pthread_mutex_init(&pool_mutex, NULL);
    pthread_mutex_init(&free_list_mutex, NULL);
    pthread_mutex_init(&threads_mutex, NULL);

    initialize_pool();

    return;
  }
}

static void __attribute__((destructor)) deinitialize_memalloc() {

  if (constructed) {
    deinitialize_pool();

    pthread_mutex_destroy(&threads_mutex);
    pthread_mutex_destroy(&free_list_mutex);
    pthread_mutex_destroy(&pool_mutex);
    constructed = false;
  }
}

static inline uint16_t min_u16(uint16_t a, uint16_t b) { return a < b ? a : b; }

uint64_t align_size(uint64_t size) {
  return (size + (WORD_SIZE - 1)) & ~(WORD_SIZE - 1);
}

block *create_block(uint64_t size) {
  uint64_t aligned_size = align_size(size + HEADER_SIZE);

  pthread_mutex_lock(&pool_mutex);

  block *block = (struct block *)pool.current_break;
  block->head.block_size = size;
  block->head.live = true;
  block->head.mark = false;
  block->head.magic_number = MAGIC_NUMBER;

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
    return NULL;
  }

  uint64_t extra_size = best_fit->head.block_size - HEADER_SIZE - size;

  if (best_fit->head.block_size == size || extra_size < align_size(WORD_SIZE)) {
    return best_fit;
  }

  block *extra_block = (block *)((uintptr_t)best_fit + HEADER_SIZE + size);
  extra_block->head.block_size = extra_size;
  extra_block->head.live = true;
  extra_block->head.magic_number = MAGIC_NUMBER;

  best_fit->head.block_size = size;
  best_fit->head.live = true;
  best_fit->head.mark = false;

  add_to_free_list(extra_block);
  return best_fit;
}

block *get_best_fit_block(uint64_t size) {
  if (!free_list) {
    return NULL;
  }

  pthread_mutex_lock(&free_list_mutex);

  block *best_fit = NULL;
  block *prev_block = NULL;
  block *current_block = free_list;

  while (current_block->next_block) {
    if (!best_fit) {
      if (current_block->head.block_size >= size) {
        best_fit = current_block;
      }
    } else {
      if (current_block->head.block_size >= size &&
          current_block->head.block_size < best_fit->head.block_size) {
        best_fit = current_block;
      }
      if (best_fit->head.block_size == size)
        break;
    }
    prev_block = current_block;
    current_block = current_block->next_block;
  }

  if (best_fit != NULL) {
    if (prev_block != NULL) {
      prev_block->next_block = best_fit->next_block;
    } else {
      free_list = best_fit->next_block;
    }
    best_fit->head.live = true;
  }

  pthread_mutex_unlock(&free_list_mutex);

  return fit_block(best_fit, size);
}

void *allocate(uint64_t size) {
  if (!constructed) {
    initialize_memalloc();
  }

  if (init_stack_ptr == NULL) {
    volatile int a = 0;
    typedef void (*sig_seg_f_t)(int);
    init_stack_ptr = (void *)&a;
    volatile uintptr_t base = (volatile uintptr_t)init_stack_ptr;
    sig_seg_f_t sigsegv = signal(SIGSEGV, stack_base_signal);
    if (setjmp(jmp_buffer) == 0)
      while (true) {

        base += sizeof(void *);
        init_stack_ptr = (void *)base;
        a = *(int *)init_stack_ptr;
        if (setjmp(jmp_buffer) != 0)
          break;
      }
    signal(SIGSEGV, sigsegv);
    init_stack_ptr = (void *)base;
  }

  float ratio = (float)pool.available_size / pool.max_size;
#if 0
  if (fabsf(ratio - .25f) <= 1e-6 || fabsf(ratio - .5f) <= 1e-6 ||
      fabsf(ratio - .75f) <= 1e-6 || fabsf(ratio - 1.f) <= 1e-6)
#else
  if (fabsf(ratio - .5f) <= 1e-6 || fabsf(ratio - .75f) <= 1e-6 ||
      fabsf(ratio - .875f) <= 1e-6 || fabsf(ratio - 1.f) <= 1e-6)
#endif
  {
    scan_for_garbage();
  }

  uint64_t aligned_size = align_size(size);
  block *block = get_best_fit_block(aligned_size);
  if (!block) {
    block = create_block(aligned_size);
  }
  if (!block) {
    return NULL;
  }

  return (void *)((uintptr_t)block + HEADER_SIZE);
}

void claim_block(block *free_block) {
  if (free_block->head.live)
    add_to_free_list(free_block);
}

void coalesce() {
  pthread_mutex_lock(&free_list_mutex);

  free_list = NULL;

  pthread_mutex_lock(&pool_mutex);

  uintptr_t current_address = (uintptr_t)pool.head;
  while (current_address <= pool.current_break &&
         current_address + sizeof(struct block) <= pool.current_break) {
    block *current_block = (block *)current_address;
    uintptr_t next_address =
        current_address + HEADER_SIZE + current_block->head.block_size;

    if (next_address >= pool.current_break) {
      if (!current_block->head.live && current_block != free_list) {
        current_block->next_block = free_list;
        free_list = current_block;
      }
      break;
    }

    if (current_block->head.live) {
      current_address = next_address;
      continue;
    }

    if (next_address <= pool.current_break &&
        next_address + sizeof(struct block) <= pool.current_break) {

      block *next_block = (block *)next_address;

      if (next_block->head.live) {
        current_block->next_block = free_list;
        free_list = current_block;
        current_address =
            next_address + HEADER_SIZE + next_block->head.block_size;

        continue;
      }
      current_block->head.block_size +=
          next_block->head.block_size + HEADER_SIZE;
    } else {
      break;
    }
  }
  pthread_mutex_unlock(&pool_mutex);

  pthread_mutex_unlock(&free_list_mutex);
}

bool claim(void *ptr) {
  if (!ptr)
    return false;

  pthread_mutex_lock(&pool_mutex);

  if (ptr < pool.head || (uintptr_t)ptr > pool.current_break) {
    pthread_mutex_unlock(&pool_mutex);
    return false;
  }
  pthread_mutex_unlock(&pool_mutex);

  block *free_block = (block *)(((char *)ptr) - HEADER_SIZE);

  claim_block(free_block);

  coalesce();

  return true;
}

static inline uint64_t min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }

void *reallocate(void *old_ptr, uint64_t new_size) {
  if (!old_ptr)
    return NULL;

  block *old_block = (block *)(((char *)old_ptr) - HEADER_SIZE);
  if (old_block->head.block_size == align_size(new_size))
    return old_ptr;

  void *new_ptr = allocate(new_size);
  if (!new_ptr) {
    return NULL;
  }

  block *new_block = (block *)(((char *)new_ptr) - HEADER_SIZE);

  memcpy(new_ptr, old_ptr,
         min_u64(old_block->head.block_size, new_block->head.block_size));

  return new_ptr;
}

void scan_memory_section(void *start, void *end) {
  uintptr_t current_address = (uintptr_t)start;
  uintptr_t end_address = (uintptr_t)end;
  while (current_address < end_address) {
    void **location = (void **)current_address;
    // printf("%p ----\n", location);
    // fflush(stdout);

    if (current_address + sizeof(void *) <= end_address) {
      void *potential_ptr = *location;

      if (potential_ptr > pool.head &&
          (uintptr_t)potential_ptr <= pool.current_break &&
          ((uintptr_t)potential_ptr + WORD_SIZE) <= pool.current_break) {

        // printf("p *(block*)%p\n-- %p\n",
        //        (void *)((uintptr_t)potential_ptr - HEADER_SIZE),
        //        potential_ptr);

        volatile block *block =
            (struct block *)((uintptr_t)potential_ptr - HEADER_SIZE);

        if (block->head.magic_number == MAGIC_NUMBER && block->head.live) {
          block->head.mark = true;
        }
      }
    }

    current_address += sizeof(void *);
  }
}

#ifdef _WIN32
void *_bss_start;
void *_bss_end;
void *_data_start;
void *_data_end;

bool win_pe_hdr() {
  HMODULE h_module = GetModuleHandle(NULL);
  if (!h_module) {
    fprintf(stderr, "Failed to get module handle.\n");
    return false;
  }

  PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)h_module;
  PIMAGE_NT_HEADERS nt_headers =
      (PIMAGE_NT_HEADERS)((uintptr_t)h_module + dos_header->e_lfanew);

  uintptr_t image_base = (uintptr_t)nt_headers->OptionalHeader.ImageBase;

  // BaseOfCode is an RVA (relative virtual address) and not the actual address
  // of the base of code.
  _data_start = (void *)(image_base + nt_headers->OptionalHeader.BaseOfCode);
  _data_end = (void *)((uintptr_t)_data_start +
                       nt_headers->OptionalHeader.SizeOfInitializedData);

  _bss_start = (void *)((uintptr_t)_data_end);
  _bss_end = (void *)((uintptr_t)_bss_start +
                      nt_headers->OptionalHeader.SizeOfUninitializedData);

  return true;
}
#endif

void scan_for_garbage() {
  // check all memory locations such as bss,stack, etc for any likely block
  // allocation if any found mark them
#ifndef _WIN32
#if defined __GNUC__ || defined __clang__
  extern char _etext, _edata, _end;
  scan_memory_section(&_etext, &_edata);
  scan_memory_section(&_edata, &_end);
#else
#error Unknown compiler
#endif
#else
  scan_memory_section(_bss_start, _bss_end);
  scan_memory_section(_data_start, _data_end);
#endif

  void *stack_pointer;

#ifdef __x86_64__
  __asm__("mov %%rsp, %0" : "=r"(stack_pointer));
#elif defined __i364__
  __asm__("mov %%esp, %0" : "=r"(stack_pointer));
#elif defined __arm__
  __asm__("mov %0, sp" : "=r"(stack_pointer));
#else
#error Assembly for stack pointer is not defined for this arch
#endif

  void *start, *end;

  if (init_stack_ptr < stack_pointer) {
    start = (void *)init_stack_ptr;
    end = stack_pointer;
  } else {
    start = stack_pointer;
    end = (void *)init_stack_ptr;
  }

  scan_memory_section(start, end);

  // check the memory live blocks for block allocations if found mark as well
  pthread_mutex_lock(&pool_mutex);
  uintptr_t current_address = (uintptr_t)pool.head;
  while (current_address <= pool.current_break &&
         (current_address + sizeof(struct block)) <= pool.current_break) {
    block *current_block = (block *)current_address;

    uintptr_t next_address =
        current_address + HEADER_SIZE + current_block->head.block_size;

    if (current_block->head.magic_number == MAGIC_NUMBER &&
        current_block->head.live && current_block->head.mark) {
      scan_memory_section((void *)(current_address + HEADER_SIZE),
                          (void *)next_address);
    }
    current_address = next_address;
  }

  // begin sweep
  current_address = (uintptr_t)pool.head;
  while (current_address <= pool.current_break &&
         current_address + sizeof(struct block) <= pool.current_break) {
    block *current_block = (block *)current_address;
    uintptr_t next_address =
        current_address + HEADER_SIZE + current_block->head.block_size;

    if (current_block->head.live && !current_block->head.mark) {
      claim_block(current_block);
    } else {
      current_block->head.mark = false;
    }

    current_address = next_address;
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
