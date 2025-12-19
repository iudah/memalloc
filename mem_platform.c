// -----------------------------------------------------------
// mem_platform.c
// -----------------------------------------------------------
#include "mem_internal.h"
#include <setjmp.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN (4096)
#endif

// --- Windows Globals ---
void *_bss_start;
void *_bss_end;
void *_data_start;
void *_data_end;

bool win_pe_hdr()
{
  HMODULE h_module = GetModuleHandle(NULL);
  if (!h_module)
  {
    fprintf(stderr, "Failed to get module handle.\n");
    return false;
  }

  PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)h_module;
  PIMAGE_NT_HEADERS nt_headers =
      (PIMAGE_NT_HEADERS)((uintptr_t)h_module + dos_header->e_lfanew);

  uintptr_t image_base = (uintptr_t)nt_headers->OptionalHeader.ImageBase;

  // BaseOfCode is an RVA (relative virtual address) and not the actual
  // address of the base of code.
  _data_start = (void *)(image_base + nt_headers->OptionalHeader.BaseOfCode);
  _data_end = (void *)((uintptr_t)_data_start +
                       nt_headers->OptionalHeader.SizeOfInitializedData);

  _bss_start = (void *)((uintptr_t)_data_end);
  _bss_end = (void *)((uintptr_t)_bss_start +
                      nt_headers->OptionalHeader.SizeOfUninitializedData);

  return true;
}

// Allocate anonymous shared memory using system paging file
void *win_mmap_anon(size_t size)
{
  HANDLE hMap = CreateFileMapping(
      INVALID_HANDLE_VALUE,               // Use the system paging file (anonymous)
      NULL,                               // Default security
      PAGE_READWRITE,                     // Read/write access
      (DWORD)((size >> 32) & 0xFFFFFFFF), // High-order DWORD of size
      (DWORD)(size & 0xFFFFFFFF),         // Low-order DWORD of size
      NULL                                // No name = not shared between processes
  );

  if (hMap == NULL)
  {
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

  if (addr == NULL)
  {
    fprintf(stderr, "MapViewOfFile failed with error %lu\n", GetLastError());
  }

  return addr;
}

void munmap(void *addr, size_t size)
{
  if (!UnmapViewOfFile(addr))
  {
    fprintf(stderr, "UnmapViewOfFile failed with error %lu\n", GetLastError());
  }
}

#else
// --- Linux/Unix Globals ---
#include <sys/mman.h>
#endif

bool constructed = false;

void *platform_get_memory(uint64_t size)
{
#ifdef _WIN32
  return win_mmap_anon(size);
#else
  return mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1,
              0);
#endif
}

jmp_buf jmp_buffer;
void stack_base_signal(int signal) { longjmp(jmp_buffer, 50); }

void initialize_stack_ptr()
{
#ifdef _WIN32
  win_pe_hdr();
  NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
  init_stack_ptr = tib->StackBase;
#else
  volatile int a = 0;
  typedef void (*sig_seg_f_t)(int);
  init_stack_ptr = (void *)&a;
  volatile uintptr_t base = (volatile uintptr_t)init_stack_ptr;
  sig_seg_f_t sigsegv = signal(SIGSEGV, stack_base_signal);
  if (setjmp(jmp_buffer) == 0)
    while (true)
    {

      base += sizeof(void *);
      init_stack_ptr = (void *)base;
      a = *(int *)init_stack_ptr;
      if (setjmp(jmp_buffer) != 0)
        break;
    }
  signal(SIGSEGV, sigsegv);
  init_stack_ptr = (void *)base - sizeof(void *);
#endif
}

void platform_free_memory(void *ptr, uint64_t size) { munmap(ptr, size); }

void platform_get_stack_bounds(void **start, void **end)
{

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

  if (init_stack_ptr < stack_pointer)
  {
    *start = (void *)init_stack_ptr;
    *end = stack_pointer;
  }
  else
  {
    *start = stack_pointer;
    *end = (void *)init_stack_ptr;
  }
}

void *get_memory_pool(uint64_t pool_size)
{
  void *pool = platform_get_memory(pool_size);

  if (pool == (void *)-1)
  {
    return NULL;
  }

  return pool;
}

bool initialize_pool()
{
  static bool initialized = false;
  if (initialized)
    return false;
  else
    initialized = true;

  if (pool.max_size != 0)
    return true;

  pthread_mutex_lock(&pool_mutex);

  pool.head = pool.prehead = get_memory_pool(POOL_SIZE);
  // check mem_pool success
  if (!pool.head)
    abort();

  pool.available_size = pool.max_size = POOL_SIZE;
  pool.current_break = (uintptr_t)pool.head;

  pthread_mutex_unlock(&pool_mutex);

  if (!pool.head)
  {
    return false;
  }

  return true;
}

// --- Global constructor ---
static void __attribute__((constructor(101))) mem_init()
{

  if (constructed)
    return;

  constructed = true;

  pthread_mutex_init(&pool_mutex, NULL);
  pthread_mutex_init(&free_list_mutex, NULL);
  pthread_mutex_init(&mark_queue_mutex, NULL);
  pthread_mutex_init(&threads_mutex, NULL);

  initialize_pool();

  return;
}

// --- Pool Destruction ---
void return_memory_pool(void *pool, uint64_t pool_size)
{
  platform_free_memory(pool, pool_size);
}

bool deinitialize_pool()
{
  if (pool.max_size == 0)
    return true;

  pthread_mutex_lock(&pool_mutex);
  uint64_t size = pool.max_size;
  void *prehead = pool.prehead;

  pool.available_size = 0;
  pool.max_size = 0;
  pool.head = NULL;
  pool.prehead = NULL;
  pool.current_break = 0;

  pthread_mutex_unlock(&pool_mutex);
  return_memory_pool(prehead, size);
  return true;
}

// --- Library Destructor ---
static void __attribute__((destructor(101))) deinitialize_memalloc()
{
  // 'constructed' flag should be in mem_internal.h or static here
  extern bool constructed;
  if (constructed)
  {
    deinitialize_pool();
    pthread_mutex_destroy(&threads_mutex);
    pthread_mutex_destroy(&free_list_mutex);
    pthread_mutex_destroy(&pool_mutex);
    constructed = false;
  }
}
// -----------------------------------------------------------
