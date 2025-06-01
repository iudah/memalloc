#ifndef MEM_H
#define MEM_H

#ifndef __clang__
#define _Nonnull
#define _Nullable
#endif

#include <pthread.h>
#include <stdint.h>

void *_Nullable allocate(uint64_t size);
void claim(void *_Nonnull ptr);
void *_Nullable reallocate(void *_Nonnull oldptr, uint64_t size);
int create_thread(pthread_t *_Nonnull thread_ptr,
                  pthread_attr_t const *_Nullable thread_attr,
                  void *_Nonnull (*_Nonnull start_routine)(void *_Nonnull),
                  void *_Nullable input);

#endif