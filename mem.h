#ifndef MEM_H
#define MEM_H
#include <stdint.h>

void *allocate(uint64_t size);
void claim(void *ptr);
void *reallocate(void *oldptr, uint64_t size);

#endif