#include <stdint.h>
#include <stdio.h>

void *allocate(uint64_t size);
bool claim(void *ptr);
void scan_for_garbage();

char xter = 'x';
void **data_var = (void *)1;
void **bss_var;

int main() {
  // allocate memory
  void *one_char = allocate(sizeof(char));
  void *one_int = allocate(sizeof(int));
  void *one_ptr = allocate(sizeof(void *));
  void *five_zero_three = allocate(503);

  claim(one_char);
  claim(one_int);
  claim(five_zero_three);

  void *two_four_four = allocate(244);

  claim(two_four_four);
  claim(one_ptr);

  data_var = allocate(100);
  printf("%p\n", data_var);
  data_var = allocate(100);
  printf("%p\n", data_var);
  *data_var = allocate(100);
  printf("%p\n", *data_var);
  data_var = allocate(100);
  printf("%p\n", data_var);
  bss_var = allocate(100);
  printf("%p\n", bss_var);
  *bss_var = allocate(100);
  printf("%p\n", *bss_var);
  *bss_var = allocate(100);
  printf("%p\n", *bss_var);

  puts("--------------------");
  scan_for_garbage();

  for (int i = 0; i < 10000; i++) {
    allocate(300);
  }

  return 0;
}
