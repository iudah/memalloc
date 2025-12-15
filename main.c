#include "mem.h"
#include <stdint.h>
#include <stdio.h>
#include <unistd.h> // for usleep/sleep

// A simple struct to test linking
typedef struct Node {
  int id;
  struct Node *next;
  struct Node *prev;    // Double link to test cycles
  uint8_t payload[100]; // Padding to make blocks sizeable
} Node;

// Helper to print stats
void print_stats(const char *tag) {
  // We can't access pool directly here as it's internal,
  // but we can see the effects by trying to allocate.
  // Ideally, expose a 'mem_get_available()' in mem.h for debugging.
  printf("[%s] Running...\n", tag);
}

void create_garbage() {
  printf("  -> creating 1000 pieces of garbage...\n");
  for (int i = 0; i < 1000; i++) {
    // Allocate and immediately forget
    Node *n = (Node *)allocate(sizeof(Node));
    n->id = i;
    // Pointer 'n' goes out of scope here, becoming garbage
  }
}

Node *create_linked_list() {
  printf("  -> creating reachable linked list...\n");
  Node *head = (Node *)allocate(sizeof(Node));
  head->id = 9999;
  head->next = (Node *)allocate(sizeof(Node));
  head->next->id = 8888;
  head->next->next = NULL;
  return head; // Returning head keeps it reachable!
}

void create_cycle() {
  printf("  -> creating isolated cycle (A <-> B)...\n");
  Node *a = (Node *)allocate(sizeof(Node));
  Node *b = (Node *)allocate(sizeof(Node));

  a->next = b;
  b->prev = a;

  // a and b go out of scope here.
  // In a ref-counted system, these would leak.
  // In your Mark-and-Sweep, they should be collected!
}

int main() {
  printf("=== Memory Allocator Stress Test ===\n");

  // 1. Fill memory with garbage
  create_garbage();

  // 2. Create something we want to KEEP
  Node *my_list = create_linked_list();

  // 3. Create a cycle that should be FREE
  create_cycle();

  printf("\n--- Triggering Allocation to force GC ---\n");

  // This allocation should trigger scan_for_garbage internally
  // if thresholds are met. To be sure, we allocate enough to force it.
  for (int i = 0; i < 10; i++) {
    allocate(1024 * 1024); // Allocate 1MB chunks
  }

  // Verify the list is still valid (was not swept)
  if (my_list->id == 9999 && my_list->next->id == 8888) {
    printf("[SUCCESS] Reachable list survived GC!\n");
  } else {
    printf("[FAILURE] Reachable list was corrupted!\n");
  }

  return 0;
}