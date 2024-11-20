#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <list.h>

/// Item to insert into the frame table
struct frame {
  void *kvaddr;                /* Kernel virtual address */
  bool ref_bit;                /* Reference bit for eviction */
  struct list owners;          /* List of processes which own the frame */
  struct list_elem queue_elem; /* For insertion into eviction queue */
  struct hash_elem table_elem; /* For insertion into frame table */
};

struct hash frame_table;
struct lock frame_table_lock;

void frame_table_init(void);
void *user_get_page(void);
void user_free_page(void *page);

#endif /* vm/frame.h */
