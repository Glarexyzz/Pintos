#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <list.h>
#include "threads/palloc.h"
#include "threads/synch.h"

/// The item to be inserted into the frame struct's owners list
struct owner {
  struct thread *process; /* The thread/process which owns a page */
  void *uvaddr;           /* The user virtual address for the page */
  struct list_elem elem;  /* For insertion into the frame's owner list */
};

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
void *user_get_page(enum palloc_flags flags);
void user_free_page(void *page);

void eviction_list_init(void);
void pin_page(void *uaddr);
void unpin_page(void *uaddr);
void evict_frame(void);

#endif /* vm/frame.h */
