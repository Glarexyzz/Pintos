#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <list.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/share.h"

/// Item to insert into the frame/share table
struct frame {
  void *kvaddr;                      /* Kernel virtual address. */

  struct shared_frame *shared_frame; /* Pointer to the shared frame data, if
                                      * applicable. */
  struct thread *owner;              /* Pointer to the single owner, if
                                      * applicable. */

  struct list_elem queue_elem;       /* For insertion into eviction queue. */
  struct hash_elem table_elem;       /* For insertion into frame table. */
};

/// The frame table
struct hash frame_table;
/// The lock for the frame table
struct lock frame_table_lock;

void frame_table_init(void);
struct frame *create_frame(enum palloc_flags flags);
void *user_get_page(enum palloc_flags flags);
void user_free_page(void *page);

#endif /* vm/frame.h */
