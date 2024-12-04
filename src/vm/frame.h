#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <list.h>
#include "threads/palloc.h"
#include "threads/synch.h"

/// Item to insert into the frame table
struct frame {
  void *kvaddr;                      /* Kernel virtual address */
  struct list owners;                /* List of processes which own the frame */

  // Used for shared read-only executables
  int offset;                        /* The offset of the frame within the
                                      * file */
  struct file *file;                 /* The file to which the frame belongs */

  struct list_elem queue_elem;       /* For insertion into eviction queue */
  struct hash_elem frame_table_elem; /* For insertion into frame table */
  struct hash_elem share_table_elem; /* For insertion into share table */
};

struct hash frame_table;
struct lock frame_table_lock;

void frame_table_init(void);
void share_table_init(void);
void *user_get_page(enum palloc_flags flags);
void user_free_page(void *page);

#endif /* vm/frame.h */
