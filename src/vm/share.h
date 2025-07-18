#ifndef VM_SHARE_H
#define VM_SHARE_H

#include "threads/synch.h"

/// The table of read-only file mappings
struct hash share_table;
/// The lock for the share table
struct lock share_table_lock;

struct shared_frame {
  struct list owners;    /* List of processes which own the frame. */
  struct file *file;     /* The file to which the frame belongs. */
  int offset;            /* The offset of the frame within the file. */
  struct lock lock;      /* Lock for the shared frame. */
  struct frame *frame;   /* The frame in the frame table. */
  struct hash_elem elem; /* For insertion into the share table. */
};

void share_table_init(void);
void shared_frame_add_owner(
  struct shared_frame *shared_frame,
  struct thread *t,
  void *uvaddr
);
void shared_frame_delete_owner(
  struct shared_frame *shared_frame,
  struct thread *t
);
struct file *open_shared_file(char *filename);
void increase_open_count(struct file *file);
void close_shared_file(struct file *file);

#endif //VM_SHARE_H
