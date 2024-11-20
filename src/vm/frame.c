#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/thread.h"

/// The item to be inserted into the frame struct's owners list
struct owner {
  struct thread *process; /* The thread/process which owns a page */
  struct list_elem elem;  /* For insertion into the frame's owner list */
};

/// The frame table
struct hash frame_table;
/// The lock for the frame table
struct lock frame_table_lock;
