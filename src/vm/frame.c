#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

/// The item to be inserted into the frame struct's owners list
struct owner {
  struct thread *process; /* The thread/process which owns a page */
  struct list_elem elem;  /* For insertion into the frame's owner list */
};

/// The frame table
struct hash frame_table;
/// The lock for the frame table
struct lock frame_table_lock;

static unsigned frame_hash(const struct hash_elem *element, void *aux UNUSED);
static bool frame_kvaddr_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);


/**
 * A hash_hash_func for frame struct.
 * @param element The pointer to the hash_elem in the frame struct.
 * @param aux Unused.
 * @return The hash of the frame.
 */
static unsigned frame_hash(const struct hash_elem *element, void *aux UNUSED) {
  void *kvaddr = hash_entry(element, struct frame, table_elem)->kvaddr;
  return hash_bytes(kvaddr, sizeof (void *));
}

/**
 * A hash_less_func for frame struct.
 * @param a The pointer to the hash_elem in the first frame struct.
 * @param b The pointer to the hash_elem in the second frame struct.
 * @param aux Unused.
 * @return True iff a < b.
 */
static bool frame_kvaddr_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  void *a_kvaddr = hash_entry(a, struct frame, table_elem)->kvaddr;
  void *b_kvaddr = hash_entry(b, struct frame, table_elem)->kvaddr;
  return a_kvaddr < b_kvaddr;
}

/**
 * Initialise the frame table and frame table lock.
 * @remark Panics the kernel if initialisation fails.
 */
void frame_table_init() {
  bool success = hash_init(
    &frame_table,
    &frame_hash,
    &frame_kvaddr_smaller,
    NULL
  );
  if (!success) {
    PANIC("Could not initialise frame table!");
  }
  lock_init(&frame_table_lock);
}

/**
 * Obtain a page from the user pool.
 * @return The kernel virtual address for the page.
 * @remark Also updates the frame table.
 */
void *user_get_page() {
  ASSERT(thread_current()->is_user);

  // Get the kernel virtual address
  void *kvaddr = palloc_get_page(PAL_USER);
  if (kvaddr == NULL) {
    PANIC("No free pages!");
  }

  // Initialise the page
  struct frame *new_frame = malloc(sizeof (struct frame));
  if (new_frame == NULL) {
    PANIC("Kernel out of memory!");
  }
  new_frame->kvaddr = kvaddr;
  list_init(&new_frame->owners);

  // Insert the page into the page table
  lock_acquire(&frame_table_lock);
  hash_insert(&frame_table, &new_frame->table_elem);
  lock_release(&frame_table_lock);

  return kvaddr;
}
