#include "vm/frame.h"
#include "threads/malloc.h"
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
 * @param flags The flags for the palloc_get_page call.
 * @return The kernel virtual address for the page.
 * @pre The caller is a user process.
 * @remark Also updates the frame table.
 */
void *user_get_page(enum palloc_flags flags) {
  struct thread *cur_thread = thread_current();
  ASSERT(cur_thread->is_user);

  // Get the kernel virtual address
  void *kvaddr = palloc_get_page(PAL_USER | flags);
  if (kvaddr == NULL) {
    PANIC("No free pages!");
  }

#ifdef VM

  // Initialise the page
  struct frame *new_frame = malloc(sizeof (struct frame));
  if (new_frame == NULL) {
    PANIC("Kernel out of memory!");
  }
  new_frame->kvaddr = kvaddr;
  list_init(&new_frame->owners);

  // Add the current process to the new frame's list of owners
  struct owner *new_frame_owner = malloc(sizeof (struct owner));
  if (new_frame_owner == NULL) {
    PANIC("Kernel out of memory!");
  }
  new_frame_owner->process = cur_thread;
  list_push_front(&new_frame->owners, &new_frame_owner->elem);

  // Insert the page into the page table
  lock_acquire(&frame_table_lock);
  hash_insert(&frame_table, &new_frame->table_elem);
  lock_release(&frame_table_lock);

#endif

  return kvaddr;
}

/**
 * Frees a page from the user pool.
 * @param page The page to free.
 * @pre The caller is a user process.
 * @remark Also updates the frame table.
 */
void user_free_page(void *page) {
  struct thread *cur_thread = thread_current();
  ASSERT(cur_thread->is_user);

  palloc_free_page(page);

#ifdef VM

  // Find and update the frame in the frame table
  struct frame frame_to_find;
  frame_to_find.kvaddr = page;

  lock_acquire(&frame_table_lock);
  struct hash_elem *found_frame_elem = hash_find(
    &frame_table,
    &frame_to_find.table_elem
  );
  ASSERT(found_frame_elem != NULL);
  struct frame *found_frame = hash_entry(
    found_frame_elem,
    struct frame,
    table_elem
  );

  // Iterate through the frame's owners
  for (
    struct list_elem *cur_elem = list_begin(&found_frame->owners);
    cur_elem != list_end(&found_frame->owners);
    cur_elem = list_next(cur_elem)
  ) {

    // If the current owner is the current thread
    struct owner *cur_owner = list_entry(cur_elem, struct owner, elem);
    if (cur_owner->process->tid == cur_thread->tid) {

      // Remove the thread from the frame's owners
      list_remove(cur_elem);
      free(cur_owner);
      break;
    }
  }

  lock_release(&frame_table_lock);

#endif
}
