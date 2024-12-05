#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/share.h"
#include <stdio.h>

static unsigned frame_kvaddr_hash(
  const struct hash_elem *element,
  void *aux UNUSED
);
static bool frame_kvaddr_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);


/**
 * A hash_hash_func for frame struct, based on the kvaddr.
 * @param element The pointer to the table_elem in the frame struct.
 * @param aux Unused.
 * @return The hash of the frame.
 */
static unsigned frame_kvaddr_hash(
  const struct hash_elem *element,
  void *aux UNUSED
) {
  void *kvaddr = hash_entry(element, struct frame, table_elem)->kvaddr;
  return hash_bytes(&kvaddr, sizeof (void *));
}

/**
 * A hash_less_func for frame struct, based on the kvaddr.
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
    &frame_kvaddr_hash,
    &frame_kvaddr_smaller,
    NULL
  );
  if (!success) {
    PANIC("Could not initialise frame table!");
  }
  lock_init(&frame_table_lock);
}

/**
 * Get a page from the user pool and create an associated frame.
 * @param flags The flags for the palloc_get_page call.
 * @return The new frame.
 * @remark Does not update the frame table.
 */
struct frame *create_frame(enum palloc_flags flags) {
  struct thread *cur_thread = thread_current();
  ASSERT(cur_thread->is_user);

  // Get the kernel virtual address
  void *kvaddr = palloc_get_page(PAL_USER | flags);
  if (kvaddr == NULL) {
    PANIC("No free pages!");
  }

  // Initialise the page
  struct frame *new_frame = malloc(sizeof (struct frame));
  if (new_frame == NULL) {
    PANIC("Kernel out of memory!");
  }
  new_frame->kvaddr = kvaddr;

  // Add the current process as the frame's owner
  new_frame->owner = cur_thread;
  new_frame->shared_frame = NULL;

  return new_frame;
}

/**
 * Obtain a page from the user pool.
 * @param flags The flags for the palloc_get_page call.
 * @return The kernel virtual address for the page.
 * @pre The caller is a user process.
 * @remark Updates the frame table.
 */
void *user_get_page(enum palloc_flags flags) {
  struct frame *new_frame = create_frame(flags);
//  printf("Attempting to insert %p to frame table\n", new_frame);

  // Insert the page into the page table
  lock_acquire(&frame_table_lock);
  hash_insert(&frame_table, &new_frame->table_elem);
  lock_release(&frame_table_lock);

  return new_frame->kvaddr;
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

  if (found_frame->shared_frame == NULL) {
    // Frame only has a single owner, so we can delete the frame.
    ASSERT(found_frame->owner != NULL);
    hash_delete(&frame_table, found_frame_elem);
    palloc_free_page(page);

  } else {
    struct shared_frame *shared_frame = found_frame->shared_frame;

    // Frame is shared, so we must remove ourselves as an owner.
    lock_acquire(&share_table_lock);
    lock_acquire(&shared_frame->lock);
    shared_frame_delete_owner(shared_frame, cur_thread);

    // If the list of owners is now empty, we can delete both the frame and the
    // shared_frame.
    if (list_empty(&shared_frame->owners)) {
      struct hash_elem *thing = hash_delete(&share_table, &shared_frame->elem);
      ASSERT(thing != NULL);

      close_shared_file(shared_frame->file);

      hash_delete(&frame_table, found_frame_elem);
      palloc_free_page(page);
      lock_release(&shared_frame->lock);
      lock_release(&share_table_lock);
      free(shared_frame);

    } else {
      lock_release(&shared_frame->lock);
      lock_release(&share_table_lock);
    }
  }

  lock_release(&frame_table_lock);
#endif
}
