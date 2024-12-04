#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

/// The item to be inserted into the frame struct's owners list
struct owner {
  struct thread *process; /* The thread/process which owns a page */
  struct list_elem elem;  /* For insertion into the frame's owner list */
};

/// The frame table
struct hash frame_table;
/// The lock for the frame table
struct lock frame_table_lock;

/// The table of read-only file mappings
struct hash share_table;
/// The lock for the share table
struct lock share_table_lock;

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
 * @param element The pointer to the frame_table_elem in the frame struct.
 * @param aux Unused.
 * @return The hash of the frame.
 * @remark Used for the frame table.
 */
static unsigned frame_kvaddr_hash(
  const struct hash_elem *element,
  void *aux UNUSED
) {
  void *kvaddr = hash_entry(element, struct frame, frame_table_elem)->kvaddr;
  return hash_bytes(&kvaddr, sizeof (void *));
}

/**
 * A hash_less_func for frame struct, based on the kvaddr.
 * @param a The pointer to the hash_elem in the first frame struct.
 * @param b The pointer to the hash_elem in the second frame struct.
 * @param aux Unused.
 * @return True iff a < b.
 * @remark Used for the frame table.
 */
static bool frame_kvaddr_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  void *a_kvaddr = hash_entry(a, struct frame, frame_table_elem)->kvaddr;
  void *b_kvaddr = hash_entry(b, struct frame, frame_table_elem)->kvaddr;
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
 * A hash_hash_func for frame struct, based on the file and offset.
 * @param element The pointer to the hash_elem in the frame struct.
 * @param aux Unused.
 * @return The hash of the frame, based on file and offset.
 * @remark Used for the share table.
 */
static unsigned frame_file_hash(
  const struct hash_elem *element,
  void *aux UNUSED
) {
  struct frame *frame = hash_entry(element, struct frame, share_table_elem);
  return file_hash(frame->file) + hash_int(frame->offset);
}

/**
 * A hash_less_func for frame struct, based on the file and offset.
 * @param a The pointer to the hash_elem in the first frame struct.
 * @param b The pointer to the hash_elem in the second frame struct.
 * @param aux Unused.
 * @return True iff a < b.
 * @remark Used for the share table.
 */
static bool frame_file_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  struct frame *a_frame = hash_entry(a, struct frame, share_table_elem);
  struct frame *b_frame = hash_entry(b, struct frame, share_table_elem);

  return (file_hash(a_frame->file) + a_frame->offset) <
  (file_hash(a_frame->file) + b_frame->offset);
}

/**
 * Initialise the share table and share table lock.
 * @remark Panics the kernel if initialisation fails.
 */
void share_table_init() {
  bool success = hash_init(
    &share_table,
    &frame_file_hash,
    &frame_file_smaller,
    NULL
  );
  if (!success) {
    PANIC("Could not initialise share table!");
  }
  lock_init(&share_table_lock);
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
  hash_insert(&frame_table, &new_frame->frame_table_elem);
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
    &frame_to_find.frame_table_elem
  );
  ASSERT(found_frame_elem != NULL);
  struct frame *found_frame = hash_entry(
    found_frame_elem,
    struct frame,
    frame_table_elem
  );

  // Iterate through the frame's owners
  bool owner_found = false;
  for (
    struct list_elem *cur_elem = list_begin(&found_frame->owners);
    cur_elem != list_end(&found_frame->owners);
    cur_elem = list_next(cur_elem)
  ) {

    // If the current owner is the current thread
    struct owner *cur_owner = list_entry(cur_elem, struct owner, elem);
    if (cur_owner->process->tid == cur_thread->tid) {

      // Remove the thread from the frame's owners
      owner_found = true;
      list_remove(cur_elem);
      free(cur_owner);
      break;
    }
  }
  ASSERT(owner_found);

  hash_delete(&frame_table, found_frame_elem);
  lock_release(&frame_table_lock);

#endif
}
