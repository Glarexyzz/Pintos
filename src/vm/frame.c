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

static void print_frame(struct hash_elem *elem, void *aux UNUSED) {
  struct frame *frame = hash_entry(elem, struct frame, table_elem);
  printf("kvaddr %p, shared_frame %p, owner %p\n", frame->kvaddr, frame->shared_frame, frame->owner);
}

static void print_frame_table(void) {
  printf("--- Single frames [\n");
  hash_apply(&frame_table, print_frame);
  printf("] --- \n");
}

struct mock_owner {
  struct thread *process; /* The thread/process which owns a page */
  struct list_elem elem;  /* For insertion into the frame's owner list */
};

static void print_shared_frame(struct hash_elem *elem, void *aux UNUSED) {
  struct shared_frame *shared_frame = hash_entry(elem, struct shared_frame, elem);
  printf("shared frame %p, has frame %p, inode %p, offset %d, owners: {", shared_frame, shared_frame->frame != NULL ? shared_frame->frame->kvaddr : NULL,
         file_get_inode(shared_frame->file), shared_frame->offset);
  for (struct list_elem *e = list_begin(&shared_frame->owners); e != list_end(&shared_frame->owners); e = list_next(e)) {
    struct mock_owner *owner = list_entry(e, struct mock_owner, elem);
    printf("Proc %d (%s); ", owner->process->tid, owner->process->name);
  }
  printf("}\n");
}

static void print_shared_frame_table(void) {
  printf("--- Shared frames [\n");
  hash_apply(&share_table, print_shared_frame);
  printf("] --- \n");
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

//  printf("After inserting %p, frame table:\n", new_frame);
//  print_frame_table();

  return new_frame->kvaddr;
}

/**
 * Frees a page from the user pool.
 * @param page The page to free.
 * @pre The caller is a user process.
 * @remark Also updates the frame table.
 */
void user_free_page(void *page) {
//  printf(">>>>>>>>> %d Freeing %p\n", thread_current()->tid, page);
  struct thread *cur_thread = thread_current();
  ASSERT(cur_thread->is_user);


#ifdef VM
//  printf("Attempting to free page %p, current frame table:\n", page);
//  print_frame_table();
//  printf("Current shared frame table:\n");
//  print_shared_frame_table();

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
//    printf(">>>>> One owner only\n");
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

//    printf("After deleting owner\n"); print_shared_frame_table();

    // If the list of owners is now empty, we can delete both the frame and the
    // shared_frame.
    if (list_empty(&shared_frame->owners)) {
//      printf(">>>>> No owners\n");
//      printf("Removing: %p\n", shared_frame);
//      print_shared_frame(&shared_frame->elem, NULL);
//      printf("================= Before removing from share table =============\n");
//      print_shared_frame_table();
      struct hash_elem *thing = hash_delete(&share_table, &shared_frame->elem);
//      printf("================= After removing from share table =============\n");
//      print_shared_frame_table();
      ASSERT(thing != NULL);

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
