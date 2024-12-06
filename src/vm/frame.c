#include <debug.h>
#include <stdio.h>
#include "devices/swap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/share.h"

/// The list that stores all frames that are eligible for eviction.
struct list eviction_list;
/// The lock for the eviction_list
struct lock eviction_lock;
/// Points to the current frame that is being considered for eviction.
struct list_elem *eviction_cursor;

static unsigned frame_hash(const struct hash_elem *element, void *aux UNUSED);
static bool frame_kvaddr_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);


/**
 * A hash_hash_func for frame struct.
 * @param element The pointer to the table_elem in the frame struct.
 * @param aux Unused.
 * @return The hash of the frame.
 */
static unsigned frame_hash(const struct hash_elem *element, void *aux UNUSED) {
  void *kvaddr = hash_entry(element, struct frame, table_elem)->kvaddr;
  return hash_bytes(&kvaddr, sizeof (void *));
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
  while (kvaddr == NULL) {
    printf("Kernel out of memory! Evicting...\n");
    evict_frame();
    kvaddr = palloc_get_page(PAL_USER | flags);
  }

  // Initialise the page
  struct frame *new_frame = malloc(sizeof (struct frame));
  if (new_frame == NULL) {
    PANIC("Kernel out of memory!");
  }
  new_frame->kvaddr = kvaddr;

  // Add the current process as the frame's owner
  struct owner *owner = malloc(sizeof(struct owner));
  if (owner == NULL) {
    PANIC("Kernel out of memory!");
  }
  // TODO: Free appropriately in evict and user_free_page!

  owner->process = cur_thread;
  // TODO: Add uvaddr!

  new_frame->owner = owner;
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

  // Find and update the frame in the frame table
  struct frame frame_to_find;
  frame_to_find.kvaddr = page;

  lock_acquire(&frame_table_lock);
  // Acquire own lock
  // After acquiring, check if the frame we wanted to free still exists, as
  // it might've gotten evicted.
  // TODO: Ensure proper synchronisation with eviction.
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

  bool delete_frame = false;
  if (found_frame->shared_frame == NULL) {
    // Frame only has a single owner, so we can delete the frame.
    ASSERT(found_frame->owner != NULL);
    hash_delete(&frame_table, found_frame_elem);
    palloc_free_page(page);

    delete_frame = true;
  } else {
    struct shared_frame *shared_frame = found_frame->shared_frame;

    // Frame is shared, so we must remove ourselves as an owner.
    lock_acquire(&share_table_lock);
    lock_acquire(&shared_frame->lock);
    shared_frame_delete_owner(shared_frame, cur_thread);

    // If the list of owners is now empty, we can delete both the frame and the
    // shared_frame.
    if (list_empty(&shared_frame->owners)) {

      // Delete the shared_frame
      struct hash_elem *deleted_shared_frame_elem = hash_delete(
        &share_table,
        &shared_frame->elem
      );
      ASSERT(deleted_shared_frame_elem != NULL);
      close_shared_file(shared_frame->file);

      // Delete the frame and free the shared_frame
      hash_delete(&frame_table, found_frame_elem);
      palloc_free_page(page);
      lock_release(&shared_frame->lock);
      lock_release(&share_table_lock);
      free(shared_frame);

      delete_frame = true;
    } else {
      // The shared_frame still has owners.
      lock_release(&shared_frame->lock);
      lock_release(&share_table_lock);
    }
  }

  if (delete_frame) {
    free(found_frame->owner);
    free(found_frame);
  }
  lock_release(&frame_table_lock);
}

void eviction_list_init(void) {
  list_init(&eviction_list);
  lock_init(&eviction_lock);
  eviction_cursor = list_begin(&eviction_list);
}

void pin_page(void *uvaddr) {
  // TODO
}

static void assert_pinned(struct frame *found_frame) {
  for (
      struct list_elem *elem = list_begin(&eviction_list);
      elem != list_end(&eviction_list);
      elem = list_next(elem)
      ) {
    struct frame *cur_frame = list_entry(elem, struct frame, queue_elem);

    if (found_frame->kvaddr == cur_frame->kvaddr) {
      PANIC(
          "Page %p, is already in the eviction list!\n",
          found_frame->kvaddr
      );
    }
  }
}

/**
 * Pins a page, given a uvaddr, preventing it from getting evicted.
 * @param uvaddr
 */
void unpin_page(void *uvaddr) {
  ASSERT(pg_ofs(uvaddr) == 0);
  void *kvaddr = pagedir_get_page(thread_current()->pagedir, uvaddr);

  // Find the correct frame to pin.
  struct frame frame_to_find;
  frame_to_find.kvaddr = kvaddr;

  lock_acquire(&frame_table_lock);
  struct hash_elem *found_elem = hash_find(
    &frame_table,
    &frame_to_find.table_elem
  );
  lock_release(&frame_table_lock);
  ASSERT(found_elem != NULL);

  struct frame *found_frame = hash_entry(
    found_elem,
    struct frame,
    table_elem
  );

  // TODO: REMOVE THIS AS IT IS FOR DEBUGGING
  assert_pinned(found_frame);

  lock_acquire(&eviction_lock);
  list_push_back(&eviction_list, &found_frame->queue_elem);
  lock_release(&eviction_lock);
}

void evict_frame(void) {
  lock_acquire(&frame_table_lock);
  lock_acquire(&eviction_lock);

  if (list_empty(&eviction_list)) {
    printf("No more frames to evict!\n");
    lock_release(&eviction_lock);
    lock_release(&frame_table_lock);
    exit_user_process(ERROR_STATUS_CODE);
    return;
  }


  for (;;) {
    if (eviction_cursor == list_end(&eviction_list)) {
      eviction_cursor = list_begin(&eviction_list);
    }
    struct frame *cur_frame = list_entry(
      eviction_cursor,
      struct frame,
      queue_elem
    );
    struct owner *owner = cur_frame->owner;
    // TODO: Check if there are multiple owners!

    // Check the frame accessed bit to determine if it has a second chance.
    if (!pagedir_is_accessed(owner->process->pagedir, owner->uvaddr)) {
      // Evict!
      eviction_cursor = list_remove(eviction_cursor);
      hash_delete(&frame_table, &cur_frame->table_elem);
      // Since this is the only exit point of the loop, we can release the
      // locks here, minimising the time other threads spend blocked.

      // Check if there's an SPT entry already, and handle accordingly.
      struct spt_entry entry_to_find;
      entry_to_find.uvaddr = owner->uvaddr;

      lock_acquire(&owner->process->spt_lock);
      struct hash_elem *found_elem = hash_find(
        &owner->process->spt,
        &entry_to_find.elem
      );

      if (found_elem != NULL) {
        // Entry to find, handle accordingly.
        struct spt_entry *found_entry = hash_entry(
          found_elem,
          struct spt_entry,
          elem
        );

        switch (found_entry->type) {
          case UNINITIALISED_EXECUTABLE:
            pagedir_clear_page(owner->process->pagedir, owner->uvaddr);
            break;
          case MMAP:
            mmap_flush_entry(found_entry, owner->process);
            // TODO: POSSIBLE RACE CONDITION HERE; WHERE THREAD
            break;
          default:
            PANIC("Unrecognised spt_entry type!\n");
        }
      } else {
        // No entry, so we can evict normally.
        pagedir_clear_page(owner->process->pagedir, owner->uvaddr);
        size_t swap_slot = swap_out(cur_frame->kvaddr);

        // Create and add an SPT entry to signify the page being evicted.
        struct spt_entry *new_entry = malloc(sizeof(struct spt_entry));
        new_entry->uvaddr = owner->uvaddr;
        new_entry->type = SWAPPED;
        new_entry->swap_slot = swap_slot;

        hash_insert(&owner->process->spt, &new_entry->elem);
      }
      lock_release(&owner->process->spt_lock);


      free(cur_frame);
      break;
    }

    // TODO: SET ACCESSED TO FALSE AND NEXT
    pagedir_set_accessed(owner->process->pagedir, owner->uvaddr, false);
    eviction_cursor = list_next(eviction_cursor);
  }

  lock_release(&eviction_lock);
  lock_release(&frame_table_lock);
}
