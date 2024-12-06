#include <debug.h>
#include <stdio.h>
#include "devices/swap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/exception.h"
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
struct frame *create_frame(enum palloc_flags flags, const void *uvaddr) {
  struct thread *cur_thread = thread_current();
  ASSERT(cur_thread->is_user);

  // Get the kernel virtual address
  void *kvaddr = palloc_get_page(PAL_USER | flags);
  while (kvaddr == NULL) {
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

  owner->process = cur_thread;
  owner->uvaddr = uvaddr;

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
void *user_get_page(enum palloc_flags flags, const void *uvaddr) {
  struct frame *new_frame = create_frame(flags, uvaddr);
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
    lock_acquire(&cur_thread->spt_lock);
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
      lock_release(&cur_thread->spt_lock);
      free(shared_frame);

      delete_frame = true;
    } else {
      // The shared_frame still has owners.
      lock_release(&shared_frame->lock);
      lock_release(&share_table_lock);
      lock_release(&cur_thread->spt_lock);
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

/**
 * Pins a page, preventing it from getting evicted.
 * @param uvaddr The address of the page to be pinned.
 */
void pin_page(void *uvaddr) {
  lock_acquire(&frame_table_lock);
  lock_acquire(&eviction_lock);
  lock_acquire(&thread_current()->spt_lock);
  void *kvaddr = pagedir_get_page(thread_current()->pagedir, uvaddr);
  if (kvaddr == NULL) {
    lock_release(&frame_table_lock);
    lock_release(&eviction_lock);

    // The page has been evicted, so we must bring it back in.
    struct spt_entry entry_to_find;
    entry_to_find.uvaddr = uvaddr;

    struct hash_elem *found_elem = hash_find(
      &thread_current()->spt,
      &entry_to_find.elem
    );

    // If the element is not found, that means we have tried to pin a
    // non-existent page.
    ASSERT(found_elem != NULL);
    struct spt_entry *found_entry = hash_entry(
      found_elem,
      struct spt_entry,
      elem
    );

    // This will load the page into memory, pinning it.
    bool success = process_spt_entry(found_entry);

    // For debugging.
    ASSERT(success);
    kvaddr = pagedir_get_page(thread_current()->pagedir, uvaddr);
    ASSERT(kvaddr != NULL);
  } else {
    // The page is in memory, so we find its frame and remove it from the
    // eviction list.
    ASSERT(kvaddr != NULL);

    struct frame frame_to_find;
    frame_to_find.kvaddr = kvaddr;

    struct hash_elem *found_elem = hash_find(
      &frame_table,
      &frame_to_find.table_elem
    );
    ASSERT(found_elem != NULL);

    struct frame *found_frame = hash_entry(
      found_elem,
      struct frame,
      table_elem
    );
    list_remove(&found_frame->queue_elem);

    lock_release(&frame_table_lock);
    lock_release(&eviction_lock);
  }

  lock_release(&thread_current()->spt_lock);
}

static bool assert_pinned(struct frame *found_frame) {
  for (
    struct list_elem *elem = list_begin(&eviction_list);
    elem != list_end(&eviction_list);
    elem = list_next(elem)
  ) {
    struct frame *cur_frame = list_entry(elem, struct frame, queue_elem);

    if (found_frame->kvaddr == cur_frame->kvaddr) {
      return false;
    }
  }

  return true;
}

/**
 * Pins a page, given a uvaddr, allowing it to get evicted again.
 * @param uvaddr The user address for the page to be unpinned.
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

  lock_acquire(&eviction_lock);
  if (!assert_pinned(found_frame)) {
    lock_release(&eviction_lock);
    return;
  }

  list_push_back(&eviction_list, &found_frame->queue_elem);
  lock_release(&eviction_lock);
}

/**
 * Grabs the spt locks of two threads (that are possibly the same thread)
 * in an established partial order, avoiding deadlocks.
 * @param a The first thread.
 * @param b The second thread.
 */
static void acquire_two_spt_locks(struct thread *a, struct thread *b) {
  if (a->tid == b->tid) {
    // They are the same process, so we only need to acquire the lock once.
    lock_acquire(&a->spt_lock);
    return;
  }

  if (a->tid < b->tid) {
    lock_acquire(&a->spt_lock);
    lock_acquire(&b->spt_lock);
  } else {
    lock_acquire(&b->spt_lock);
    lock_acquire(&a->spt_lock);
  }
}

/**
 * Releases the spt locks of two threads, making sure to only release once if
 * they are the same.
 * @param a The first thread.
 * @param b The second thread.
 */
static void release_two_spt_locks(struct thread *a, struct thread *b) {
  if (a->tid == b->tid) {
    lock_release(&a->spt_lock);
  } else {
    lock_release(&b->spt_lock);
    lock_release(&a->spt_lock);
  }
}

/**
 * Acquires the lock of multiple threads, making sure not to acquire thread a's
 * spt_lock twice in case it appears in bs
 * @param a The first thread.
 * @param bs A list of owners.
 * @pre bs is sorted in order of ascending tid.
 */
static void acquire_multiple_spt_locks(struct thread *a, struct list *bs) {
  bool a_is_locked = false;
  for (
    struct list_elem *cur_elem = list_begin(bs);
    cur_elem != list_end(bs);
    cur_elem = list_next(cur_elem)
  ) {
    struct thread *cur_b = list_entry(cur_elem, struct owner, elem)->process;
    if (a->tid < cur_b->tid) {
      // a is smaller, so grab a first
      if (!a_is_locked) {
        lock_acquire(&a->spt_lock);
        a_is_locked = true;
      }
      lock_acquire(&cur_b->spt_lock);

    } else if (a->tid == cur_b->tid) {
      if (!a_is_locked) {
        lock_acquire(&a->spt_lock);
        a_is_locked = true;
      }

    } else {
      // b is smaller, so grab b first
      lock_acquire(&cur_b->spt_lock);
    }
  }

  // If a isn't acquired, it had the largest tid and therefore needs to be
  // locked now.
  if (!a_is_locked) {
    lock_acquire(&a->spt_lock);
  }
}

static void release_multiple_spt_locks(struct thread *a, struct list *bs) {
  bool a_is_released = false;
  for (
    struct list_elem *cur_elem = list_begin(bs);
    cur_elem != list_end(bs);
    cur_elem = list_next(cur_elem)
  ) {
    struct thread *cur_b = list_entry(cur_elem, struct owner, elem)->process;
    if (a->tid == cur_b->tid) {
      if (!a_is_released) {
        lock_release(&a->spt_lock);
        a_is_released = true;
      }
    } else {
      lock_release(&cur_b->spt_lock);
    }
  }

  // If a isn't acquired, it had the largest tid and therefore needs to be
  // locked now.
  if (!a_is_released) {
    lock_release(&a->spt_lock);
  }
}

static void acquire_frame_locks(struct thread *a, struct frame* frame) {
  if (frame->shared_frame == NULL) {
    acquire_two_spt_locks(a, frame->owner->process);
  } else {
    acquire_multiple_spt_locks(a, &frame->shared_frame->owners);
  }
}

static void release_frame_locks(struct thread *a, struct frame* frame) {
  if (frame->shared_frame == NULL) {
    release_two_spt_locks(a, frame->owner->process);
  } else {
    release_multiple_spt_locks(a, &frame->shared_frame->owners);
  }
}

bool frame_accessed(struct frame *frame) {
  bool accessed = false;
  if (frame->shared_frame == NULL) {
    // Single owner case. Check if it is accessed and reset the bit.
    accessed = pagedir_is_accessed(
      frame->owner->process->pagedir,
      frame->owner->uvaddr
    );
    pagedir_set_accessed(
      frame->owner->process->pagedir,
      frame->owner->uvaddr,
      false
    );
  } else {
    // Multiple owners, so we only need one to have accessed it.
    struct list *owners = &frame->shared_frame->owners;
    for (
      struct list_elem *cur_elem = list_begin(owners);
      cur_elem != list_end(owners);
      cur_elem = list_next(cur_elem)
    ) {
      struct owner *cur_owner = list_entry(cur_elem,
      struct owner, elem);
      accessed |= pagedir_is_accessed(
        cur_owner->process->pagedir,
        cur_owner->uvaddr
      );
      pagedir_set_accessed(
        cur_owner->process->pagedir,
        cur_owner->uvaddr,
        false
      );
    }
  }
  return accessed;
}

void evict_frame(void) {
  lock_acquire(&frame_table_lock);
  lock_acquire(&eviction_lock);

  if (list_empty(&eviction_list)) {
    lock_release(&eviction_lock);
    lock_release(&frame_table_lock);
    exit_user_process(ERROR_STATUS_CODE);
  }

  struct frame *frame_to_evict;
  // Find the frame to evict.
  while (true) {
    if (eviction_cursor == list_end(&eviction_list)) {
      eviction_cursor = list_begin(&eviction_list);
    }

    frame_to_evict = list_entry(
      eviction_cursor,
      struct frame,
      queue_elem
    );

    // Grab all the owner locks! And also the shared_frame lock if needed.
    acquire_frame_locks(thread_current(), frame_to_evict);
    if (frame_to_evict->shared_frame != NULL) {
      lock_acquire(&frame_to_evict->shared_frame->lock);
    }

    eviction_cursor = list_next(eviction_cursor);
    if (!frame_accessed(frame_to_evict)) {
      break;
    }

    if (frame_to_evict->shared_frame != NULL) {
      lock_release(&frame_to_evict->shared_frame->lock);
    }
    release_frame_locks(thread_current(), frame_to_evict);
  }

  // Remove the frame_to_evict from the frame table and eviction list, avoiding
  // any further interference.
  hash_delete(&frame_table, &frame_to_evict->table_elem);
  list_remove(&frame_to_evict->queue_elem);
  lock_release(&eviction_lock);
  lock_release(&frame_table_lock);

  struct owner *owner = frame_to_evict->owner;
  // Find an spt_entry if there exists one.
  struct spt_entry entry_to_find;
  entry_to_find.uvaddr = owner->uvaddr;

  struct hash_elem *found_elem = hash_find(
    &owner->process->spt,
    &entry_to_find.elem
  );

  if (found_elem == NULL) {
    // No spt_entry, so we swap out the frame and add the swap slot to the spt.
    bool writable = pagedir_is_writable(owner->process->pagedir, owner->uvaddr);
    pagedir_clear_page(owner->process->pagedir, owner->uvaddr);
    size_t swap_slot = swap_out(frame_to_evict->kvaddr);

    struct spt_entry *new_entry = malloc(sizeof(struct spt_entry));
    if (new_entry == NULL) {
      PANIC("Kernel out of memory!");
    }

    new_entry->uvaddr = owner->uvaddr;
    new_entry->type = SWAPPED;
    new_entry->writable = writable;
    new_entry->swap_slot = swap_slot;

    hash_insert(&owner->process->spt, &new_entry->elem);
    free(frame_to_evict);
    lock_release(&owner->process->spt_lock);
    free(owner);
  } else {
    struct spt_entry *found_entry = hash_entry(
      found_elem,
      struct spt_entry,
      elem
    );

    switch (found_entry->type) {
      case SWAPPED:
        PANIC("We should not be able to evict a swapped out frame!\n");
        break;
      case UNINITIALISED_EXECUTABLE:
        if (found_entry->writable) {
          // Swap the data out, change the old spt entry, essentially replacing
          // it with a swap slot entry.
          pagedir_clear_page(owner->process->pagedir, owner->uvaddr);
          size_t swap_slot = swap_out(frame_to_evict->kvaddr);
          found_entry->type = SWAPPED;
          found_entry->swap_slot = swap_slot;

          free(frame_to_evict);
          lock_release(&owner->process->spt_lock);
          free(owner);
        } else {
          // We now have multiple owners to consider, so we must update all
          // their page directories.
          struct shared_frame *shared_frame = frame_to_evict->shared_frame;

          // Clear all the page directories.
          for (
            struct list_elem *cur_elem = list_begin(&shared_frame->owners);
            cur_elem != list_end(&shared_frame->owners);
            cur_elem = list_next(cur_elem)
          ) {
            struct owner *cur_owner = list_entry(
              cur_elem,
              struct owner,
              elem
            );
            pagedir_clear_page(cur_owner->process->pagedir, cur_owner->uvaddr);
          }

          shared_frame->frame = NULL;
          palloc_free_page(frame_to_evict->kvaddr);
          free(frame_to_evict);

          lock_release(&shared_frame->lock);
          release_multiple_spt_locks(thread_current(), &shared_frame->owners);
        }
        break;
      case MMAP:
        // This clears the page directory for us, and writes back to file.
        mmap_flush_entry(found_entry, owner->process);

        // Free up memory and free frame.
        palloc_free_page(frame_to_evict->kvaddr);
        free(frame_to_evict);

        lock_release(&owner->process->spt_lock);
        free(owner);
        break;
      default:
        PANIC("Unrecognised spt_entry type!\n");
        break;
    }
  }
}
