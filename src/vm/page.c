#include <hash.h>
#include <list.h>
#include <stdio.h>
#include "devices/swap.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "page.h"

/**
 * A hash_hash_func for spt_entry struct.
 * @param element The pointer to the hash_elem in the spt_entry struct.
 * @param aux Unused.
 * @return The hash of the spt_entry.
 */
unsigned spt_entry_hash(const struct hash_elem *element, void *aux UNUSED) {
  void *uvaddr = hash_entry(element, struct spt_entry, elem)->uvaddr;
  return hash_bytes(&uvaddr, sizeof (void *));
}

/**
 * A hash_less_func for spt_entry struct.
 * @param a The pointer to the hash_elem in the first spt_entry struct.
 * @param b The pointer to the hash_elem in the second spt_entry struct.
 * @param aux Unused.
 * @return True iff a < b.
 */
bool spt_entry_kvaddr_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  void *a_uvaddr = hash_entry(a, struct spt_entry, elem)->uvaddr;
  void *b_uvaddr = hash_entry(b, struct spt_entry, elem)->uvaddr;
  return a_uvaddr < b_uvaddr;
}

static void free_uninitialised_executable(struct spt_entry *entry) {
  // Nothing to do if the entry is writable except freeing the spt_entry,
  // which will happen in free_spt_entry()
  if (entry->writable) return;

  // Otherwise, we have a shared frame and we need to remove ourselves as an
  // owner.
  struct shared_frame *shared_frame = entry->shared_exec_file.shared_frame;

  lock_acquire(&share_table_lock);
  lock_acquire(&shared_frame->lock);
  shared_frame_delete_owner(shared_frame, thread_current());

  if (list_empty(&shared_frame->owners)) {
    // Free the shared frame.
    hash_delete(
      &share_table,
      &shared_frame->elem
    );
    close_shared_file(shared_frame->file);

    lock_release(&share_table_lock);
    lock_release(&shared_frame->lock);
    free(shared_frame);
  } else {
    lock_release(&share_table_lock);
    lock_release(&shared_frame->lock);
  }
}

static void free_spt_entry(
  struct hash_elem *cur_elem,
  void *aux UNUSED
) {
  struct spt_entry *cur_entry = hash_entry(
    cur_elem,
    struct spt_entry,
    elem
  );

  // Determine the spt_entry type and handle accordingly.
  // Note that MMAP files are handled in a different function.
  switch (cur_entry->type) {
    case SWAPPED:
      swap_drop(cur_entry->swap_slot);
      break;
    case UNINITIALISED_EXECUTABLE:
      free_uninitialised_executable(cur_entry);
      break;
    case MMAP:
      PANIC("Memory mapped files should have already been freed!\n");
      break;
    default:
      PANIC("Unrecognised spt_entry type!\n");
      break;
  }
  free(cur_entry);
}

/**
 * Destroys the current thread's SPT, freeing resources as appropriate.
 * @pre Both mmap_destroy() and pagedir_destroy() have already been called for
 * this thread.
 */
void spt_destroy(void) {
  hash_destroy(&thread_current()->spt, &free_spt_entry);
}
