#include <list.h>
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

void spt_destroy(void) {
  // TODO
}

static void free_uninitialised_executable(struct spt_entry *entry) {
  // TODO: Add synchronisation.
  void *kvaddr = pagedir_get_page(thread_current()->pagedir, entry->uvaddr);

  if (entry->writable) {
    // The file might be in memory, so we must check that first.
    if (kvaddr != NULL) {
      // The file is in memory, so we must remove it from the frame table and
      // invalidate the pagedir entry.
      user_free_page(kvaddr);
      /*pagedir_clear_page(thread_current()->pagedir, entry->uvaddr);

      struct frame frame_to_find;
      frame_to_find.kvaddr = kvaddr;

      struct hash_elem *found_elem = hash_find(
          &frame_table,
          &frame_to_find.table_elem
      );
      ASSERT(found_elem != NULL); // TODO: can the frame get removed by the time we find it (e.g. by eviction?)

      struct frame *found_frame = hash_entry(
          found_elem,
      struct frame,
      table_elem
      );

      // Remove from frame table, eviction list, and free resources.
      hash_delete(&frame_table, &found_frame->table_elem);
      list_remove(&found_frame->queue_elem);
      free(found_frame->owner);
      free(found_frame);
      // TODO: Perhaps replace with user_free_page?*/
    }

  } else {
    if (kvaddr != NULL) {
      user_free_page(kvaddr);
    }
  }
  free(entry);
}

static void free_spt_entry(
  struct hash_elem *cur_elem,
  void *aux UNUSED
) {
  // TODO: Add synchronisation!
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
    default:
      break;
  }
}
