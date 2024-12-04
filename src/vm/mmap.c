#include "mmap.h"
#include "page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/exception.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

/// Functions for operating on internal elements in the mapping table.
static inline struct mmap_entry *from_hash_elem(
  const struct hash_elem *element
);
static unsigned mmap_entry_hash(
  const struct hash_elem *element,
  void *aux UNUSED
);
static bool mmap_entry_id_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);
/**
 * Converts a generic hash-table element to a memory-mapping entry, returning
 * NULL if the address to the hash element itself is NULL.
 * Produces undefined behaviour if the given element is a different type of
 * hashing element.
 * @param element The generic hash table element.
 * @return `NULL` if element is NULL, and the memory mapping entry otherwise.
 */
static inline struct mmap_entry *from_hash_elem(
  const struct hash_elem *element
) {
  return (element == NULL) ? NULL
    : hash_entry(element, struct mmap_entry, elem);
}

/**
 * Returns the mapping entry corresponding to a given mapping ID in the
 * current thread's file memory-mapping table, or NULL if none exists.
 * @param mapping_id The mapping ID to be keyed.
 * @return The (possibly `NULL`) mapping entry.
 */
struct mmap_entry *mmap_get_entry(mapid_t mapping_id) {
  struct mmap_entry key;
  key.mapping_id = mapping_id;
  struct hash_elem *elem = hash_find(get_mmap_table(), &key.elem);
  return from_hash_elem(elem);
}

/**
 * A hash_hash_func for mmap_entry struct.
 * @param element The pointer to the hash_elem in the mmap_entry struct.
 * @param aux Unused.
 * @return The hash of the mmap_entry.
 */
static unsigned mmap_entry_hash(
  const struct hash_elem *element,
  void *aux UNUSED
) {
  ASSERT(element != NULL);
  return hash_int(from_hash_elem(element)->mapping_id);
}

/**
 * A hash_less_func for mmap_entry struct.
 * @param a The pointer to the hash_elem in the first mmap_entry struct.
 * @param b The pointer to the hash_elem in the second mmap_entry struct.
 * @param aux Unused.
 * @return True iff the mapping ID of a < the mapping ID of b.
 */
static bool mmap_entry_id_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  ASSERT(a != NULL && b != NULL);
  mapid_t a_id = from_hash_elem(a)->mapping_id;
  mapid_t b_id = from_hash_elem(b)->mapping_id;
  return a_id < b_id;
}

/**
 * Obtain the current thread's file memory-mapping table.
 * @return The mapping hash table.
 */
struct hash *get_mmap_table(void) {
  return &thread_current()->mmap_table;
}
/**
 * Flushes a given frame in a memory-mapped page to the disk, if it is present
 * and has been written to (the dirty bit is set to `true`).
 * @param entry The entry in the current thread's SPT.
 * @pre The entry is non-null, and the type is MMAP.
 */
void mmap_flush_entry(struct spt_entry *entry) {
  ASSERT(entry != NULL);
  ASSERT(entry->type == MMAP);
  // Get the frame from the page, if one exists.
  void *frame = pagedir_get_page(thread_current()->pagedir, entry->uvaddr);
  // If the frame is not present, we must have already flushed its changes out
  // or the page was never in memory in the first place.
  if (frame == NULL) {
    return;
  }
  // If the frame hasn't been written to, we don't need to write to the disk.
  if (!entry->mmap.dirty_bit) {
    return;
  }
  struct mmap_entry *in_mmap_entry = entry->mmap.mmap_entry;
  // Verify that the reference to the parent entry is valid.
  ASSERT(in_mmap_entry != NULL);
  off_t offset = entry->uvaddr - in_mmap_entry->maddr;
  off_t write_amount = entry->mmap.page_file_bytes;
  // Write to the file.
  lock_acquire(&file_system_lock);
  file_write_at(in_mmap_entry->file, frame, offset, write_amount);
  lock_release(&file_system_lock);
}
