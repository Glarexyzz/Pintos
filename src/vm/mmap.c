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
