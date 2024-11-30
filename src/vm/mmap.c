#include "mmap.h"

unsigned mmap_entry_hash(const struct hash_elem *element, void *aux UNUSED);

/**
 * A hash_hash_func for mmap_entry struct.
 * @param element The pointer to the hash_elem in the mmap_entry struct.
 * @param aux Unused.
 * @return The hash of the mmap_entry.
 */
unsigned mmap_entry_hash(const struct hash_elem *element, void *aux UNUSED) {
  const void *maddr = hash_entry(element, struct mmap_entry, elem)->maddr;
  return hash_bytes(&maddr, sizeof (const void *));
}

/**
 * A hash_less_func for mmap_entry struct.
 * @param a The pointer to the hash_elem in the first mmap_entry struct.
 * @param b The pointer to the hash_elem in the second mmap_entry struct.
 * @param aux Unused.
 * @return True iff a < b.
 */
bool mmap_entry_maddr_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  const void *a_uvaddr = hash_entry(a, struct mmap_entry, elem)->maddr;
  const void *b_uvaddr = hash_entry(b, struct mmap_entry, elem)->maddr;
  return a_uvaddr < b_uvaddr;
}
