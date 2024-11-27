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
