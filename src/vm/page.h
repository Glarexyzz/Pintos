#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <debug.h>
#include <hash.h>

/// Describes where the data referred to by the SPT is located.
enum spt_entry_type {
  PLACEHOLDER // TODO: Remove this
};

/// Entry for the supplemental page table.
struct spt_entry {
  void *uvaddr;             /* The user virtual address. */
  enum spt_entry_type type; /* The type of the data, used to decode the
                             * union. */
  union {                   /* The spt_entry_type-specific data. */
  };

  struct hash_elem elem;    /* For insertion into the supplemental page
                             * table. */
};

unsigned spt_entry_hash(const struct hash_elem *element, void *aux UNUSED);
bool spt_entry_kvaddr_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);

#endif //VM_PAGE_H
