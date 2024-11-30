#ifndef MMAP_H
#define MMAP_H

#include <debug.h>
#include <hash.h>
#include <user/syscall.h>
#include "filesys/file.h"

struct mmap_entry {
  mapid_t mapping_id;     /* The identifier for the map entry. */
  struct file *file;      /* The structrue of the actual file. */
  const void *maddr;      /* The address to map the file to. */
  struct list pages;      /* List of pages currently mapped to the file. */
  struct hash_elem elem;  /* Used to insert the element into mmap_table. */
};

unsigned mmap_entry_hash(const struct hash_elem *element, void *aux UNUSED);
bool mmap_entry_maddr_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);

#endif //MMAP_H
