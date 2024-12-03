#ifndef MMAP_H
#define MMAP_H

#include <debug.h>
#include <hash.h>
#include <user/syscall.h>
#include "filesys/file.h"

struct mmap_entry {
  mapid_t mapping_id;     /* The identifier for the map entry. */
  struct file *file;      /* The structure of the actual file. */
  void *maddr;            /* The basal address to map the file to. */
  struct list pages;      /* List of pages currently mapped to the file. */
  struct hash_elem elem;  /* Used to insert the element into mmap_table. */
};

#endif //MMAP_H
