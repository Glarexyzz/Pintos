#ifndef MMAP_H
#define MMAP_H

#include <debug.h>
#include <hash.h>
#include <user/syscall.h>
#include "filesys/file.h"

/// A pointer to a supplemental page table entry.
/// Necessary to avoid circular dependencies with page.h
typedef struct spt_entry *spt_entry_ptr;

struct mmap_entry {
  mapid_t mapping_id;     /* The identifier for the map entry. */
  struct file *file;      /* The structure of the actual file. */
  void *maddr;            /* The basal address to map the file to. */
  struct list pages;      /* List of pages currently mapped to the file. */
  struct hash_elem elem;  /* Used to insert the element into mmap_table. */
};

/// Function for updating changes to a singular memory-mapped page to the disk.
void mmap_flush_entry(spt_entry_ptr entry);

/// Functions for initialising, obtaining and destroying the mapping table.
bool mmap_init(void);
struct hash *get_mmap_table(void);
void mmap_destroy(void);

struct mmap_entry *mmap_get_entry(mapid_t mapping_id);
void mmap_remove_mapping(mapid_t mapping_id);

#endif //MMAP_H
