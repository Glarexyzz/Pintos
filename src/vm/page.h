#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <debug.h>
#include <hash.h>
#include "filesys/off_t.h"
#include "vm/mmap.h"

/// spt_entry data for an uninitialised executable.
struct uninitialised_executable {
  int page_read_bytes;      /* Number of bytes to read. */
  int page_zero_bytes;      /* Number of bytes to set to zero. */
  int offset;               /* Offset in the file to read from. */
};

// Page mapped to a file in memory.
struct memory_mapped_file {
  struct mmap_entry *mmap_entry; /* Entry in the table of file mappings. */
  struct list_elem elem;         /* For insertion in the list of pages
                                        in the mmap_entry. */
  /* The portion of the page to read/write to the file. */
  size_t page_file_bytes;
  /* The portion of the page not included in the file. */
  size_t page_zero_bytes;
};

/// Describes where the data referred to by the SPT is located.
enum spt_entry_type {
  UNINITIALISED_EXECUTABLE,
  MMAP, // A page mapped to a part of a file in the user's address space.
};

/// Entry for the supplemental page table.
struct spt_entry {
  void *uvaddr;             /* The user virtual address. */
  enum spt_entry_type type; /* The type of the data, used to decode the
                             * union. */
  bool writable;            /* Whether the page is writable. */
  union {                   /* The spt_entry_type-specific data. */
    struct uninitialised_executable exec_file;
    struct memory_mapped_file mmap;
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
