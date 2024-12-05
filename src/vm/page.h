#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <debug.h>
#include <hash.h>
#include "filesys/file.h"
#include "vm/frame.h"

/// spt_entry data for a read-only uninitialised executable.
struct uninitialised_executable {
  int page_read_bytes;               /* Number of bytes to read. */
  int page_zero_bytes;               /* Number of bytes to set to zero. */
  struct shared_frame *shared_frame; /* The shared frame in the share table. */
};

/// spt_entry data for a writable uninitialised executable.
struct writable_executable {
  int page_read_bytes;               /* Number of bytes to read. */
  int page_zero_bytes;               /* Number of bytes to set to zero. */
  struct file *file;                 /* The file to which the frame belongs. */
  int offset;                        /* The offset of the frame within the
                                      * file. */
};

/// Describes where the data referred to by the SPT is located.
enum spt_entry_type {
  UNINITIALISED_EXECUTABLE
};

/// Entry for the supplemental page table.
struct spt_entry {
  void *uvaddr;             /* The user virtual address. */
  enum spt_entry_type type; /* The type of the data, used to decode the
                             * union. */
  bool writable;            /* Whether the page is writable. */
  union {                   /* The spt_entry_type-specific data. */
    struct uninitialised_executable shared_exec_file;
    struct writable_executable writable_exec_file;
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
