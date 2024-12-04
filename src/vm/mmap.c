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

/// Functions for obtaining and releasing allocated memory
/// for the mapping table.
static bool create_spt_entries(struct mmap_entry *dest_mmap_entry, off_t len);
static void remove_spt_entries(struct list *mapped_pages);
static void free_mmap_elem(struct hash_elem *mmap_hash_elem, void *aux UNUSED);

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
 * Initialises the memory-mapped file table.
 * @return `true` if initialisation succeeded,
 * `false` if memory allocation failed.
 */
bool mmap_init(void) {
  // Initialise the memory-mapping descriptor counter.
  thread_current()->mmap_id_counter = 0;
  return hash_init(
    get_mmap_table(),
    &mmap_entry_hash,
    &mmap_entry_id_smaller,
    NULL
  );
}

/**
 * Allocates and inserts entries for the given memory-mapped region into the
 * current thread's SPT, if the region is valid.
 * The calling function is responsible for freeing the destination entry
 * in the memory-mapping table.
 * @param dest_mmap_entry The (non-null) entry, not yet inserted into the
 * mapping table.
 * @param len The length of the file.
 * @return `false` iff the memory-mapping region overlaps with existing pages
 * in the SPT or the stack.
 */
static bool create_spt_entries(
    struct mmap_entry *dest_mmap_entry,
    off_t len
) {
  ASSERT(dest_mmap_entry != NULL);
  ASSERT(len > 0);
  // First, check that the file's memory-mapped region does not overlap with
  // the stack.
  // The address of the start of the last page in the mapped file.
  void *end_addr = pg_round_down(dest_mmap_entry->maddr + len);
  if (end_addr >= PHYS_BASE - STACK_MAX) {
    return false;
  }
  // Now attempt to allocate SPT entries for insertion.
  bool success = true;
  struct list *spt_entries = &dest_mmap_entry->pages;
  for (off_t cur_off = 0; cur_off < len; cur_off += PGSIZE) {
    struct spt_entry *entry = malloc(sizeof(struct spt_entry));
    if (entry == NULL) {
      success = false;
      break;
    }
    entry->uvaddr = dest_mmap_entry->maddr + cur_off;
    // Check if the entry is present in the SPT.
    // This is needed to check for overlap with existing pages, such as the
    // program's executable pages.
    struct hash *spt = &thread_current()->spt;
    if (hash_find(spt, &entry->elem) != NULL) {
      free(entry);
      success = false;
      break;
    }
    // Add the fields to the SPT entry.
    entry->type = MMAP;
    entry->mmap.mmap_entry = dest_mmap_entry;
    entry->mmap.dirty_bit = false;
    list_push_back(spt_entries, &entry->mmap.elem);
    // Insert the SPT entry into the table.
    struct hash_elem *prev = hash_insert(spt, &entry->elem);
    ASSERT(prev == NULL);
  }
  if (!success) {
    remove_spt_entries(&dest_mmap_entry->pages);
    return false;
  }
  return success;
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

/**
 * Frees a list of mapped pages corresponding to memory-mapped files, flushing
 * changes if required.
 * @param mapped_pages A list of mapped pages.
 * @remark mapped_pages itself is not freed.
 */
static void remove_spt_entries(struct list *mapped_pages) {
  ASSERT(!list_empty(mapped_pages));
  struct list_elem *cur = list_begin(mapped_pages);
  struct hash *spt = &thread_current()->spt;
  while (cur != list_end(mapped_pages)) {
    struct list_elem *next = list_next(cur);
    // Delete from the list.
    list_remove(cur);
    // The SPT entry is chained to the list of mapped pages using mmap.elem;
    // obtain the underlying SPT entry
    struct spt_entry *spt_entry = list_entry(cur, struct spt_entry, mmap.elem);
    // Flush changes in any currently-allocated frames if they have been
    // written to.
    mmap_flush_entry(spt_entry);
    // Remove the mapped page from the SPT; this must have been malloced
    // beforehand.
    hash_delete(spt, &spt_entry->elem);
    free(spt_entry);
    cur = next;
  }
  ASSERT(list_empty(mapped_pages));
}

static void free_mmap_elem(
    struct hash_elem *mmap_hash_elem,
    void *aux UNUSED
) {
  ASSERT(mmap_hash_elem != NULL);
  // Obtain the underlying memory-mapping entry.
  struct mmap_entry *mmap_entry = from_hash_elem(mmap_hash_elem);
  // Remove all the mapped pages, close the file, and free the entry.
  remove_spt_entries(&mmap_entry->pages);
  file_close(mmap_entry->file);
  free(mmap_entry);
}

void mmap_destroy(void) {
  hash_destroy(get_mmap_table(), &free_mmap_elem);
}

void mmap_remove_mapping(mapid_t mapping_id) {
  struct mmap_entry key;
  key.mapping_id = mapping_id;
  struct hash_elem *found_elem = hash_delete(get_mmap_table(), &key.elem);
  // Do nothing if we don't find the given mapping in our table.
  if (found_elem == NULL) {
      return;
    }
  // Release the resources used to create the entry.
  free_mmap_elem(found_elem, NULL);
}
