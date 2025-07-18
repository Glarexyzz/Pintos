#include "mmap.h"
#include <string.h>
#include "page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
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
 * current process's file memory-mapping table, or NULL if none exists.
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
 * Obtain the current process's file memory-mapping table.
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
 * current process's SPT, if the region is valid.
 * The calling function is responsible for freeing the destination entry
 * in the memory-mapping table.
 * @param dest_mmap_entry The (non-null) entry, not yet inserted into the
 * mapping table.
 * @param len The length of the file.
 * @pre The SPT lock should not already be held by the current process.
 * @return `false` iff the memory-mapping region overlaps with existing pages
 * in the SPT or the stack.
 */
static bool create_spt_entries(
  struct mmap_entry *dest_mmap_entry,
  off_t len
) {
  uint32_t *pagedir = thread_current()->pagedir;
  struct hash *spt = &thread_current()->spt;
  struct lock *spt_lock = &thread_current()->spt_lock;
  ASSERT(!lock_held_by_current_thread(spt_lock));

  ASSERT(dest_mmap_entry != NULL);
  ASSERT(len > 0);
  // First, check that the file's memory-mapped region does not overlap with
  // the stack, NULL pointer, or the basal address is misaligned.
  void *base_addr = dest_mmap_entry->maddr;
  if (base_addr == NULL || pg_ofs(base_addr) != 0) {
    return false;
  }

  // The address of the start of the last page in the mapped file.
  void *end_addr = pg_round_down(base_addr + len);
  if (end_addr >= PHYS_BASE - STACK_MAX) {
    return false;
  }

  // Now attempt to allocate SPT entries for insertion.

  // Check if any entry is present in the SPT or page directory.
  // This is needed to check for overlap with existing pages, such as the
  // program's executable pages.
  lock_acquire(spt_lock);

  bool success = true;
  struct list *spt_entries = &dest_mmap_entry->pages;
  list_init(spt_entries);
  for (off_t cur_off = 0; cur_off < len; cur_off += PGSIZE) {

    struct spt_entry *entry = malloc(sizeof(struct spt_entry));
    if (entry == NULL) {
      success = false;
      break;
    }

    entry->uvaddr = base_addr + cur_off;
    ASSERT(pg_ofs(entry->uvaddr) == 0);

    bool page_present = pagedir_get_page(pagedir, entry->uvaddr) != NULL
      || hash_find(spt, &entry->elem) != NULL;
    if (page_present) {
      free(entry);
      success = false;
      break;
    }

    // Add the fields to the SPT entry.
    entry->type = MMAP;
    entry->mmap.mmap_entry = dest_mmap_entry;
    entry->writable = true;

    // Add the expected number of page and zero bytes.
    off_t remaining = len - cur_off;
    size_t page_file_bytes = remaining % PGSIZE;
    entry->mmap.page_file_bytes = page_file_bytes;
    entry->mmap.page_zero_bytes = PGSIZE - page_file_bytes;
    list_push_back(spt_entries, &entry->mmap.elem);

    // Insert the SPT entry into the table.
    struct hash_elem *prev = hash_insert(spt, &entry->elem);
    ASSERT(prev == NULL);
  }

  lock_release(spt_lock);

  if (!success) {
    remove_spt_entries(&dest_mmap_entry->pages);
    return false;
  }
  return success;
}

/**
 * Adds the current mapping to the current process's memory-mapped file table.
 * @param base_addr The basal address to the region in memory.
 * @param fd The requested FD to map in memory to the region.
 * @return The nonnegative mapping ID if mapping succeeded, or MAP_FAILED
 * otherwise. This could be if allocation failed, the given FD is not in the
 * process's FD table, or the memory location given by the basal address is
 * invalid (i.e., there is an overlap with the stack or existing pages in the
 * process's SPT).
 * @remark This function needs to acquire the file system lock.
 */
mapid_t mmap_add_mapping(int fd, void *base_addr) {
  // First check if the file is currently in the user's file directory,
  // and that we can reopen it.
  struct fd_entry *fd_entry;
  struct file *reopened;
  bool open_file_success = (fd_entry = get_fd_entry(fd)) != NULL
    && (reopened = file_reopen(fd_entry->file)) != NULL;
  if (!open_file_success) {
    return MAP_FAILED;
  }
  // We cannot map an empty file.
  off_t len = file_length(reopened);
  if (len == 0) {
    file_close(reopened);
    return MAP_FAILED;
  }
  // Check if memory allocation fails.
  struct mmap_entry *entry;
  if ((entry = malloc(sizeof(struct mmap_entry))) == NULL) {
    file_close(reopened);
    return MAP_FAILED;
  }
  entry->maddr = base_addr;
  entry->file = reopened;
  if (!create_spt_entries(entry, len)) {
    file_close(reopened);
    free(entry);
    return MAP_FAILED;
  }
  mapid_t mapping_id = thread_current()->mmap_id_counter++;
  entry->mapping_id = mapping_id;
  // Insert into the memory mapping table.
  struct hash_elem *prev = hash_insert(get_mmap_table(), &entry->elem);
  ASSERT(prev == NULL);
  return mapping_id;
}

/**
 * Flushes and frees a given frame in a memory-mapped page to the disk, if it
 * is present and has been written to (the dirty bit is set to `true`).
 * This will also invalidate the thread's page directory entry at the virtual
 * address, if it exists.
 * @param entry The entry in the current process's SPT.
 * @param t The thread that owns the entry, for getting the correct pagedir.
 * @pre The entry is non-null, and the type is MMAP.
 * @remark The caller is responsible for freeing the underlying page.
 */
void mmap_flush_entry(struct spt_entry *entry, struct thread *t) {
  ASSERT(entry != NULL);
  ASSERT(entry->type == MMAP);
  ASSERT(lock_held_by_current_thread(&thread_current()->spt_lock));

  // Get the frame from the page, if one exists.
  uint32_t *pagedir = t->pagedir;
  void *frame = pagedir_get_page(pagedir, entry->uvaddr);

  // Invalidate the entry at that page.
  pagedir_clear_page(pagedir, entry->uvaddr);

  // If the frame is not present, we must have already flushed its changes out
  // or the page was never in memory in the first place.
  if (frame == NULL) {
    return;
  }

  // If the frame hasn't been written to, we don't need to write to the disk.
  if (!pagedir_is_dirty(pagedir, entry->uvaddr)) {
    return;
  }
  struct mmap_entry *in_mmap_entry = entry->mmap.mmap_entry;

  // Verify that the reference to the parent entry is valid.
  ASSERT(in_mmap_entry != NULL);
  off_t offset = entry->uvaddr - in_mmap_entry->maddr;
  off_t write_amount = entry->mmap.page_file_bytes;

  // Write to the file.
  lock_acquire(&file_system_lock);
  file_write_at(in_mmap_entry->file, frame, write_amount, offset);
  lock_release(&file_system_lock);
}

/**
 * Allocates a given frame for a memory-mapped page, if none is already present.
 * @param entry The entry in the current process's SPT.
 * @return `true` if an allocation occurred (i.e., no frame was previously
 * allocated for the page, and allocation succeeded.)
 * @pre The entry is non-null, and the type is MMAP.
 * @pre The SPT lock needs to be held by the current thread.
 * @remark This function needs to acquire the file system lock.
 * @remark The caller is responsible for freeing the allocated frame.
 */
bool mmap_load_entry(struct spt_entry *entry) {
  ASSERT(entry != NULL);
  ASSERT(entry->type == MMAP);
  ASSERT(lock_held_by_current_thread(&thread_current()->spt_lock));

  uint32_t *pagedir = thread_current()->pagedir;
  // If a frame is already allocated to the page, do nothing.
  if (pagedir_get_page(pagedir, entry->uvaddr) != NULL) {
    return false;
  }

  // Attempt to add to the page directory as rewritable, so that we can
  // manipulate the frame.
  lock_release(&thread_current()->spt_lock);
  void *frame = user_get_page(0, entry->uvaddr);
  lock_acquire(&thread_current()->spt_lock);

  if (!pagedir_set_page(pagedir, entry->uvaddr, frame, true)) {
    palloc_free_page(frame);
    return false;
  }
  struct mmap_entry *in_mmap_entry = entry->mmap.mmap_entry;
  // Verify that the reference to the parent entry is valid.
  ASSERT(in_mmap_entry != NULL);
  struct file *source = in_mmap_entry->file;
  void *base_address = in_mmap_entry->maddr;
  off_t offset = entry->uvaddr - base_address;
  off_t bytes_to_read = entry->mmap.page_file_bytes;
  off_t bytes_to_zero = entry->mmap.page_zero_bytes;

  // Write file bytes to the frame.
  lock_acquire(&file_system_lock);
  off_t read_bytes = file_read_at(source, frame, bytes_to_read, offset);
  lock_release(&file_system_lock);

  if (read_bytes != bytes_to_read) {
    pagedir_clear_page(pagedir, entry->uvaddr);
    free(frame);
    return false;
  }

  // Success; zero the rest of the frame.
  memset(frame + bytes_to_read, 0, bytes_to_zero);
  // Set the dirty bit to false on initiation.
  pagedir_set_dirty(pagedir, entry->uvaddr, false);
  unpin_page(entry->uvaddr);
  return true;
}

/**
 * Frees a list of mapped pages corresponding to memory-mapped files, flushing
 * changes if required.
 * @param mapped_pages A list of mapped pages.
 * @pre The current process has not acquired the frame table, SPT and file
 * system lock.
 * @remark mapped_pages itself is not freed.
 */
static void remove_spt_entries(struct list *mapped_pages) {
  struct list_elem *cur = list_begin(mapped_pages);
  uint32_t *pagedir = thread_current()->pagedir;
  struct hash *spt = &thread_current()->spt;
  struct lock *spt_lock = &thread_current()->spt_lock;

  ASSERT(!lock_held_by_current_thread(&frame_table_lock));
  ASSERT(!lock_held_by_current_thread(spt_lock));
  ASSERT(!lock_held_by_current_thread(&file_system_lock));

  while (cur != list_end(mapped_pages)) {
    // Acquire the frame table lock, then the SPT lock of the current thread.
    // We need to acquire the first before the second to avoid race conditions,
    // to maintain a partial ordering.
    lock_acquire(&frame_table_lock);
    lock_acquire(spt_lock);

    struct list_elem *next = list_next(cur);
    // Delete from the list.
    list_remove(cur);

    // The SPT entry is chained to the list of mapped pages using mmap.elem;
    // obtain the underlying SPT entry
    struct spt_entry *spt_entry = list_entry(cur, struct spt_entry, mmap.elem);

    // Flush changes in any currently-allocated frames if they have been
    // written to.
    // Get kernel address right now, as the page entry gets removed when the
    // memory mapped file gets flushed.
    void *kvaddr = pagedir_get_page(pagedir, spt_entry->uvaddr);

    // Update changes to the disk, if there are any.
    mmap_flush_entry(spt_entry, thread_current());

    // If the frame exists, we must remove it from the frame table and free it.
    if (kvaddr != NULL) {
      // Attempt to index into the frame table again, removing if still present.
      struct frame key;
      key.kvaddr = kvaddr;
      struct hash_elem *found_elem = hash_delete(&frame_table, &key.table_elem);
      struct frame *frame = hash_entry(found_elem, struct frame, table_elem);

      if (found_elem != NULL) {
        // Remove it from the eviction queue.
        palloc_free_page(frame->kvaddr);
        free(frame->owner);
        free(frame);
      }
    }

    // Remove the mapped page from the SPT; this must have been malloced
    // beforehand.
    struct hash_elem *found_elem = hash_delete(spt, &spt_entry->elem);
    ASSERT(found_elem == &spt_entry->elem);

    lock_release(&frame_table_lock);
    lock_release(spt_lock);

    free(spt_entry);
    cur = next;
  }
}

/**
 * Frees a current process's memory-mapped entry given by a generic hashing
 * element.
 * Produces undefined behaviour if the hash element does not correspond to a
 * memory-mapping entry.
 * @param mmap_hash_elem The (generic) hash table element.
 * @param aux (Unused.)
 * @pre The frame table lock, SPT lock and file system lock should all not
 * be held by the current thread.
 */
static void free_mmap_elem(
  struct hash_elem *mmap_hash_elem,
  void *aux UNUSED
) {
  ASSERT(mmap_hash_elem != NULL);
  ASSERT(!lock_held_by_current_thread(&frame_table_lock));
  ASSERT(!lock_held_by_current_thread(&thread_current()->spt_lock));
  ASSERT(!lock_held_by_current_thread(&file_system_lock));
  // Obtain the underlying memory-mapping entry.
  struct mmap_entry *mmap_entry = from_hash_elem(mmap_hash_elem);
  // Remove all the mapped pages, close the file, and free the entry.
  remove_spt_entries(&mmap_entry->pages);
  lock_acquire(&file_system_lock);
  file_close(mmap_entry->file);
  lock_release(&file_system_lock);
  free(mmap_entry);
}

/**
 * Destroys the current hash table, implicitly unmapping all entries
 * and freeing any owned resources.
 * @pre The frame table lock, SPT lock and file system lock should all not
 * be held by the current thread.
 */
void mmap_destroy(void) {
  ASSERT(!lock_held_by_current_thread(&frame_table_lock));
  ASSERT(!lock_held_by_current_thread(&thread_current()->spt_lock));
  ASSERT(!lock_held_by_current_thread(&file_system_lock));

  hash_destroy(get_mmap_table(), &free_mmap_elem);
}

/**
 * Unmaps an entry from the current process's memory-mapped file table,
 * flushing changes if needed.
 * Does nothing if the entry is not mapped.
 * @pre The frame table lock, SPT lock and file system lock should all not
 * be held by the current thread.
 */
void mmap_remove_mapping(mapid_t mapping_id) {
  ASSERT(!lock_held_by_current_thread(&frame_table_lock));
  ASSERT(!lock_held_by_current_thread(&thread_current()->spt_lock));
  ASSERT(!lock_held_by_current_thread(&file_system_lock));

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
