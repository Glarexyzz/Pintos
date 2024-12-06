#include <string.h>
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "vm/share.h"
#include "vm/page.h"

/// A file shared between multiple processes
struct shared_file {
  struct file *file;       /* The open file which is to be shared */
  int num_opens;           /* The number of active references to the file */
  struct hash_elem elem;   /* For insertion into the shared_file_table */
};

/// A table of the open files which are shared
static struct hash shared_file_table;
/// The lock for the shared file table
static struct lock shared_file_table_lock;

static unsigned shared_file_hash(
  const struct hash_elem *element,
  void *aux UNUSED
);
static bool shared_file_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);
static unsigned shared_frame_file_hash(
  const struct hash_elem *element,
  void *aux UNUSED
);
static bool shared_frame_file_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);
static bool shared_frame_owner_smaller(
  const struct list_elem *a,
  const struct list_elem *b,
  void *aux UNUSED
);

/**
 * A hash_hash_func for shared_file struct.
 * @param element The pointer to the hash_elem in the shared_file struct.
 * @param aux Unused.
 * @return The hash of the shared_file.
 */
static unsigned shared_file_hash(
  const struct hash_elem *element,
  void *aux UNUSED
) {
  struct shared_file *shared_file = hash_entry(
    element,
    struct shared_file,
    elem
  );
  return file_hash(shared_file->file);
}

/**
 * A hash_less_func for shared_file struct.
 * @param a The pointer to the hash_elem in the first shared_file struct.
 * @param b The pointer to the hash_elem in the second shared_file struct.
 * @param aux Unused.
 * @return True iff a < b.
 */
static bool shared_file_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  struct shared_file *a_shared_file = hash_entry(
    a,
    struct shared_file,
    elem
  );
  struct shared_file *b_shared_file = hash_entry(
    b,
    struct shared_file,
    elem
  );
  return file_get_inode(a_shared_file->file) <
    file_get_inode(b_shared_file->file);
}

/**
 * A hash_hash_func for shared_frame struct, based on the file and offset.
 * @param element The pointer to the hash_elem in the shared_frame struct.
 * @param aux Unused.
 * @return The hash of the shared_frame, based on file and offset.
 */
static unsigned shared_frame_file_hash(
  const struct hash_elem *element,
  void *aux UNUSED
) {
  struct shared_frame *shared_frame = hash_entry(
    element,
    struct shared_frame,
    elem
  );
  return file_hash(shared_frame->file) ^ hash_int(shared_frame->offset);
}

/**
 * A hash_less_func for shared_frame struct, based on the file and offset.
 * @param a The pointer to the hash_elem in the first shared_frame struct.
 * @param b The pointer to the hash_elem in the second shared_frame struct.
 * @param aux Unused.
 * @return True iff a < b.
 */
static bool shared_frame_file_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  struct shared_frame *a_shared_frame = hash_entry(
    a,
    struct shared_frame,
    elem
  );
  struct shared_frame *b_shared_frame = hash_entry(
    b,
    struct shared_frame,
    elem
  );

  // Lexicographical ordering on inode ptr, then offset
  if (!file_compare(a_shared_frame->file, b_shared_frame->file)) {
    return file_get_inode(a_shared_frame->file) <
      file_get_inode(b_shared_frame->file);
  }

  return a_shared_frame->offset < b_shared_frame->offset;
}

/**
 * Initialise the share table and share table lock.
 * @remark Panics the kernel if initialisation fails.
 */
void share_table_init() {
  bool success = hash_init(
    &share_table,
    &shared_frame_file_hash,
    &shared_frame_file_smaller,
    NULL
  );
  if (!success) {
    PANIC("Could not initialise share table!");
  }
  lock_init(&share_table_lock);

  success = hash_init(
    &shared_file_table,
    &shared_file_hash,
    &shared_file_smaller,
    NULL
  );
  if (!success) {
    PANIC("Could not initialise shared file table!");
  }
  lock_init(&shared_file_table_lock);
}

/**
 * A list_less_func for owner structs.
 * @param a The pointer to the list_elem in the first owner struct.
 * @param b The pointer to the list_elem in the second owner struct.
 * @param aux Unused
 * @return True iff a < b
 */
static bool shared_frame_owner_smaller(
  const struct list_elem *a,
  const struct list_elem *b,
  void *aux UNUSED
) {
  pid_t a_pid = list_entry(a, struct owner, elem)->process->tid;
  pid_t b_pid = list_entry(b, struct owner, elem)->process->tid;

  return a_pid < b_pid;
}

/**
 * Adds an owner to a shared_frame.
 * @param shared_frame The shared_frame.
 * @param t The thread to be added as an owner.
 * @pre The share_table_lock is owned by the caller.
 */
void shared_frame_add_owner(
  struct shared_frame *shared_frame,
  struct thread *t,
  void *uvaddr
) {
  struct owner *owner = malloc(sizeof(struct owner));
  if (owner == NULL) {
    PANIC("Kernel out of memory!");
  }
  owner->process = t;
  owner->uvaddr = uvaddr;

  list_insert_ordered(
    &shared_frame->owners,
    &owner->elem,
    &shared_frame_owner_smaller,
    NULL
  );
}

/**
 * Deletes an owner from a shared_frame.
 * @param shared_frame The shared_frame.
 * @param t The thread to be deleted as an owner.
 * @pre The share_table_lock is owned by the caller.
 * @pre The thread's SPT lock is owned by the caller.
 * @remark The function will panic if it tries to delete an owner that isn't in
 * the shared_frame.
 */
void shared_frame_delete_owner(
  struct shared_frame *shared_frame,
  struct thread *t
) {
  for (
    struct list_elem *cur_elem = list_begin(&shared_frame->owners);
    cur_elem != list_end(&shared_frame->owners);
    cur_elem = list_next(cur_elem)
  ) {
    // If the current owner is the current thread
    struct owner *cur_owner = list_entry(cur_elem, struct owner, elem);
    if (cur_owner->process->tid == t->tid) {

      // Remove the thread from the frame's owners
      list_remove(cur_elem);

      // Remove the SPT entry from the frame's owners, if it exists
      struct spt_entry entry_to_find;
      entry_to_find.uvaddr = cur_owner->uvaddr;

      struct hash_elem *found_elem = hash_delete(&t->spt, &entry_to_find.elem);
      struct spt_entry *found_entry = (found_elem == NULL) ? NULL
        : hash_entry(found_elem, struct spt_entry, elem);
      free(found_entry);



      free(cur_owner);
      return;
    }
  }

  // Element to delete not found, so we panic.
  PANIC("Can't delete an owner that isn't in the shared_frame!\n");
}


/**
 * Open a shared file, or create a new shared file if it doesn't exist.
 * @param filename The name of the file to open.
 * @return The file that was opened.
 */
struct file *open_shared_file(char *filename) {
  lock_acquire(&file_system_lock);
  struct file *file = filesys_open(filename);
  lock_release(&file_system_lock);
  if (file == NULL) {
    return NULL;
  }

  // Try to find the shared file in the shared file table
  struct shared_file shared_file_to_find;
  shared_file_to_find.file = file;

  lock_acquire(&shared_file_table_lock);
  struct hash_elem *found_elem = hash_find(
    &shared_file_table,
    &shared_file_to_find.elem
  );

  struct shared_file *shared_file;

  if (found_elem != NULL) {
    // If the shared file exists already, use it
    shared_file = hash_entry(
      found_elem,
      struct shared_file,
      elem
    );
    lock_acquire(&file_system_lock);
    file_close(file);
    lock_release(&file_system_lock);
  } else {

    // Otherwise, create a new shared file
    shared_file = malloc(sizeof(shared_file));
    if (shared_file == NULL) {
      PANIC("Kernel out of memory!");
    }

    shared_file->file = file;
    shared_file->num_opens = 0;
    hash_insert(&shared_file_table, &shared_file->elem);
  }

  shared_file->num_opens++;
  lock_release(&shared_file_table_lock);

  return shared_file->file;
}

/**
 * Increase the open count of a shared file.
 * @param file The file to increase the open count of.
 * @pre The file is in the shared file table.
 */
void increase_open_count(struct file *file) {
  // Find the shared file in the shared file table
  struct shared_file shared_file_to_find;
  shared_file_to_find.file = file;

  lock_acquire(&shared_file_table_lock);
  struct hash_elem *found_elem = hash_find(
    &shared_file_table,
    &shared_file_to_find.elem
  );

  if (found_elem == NULL) {
    PANIC("Shared file doesn't exist!");
  }

  struct shared_file *shared_file = hash_entry(
    found_elem,
    struct shared_file,
    elem
  );

  // Increase the open count
  shared_file->num_opens++;
  lock_release(&shared_file_table_lock);
}

/**
 * Close a shared file.
 * @param file The file to close.
 */
void close_shared_file(struct file *file) {
  // Find the shared file in the shared file table
  struct shared_file shared_file_to_find;
  shared_file_to_find.file = file;

  lock_acquire(&shared_file_table_lock);
  struct hash_elem *found_elem = hash_find(
    &shared_file_table,
    &shared_file_to_find.elem
  );

  if (found_elem == NULL) {
    PANIC("Tried to close a shared file that doesn't exist!");
  }

  struct shared_file *shared_file = hash_entry(
    found_elem,
    struct shared_file,
    elem
  );

  shared_file->num_opens--;

  // If the file has no more open references, close it and free the shared file
  if (shared_file->num_opens == 0) {
    hash_delete(&shared_file_table, found_elem);
    lock_acquire(&file_system_lock);
    file_close(file);
    lock_release(&file_system_lock);
    free(shared_file);
  }

  lock_release(&shared_file_table_lock);
}
