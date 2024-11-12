#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <hash.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"


/// The maximum number of bytes to write to the console at a time
#define MAX_WRITE_SIZE 300

/**
 * Get the argument of type `type` and index `arg_no` from an `intr_frame`
 * @param type The type of the argument
 * @param arg_no The 1-indexed index of the argument
 * @pre The `intr_frame` is called `f` and is in scope
 * @example \code
 * void example(struct intr_frame *f) {
 *   // example(int x, char y)
 *   int x = ARG(int, 1);
 *   char y = ARG(int, 2);
 * }
 * \endcode
 */
#define ARG(type, arg_no) (*((type *) (((uint32_t *) f->esp)+(arg_no))))

/// Type of system call handler functions.
typedef void (*syscall_handler_func) (struct intr_frame *);

/**
 * Type of auxiliary functions to handle memory held in pages mapped by a given
 * user's buffer.
 * Takes a pointer to the kernel address to a given (part or whole) page,
 * the size of memory in that page, and a helper state.
 */
typedef void (*block_foreach_func) (void *, unsigned, void *);

/**
 * Iterates over all pages to read mapped by the buffer of given size,
 * applying the foreach function to each page with the size of the section of
 * buffer in that page, and the state.
 * The function panics if the buffer does not map to a block of memory owned
 * by the user, so this must be checked beforehand.
 * Care must be taken to ensure that the foreach function does not attempt to
 * write to read-only data, if the provided `user_buffer` is also read-only.
 * @pre `user_buffer` is owned completely by the user (checked by
 * `user_owns_memory_range`).
 * @param user_buffer The virtual (user) address to the buffer.
 * @param size The size of the buffer provided by the user.
 * @param f Iterator function to handle a part of the buffer in one page.
 * @param state State for the helper function to use.
 */
static void buffer_pages_foreach(
  void *user_buffer,
  unsigned size,
  block_foreach_func f,
  void *state
);

void close_file(struct hash_elem *element, void *aux UNUSED);
static void exit_process(int status) NO_RETURN;
static void *access_user_memory(uint32_t *pd, const void *uaddr);
static bool user_owns_memory_range(const void *buffer, unsigned size);
static void syscall_handler (struct intr_frame *);

// Helper functions for reading to and writing from buffer pages.

/**
 * Prints a given page of the buffer to the console.
 * The function does not provide synchronisation for console writes on its own.
 * @param buffer_page_ The physical address of the portion of the buffer.
 * @param page_size The size of the portion held in the page.
 * @param state State parameter (Unused.)
 */
static void buffer_page_print(
  void *buffer_page_,
  unsigned buffer_page_size,
  void *state UNUSED
);

static void syscall_not_implemented(struct intr_frame *f);
static void halt(struct intr_frame *f) NO_RETURN;
static void exit(struct intr_frame *f);
static void exec(struct intr_frame *f);
static void wait(struct intr_frame *f);
static void write(struct intr_frame *f);

/**
 * Lock for reading to and writing from the console.
 * Unlike the built-in lock, this is not reentrant.
 */
struct lock console_lock;

// Handler for system calls corresponding to those defined in syscall-nr.h
const syscall_handler_func syscall_handlers[] = {
  &halt,
  &exit,
  &exec,
  &wait,
  &syscall_not_implemented,
  &syscall_not_implemented,
  &syscall_not_implemented,
  &syscall_not_implemented,
  &syscall_not_implemented,
  &write,
  &syscall_not_implemented,
  &syscall_not_implemented,
  &syscall_not_implemented,
  &syscall_not_implemented,
  &syscall_not_implemented
};

void
syscall_init (void) 
{
  lock_init(&console_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/**
* The hash_action_func used to close the file in fd_entry struct and free the
* memory.
* @param element The hash_elem of the file descriptor in the fd table.
* @param aux (UNUSED).
*/
void close_file(struct hash_elem *element, void *aux UNUSED) {
  struct fd_entry *fd_entry = hash_entry(element, struct fd_entry, elem);
  lock_acquire(&file_system_lock);
  file_close(fd_entry->file);
  lock_release(&file_system_lock);
  free(fd_entry);
}

/**
 * Exits a user program with the provided status code.
 * @param status The exit status code.
 */
static void exit_process(int status) {

  struct thread *cur_thread = thread_current();

  // When a process exits, we must update its exit status in the user_processes
  // hashmap, and up its semaphore

  // Setup to find the current process in the user_processes hashmap
  struct process_status process_to_find;
  process_to_find.tid = cur_thread->tid;

  lock_acquire(&user_processes_lock);

  // Check if this process has an entry in the user_processes hashmap
  struct hash_elem *process_found_elem = hash_find(
    &user_processes,
    &process_to_find.elem
  );

  // We must keep the user_processes_lock here since the parent of this process
  // reserves the right to delete the entry corresponding to this process at any
  // time, possibly while we're modifying it

  // If the process does have an entry
  if (process_found_elem != NULL) {
    // Get the process's entry
    struct process_status *process_found = hash_entry(
      process_found_elem,
      struct process_status,
      elem
    );

    // Update the entry's exit status and up its semaphore to unblock its waiter
    process_found->status = status;
    sema_up(&process_found->sema);
  }

  lock_release(&user_processes_lock);

  // Close all the files and free all the file descriptors,
  // and the file descriptor table
  struct hash *fd_table = cur_thread->fd_table;
  hash_destroy(fd_table, &close_file);

  // Print the exit status
  printf("%s: exit(%d)\n", thread_current()->name, status);

  // Free the process's resources.
  thread_exit();
}

/**
 * Get the kernel virtual address of a virtual user address from the page
 * directory provided.
 * @param pd The page directory from which to read.
 * @param uaddr The user address.
 * @return The physical address, or NULL if the user address is invalid.
 * @remark For safety, do not perform pointer arithmetic on the returned pointer
 * from this function.
 * @remark If NULL is returned, the caller should free its resources and call
 * exit_process(-1).
 */
static void *access_user_memory(uint32_t *pd, const void *uaddr) {
  // Return NUll if we're not accessing an address in user-space
  if (!is_user_vaddr(uaddr)) {
	return NULL;
  }

  return pagedir_get_page(pd, uaddr);
}

/**
 * Placeholder for unimplemented system calls.
 * @param f The interrupt stack frame
 */
static void syscall_not_implemented(struct intr_frame *f UNUSED) {
  printf("System call not implemented.\n");
}

/**
 * Handles halt system calls.
 * @param f The interrupt stack frame
 */
static void halt(struct intr_frame *f UNUSED) {
  // void halt(void)
  shutdown_power_off();
}

/**
 * Handles exit system calls.
 * @param f The interrupt stack frame
 */
static void exit(struct intr_frame *f UNUSED) {
  // void exit(int status)
  int status = ARG(int, 1);
  exit_process(status);
}

/**
 * Handles exec system calls.
 * @param f The interrupt stack frame
 */
static void exec(struct intr_frame *f) {
  // pid_t exec(const char *cmd_line)
  char *cmd_line = ARG(char *, 1);
  f->eax = process_execute(cmd_line);
}

/**
 * Handles wait system calls.
 * @param f The interrupt stack frame
 */
static void wait(struct intr_frame *f) {
  // void wait(pid_t pid)
  int pid = ARG(int, 1);
  f->eax = process_wait(pid);
}

/**
 * Checks whether the user owns a given block of memory of a given size, that
 * starts at a given (virtual) address.
 * @param buffer The virtual address to the buffer.
 * @param size The length of the buffer that would be read from
 * or written to.
 * @return `true` if and only if all parts of the buffer are owned by the user.
 */
static bool user_owns_memory_range(const void *buffer, unsigned size) {
  uint32_t *pd = thread_current()->pagedir;
  // Performing pointer arithmetic on a void* is undefined behaviour,
  // so cast to a uint8_t* to comply with the standard.
  for (unsigned i = 0; i < size; i += PGSIZE) {
    if (access_user_memory(pd, &((uint8_t *)buffer)[i]) == NULL) {
      return false;
    }
  }
  // Check the end of the buffer as well.
  if (access_user_memory(pd, &((uint8_t *)buffer)[size - 1]) == NULL) {
    return false;
  }
  return true;
}

static void buffer_pages_foreach(
  void *user_buffer,
  unsigned size,
  block_foreach_func f,
  void *state
) {
  uint32_t *pd = thread_current()->pagedir;
  void *buffer = access_user_memory(pd, user_buffer);
  if (!user_owns_memory_range(user_buffer, size))
    PANIC(
      "User-provided buffer %p with size %u not owned by user",
      user_buffer,
      size
    );
  ASSERT(buffer != NULL);
  // The trivial case, when the entire buffer fits inside the page.
  unsigned buffer_end_offset = pg_ofs(buffer) + size - 1;
  if (buffer_end_offset < PGSIZE) {
      (*f)(buffer, size, state);
      return;
  }

  // Otherwise, we have the start of the buffer reaching the end of a page,
  // an optional number of full pages in the middle of the buffer,
  // and the end of the buffer possibly ending at a different page.

  // The size occupied in the first page by the buffer.
  unsigned buffer_start_page_size = 0;
  if (pg_ofs(user_buffer) != 0) {
    // Read the first page
    buffer_start_page_size = PGSIZE - pg_ofs(user_buffer);
    (*f)(buffer, buffer_start_page_size, state);
    // Progress to the end of the page
    user_buffer += buffer_start_page_size;
    size -= buffer_start_page_size;
  }
  // Read all the full pages in the middle of the buffer, plus the
  // page at the end.
  while (size > 0) {
    ASSERT(pg_ofs(user_buffer) == 0);
    buffer = access_user_memory(pd, user_buffer);
    ASSERT(buffer != NULL);
    unsigned consumed = size < PGSIZE ? size : PGSIZE;
    (*f)(buffer, consumed, state);
    // If the last page is reached, consumed == size.
    user_buffer += consumed;
    size -= consumed;
  }
}

/**
 * Handles read system calls.
 * @param f The interrupt stack frame
 */
static void read(struct intr_frame *f) {
  // int read(int fd, void *buffer, unsigned size)
  int fd = ARG(int, 1);
  void *user_buffer = ARG(void *, 2);
  unsigned size = ARG(unsigned, 3);

  int bytes_read;

  void *buffer = access_user_memory(
    thread_current()->pagedir,
    user_buffer
  );
  // Terminating the offending process and freeing its resources
  // for invalid pointer address.
  if (buffer == NULL) {
    exit_process(-1);
    NOT_REACHED();
  }

  if (fd == 0) {
    // Read from the console.
    lock_acquire(&console_lock);

    for (unsigned i = 0; i < size; i++)
      ((uint8_t *)buffer)[i] = input_getc();

    lock_release(&console_lock);

    bytes_read = size;
  } else {
    // Read from file

    // Search up the fd-file mapping from the fd table.
  	struct fd_entry fd_to_find;
  	fd_to_find.fd = fd;
  	struct hash_elem *fd_found_elem = hash_find(
  	  thread_current()->fd_table,
  	  &fd_to_find.elem
  	);
  	if (fd_found_elem == NULL) {
      f->eax = -1;
      return;
  	}
  	struct fd_entry *fd_found = hash_entry(fd_found_elem, struct fd_entry, elem);

    lock_acquire(&file_system_lock);
    bytes_read = file_read(fd_found->file, buffer, size);
    lock_release(&file_system_lock);
  }
  f->eax = bytes_read;
}

static void buffer_page_print(
  void *buffer_page_,
  unsigned buffer_page_size,
  void *state UNUSED
) {
  unsigned bytes_written;
  const void *buffer_page = (const void *)buffer_page_;
  // Keep writing MAX_WRITE_SIZE bytes as long as it's less than the amount
  // this part of the buffer occupies in memory
  for (
    bytes_written = 0;
    bytes_written + MAX_WRITE_SIZE < buffer_page_size;
    bytes_written += MAX_WRITE_SIZE
  ) {
    putbuf(buffer_page + bytes_written, MAX_WRITE_SIZE);
  }
  // Write the remaining bytes in the page
  putbuf(buffer_page + bytes_written, buffer_page_size - bytes_written);
}

/**
 * Handles write system calls.
 * @param f The interrupt stack frame
 */
static void write(struct intr_frame *f) {
  // write(int fd, const void *buffer, unsigned size)
  int fd = ARG(int, 1);
  const void *buffer = ARG(const void *, 2);
  unsigned size = ARG(unsigned, 3);

  // If we don't own the buffer's memory, the operation is invalid.
  if (!user_owns_memory_range(buffer, size)) {
    exit_process(-1);
    NOT_REACHED();
  }

  if (fd == 1) {
    // Console write

    lock_acquire(&console_lock);
    buffer_pages_foreach((void *)buffer, size, &buffer_page_print, NULL);
    lock_release(&console_lock);

    // Given the original memory is valid, putbuf will succeed
    // so all bytes will have been written.
    f->eax = size;
  }
}

/**
 * Dispatches system calls to the appropriate handler.
 * @param f The interrupt stack frame
 */
static void
syscall_handler (struct intr_frame *f)
{
  uint32_t syscall_no = *(uint32_t *)f->esp;
  ASSERT(syscall_no < sizeof(syscall_handlers) / sizeof(syscall_handler_func));
  printf("System call with code: %d\n", syscall_no);
  (*syscall_handlers[syscall_no])(f);
}
