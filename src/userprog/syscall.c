#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <hash.h>
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/mmap.h"

/// The maximum number of bytes to write to the console at a time
#define MAX_WRITE_SIZE 300
#define SYSCALL_ERROR_CODE -1
#define STDIN_FD 0
#define STDOUT_FD 1

// Helper macro for ONE_ARG, TWO_ARG, and THREE_ARG
#define AN_ARG(type, name, number)                           \
  void *arg ## number ## _ = ((uintptr_t *) f->esp)+number;  \
  user_owns_memory_range(arg ## number ## _, sizeof(type));  \
  type name = *(type *)arg ## number ## _;


/**
 * Get one argument from the interrupt frame.
 * @param t1 The type of the argument.
 * @param n1 The name of the argument.
 * @pre The struct intr_frame pointer is in scope and called `f`.
 * @remark The process will be exited if the stack pointer in the interrupt
 * frame is invalid.
 * @example \code{.c}
 * static void example(struct intr_frame *f) {
 *   // void example(const char *string_arg)
 *   ONE_ARG(const char *, string_arg);
 *
 *   // do stuff
 * }
 * \endcode
 */
#define ONE_ARG(t1, n1) \
  AN_ARG(t1, n1, 1)

/**
 * Get two arguments from the interrupt frame.
 * @param t1 The type of the first argument.
 * @param n1 The name of the first argument.
 * @param t2 The type of the second argument.
 * @param n2 The name of the second argument.
 * @pre The struct intr_frame pointer is in scope and called `f`.
 * @remark The process will be exited if the stack pointer in the interrupt
 * frame is invalid.
 * @example \code{.c}
 * static void example(struct intr_frame *f) {
 *   // void example(const char *string_arg, int size)
 *   TWO_ARG(
 *     const char *, string_arg,
 *     int, size
 *   );
 *
 *   // do stuff
 * }
 * \endcode
 */
#define TWO_ARG(t1, n1, t2, n2) \
  AN_ARG(t1, n1, 1)             \
  AN_ARG(t2, n2, 2)

/**
 * Get three arguments from the interrupt frame.
 * @param t1 The type of the first argument.
 * @param n1 The name of the first argument.
 * @param t2 The type of the second argument.
 * @param n2 The name of the second argument.
 * @param t3 The type of the third argument.
 * @param n3 The name of the third argument.
 * @pre The struct intr_frame pointer is in scope and called `f`.
 * @remark The process will be exited if the stack pointer in the interrupt
 * frame is invalid.
 * @example \code{.c}
 * static void example(struct intr_frame *f) {
 *   // void example(const char *string_arg, int size, unsigned max)
 *   THREE_ARG(
 *     const char *, string_arg,
 *     int, size,
 *     unsigned, max
 *   );
 *
 *   // do stuff
 * }
 * \endcode
 */
#define THREE_ARG(t1, n1, t2, n2, t3, n3) \
  AN_ARG(t1, n1, 1)                       \
  AN_ARG(t2, n2, 2)                       \
  AN_ARG(t3, n3, 3)

/// Type of system call handler functions.
typedef void (*syscall_handler_func) (struct intr_frame *);

/**
 * Type of auxiliary functions to handle memory held in pages mapped by a given
 * user's buffer at a specified memory range.
 * Takes a pointer to the kernel address to a given (part or whole) page,
 * the size of memory in that page, and a helper state.
 */
typedef void (*page_foreach_func) (void *, unsigned, void *);

/// State struct to be used by the buffer page iterator, storing the file being
/// read, the total number of bytes read, and whether EOF has been reached.
struct file_read_state {
  struct file *file;
  unsigned bytes_read;
  bool eof_reached;
};

/// State struct to be used by the buffer page iterator, storing the file being
/// written to, and the total number of bytes written.
struct file_write_state {
  struct file *file;
  unsigned bytes_written;
};

static void exit_if_false(bool cond);

static void user_memory_pages_foreach(
  void *user_address,
  unsigned size,
  page_foreach_func f,
  void *state
);

static void user_owns_byte(const void *uvaddr);
static struct fd_entry *get_fd_entry(int fd);
static void user_owns_memory_range(const void *buffer_, unsigned size);
static bool user_owns_string(const char *base, int max_length);
static void syscall_handler (struct intr_frame *);

// Helper functions for reading to and writing from sections of pages.

static void page_print(void *page, unsigned size, void *state UNUSED);
static void page_console_read(void *page_, unsigned size, void *state UNUSED);
static void page_file_read(void *page, unsigned size, void *state_);
static void page_file_write(void *page, unsigned size, void *state_);

static void syscall_halt(struct intr_frame *f) NO_RETURN;
static void syscall_exit(struct intr_frame *f);
static void syscall_exec(struct intr_frame *f);
static void syscall_wait(struct intr_frame *f);
static void syscall_create(struct intr_frame *f);
static void syscall_remove(struct intr_frame *f);
static void syscall_open(struct intr_frame *f);
static void syscall_filesize(struct intr_frame *f);
static void syscall_read(struct intr_frame *f);
static void syscall_write(struct intr_frame *f);
static void syscall_seek(struct intr_frame *f);
static void syscall_tell(struct intr_frame *f);
static void syscall_close(struct intr_frame *f);
static void syscall_mmap(struct intr_frame *f);
static void syscall_munmap(struct intr_frame *f);

// Handler for system calls corresponding to those defined in syscall-nr.h
const syscall_handler_func syscall_handlers[] = {
  &syscall_halt,
  &syscall_exit,
  &syscall_exec,
  &syscall_wait,
  &syscall_create,
  &syscall_remove,
  &syscall_open,
  &syscall_filesize,
  &syscall_read,
  &syscall_write,
  &syscall_seek,
  &syscall_tell,
  &syscall_close,
  &syscall_mmap,
  &syscall_munmap
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/**
 * Exit the user process with an error status if the condition is false.
 * @param cond The condition to check.
 * @remark Will not return if the condition is false.
 */
static inline void exit_if_false(bool cond) {
  if (!cond) {
    exit_user_process(ERROR_STATUS_CODE);
    NOT_REACHED();
  }
}

/**
 * Iterator for all parts of pages mapped by memory of a given length (e.g.
 * an array).
 * Applies the foreach function to each section of a page with the size of
 * the section of memory held in that page, and the state.
 * Care must be taken to ensure that the foreach function does not attempt to
 * write to read-only data, if the provided memory range is also read-only.
 * @param user_address The virtual (user) address to the start of the range.
 * @param size The size of the memory range provided by the user.
 * @param f Iterator function to handle a part of the memory range in one page.
 * @param state State for the helper function to use.
 */
static void user_memory_pages_foreach(
  void *user_address,
  unsigned size,
  page_foreach_func f,
  void *state
) {
  // The trivial case, when the entire buffer fits inside the page.
  unsigned buffer_end_offset = pg_ofs(user_address) + size - 1;
  if (buffer_end_offset < PGSIZE) {
    (*f)(user_address, size, state);
    return;
  }

  // Otherwise, we have the start of the buffer reaching the end of a page,
  // an optional number of full pages in the middle of the buffer,
  // and the end of the buffer possibly ending at a different page.

  // The size occupied in the first page by the buffer.
  unsigned buffer_start_page_size = 0;
  if (pg_ofs(user_address) != 0) {
    // Read the first page
    buffer_start_page_size = PGSIZE - pg_ofs(user_address);
    (*f)(user_address, buffer_start_page_size, state);
    // Progress to the end of the page
    user_address += buffer_start_page_size;
    size -= buffer_start_page_size;
  }
  // Read all the full pages in the middle of the buffer, plus the
  // page at the end.
  while (size > 0) {
    ASSERT(pg_ofs(user_address) == 0);
    unsigned consumed = size < PGSIZE ? size : PGSIZE;
    (*f)(user_address, consumed, state);
    // If the last page is reached, consumed == size.
    user_address += consumed;
    size -= consumed;
  }
}

/**
 * Checks if given user virtual address is owned by the caller. Terminates the
 * user process if not.
 * @param uvaddr The user virtual address to check.
 * @remark This function may trigger a page fault and may kill the caller.
 */
static void user_owns_byte(const void *uvaddr) {
  // If not within the range of user virtual memory, exit the process.
  if (!is_user_vaddr(uvaddr)) {
    exit_user_process(ERROR_STATUS_CODE);
  }

  // Read the uaddr to initiate page fault handling if needed.
  // If the address is not owned by the user, the page fault handler will
  // exit the user process.
  if (*(uint8_t *) uvaddr) barrier();
}

/**
 * Checks if a given range of user virtual memory is owned by the caller. Exit
 * the user process if not.
 * @param buffer_ The base address of the range of memory to check.
 * @param size The size of the range of memory to check, in bytes.
 * @remark This function may trigger a page fault and may kill the caller.
 */
static void user_owns_memory_range(const void *buffer_, unsigned size) {
  // Performing pointer arithmetic on a void* is undefined behaviour,
  // so cast to a uint8_t* to comply with the standard.
  const uint8_t *buffer = (uint8_t *) buffer_;

  for (unsigned i = 0; i < size; i += PGSIZE) {
    user_owns_byte(buffer + i);
  }
  // Check the end of the buffer as well, if the buffer is larger than one page.
  if (pg_round_down(buffer) != pg_round_down(buffer + size - 1)) {
    user_owns_byte(buffer + size - 1);
  }
}

/**
 * Prints a given part of the page from a buffer to the console.
 * The function does not provide synchronisation for console writes on its own.
 * @param page_ The physical address of the portion of the buffer.
 * @param size The size of the portion held in the page.
 * @param state State parameter (Unused.)
 */
static void page_print(void *page, unsigned size, void *state UNUSED) {
  unsigned bytes_written;
  const void *page_part = (const void *)page;
  // Keep writing MAX_WRITE_SIZE bytes as long as it's less than the amount
  // this part of the buffer occupies in memory
  for (
    bytes_written = 0;
    bytes_written + MAX_WRITE_SIZE < size;
    bytes_written += MAX_WRITE_SIZE
  ) {
    putbuf(page_part + bytes_written, MAX_WRITE_SIZE);
  }
  // Write the remaining bytes in the page
  putbuf(page_part + bytes_written, size - bytes_written);
}

/**
 * Reads input from the console, writing it to the given page of the buffer.
 * The original buffer should not point to a read-only section of memory.
 * The function does not provide synchronisation for console reads on its own.
 * @param page_ The physical address of the portion of the buffer.
 * @param size The size of the portion held in the page.
 * @param state State parameter (Unused.)
 */
static void page_console_read(void *page_, unsigned size, void *state UNUSED) {
  uint8_t *page_part = (uint8_t *)page_;
  for (unsigned i = 0; i < size; i++) {
    page_part[i] = input_getc();
  }
}

/**
 * Helper function for reading from a file, and writing it to the given page
 * of the buffer. Will do nothing once an EOF has been reached.
 * The original buffer should not point to a read-only section of memory.
 * The function does not provide synchronisation for file reads on its own.
 * @param page The portion of the page in part of the buffer, to be written to.
 * @param size The size of the portion of the page
 * @param state_ A pointer to a `struct file_read_state`
 * @see struct file_read_state
 */
static void page_file_read(void *page, unsigned size, void *state_) {
  struct file_read_state *state = (struct file_read_state *)state_;
  if (state->eof_reached) return;
  lock_acquire(&file_system_lock);
  unsigned bytes_read = file_read(state->file, page, size);
  lock_release(&file_system_lock);
  if (bytes_read < size) {
    // The buffer has not been fully written to, indicating we are at the
    // end of the file.
    state->eof_reached = true;
  }
  state->bytes_read += bytes_read;
}

/**
 * Helper function for writing to a file, from a given page of the buffer.
 * The function does not provide synchronisation for file reads on its own.
 * @param page The portion of the page in part of the buffer, to be read from.
 * @param size The size of the portion of the page
 * @param state_ A pointer to a `struct file_write_state`
 * @see struct file_write_state
 */
static void page_file_write(void *page, unsigned size, void *state_) {
  struct file_write_state *state = (struct file_write_state *)state_;
  lock_acquire(&file_system_lock);
  state->bytes_written += (unsigned)file_write(state->file, page, size);
  lock_release(&file_system_lock);
}

/**
 * Handles halt system calls.
 * @param f The interrupt stack frame
 */
static void syscall_halt(struct intr_frame *f UNUSED) {
  // void halt(void)
  shutdown_power_off();
}

/**
 * Handles exit system calls.
 * @param f The interrupt stack frame
 */
static void syscall_exit(struct intr_frame *f) {
  // void exit(int status)
  ONE_ARG(int, status);
  exit_user_process(status);
}

/**
 * Asserts that a user owns every byte from str_base up to str_base + max_length
 * (exclusive) or a null terminator, whichever comes first.
 * @param base The basal pointer of the string to check.
 * @param max_length The number of bytes to check are owned by the user.
 * @return if the checked portion of the string is null-terminated.
 * @remark Will exit the user process on failure.
 */
static bool user_owns_string(const char *base, int max_length) {
  for (int i = 0; i < max_length; i++) {
    user_owns_byte(base + i);
    if (base[i] == '\0') return true;
  }
  return false;
}

/**
 * Handles exec system calls.
 * @param f The interrupt stack frame
 */
static void syscall_exec(struct intr_frame *f) {
  // pid_t exec(const char *cmd_line)
  ONE_ARG(char *, cmd_line);

  // Check that the user owns the whole cmd_line string
  user_owns_byte(cmd_line);
  if (is_kernel_vaddr(cmd_line + PGSIZE - 1)) {
    user_owns_string(cmd_line, PGSIZE - 1);
  }

  f->eax = process_execute(cmd_line);
}

/**
 * Handles wait system calls.
 * @param f The interrupt stack frame
 */
static void syscall_wait(struct intr_frame *f) {
  // int wait(pid_t pid)
  ONE_ARG(int, pid);
  f->eax = process_wait(pid);
}

/**
 * Handles create system calls.
 * @param f The interrupt stack frame
 */
static void syscall_create(struct intr_frame *f) {
  // bool create(const char *file, unsigned initial_size)
  TWO_ARG(
    const char *, user_filename,
    unsigned, initial_size
  );

  if (!user_owns_string(user_filename, NAME_MAX+1)) {
    f->eax = false;
    return;
  }

  lock_acquire(&file_system_lock);
  bool success = filesys_create(user_filename, initial_size);
  lock_release(&file_system_lock);

  f->eax = success;
}

/**
 * Handles remove system calls.
 * @param f The interrupt stack frame
 */
static void syscall_remove(struct intr_frame *f) {
  // bool remove(const char *file)
  ONE_ARG(const char *, user_filename);

  // Check that the user owns the whole user_filename string
  if (!user_owns_string(user_filename, NAME_MAX+1)) {
    f->eax = false;
    return;
  }

  lock_acquire(&file_system_lock);
  bool success = filesys_remove(user_filename);
  lock_release(&file_system_lock);

  f->eax = success;
}

/**
 * Handles open system calls.
 * @param f The interrupt stack frame
 */
static void syscall_open(struct intr_frame *f) {
  // int open(const char *file)
  ONE_ARG(const char *, user_filename);

  struct thread *cur_thread = thread_current();

  // Check that the user owns the whole user_filename string
  if (!user_owns_string(user_filename, NAME_MAX+1)) {
    f->eax = false;
    return;
  }

  lock_acquire(&file_system_lock);
  struct file *new_file = filesys_open(user_filename);
  lock_release(&file_system_lock);

  if (new_file == NULL) {
    f->eax = SYSCALL_ERROR_CODE;
    return;
  }

  // Initialise the hashmap entry for fd table
  struct fd_entry *new_fd_entry =
    malloc(sizeof(struct fd_entry));
  if (new_fd_entry == NULL) {
    f->eax = SYSCALL_ERROR_CODE;
    return;
  }

  new_fd_entry->file = new_file;
  new_fd_entry->fd = cur_thread->fd_counter++;

  // Add the entry to the FD table
  hash_insert(&cur_thread->fd_table, &new_fd_entry->elem);

  f->eax = new_fd_entry->fd;
}

/**
 * Handles filesize system calls.
 * @param f The interrupt stack frame
 */
static void syscall_filesize(struct intr_frame *f) {
  // int filesize(int fd)
  ONE_ARG(int, fd);

  // Get the FD entry, error if there is none
  struct fd_entry *entry = get_fd_entry(fd);
  exit_if_false(entry != NULL);

  lock_acquire(&file_system_lock);
  int size = file_length(entry->file);
  lock_release(&file_system_lock);

  f->eax = size;
}

/**
 * Handles read system calls.
 * @param f The interrupt stack frame
 */
static void syscall_read(struct intr_frame *f) {
  // int read(int fd, void *buffer, unsigned size)
  THREE_ARG(
    int, fd,
    void *, buffer,
    unsigned, size
  );

  int bytes_read;

  if (fd == STDIN_FD) {
    user_owns_memory_range(buffer, size);
    // Read from the console.
    user_memory_pages_foreach(buffer, size, &page_console_read, NULL);
    // Given the original memory is valid, we will record all `size` bytes
    // from stdin.
    bytes_read = size;
  } else {
    // Read from file.

    struct fd_entry *entry = get_fd_entry(fd);
    if (entry == NULL) {
      f->eax = SYSCALL_ERROR_CODE;
      return;
    }

    // Initialise the current state of reading the file to the buffer.
    struct file_read_state state;
    state.file = entry->file;
    state.eof_reached = false;
    state.bytes_read = 0;

    user_owns_memory_range(buffer, size);
    user_memory_pages_foreach(buffer, size, &page_file_read, &state);

    bytes_read = state.bytes_read;
  }
  f->eax = bytes_read;
}

/**
 * Handles write system calls.
 * @param f The interrupt stack frame
 */
static void syscall_write(struct intr_frame *f) {
  // write(int fd, const void *buffer, unsigned size)
  THREE_ARG(
    int, fd,
    const void *, buffer,
    unsigned, size
  );

  user_owns_memory_range(buffer, size);

  if (fd == STDOUT_FD) {
    // Console write

    user_memory_pages_foreach((void *)buffer, size, &page_print, NULL);
    // Given the original memory is valid, putbuf will succeed
    // so all bytes will have been written.
    f->eax = size;
  } else {
    // Write to file

    // Get the FD entry, return 0 if there is none.
    struct fd_entry *entry = get_fd_entry(fd);
    if (entry == NULL) {
      f->eax = 0;
      return;
    }

    // Initialise the current state of writing to the file from the buffer.
    struct file_write_state state;
    state.file = entry->file;
    state.bytes_written = 0;

    // The iterator will check the user-provided buffer.
    // If it is invalid, no copying will take place.
    user_memory_pages_foreach((void *)buffer, size, &page_file_write, &state);

    f->eax = state.bytes_written;
  }
}

/**
 * Handles seek system calls.
 * @param f The interrupt stack frame
 */
static void syscall_seek(struct intr_frame *f) {
  // void seek(int fd, unsigned position)
  TWO_ARG(
    int, fd,
    unsigned, position
  );

  // Get the FD entry, error if there is none
  struct fd_entry *entry = get_fd_entry(fd);
  exit_if_false(entry != NULL);

  lock_acquire(&file_system_lock);
  file_seek(entry->file, position);
  lock_release(&file_system_lock);
}

/**
 * Handles tell system calls.
 * @param f The interrupt stack frame
 */
static void syscall_tell(struct intr_frame *f) {
  // unsigned tell(int fd)
  ONE_ARG(int, fd);

  // Get the FD entry, error if there is none
  struct fd_entry *entry = get_fd_entry(fd);
  exit_if_false(entry != NULL);

  lock_acquire(&file_system_lock);
  unsigned position = file_tell(entry->file);
  lock_release(&file_system_lock);

  f->eax = position;
}

/**
 * Handles close system calls.
 * @param f The interrupt stack frame
 */
static void syscall_close(struct intr_frame *f) {
  // void close(int fd)
  ONE_ARG(int, fd);

  // Get the FD entry, error if there is none
  struct fd_entry *entry = get_fd_entry(fd);
  exit_if_false(entry != NULL);

  // close file, free it, delete from fd_table.
  hash_delete(&thread_current()->fd_table, &entry->elem);
  close_file(&entry->elem, NULL);
}

/**
 * Handles memory mapping file system calls.
 * @param f The interrupt stack frame
 */
static void syscall_mmap(struct intr_frame *f) {
  // mapid_t mmap(int fd, void *addr)
  TWO_ARG(
    int, fd,
    void *, addr
  );
  f->eax = mmap_add_mapping(fd, addr);
}

/**
 * Handles memory unmapping file system calls.
 * @param f The interrupt stack frame
 */
static void syscall_munmap(struct intr_frame *f) {
  // void munmap(mapid_t mapping)
  ONE_ARG(mapid_t, mapping);
  mmap_remove_mapping(mapping);
}

/**
 * Dispatches system calls to the appropriate handler.
 * @param f The interrupt stack frame
 */
static void
syscall_handler (struct intr_frame *f)
{
  AN_ARG(uint32_t, syscall_no, 0);

  exit_if_false(syscall_no <
                sizeof(syscall_handlers) / sizeof(syscall_handler_func));

  (*syscall_handlers[syscall_no])(f);
}
