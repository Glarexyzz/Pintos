#include "devices/input.h"
#include "devices/shutdown.h"
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


/// The maximum number of bytes to write to the console at a time
#define MAX_WRITE_SIZE 300

#define SYSCALL_ERROR_CODE -1
#define STDIN_FD 0
#define STDOUT_FD 1

// Helper macro for ONE_ARG, TWO_ARG, and THREE_ARG
#define AN_ARG(type, name, number)                           \
  void *arg ## number ## _ = ((uintptr_t *) f->esp)+number;  \
  type name;                                                 \
  void *start ## number ## _kernel = (void *) &name;         \
  /* copy argument, which may be on separate pages */        \
  if (!buffer_pages_foreach(                                 \
    arg ## number ## _,                                      \
    sizeof(type),                                            \
    &buffer_page_copy,                                       \
    (void *) &start ## number ## _kernel                     \
  )) {                                                       \
    exit_user_process(ERROR_STATUS_CODE);                    \
    NOT_REACHED();                                           \
  }

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
 * Get one argument from the interrupt frame.
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
 * Get one argument from the interrupt frame.
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
 * user's buffer.
 * Takes a pointer to the kernel address to a given (part or whole) page,
 * the size of memory in that page, and a helper state.
 */
typedef void (*block_foreach_func) (void *, unsigned, void *);

static void exit_if_null(const void *ptr);

static bool buffer_pages_foreach(
  void *user_buffer,
  unsigned size,
  block_foreach_func f,
  void *state
);

static void *get_kernel_address(const void *uaddr);
static bool user_owns_memory_range(const void *buffer, unsigned size);
static void syscall_handler (struct intr_frame *);

// Helper functions for reading to and writing from buffer pages.

static void buffer_page_copy(
  void *buffer_page,
  unsigned buffer_page_size,
  void *state
);
static void buffer_page_print(
  void *buffer_page_,
  unsigned buffer_page_size,
  void *state UNUSED
);
static void buffer_page_record_stdin(
  void *buffer_page_,
  unsigned buffer_page_size,
  void *state UNUSED
);
static void buffer_page_file_read(
  void *buffer_page,
  unsigned buffer_page_size,
  void *state_
);

static void syscall_not_implemented(struct intr_frame *f);
static void halt(struct intr_frame *f) NO_RETURN;
static void exit(struct intr_frame *f);
static void exec(struct intr_frame *f);
static void wait(struct intr_frame *f);
static void create(struct intr_frame *f);
static void remove_handler(struct intr_frame *f);
static void open(struct intr_frame *f);
static void filesize(struct intr_frame *f);
static void read(struct intr_frame *f);
static void write(struct intr_frame *f);
static void seek(struct intr_frame *f);
static void tell(struct intr_frame *f);
static void close(struct intr_frame *f);

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
  &create,
  &remove_handler,
  &open,
  &filesize,
  &read,
  &write,
  &seek,
  &tell,
  &close,
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
 * Exit the user process with an error status if the provided pointer is NULL.
 * @param ptr The pointer to check.
 * @remark Will not return if the pointer is NULL.
 */
static void exit_if_null(const void *ptr) {
  if (ptr == NULL) {
    exit_user_process(ERROR_STATUS_CODE);
    NOT_REACHED();
  }
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
 * exit_user_process(ERROR_STATUS_CODE).
 */
static void *get_kernel_address(const void *uaddr) {
  // Return NUll if we're not accessing an address in user-space
  if (!is_user_vaddr(uaddr)) {
    return NULL;
  }

  return pagedir_get_page(thread_current()->pagedir, uaddr);
}

/**
 * Takes a pointer to a memory address, and copies buffer_page_size bytes from
 * the beginning of the address stored at `state`, also incrementing the
 * address by `buffer_page_size` bytes.
 * @param buffer_page_
 * @param buffer_page_size
 * @param state The address (of type `uint8_t **`) to the value being copied
 * (and incremented).
 */
static void buffer_page_copy(
    void *buffer_page,
    unsigned buffer_page_size,
    void *state
) {
  uint8_t **start = (uint8_t **)state;
  memcpy(
    (void *)*start,
    (const void *)buffer_page,
    (unsigned long)buffer_page_size
  );
  *start += buffer_page_size;
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
  ONE_ARG(int, status);
  exit_user_process(status);
}

/**
 * Handles exec system calls.
 * @param f The interrupt stack frame
 */
static void exec(struct intr_frame *f) {
  // pid_t exec(const char *cmd_line)
  ONE_ARG(char *, cmd_line);

  char *physical_cmd_line = get_kernel_address(cmd_line);
  exit_if_null(physical_cmd_line);

  f->eax = process_execute(physical_cmd_line);
}

/**
 * Handles wait system calls.
 * @param f The interrupt stack frame
 */
static void wait(struct intr_frame *f) {
  // int wait(pid_t pid)
  ONE_ARG(int, pid);
  f->eax = process_wait(pid);
}

/**
 * Handles create system calls.
 * @param f The interrupt stack frame
 */
static void create(struct intr_frame *f) {
  // bool create(const char *file, unsigned initial_size)
  TWO_ARG(
    const char *, user_filename,
    unsigned, initial_size
  );

  const char *physical_filename = get_kernel_address(user_filename);
  exit_if_null(physical_filename);

  lock_acquire(&file_system_lock);
  bool success = filesys_create(physical_filename, initial_size);
  lock_release(&file_system_lock);

  f->eax = success;
}

/**
 * Handles remove system calls.
 * @param f The interrupt stack frame
 */
static void remove_handler(struct intr_frame *f) {
  // bool remove(const char *file)
  ONE_ARG(const char *, user_filename);

  const char *physical_filename = get_kernel_address(user_filename);
  exit_if_null(physical_filename);

  lock_acquire(&file_system_lock);
  bool success = filesys_remove(physical_filename);
  lock_release(&file_system_lock);

  f->eax = success;
}

/**
 * Handles open system calls.
 * @param f The interrupt stack frame
 */
static void open(struct intr_frame *f) {
  // int open(const char *file)
  ONE_ARG(const char *, user_filename);

  struct thread *cur_thread = thread_current();

  const char *physical_filename = get_kernel_address(user_filename);
  exit_if_null(physical_filename);

  lock_acquire(&file_system_lock);
  struct file *new_file = filesys_open(physical_filename);
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
static void filesize(struct intr_frame *f) {
  // int filesize(int fd)
  ONE_ARG(int, fd);

  struct fd_entry fd_to_find;
  fd_to_find.fd = fd;

  // Search up the fd-file mapping from the fd table.
  struct hash_elem *fd_found_elem = hash_find(
    &thread_current()->fd_table,
    &fd_to_find.elem
  );
  exit_if_null(fd_found_elem);
  struct fd_entry *fd_found = hash_entry(fd_found_elem, struct fd_entry, elem);

  lock_acquire(&file_system_lock);
  int size = file_length(fd_found->file);
  lock_release(&file_system_lock);

  f->eax = size;
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
  // Performing pointer arithmetic on a void* is undefined behaviour,
  // so cast to a uint8_t* to comply with the standard.
  for (unsigned i = 0; i < size; i += PGSIZE) {
    if (get_kernel_address(&((uint8_t *)buffer)[i]) == NULL) {
      return false;
    }
  }
  // Check the end of the buffer as well.
  if (get_kernel_address(&((uint8_t *)buffer)[size - 1]) == NULL) {
    return false;
  }
  return true;
}

/**
 * Iterates over all pages to read mapped by the buffer of given size,
 * applying the foreach function to each page with the size of the section of
 * buffer in that page, and the state.
 * Fails, returning false, if the buffer does not map to a block of memory
 * owned by the user.
 * Care must be taken to ensure that the foreach function does not attempt to
 * write to read-only data, if the provided `user_buffer` is also read-only.
 * @param user_buffer The virtual (user) address to the buffer.
 * @param size The size of the buffer provided by the user.
 * @param f Iterator function to handle a part of the buffer in one page.
 * @param state State for the helper function to use.
 * @return `true` if and only if accessing the entire buffer succeeded.
 */
static bool buffer_pages_foreach(
  void *user_buffer,
  unsigned size,
  block_foreach_func f,
  void *state
) {
  void *buffer = get_kernel_address(user_buffer);
  if (!user_owns_memory_range(user_buffer, size)) {
    return false;
  }
  ASSERT(buffer != NULL);
  // The trivial case, when the entire buffer fits inside the page.
  unsigned buffer_end_offset = pg_ofs(buffer) + size - 1;
  if (buffer_end_offset < PGSIZE) {
    (*f)(buffer, size, state);
    return true;
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
    buffer = get_kernel_address(user_buffer);
    ASSERT(buffer != NULL);
    unsigned consumed = size < PGSIZE ? size : PGSIZE;
    (*f)(buffer, consumed, state);
    // If the last page is reached, consumed == size.
    user_buffer += consumed;
    size -= consumed;
  }
  return true;
}

/**
 * Reads input from the console, writing it to the given page of the buffer.
 * The original buffer should not point to a read-only section of memory.
 * The function does not provide synchronisation for console reads on its own.
 * @param buffer_page_ The physical address of the portion of the buffer.
 * @param page_size The size of the portion held in the page.
 * @param state State parameter (Unused.)
 */
static void buffer_page_record_stdin(
  void *buffer_page_,
  unsigned buffer_page_size,
  void *state UNUSED
) {
  uint8_t *buffer_page = (uint8_t *)buffer_page_;
  for (unsigned i = 0; i < buffer_page_size; i++) {
    buffer_page[i] = input_getc();
  }
}

/// State struct to be used by the buffer page iterator, storing the file being
/// read, the total number of bytes read, and whether EOF has been reached.
struct file_read_state {
  struct file *file;
  unsigned bytes_read;
  bool eof_reached;
};

/**
 * Helper function for reading from a file, and writing it to the given page
 * of the buffer. Will do nothing once an EOF has been reached.
 * The original buffer should not point to a read-only section of memory.
 * The function does not provide synchronisation for file reads on its own.
 * @param buffer_page
 * @param buffer_page_size
 * @param state_ A pointer to a `struct file_read_state`
 * @see struct file_read_state
 */
static void buffer_page_file_read(
  void *buffer_page,
  unsigned buffer_page_size,
  void *state_
) {
  struct file_read_state *state = (struct file_read_state *)state_;
  if (state->eof_reached) return;
  unsigned bytes_read = file_read(state->file, buffer_page, buffer_page_size);
  if (bytes_read < buffer_page_size) {
    // The buffer has not been fully written to, indicating we are at the
    // end of the file.
    state->eof_reached = true;
  } else {
    state->bytes_read += bytes_read;
  }
}

/**
 * Handles read system calls.
 * @param f The interrupt stack frame
 */
static void read(struct intr_frame *f) {
  // int read(int fd, void *buffer, unsigned size)
  THREE_ARG(
    int, fd,
    void *, buffer,
    unsigned, size
  );

  int bytes_read;

  if (fd == STDIN_FD) {
    // Read from the console.
    lock_acquire(&console_lock);
    bool success = buffer_pages_foreach(
      buffer,
      size,
      &buffer_page_record_stdin,
      NULL
    );
    lock_release(&console_lock);
    if (!success) {
      exit_user_process(ERROR_STATUS_CODE);
      NOT_REACHED();
    }
    // Given the original memory is valid, we will record all `size` bytes
    // from stdin.
    bytes_read = size;
  } else {
    // Read from file.

    // Search up the fd-file mapping from the fd table.
  	struct fd_entry fd_to_find;
  	fd_to_find.fd = fd;

  	struct hash_elem *fd_found_elem = hash_find(
  	  &thread_current()->fd_table,
  	  &fd_to_find.elem
  	);
  	if (fd_found_elem == NULL) {
      f->eax = SYSCALL_ERROR_CODE;
      return;
  	}
  	struct fd_entry *fd_found = hash_entry(fd_found_elem, struct fd_entry, elem);

    // Initialise the current state of reading the file to the buffer.
    struct file_read_state state;
    state.file = fd_found->file;
    state.eof_reached = false;
    state.bytes_read = 0;

    lock_acquire(&file_system_lock);
    bool success = buffer_pages_foreach(
      buffer,
      size,
      &buffer_page_file_read,
      &state
    );
    lock_release(&file_system_lock);
    if (!success) {
      exit_user_process(ERROR_STATUS_CODE);
      NOT_REACHED();
    }

    bytes_read = state.bytes_read;
  }
  f->eax = bytes_read;
}

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
  THREE_ARG(
    int, fd,
    const void *, user_buffer,
    unsigned, size
  );

  const char *buffer = get_kernel_address(user_buffer);
  exit_if_null(buffer);

  // If we don't own the buffer's memory, the operation is invalid.
  if (!user_owns_memory_range(user_buffer, size)) {
    exit_user_process(ERROR_STATUS_CODE);
    NOT_REACHED();
  }

  if (fd == STDOUT_FD) {
    // Console write

    lock_acquire(&console_lock);
    bool success = buffer_pages_foreach(
      user_buffer,
      size,
      &buffer_page_print,
      NULL
    );
    lock_release(&console_lock);
    if (!success) {
      exit_user_process(ERROR_STATUS_CODE);
      NOT_REACHED();
    }
    // Given the original memory is valid, putbuf will succeed
    // so all bytes will have been written.
    f->eax = size;
  } else {
    // Write to file

    // Search up the fd-file mapping from the fd table.
  	struct fd_entry fd_to_find;
  	fd_to_find.fd = fd;
  	struct hash_elem *fd_found_elem = hash_find(
  	  &thread_current()->fd_table,
  	  &fd_to_find.elem
  	);
    exit_if_null(fd_found_elem);
  	struct fd_entry *fd_found = hash_entry(fd_found_elem, struct fd_entry, elem);

    lock_acquire(&file_system_lock);
    int bytes_written = file_write(fd_found->file, buffer, size);
    lock_release(&file_system_lock);

    f->eax = bytes_written;
  }
}

/**
 * Handles seek system calls.
 * @param f The interrupt stack frame
 */
static void seek(struct intr_frame *f) {
  // void seek(int fd, unsigned position)
  TWO_ARG(
    int, fd,
    unsigned, position
  );

  // Search up the fd-file mapping from the fd table.
  struct fd_entry fd_to_find;
  fd_to_find.fd = fd;
  struct hash_elem *fd_found_elem = hash_find(
    &thread_current()->fd_table,
    &fd_to_find.elem
  );
  exit_if_null(fd_found_elem);
  struct fd_entry *fd_found = hash_entry(fd_found_elem, struct fd_entry, elem);

  lock_acquire(&file_system_lock);
  file_seek(fd_found->file, position);
  lock_release(&file_system_lock);
}

/**
 * Handles tell system calls.
 * @param f The interrupt stack frame
 */
static void tell(struct intr_frame *f) {
  // unsigned tell(int fd)
  ONE_ARG(int, fd);

  // Search up the fd-file mapping from the fd table.
  struct fd_entry fd_to_find;
  fd_to_find.fd = fd;
  struct hash_elem *fd_found_elem = hash_find(
    &thread_current()->fd_table,
    &fd_to_find.elem
  );
  exit_if_null(fd_found_elem);
  struct fd_entry *fd_found = hash_entry(fd_found_elem, struct fd_entry, elem);

  lock_acquire(&file_system_lock);
  unsigned position = file_tell(fd_found->file);
  lock_release(&file_system_lock);

  f->eax = position;
}

/**
 * Handles close system calls.
 * @param f The interrupt stack frame
 */
static void close(struct intr_frame *f UNUSED) {
  // void close(int fd)
  ONE_ARG(int, fd);

  // Search up the fd-file mapping from the fd table.
  struct fd_entry fd_to_find;
  fd_to_find.fd = fd;
  struct hash_elem *fd_found_elem = hash_find(
    &thread_current()->fd_table,
    &fd_to_find.elem
  );
  exit_if_null(fd_found_elem);

  // close file, free it, delete from fd_table.
  hash_delete(&thread_current()->fd_table, fd_found_elem);
  close_file(fd_found_elem, NULL);
}

/**
 * Dispatches system calls to the appropriate handler.
 * @param f The interrupt stack frame
 */
static void
syscall_handler (struct intr_frame *f)
{
  uint32_t *syscall_no_addr = f->esp;

  uint32_t *physical_syscall_no_addr = get_kernel_address(syscall_no_addr);
  exit_if_null(physical_syscall_no_addr);

  uint32_t syscall_no = *physical_syscall_no_addr;

  if (syscall_no >= sizeof(syscall_handlers) / sizeof(syscall_handler_func)) {
    exit_user_process(ERROR_STATUS_CODE);
    NOT_REACHED();
  }

  (*syscall_handlers[syscall_no])(f);
}
