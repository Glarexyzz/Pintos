#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
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

// Helper macro for ONE_ARG, TWO_ARG, and THREE_ARG
#define AN_ARG(t1, n1, number)                               \
  void *arg ## number ## _ = ((uint32_t *) f->esp)+number;   \
  void *arg ## number ## _kernel_ = access_user_memory(      \
    thread_current()->pagedir,                               \
    arg ## number ## _                                       \
  );                                                         \
  if (arg ## number ## _kernel_ == NULL) {                   \
    exit_user_process(-1);                                   \
    NOT_REACHED();                                           \
  }                                                          \
  t1 n1 = *((t1 *) arg ## number ## _kernel_);

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

static const void *access_user_memory(uint32_t *pd, const void *uaddr);
static void syscall_handler (struct intr_frame *);

static void syscall_not_implemented(struct intr_frame *f);
static void halt(struct intr_frame *f) NO_RETURN;
static void exit(struct intr_frame *f);
static void exec(struct intr_frame *f);
static void wait(struct intr_frame *f);
static void create(struct intr_frame *f);
static void remove_handler(struct intr_frame *f);
static void open(struct intr_frame *f);
static void filesize(struct intr_frame *f);
static void write(struct intr_frame *f);
static void seek(struct intr_frame *f);
static void tell(struct intr_frame *f);
static void close(struct intr_frame *f);

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
  &syscall_not_implemented,
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
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
 * exit_user_process(-1).
 */
static const void *access_user_memory(uint32_t *pd, const void *uaddr) {
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

  char *physical_cmd_line = access_user_memory(
    thread_current()->pagedir,
    cmd_line
  );

  // Terminate process if pointer is invalid.
  if (physical_cmd_line == NULL) {
    exit_user_process(-1);
    NOT_REACHED();
  }

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

  //Access memory
  const char *physical_filename = access_user_memory(
      thread_current()->pagedir,
      user_filename
  );

  // Terminating the offending process and freeing its resources
  // for invalid pointer address.
  if (physical_filename == NULL) {
    exit_user_process(-1);
    NOT_REACHED();
  }

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

  //Access memory
  const char *physical_filename = access_user_memory(
      thread_current()->pagedir,
      user_filename
  );

  // Terminating the offending process and freeing its resources
  // for invalid pointer address.
  if (physical_filename == NULL) {
    exit_user_process(-1);
    NOT_REACHED();
  }

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
  const char *physical_filename = access_user_memory(
    cur_thread->pagedir,
    user_filename
  );

  // Terminating the offending process and freeing its resources
  // for invalid pointer address.
  if (physical_filename == NULL) {
    exit_user_process(-1);
    return;
  }

  lock_acquire(&file_system_lock);
  struct file *new_file = filesys_open(physical_filename);
  lock_release(&file_system_lock);

  if (new_file == NULL) {
    f->eax = -1;
    return;
  }

  // Initialise the hashmap entry for fd table
  struct fd_entry *new_fd_entry =
    malloc(sizeof(struct fd_entry));
  if (new_fd_entry == NULL) {
    f->eax = -1;
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
  if (fd_found_elem == NULL) {
    exit_user_process(-1);
    NOT_REACHED();
  }
  struct fd_entry *fd_found = hash_entry(fd_found_elem, struct fd_entry, elem);

  lock_acquire(&file_system_lock);
  int size = file_length(fd_found->file);
  lock_release(&file_system_lock);

  f->eax = size;
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


  const char *buffer = access_user_memory(
    thread_current()->pagedir,
    user_buffer
  );
  // Terminating the offending process and freeing its resources
  // for invalid pointer address.
  if (buffer == NULL) {
    exit_user_process(-1);
    NOT_REACHED();
  }

  if (fd == 1) {
    // Console write

    unsigned bytes_written;

    // Keep writing MAX_WRITE_SIZE bytes as long as it's less than size
    for (
      bytes_written = 0;
      bytes_written + MAX_WRITE_SIZE < size;
      bytes_written += MAX_WRITE_SIZE
      ) {
      putbuf(buffer + bytes_written, MAX_WRITE_SIZE);
    }

    // Write the remaining bytes
    putbuf(buffer + bytes_written, size - bytes_written);

    // Assume all bytes have been written
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
  	if (fd_found_elem == NULL) {
  	  exit_user_process(-1);
  	  NOT_REACHED();
  	}
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
  if (fd_found_elem == NULL) {
    exit_user_process(-1);
    NOT_REACHED();
  }
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
  if (fd_found_elem == NULL) {
    exit_user_process(-1);
    NOT_REACHED();
  }
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
  if (fd_found_elem == NULL) {
    exit_user_process(-1);
    NOT_REACHED();
  }

  // close file, free it, delete from fd_table.
  close_file(fd_found_elem, NULL);
  hash_delete(&thread_current()->fd_table, fd_found_elem);
}

/**
 * Dispatches system calls to the appropriate handler.
 * @param f The interrupt stack frame
 */
static void
syscall_handler (struct intr_frame *f)
{
  uint32_t *syscall_no_addr = f->esp;

  uint32_t *physical_syscall_no_addr = access_user_memory(
    thread_current()->pagedir,
    syscall_no_addr
  );

  // Terminating the offending process and freeing its resources
  // for invalid pointer address.
  if (physical_syscall_no_addr == NULL) {
    exit_user_process(-1);
    NOT_REACHED();
  }

  uint32_t syscall_no = *physical_syscall_no_addr;

  if (syscall_no >= sizeof(syscall_handlers) / sizeof(syscall_handler_func)) {
    exit_user_process(-1);
    NOT_REACHED();
  }

  (*syscall_handlers[syscall_no])(f);
}
