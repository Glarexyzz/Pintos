#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include "threads/interrupt.h"
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

static const void *access_user_memory(uint32_t *pd, const void *uaddr);
static void exit_process(int status) NO_RETURN;
static void syscall_handler (struct intr_frame *);

static void syscall_not_implemented(struct intr_frame *f);
static void exit(struct intr_frame *f);
static void write(struct intr_frame *f);

// Handler for system calls corresponding to those defined in syscall-nr.h
const syscall_handler_func syscall_handlers[] = {
  &syscall_not_implemented,
  &exit,
  &syscall_not_implemented,
  &syscall_not_implemented,
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
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/**
 * Exits a user program with the provided status code.
 * @param status The exit status code.
 */
static void exit_process(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);
  // Free the process's resources.
  process_exit();
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
 * @remark If NULL is returned, the caller should free its resources and call exit_process(-1).
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
 * Handles exit system calls.
 * @param f The interrupt stack frame
 */
static void exit(struct intr_frame *f UNUSED) {
  // void exit(int status)
  int status = ARG(int, 1);
  exit_process(status);
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
