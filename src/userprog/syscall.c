#include "userprog/syscall.h"
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/// Type of system call handler functions.
typedef void (*syscall_handler_func) (struct intr_frame *);

static void syscall_handler (struct intr_frame *);

static void syscall_not_implemented(struct intr_frame *f);
static void write(struct intr_frame *f);

// Handler for system calls corresponding to those defined in syscall-nr.h
const syscall_handler_func syscall_handlers[] = {
  &syscall_not_implemented,
  &syscall_not_implemented,
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
 * Placeholder for unimplemented system calls.
 * @param f The interrupt stack frame
 */
static void syscall_not_implemented(struct intr_frame *f UNUSED) {
  printf("System call not implemented.\n");
}

/**
 * Handles write system calls.
 * @param f The interrupt stack frame
 */
static void write(struct intr_frame *f UNUSED) {
  printf("Write called.\n");
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
