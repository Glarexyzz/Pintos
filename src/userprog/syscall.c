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

static void exit_process(int status) NO_RETURN;
static const void *access_user_memory(uint32_t *pd, const void *uaddr);
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

  /*
   * When a user process is exited, the user_processes hashmap must be updated.
   * We must:
   * - Update the exit status of the process, and up its semaphore
   * - Delete all the process's child processes from the user_processes hashmap,
   *   since no processes can wait for them anymore
   */

  struct thread *cur_thread = thread_current();

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

  // Delete all this process's children from the hashmap
  struct list_elem *curr_child = list_begin(&cur_thread->child_tids);

  // Loop through all the process's children
  while (curr_child != list_end(&cur_thread->child_tids)) {

    // Get the process_tid struct of the child
    struct process_tid *curr_child_process_tid = list_entry(
      curr_child,
      struct process_tid,
      elem
    );

    // Setup to find the child process in the user_processes hashmap
    struct process_status child_to_find;
    child_to_find.tid = curr_child_process_tid->tid;

    // Remove the child from the current process's list, and free its struct
    struct list_elem *prev_child = curr_child;
    curr_child = list_next(prev_child);
    list_remove(prev_child);
    free(curr_child_process_tid);

    // Delete and free the child from the hash table, if it exists
    lock_acquire(&user_processes_lock);
    struct hash_elem *deleted_child = hash_delete(
      &user_processes,
      &child_to_find.elem
    );
    lock_release(&user_processes_lock);
    if (deleted_child != NULL) {
      free(deleted_child);
    }
  }

  // Print the exit status
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
 * @remark If NULL is returned, the caller should free its resources and call
 * exit_process(-1).
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
