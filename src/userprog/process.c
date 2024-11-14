#include "userprog/process.h"
#include <debug.h>
#include <hash.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "devices/timer.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/// The maximum length of the name of a file that can be opened.
#define MAX_FILENAME_LENGTH 14

struct hash user_processes;
struct lock user_processes_lock;

struct lock file_system_lock;

static unsigned user_process_hash(
  const struct hash_elem *element,
  void *aux UNUSED
);
static bool user_process_tid_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);
void user_process_hashmap_init(void);

static unsigned fd_hash(
  const struct hash_elem *element,
  void *aux UNUSED
);
static bool fd_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
);
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Structure used for argument passing. */
struct pass_args_data {
  /* The destination of argument pointers to be written on the stack. */
  char **ptrs_dest;
  /* The destination of the argument strings to be written on the stack. */
  char *params_dest;
};

/// Used as the thread auxiliary data when new processes are created
struct new_process_aux {
  struct semaphore sema; // The semaphore which process_execute waits for
  bool status;           // The startup status of the process
  char *file_name;       // The name of the file to execute
};

/**
 * Pushes (and copies) 4 bytes from the given address onto the stack.
 * @pre Both the stack pointer esp and the pointer to data are non-NULL,
 * and there is enough space in the current page to write to the stack.
 * @param esp The stack pointer.
 * @param data The generic pointer to be written to the stack.
 * @example \code
 * void push_two(void **esp) {
 *     int two = 2;
 *     push_to_stack(esp, &two);
 *     ASSERT(*(int *)*esp == 2);
 * }
 * \endcode
 */
static void stack_push(void **esp, void *data) {
  ASSERT(esp != NULL);
  ASSERT(data != NULL);
  ASSERT(*esp != NULL);
  *esp -= sizeof(uint32_t);
  *(uint32_t *)*esp = *(uint32_t *)data;
}

/**
 * The functions is called twice to parse the given filename, delimited by
 * spaces, to put on the stack.
 * In the first pass, it decrements the stack pointer and pushes char **argv,
 * argc, and the NULL return address.
 * In the second pass, it pushes the argv pointers and their corresponding
 * arguments.
 * @param args_to_split The (unsplit) arguments to be passed onto the stack.
 * @param esp The (possibly NULL) stack pointer. If esp is not NULL, it must
 * point to a valid pointer taken to be PHYS_BASE. esp should be null in the
 * second pass.
 * @param data The auxiliary data to set in the first pass and populate in the
 * second.
 * @return `true` if and only if the arguments fit within PGSIZE bytes.
 */
static bool parse_argument_string(
  const char *args_to_split,
  void **esp,
  struct pass_args_data *data
) {
  // Check the preconditions for arguments
  ASSERT(args_to_split != NULL);
  ASSERT(esp == NULL || (*esp != NULL && *esp == PHYS_BASE));
  ASSERT(data != NULL);
  int argc = 0;
  // The number of non-space characters in the input string
  int len = 0;
  const char *cur = args_to_split;
  // (1st pass) Find all words in the input string
  while (true) {
    // Skip past whitespace
    while (*cur == ' ') cur++;

    // Do not include trailing or leading whitespace in our count
    if (*cur == '\0') break;

    // At this point we have found another argument;
    // record its length and location (1st pass)
    // or write to the stack (2nd pass)
    char *arg_begin = &data->params_dest[len + argc];
    while (*cur != '\0' && *cur != ' ') {
      if (esp == NULL) {
        // (2nd pass) Copy the argument to the stack
        data->params_dest[len + argc] = *cur;
      }
      cur++;
      len++;
    }

    // (2nd pass) Add null terminator to the end of the argument
    // and the pointer to the argument (on the stack) to the argv array
    if (esp == NULL) {
      data->params_dest[len + argc] = '\0';
      data->ptrs_dest[argc] = arg_begin;
    }

    // Move to the next argument
    argc++;
  }

  // (2nd pass) Write the NULL sentinel at the end of argv,
  // and the pass is now done.
  if (esp == NULL) {
    data->ptrs_dest[argc] = NULL;
    return true;
  }

  /* The maximum (bottommost) region allocated for the stack within the same
     page. */
  void *esp_min = *esp - PGSIZE;

  /* The space needed for strings is (argc - 1) space separators,
   * plus `len` non-space characters, plus 1 for the null terminator. */
  len += argc;

  // Align to 4 bytes.
  int word_align = len % sizeof(uint32_t);
  if (word_align != 0) {
    len += sizeof(uint32_t) - word_align;
  }

  // Leave space onto the stack for the strings to be copied, if possible.
  if (*esp - len <= esp_min) return false;
  *esp -= len;
  data->params_dest = (char *) *esp;

  /* Ensure there is extra space for the argv pointers (including the NULL
     sentinel at the end of the argv array), as well as three values as per
     80x86 calling convention for calling `int main(int argc, char **argv)`:
     - the basal pointer to argv,
     - the value of argc, and
     - the NULL return address. */
  int argv_len, calling_conv_len;
  argv_len = (argc + 1) * sizeof(uint32_t);
  calling_conv_len = 3 * sizeof(uint32_t);

  if (*esp - argv_len <= esp_min) return false;
  *esp -= argv_len;
  data->ptrs_dest = *esp;

  if (*esp - calling_conv_len <= esp_min) return false;

  // At this point we can successfully push all the values onto the stack
  stack_push(esp, &data->ptrs_dest);
  stack_push(esp, &argc);
  void (**return_address) (void) = NULL;
  stack_push(esp, &return_address);
  return true;
}

/**
 * A hash_hash_func for process_status struct.
 * @param element The pointer to the hash_elem in the process_status struct.
 * @param aux Unused.
 * @return The hash of the process_status.
 */
static unsigned user_process_hash(
  const struct hash_elem *element,
  void *aux UNUSED
) {
  tid_t tid = hash_entry(element, struct process_status, elem)->tid;
  return hash_int(tid);
}

/**
 * A hash_less_func for process_status struct.
 * @param a The pointer to the hash_elem in the first process_status struct.
 * @param b The pointer to the hash_elem in the second process_status struct.
 * @param aux Unused.
 * @return True iff a < b.
 */
static bool user_process_tid_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  tid_t a_tid = hash_entry(a, struct process_status, elem)->tid;
  tid_t b_tid = hash_entry(b, struct process_status, elem)->tid;
  return a_tid < b_tid;
}

/**
 * Initialises the user_processes hashmap.
 */
void user_process_hashmap_init() {
  bool success = hash_init(
    &user_processes,
    &user_process_hash,
    &user_process_tid_smaller,
    NULL
  );
  if (!success) PANIC("Could not initialise the user programs hashmap!");
  lock_init(&user_processes_lock);
}

/**
 * Copies the first word of file_name, which is the executable name that has a
 * max length of MAX_FILENAME_LENGTH.
 * @param file_name A String containing the executable name and arguments.
 * @param executable_name A buffer of size MAX_FILENAME_LENGTH + 1 to where the
 * executable name will be copied.
 */
static void copy_executable_name(const char *file_name, char *executable_name) {
  while (*file_name == ' ') file_name++;
  int len_to_copy = MAX_FILENAME_LENGTH + 1;
  char *first_delim = strchr(file_name, ' ');
  // Include the null terminator in the calculation of the length before the
  // first delimiter, in case the file_name has leading spaces.
  if (first_delim != NULL) {
    int len_before_space = first_delim - file_name + 1;
    if (len_before_space < len_to_copy) len_to_copy = len_before_space;
  }
  // Copy the filename, including the null terminator.
  strlcpy(executable_name, file_name, len_to_copy);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  char executable_name[MAX_FILENAME_LENGTH + 1];
  copy_executable_name(file_name, executable_name);

  // Setup auxiliary data for starting the new process
  struct new_process_aux aux;
  sema_init(&aux.sema, 0);
  aux.file_name = fn_copy;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (executable_name, PRI_DEFAULT, start_process, &aux);
  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy);
  	return tid;
  }

  // Wait for the process to either start up successfully, or fail starting up
  sema_down(&aux.sema);

  // Process failed to start up
  if (!aux.status) return TID_ERROR;

  // Process successfully started up - add its TID to the parent's
  // (current thread's) list of child TIDs.

  // Initialise the tid entry
  struct process_tid *new_child_tid_struct =
    malloc(sizeof(struct process_tid));

  if (new_child_tid_struct == NULL) {
    // Remove the child's entry from the processes hashmap, since the parent
    // can never wait for it

    // Find and delete the child's entry in the hashmap
    struct process_status process_to_find;
    process_to_find.tid = tid;

    lock_acquire(&user_processes_lock);
    struct hash_elem *child_process_elem = hash_delete(
      &user_processes,
      &process_to_find.elem
    );
    lock_release(&user_processes_lock);

    // Free the child's entry struct
    struct process_status *child_process_entry = hash_entry(
      child_process_elem,
      struct process_status,
      elem
    );
    free(child_process_entry);

    return TID_ERROR;
  }

  new_child_tid_struct->tid = tid;

  // Add the child tid elem to the current parent process's child_tids list.
  list_push_back(&thread_current()->child_tids, &new_child_tid_struct->elem);

  return tid;
}

/**
 * A hash_hash_func for fd_table struct.
 * @param element The pointer to the hash_elem in the fd_table struct.
 * @param aux Unused.
 * @return The hash of the fd_table.
 */
static unsigned fd_hash(
  const struct hash_elem *element,
  void *aux UNUSED
) {
  int fd = hash_entry(element, struct fd_entry, elem)->fd;
  return hash_int(fd);
}

/**
 * A hash_less_func for fd_table struct.
 * @param a The pointer to the hash_elem in the first fd_table struct.
 * @param b The pointer to the hash_elem in the second fd_table struct.
 * @param aux Unused.
 * @return True iff a < b.
 */
static bool fd_smaller(
  const struct hash_elem *a,
  const struct hash_elem *b,
  void *aux UNUSED
) {
  int a_fd = hash_entry(a, struct fd_entry, elem)->fd;
  int b_fd = hash_entry(b, struct fd_entry, elem)->fd;
  return a_fd < b_fd;
}

/**
* Initialises the file system lock.
*/
void file_system_lock_init() {
  lock_init(&file_system_lock);
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux_)
{
  struct new_process_aux *aux = aux_;
  char *file_name = aux->file_name;
  struct intr_frame if_;
  bool success;

  thread_current()->is_user = true;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) goto startup_failure;

  // Initialise the file descriptor table.
  success = hash_init(&thread_current()->fd_table, fd_hash, fd_smaller, NULL);
  if (!success) goto startup_failure;
  thread_current()->fd_counter = 2; /* Can't use the numbers 0 or 1 -
                                       these refer to the console. */

  // Start-up successful

  // Initialise the user_processes hashmap entry for this process
  struct process_status *new_child_status =
    malloc(sizeof(struct process_status));

  if (new_child_status == NULL) goto startup_failure;

  new_child_status->tid = thread_current()->tid;
  sema_init(&new_child_status->sema, 0);

  // Add the entry to the hashmap
  lock_acquire(&user_processes_lock);
  hash_insert(&user_processes, &new_child_status->elem);
  lock_release(&user_processes_lock);

  // Signal to the process's parent that start-up was successful
  aux->status = true;
  sema_up(&aux->sema);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();

  startup_failure:

  // Signal to the process's parent that start-up was not successful
  aux->status = false;
  sema_up(&aux->sema);

  thread_exit ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread *cur_thread = thread_current();

  // Check if the provided tid is in the caller's list of children
  bool is_child = false;
  struct list_elem *child_elem;

  // Iterate through the current thread's child thread tids
  for (
    child_elem = list_begin(&cur_thread->child_tids);
    child_elem != list_end(&cur_thread->child_tids);
    child_elem = list_next(child_elem)
  ) {
    struct process_tid *child_tid_struct = list_entry(
      child_elem,
      struct process_tid,
      elem
    );
    // If the child's tid matches the tid the caller wants to wait, the wait is
    // valid
    if (child_tid_struct->tid == child_tid) {
      is_child = true;
      break;
    }
  }

  // If the provided tid was not in the caller's list of children, return
  if (!is_child) return -1;

  // Remove the thread we're waiting for from the list of children, since we can
  // only wait for a child process once
  list_remove(child_elem);
  free(list_entry(
    child_elem,
    struct process_tid,
    elem
  ));

  // Find the child process's entry in the user_processes hashmap
  struct process_status process_to_find;
  process_to_find.tid = child_tid;

  lock_acquire(&user_processes_lock);

  struct hash_elem *process_found_elem = hash_find(
    &user_processes,
    &process_to_find.elem
  );

  lock_release(&user_processes_lock);

  // The process is guaranteed to be in the hashmap, since it's only removed by
  // the parent either in process_wait, or when the parent exits
  ASSERT(process_found_elem != NULL);

  struct process_status *process_found = hash_entry(
    process_found_elem,
    struct process_status,
    elem
  );

  // Wait for the child process to exit - we can down this sema outside of the
  // user_processes_lock, since *only* the current thread has the ability to
  // down this semaphore or delete the hash entry containing the semaphore
  sema_down(&process_found->sema);

  // Store the child process's exit status
  int child_status = process_found->status;

  // Delete and free the child from the hash table, if it exists
  lock_acquire(&user_processes_lock);
  hash_delete(&user_processes, &process_to_find.elem);
  lock_release(&user_processes_lock);
  free(process_found);

  return child_status;
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
void exit_user_process(int status) {

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
  hash_destroy(&cur_thread->fd_table, &close_file);

  // Close the executable file pointer, allowing writes again.
  ASSERT(cur_thread->executable_file != NULL);
  file_close(cur_thread->executable_file);

  // Print the exit status
  printf("%s: exit(%d)\n", thread_current()->name, status);

  // Free the process's resources.
  thread_exit();
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();

  // When a process exits, we must delete all its child processes from the
  // user_processes hashmap, since no processes can wait for them anymore

  // Delete all this process's children from the hashmap
  struct list_elem *curr_child = list_begin(&cur->child_tids);

  // Loop through all the process's children
  while (curr_child != list_end(&cur->child_tids)) {

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
      free(hash_entry(
        deleted_child,
        struct process_status,
        elem
      ));
    }
  }

  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char* file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  char executable_name[MAX_FILENAME_LENGTH + 1];
  copy_executable_name(file_name, executable_name);

  lock_acquire(&file_system_lock);
  file = filesys_open (executable_name);
  lock_release(&file_system_lock);

  // Store file pointer in thread.
  t->executable_file = file;

  if (file == NULL)
    {
      printf ("load: %s: open failed\n", executable_name);
      goto done; 
    }

  // Make the file unwritable.
  lock_acquire(&file_system_lock);
  file_deny_write(file);
  lock_release(&file_system_lock);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", executable_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      /* Check if virtual page already allocated */
      struct thread *t = thread_current ();
      uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
      
      if (kpage == NULL){
        
        /* Get a new page of memory. */
        kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL){
          return false;
        }
        
        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }     
        
      } else {
        
        /* Check if writable flag for the page should be updated */
        if(writable && !pagedir_is_writable(t->pagedir, upage)){
          pagedir_set_writable(t->pagedir, upage, writable); 
        }
        
      }

      /* Load data into the page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes){
        return false; 
      }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char* file_name)
{
  uint8_t *kpage;
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      if (!install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true)) {
        palloc_free_page(kpage);
        return false;
      }
      *esp = PHYS_BASE;

      // Decrement the stack pointer.
      struct pass_args_data pass_args_data;
      if (!parse_argument_string(file_name, esp, &pass_args_data))
        return false;

      // Populate the stack.
      bool second_pass =
        parse_argument_string(file_name, NULL, &pass_args_data);
      // If the first parse was successful, the second needs to be as well.
      ASSERT(second_pass);
    }
  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
