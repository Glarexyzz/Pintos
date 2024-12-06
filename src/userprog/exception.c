#include <debug.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "devices/swap.h"
#include "filesys/file.h"
#include "userprog/exception.h"
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/mmap.h"

/// The number of bytes written to the stack in a PUSH instruction.
#define PUSH_SIZE 4
/// The number of bytes written to the stack in a PUSHA instruction.
#define PUSHA_SIZE 32

/* Number of page faults processed. */
static long long page_fault_cnt;

/// Handles stack growth using the current interrupt frame and fault address.
static bool stack_grow(struct intr_frame *f, const void *fault_addr);
static bool access_is_stack(const void *esp, const void *addr);

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      if (thread_current()->is_user) {
        exit_user_process(ERROR_STATUS_CODE);
      } else {
        thread_exit();
      }

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  
         Shouldn't happen.  Panic the kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      PANIC ("Kernel bug - this shouldn't be possible!");
    }
}

/**
 * Checks whether a given pointer is a valid location on a stack.
 * This does not check whether a stack frame is allocated at that location.
 * @param esp The stack pointer.
 * @param addr The address in memory being accessed.
 * @return `true` if and only if the address is in the correct position with
 * respect to the stack pointer (usually at or above the stack pointer, and
 * below `PHYS_BASE`), so frames are allowed to be allocated to this location.
 * @pre the stack pointer is not NULL.
 */
static bool access_is_stack(const void *esp, const void *addr) {
  ASSERT(esp != NULL);
  if (addr == NULL) {
    // Make the NULL check explicit, although it should already be covered by
    // the later check that addr >= PHYS_BASE - STACK_MAX.
    return false;
  }
  // Check if the address to be written/read to is in the valid range,
  // avoiding growth above the amount specified by `STACK_MAX`.
  bool stack_growth = PHYS_BASE - STACK_MAX <= addr && is_user_vaddr(addr);
  // For legacy reasons, allow accesses specifically at esp - PUSH/PUSHA size
  const void *normal_push_addr  = esp;
  const void *legacy_push_addr  = normal_push_addr - PUSH_SIZE;
  const void *legacy_pusha_addr = normal_push_addr - PUSHA_SIZE;
  stack_growth = stack_growth && (
    addr >= normal_push_addr
    || addr == legacy_push_addr
    || addr == legacy_pusha_addr
  );
  return stack_growth;
}

/**
 * Handles stack growth, attempting to allocate new stack pages as needed.
 * @param f The current interrupt frame.
 * @param fault_addr The address which caused a page fault, and may need to
 * grow the stack.
 * @pre The page fault was caused by a user process.
 * @return `true` if the stack growth amount is valid, and allocating the frame
 * succeeded, and `false` otherwise.
 */
static bool stack_grow(struct intr_frame *f, const void *fault_addr) {
  if (!access_is_stack(f->esp, fault_addr)) {
    return false;
  }
  // Try to map the address to the stack
  uint32_t *pd = thread_current()->pagedir;
  const void *aligned_addr = pg_round_down(fault_addr);

  // Attempt to allocate a stack page for the current process.
  // If allocation fails, return false to kill the process.
  void *stack_page = user_get_page(0, aligned_addr);
  ASSERT(stack_page != NULL);

  ASSERT(pagedir_get_page(pd, aligned_addr) == NULL);
  if (!pagedir_set_page(pd, (void *)aligned_addr, stack_page, true)) {
    user_free_page(stack_page);
    return false;
  }

  return true;
}

/**
 * Handles loading of a writable executable file into memory.
 * @param spt_entry The supplemental page table entry.
 * @return `true` iff loading was successful.
 */
static bool load_writable_executable(struct spt_entry *spt_entry) {
  int page_read_bytes = spt_entry->writable_exec_file.page_read_bytes;
  int page_zero_bytes = spt_entry->writable_exec_file.page_zero_bytes;
  struct file *file = spt_entry->writable_exec_file.file;
  int offset = spt_entry->writable_exec_file.offset;

  lock_release(&thread_current()->spt_lock);
  uint8_t *kpage = user_get_page(0, spt_entry->uvaddr);
  lock_acquire(&thread_current()->spt_lock);

  // Read the executable file into memory.
  int read_bytes = 0;
  if (page_read_bytes != 0) {
    lock_acquire(&file_system_lock);
    file_seek(file, offset);
    read_bytes = file_read(file, kpage, page_read_bytes);
    lock_release(&file_system_lock);
  }
  if (read_bytes != page_read_bytes) {
    user_free_page(kpage);
    return false;
  }
  memset(kpage + page_read_bytes, 0, page_zero_bytes);

  if (!pagedir_set_page(
    thread_current()->pagedir,
    spt_entry->uvaddr,
    kpage,
    spt_entry->writable
  )) {
    user_free_page(kpage);
    return false;
  }
  return true;
}

/**
 * Handles loading of a shared executable file into memory.
 * @param spt_entry The supplemental page table entry.
 * @return `true` iff loading was successful.
 */
static bool load_shared_executable(struct spt_entry *spt_entry) {
  int page_read_bytes = spt_entry->shared_exec_file.page_read_bytes;
  int page_zero_bytes = spt_entry->shared_exec_file.page_zero_bytes;
  struct shared_frame *shared_frame = spt_entry->shared_exec_file.shared_frame;

  // We must allocate a frame to put in shared_frame.
  struct frame *new_frame = create_frame(0, spt_entry->uvaddr);
  uint8_t *kpage = new_frame->kvaddr;

  // Read the executable file into memory.
  int read_bytes = 0;
  if (page_read_bytes != 0) {
    lock_acquire(&file_system_lock);
    file_seek(shared_frame->file, shared_frame->offset);
    read_bytes = file_read(shared_frame->file, kpage, page_read_bytes);
    lock_release(&file_system_lock);
  }
  if (read_bytes != page_read_bytes) {
    user_free_page(kpage);
    return false;
  }
  memset(kpage + page_read_bytes, 0, page_zero_bytes);

  shared_frame->frame = new_frame;
  new_frame->shared_frame = shared_frame;
  lock_release(&shared_frame->lock);

  // Insert the page into the page table.
  lock_release(&thread_current()->spt_lock);

  lock_acquire(&frame_table_lock);
  hash_insert(&frame_table, &new_frame->table_elem);
  lock_release(&frame_table_lock);

  lock_acquire(&thread_current()->spt_lock);

  lock_acquire(&shared_frame->lock);

  if (!pagedir_set_page(
    thread_current()->pagedir,
    spt_entry->uvaddr,
    kpage,
    spt_entry->writable
  )) {
    user_free_page(kpage);
    return false;
  }
  return true;
}

/**
 * Handles using a shared executable file that has already been loaded into
 * memory.
 * @param spt_entry The supplemental page table entry.
 * @return `true` iff loading was successful.
 */
static bool use_shared_executable(struct spt_entry *spt_entry) {
  return pagedir_set_page(
    thread_current()->pagedir,
    spt_entry->uvaddr,
    spt_entry->shared_exec_file.shared_frame->frame->kvaddr,
    spt_entry->writable
  );
}

/**
 * Handles loading of uninitialised executable file, allocating pages
 * and reading the executable file into them.
 * @param fault_addr The address.
 * @return `true` iff loading was successful.
 */
static bool load_uninitialised_executable(struct spt_entry *spt_entry) {
  bool success;
  // Get the status of the uninitialised executable, and handle accordingly.
  if (spt_entry->writable) {
    success = load_writable_executable(spt_entry);
  } else {
    struct shared_frame *shared_frame = spt_entry->shared_exec_file.shared_frame;

    lock_acquire(&shared_frame->lock);
    if (shared_frame->frame == NULL) {
      success = load_shared_executable(spt_entry);
    } else {
      success = use_shared_executable(spt_entry);
    }
    lock_release(&shared_frame->lock);
  }

  return success;
}

/**
 * Given an spt_entry, loads its corresponding frame from the swap partition
 * of the disk.
 * @param spt_entry The spt_entry corresponding to the frame to be swapped in.
 * @return `true` iff the frame was successfully loaded in.
 */
static bool load_swapped_page(struct spt_entry *spt_entry) {
  struct thread *cur = thread_current();
  lock_release(&cur->spt_lock);

  void *kpage = user_get_page(0, spt_entry->uvaddr); // TODO: unpin?
  swap_in(kpage, spt_entry->swap_slot); // TODO: Does it matter if kvaddr or uvaddr?

  if (!pagedir_set_page(
      cur->pagedir,
      spt_entry->uvaddr,
      kpage,
      spt_entry->writable
  )) {
    user_free_page(kpage);
    lock_acquire(&cur->spt_lock);
    return false;
  }

  // Remove the SPT entry. The lock will be released outside of this function.
  lock_acquire(&cur->spt_lock);
  struct hash_elem *found_elem = hash_delete(&cur->spt, &spt_entry->elem);
  ASSERT(found_elem != NULL);

  struct spt_entry *found_entry = hash_entry(
    found_elem,
    struct spt_entry,
    elem
  );
  free(found_entry);

  return true;
}

/**
 * Checks given spt_entry, and delegates to page fault handler according to its
 * type.
 * @param entry The spt_entry to be handled.
 * @return `true` iff loading the page was successful.
 */
bool process_spt_entry(struct spt_entry *entry) {
  switch (entry->type) {
    case UNINITIALISED_EXECUTABLE:
      return load_uninitialised_executable(entry);
    case MMAP:
      return mmap_load_entry(entry);
    case SWAPPED:
      return load_swapped_page(entry);
    default:
      PANIC("Unrecognised spt_entry type!\n");
  }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to task 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  struct thread *cur = thread_current();

  // Kill if the kernel page-faulted or writing to read-only page
  if (!(cur->is_user) || !not_present) goto fail;

  ASSERT(cur->is_user);

  // Check if the page is in the SPT

  // Find the corresponding entry in the thread SPT.
  struct spt_entry entry_to_find;
  entry_to_find.uvaddr = pg_round_down(fault_addr);

  lock_acquire(&cur->spt_lock);
  struct hash_elem *found_elem = hash_find(&cur->spt, &entry_to_find.elem);

  if (found_elem == NULL) { // The address is not in the SPT
    lock_release(&cur->spt_lock);

    // Try to grow the stack
    if (!stack_grow(f, fault_addr)) goto fail;
    ASSERT(pagedir_get_page(cur->pagedir, pg_round_down(fault_addr)));
    unpin_page(pg_round_down(fault_addr));
    return; // The stack grew successfully - we're done handling the page fault
  }

  // The address is in the SPT - handle the SPT entry appropriately

  struct spt_entry *found_entry = hash_entry(
    found_elem,
    struct spt_entry,
    elem
  );

  // Exit if writing to a read-only page
  if (write && !found_entry->writable) {
    lock_release(&cur->spt_lock);
    goto fail;
  }

  if (!process_spt_entry(found_entry)) {
    lock_release(&cur->spt_lock);
    unpin_page(found_entry->uvaddr);
    goto fail;
  }

  lock_release(&cur->spt_lock);
  return;

 fail:
  if (thread_current()->is_user) {
    exit_user_process(ERROR_STATUS_CODE);
  } else {
    printf ("Page fault at %p: %s error %s page in %s context.\n",
            fault_addr,
            not_present ? "not present" : "rights violation",
            write ? "writing" : "reading",
            user ? "user" : "kernel");
    thread_exit();
  }
}
