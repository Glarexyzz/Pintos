#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "devices/timer.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/// Number of queues for mlfqs
#define NUM_QUEUES (PRI_MAX-PRI_MIN+1)

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/// Array of queues for mlfqs
static struct list queues[NUM_QUEUES];

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/// List of all processes that need their priority updated.
static struct list update_pri_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-mlfqs". */
bool thread_mlfqs;

/// Load average for mlfqs
fix_t load_avg;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);
static int mlfq_highest_ready_priority(void);
static void ready_list_insert(struct thread *t);
static void push_to_update_pri_list(struct thread *t);
static void update_recent_cpu(struct thread *t, void *aux UNUSED);
static void mlfqs_update_priority(struct thread *t, void *aux UNUSED);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  if (thread_mlfqs) {
    // Initialise MLFQ
    for (int i = 0; i < NUM_QUEUES; i++) {
      list_init(&queues[i]);
    }

    load_avg = 0;
    list_init (&update_pri_list);
  }

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Returns the number of threads currently in the ready list. 
   Disables interrupts to avoid any race-conditions on the ready list. */
size_t
threads_ready (void)
{
  size_t ready_thread_count = 0;

  enum intr_level old_level = intr_disable ();

  if (thread_mlfqs) {
    // Sum the size of all the queues
    for (int i = 0; i < NUM_QUEUES; i++) {
      ready_thread_count += list_size (&queues[i]);
    }
  } else {
    ready_thread_count = list_size (&ready_list);
  }

  intr_set_level (old_level);
  return ready_thread_count;
}

/**
 * Add a thread to update_pri_list if it's not already in the list.
 * @param t The thread to add.
 */
static void push_to_update_pri_list(struct thread *t) {
  // only push if it's not already in the list
  if (t->update_pri_elem.next == NULL && t->update_pri_elem.prev == NULL) {
    list_push_front(&update_pri_list, &t->update_pri_elem);
  }
}

/**
 * thread_action_func for updating the recent_cpu of a thread.
 * @param t The thread that is being updated.
 * @param aux (Unused)
 */
static void update_recent_cpu(struct thread *t, void *aux UNUSED) {
  // recent_cpu = ((2 * load_avg) / (2 * load_avg  + 1)) * recent_cpu + nice
  t->recent_cpu = FI_ADD(
    FF_DIV(
      FF_MUL(FI_MUL(load_avg, 2), t->recent_cpu),
      FI_ADD(FI_MUL(load_avg, 2), 1)
    ),
    t->niceness
  );
  push_to_update_pri_list(t);
}

/**
 * thread_action_func for updating the BSD-style priority of a thread.
 * @param t The thread that is being updated.
 * @param aux (Unused)
 */
static void mlfqs_update_priority(struct thread *t, void *aux UNUSED) {
  // priority = PRI_MAX - (recent_cpu / 4) - (nice * 2)
  int priority = FIX_TO_INT_TO_0(
    FI_SUB(
      FF_SUB(INT_TO_FIX(PRI_MAX), FI_DIV(t->recent_cpu, 4)),
      t->niceness * 2
    )
  );
  if (priority < PRI_MIN) priority = PRI_MIN;
  if (priority > PRI_MAX) priority = PRI_MAX;

  // move the thread to the correct queue if its priority changes
  if (t->status == THREAD_READY && priority != t->priority) {
    t->priority = priority;

    enum intr_level old_level = intr_disable();
    ready_list_reinsert(t);
    intr_set_level(old_level);
  } else {
    t->priority = priority;
  }
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{

  struct thread *t = thread_current ();
  bool cur_thread_is_idle = t == idle_thread;

  if (thread_mlfqs) {
    // Increment recent_cpu if not idle_thread
    if (!cur_thread_is_idle) {
      t->recent_cpu += FIX_1;
      push_to_update_pri_list(t);
    }

    if (timer_ticks() % TIMER_FREQ == 0) {
      // Update load_avg and recent_cpu for all threads
      size_t ready_threads = threads_ready();
      if (!cur_thread_is_idle) ready_threads++;

      // load_avg = (59/60) * load_avg + (1/60) * ready_threads
      load_avg = FF_ADD(
        FI_DIV(FI_MUL(load_avg, 59), 60),
        FI_DIV(INT_TO_FIX(ready_threads), 60)
      );

      thread_foreach(&update_recent_cpu, NULL);
    }

    if (timer_ticks() % TIME_SLICE == 0) {
      // Update priority for all threads which need it
      struct list_elem *cur_elem = list_begin(&update_pri_list);
      while (cur_elem != list_end(&update_pri_list)) {
        struct thread *cur_thread = list_entry(
          cur_elem,
          struct thread,
          update_pri_elem
        );
        mlfqs_update_priority(cur_thread, NULL);

        struct list_elem *next_elem = cur_elem->next;

        enum intr_level old_level = intr_disable();
        list_remove(cur_elem);
        intr_set_level(old_level);
        cur_elem->next = NULL;
        cur_elem->prev = NULL;

        cur_elem = next_elem;
      }

      if (t->priority < mlfq_highest_ready_priority()) {
        intr_yield_on_return();
      }
    }
  }

  /* Update statistics. */
  if (cur_thread_is_idle)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);
  if (thread_current()->priority < priority && intr_get_level() == INTR_ON)
    thread_yield();

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/**
 * Determines whether one thread has a lower priority than another.
 * @param a The first thread.
 * @param b The second thread.
 * @param aux (Unused).
 * @return `true` iff thread `a` has lower or equal priority than thread `b`
 * @remark the reason for using lower or equal to instead of just lower is to
 * prevent a recently inserted thread from passing another thread of equal
 * priority when inserted into a list.
 */
bool thread_lower_priority(
    const struct list_elem *a,
    const struct list_elem *b,
    void *aux UNUSED
) {
  uint64_t a_priority = list_entry(a, struct thread, elem)->priority;
  uint64_t b_priority = list_entry(b, struct thread, elem)->priority;
  return a_priority <= b_priority;
}

/**
 * Removes a thread from the ready_list and reinserts it.
 * @param t
 * @pre Interrupts are disabled.
 * @pre t->status is THREAD_READY.
 */
void ready_list_reinsert(struct thread *t) {
  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (t->status == THREAD_READY);

  list_remove(&t->elem);
  ready_list_insert(t);
}

/**
 * Inserts a thread into the ready_list or the appropriate MLFQ depending on
 * the value of thread_mlfqs.
 * @param t The thread to be inserted.
 * @pre Interrupts are disabled.
 */
static void ready_list_insert(struct thread *t) {
  ASSERT (intr_get_level () == INTR_OFF);

  if (thread_mlfqs) {
    // Maintain RR behaviour
    list_push_front(&queues[t->priority - PRI_MIN], &t->elem);
  } else {
    list_insert_ordered(&ready_list, &t->elem, &thread_lower_priority, NULL);
  }
}

/**
 * @return The highest priority of all ready threads, or PRI_MIN - 1 if no
 * threads are ready.
 * @pre thread_mlfqs is true
 */
static int mlfq_highest_ready_priority() {
  ASSERT(thread_mlfqs);
  
  int highest_priority = PRI_MIN - 1;

  enum intr_level old_level = intr_disable();
  
  // Take highest priority non-empty queue
  for (int i = NUM_QUEUES - 1; i >= 0; i--) {
    if (!list_empty(&queues[i])) {
      highest_priority = i + PRI_MIN;
      break;
    }
  }

  intr_set_level(old_level);

  return highest_priority;
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);

  ready_list_insert(t);

  t->status = THREAD_READY;

  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  struct thread *current_thread = thread_current();
  current_thread->status = THREAD_DYING;

  if (thread_mlfqs) {
    // Remove thread from the update_pri_elem list if possible
    if (
      current_thread->update_pri_elem.prev != NULL &&
        current_thread->update_pri_elem.next != NULL
      ) {
      list_remove(&current_thread->update_pri_elem);
    }
  }

  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) {
    ready_list_insert(cur);
  }
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY.
   If NEW_PRIORITY is no longer the highest priority, yields. */
void
thread_set_priority (int new_priority) 
{
  ASSERT (!thread_mlfqs);
  enum intr_level old_level = intr_disable ();

  struct thread *current_thread = thread_current ();
  current_thread->priority = new_priority;

  current_thread->original_priority = new_priority;

  /* If donee's priority being modified during donation,
     it will only influence the original priority */
  if (!list_empty (&current_thread->locks_acquired)) {
    int highest_priority = list_entry(
      list_max(
        &current_thread->locks_acquired,
        &lock_lower_priority,
        NULL
      ),
      struct lock,
      elem
    )->max_priority;
    if (highest_priority > new_priority) {
      current_thread->priority = highest_priority;
    }
  }

  int ready_highest_priority = PRI_MIN;
  if (!list_empty(&ready_list)) {
    ready_highest_priority = list_entry(
      list_back(&ready_list),
      struct thread,
      elem
    )->priority;
  }

  intr_set_level (old_level);

  if (
    intr_get_level() == INTR_ON &&
    current_thread->priority < ready_highest_priority
  )
    thread_yield();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice)
{
  ASSERT(thread_mlfqs);
  thread_current()->niceness = nice;
  mlfqs_update_priority(thread_current(), NULL);

  if (
    intr_get_level() == INTR_ON &&
    thread_current()->priority < mlfq_highest_ready_priority()
  ) {
    thread_yield();
  }
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void)
{
  ASSERT(thread_mlfqs);
  return thread_current()->niceness;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  ASSERT(thread_mlfqs);
  return FIX_TO_INT_ROUND(FI_MUL(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return FIX_TO_INT_ROUND(
    FI_MUL(thread_current()->recent_cpu, 100)
  );
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;

  if (thread_mlfqs) {
    // Initialise BSD-style scheduling

    if (is_thread(running_thread())) {
      struct thread *cur = thread_current();

      t->niceness = cur->niceness;
      t->recent_cpu = cur->recent_cpu;
    } else {
      // The main thread is being initialised, so can't inherit from parent
      t->niceness = 0;
      t->recent_cpu = 0;
    }

    // Initialise priority
    mlfqs_update_priority(t, NULL);

  } else {
    t->priority = priority;
    t->original_priority = priority;
    list_init (&t->locks_acquired);
    t->lock_to_wait = NULL;
  }
#ifdef USERPROG
  list_init (&t->child_pids);
  t->is_user = false;
#endif

  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  // The list containing the highest priority thread
  struct list *ready_queue;

  if (thread_mlfqs) {
    ready_queue = &queues[0];
    for (int i = NUM_QUEUES-1; i >= 0; i--) {
      if (!list_empty(&queues[i])) {
        ready_queue = &queues[i];
        break;
      }
    }

  } else {
    ready_queue = &ready_list;
  }

  if (list_empty (ready_queue))
    return idle_thread;
  else
    return list_entry (list_pop_back (ready_queue), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
