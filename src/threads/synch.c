/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void lock_add_donation (struct lock *lock, struct thread *donor);
static void lock_revoke_donation (struct lock *lock, struct thread *donor);

/**
 * Removes the (first) element with maximal priority in a list of threads.
 * This list needs not be sorted, and as such the operation takes O(n) time
 * in the number of threads.
 * Panics if the list is empty.
 * @param thread_list the list to pop from
 * @return the thread with the maximum priority.
 */
static struct thread *
list_pop_max_priority (struct list *thread_list)
{
  ASSERT (!list_empty (thread_list));
  struct list_elem *max_priority_elem;
  max_priority_elem = list_max (
    thread_list,
    thread_lower_priority,
    NULL
  );
  ASSERT (max_priority_elem != list_end (thread_list));
  list_remove (max_priority_elem);
  return list_entry (max_priority_elem, struct thread, elem);
}

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void
sema_down (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  while (sema->value == 0) 
    {
      list_push_back (&sema->waiters, &thread_current ()->elem);
      /* Check if this thread would be waiting for a lock.
         If so, handle donation to the owner. */
      struct lock *lock = thread_current ()->lock_to_wait;
      if (lock != NULL)
        lock_add_donation (lock, thread_current ());
      thread_block ();
    }
  sema->value--;
  intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) 
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0) 
    {
      sema->value--;
      success = true; 
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (!list_empty (&sema->waiters)) {
    struct thread *max_thread = list_pop_max_priority (&sema->waiters);
    /* Check if this thread would be now acquiring a lock.
       If so, revoke donation to the owner from this thread. */
    struct lock *lock = max_thread->lock_to_wait;
    if (lock != NULL)
      {
        lock_revoke_donation (lock, max_thread);
        max_thread->lock_to_wait = NULL;
      }
    thread_unblock (max_thread);
  }
  sema->value++;
  /* Yield the current thread to the CPU, so that priorities can be updated. */
  thread_yield();
  intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) 
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) 
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) 
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
}

/**
 * Determines whether one lock has a max_priority
 * lower than another lock.
 * @param a The first lock.
 * @param b The second lock.
 * @param aux (Unused).
 * @return `true` iff lock `a` has lower max_priority than lock `b`
 */
static bool
lock_lower_priority (
  const struct list_elem *a,
  const struct list_elem *b,
  void *aux UNUSED
) {
  int a_priority = list_entry(a, struct lock, elem)->max_priority;
  int b_priority = list_entry(b, struct lock, elem)->max_priority;
  return a_priority < b_priority;
}

static struct list *
lock_donors (struct lock *lock)
{
  return &lock->semaphore.waiters;
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));
  enum intr_level old_level;

  /* If a thread tries to acquire a lock that already
     has an owner, this thread will then be blocked. */
  struct thread *current_thread;

  /* Set the current thread's lock that it is waiting for early, so that
     priority donation can be performed immediately when the semaphore is
     downed. */
  current_thread = thread_current ();
  current_thread->lock_to_wait = lock;

  sema_down (&lock->semaphore);
  ASSERT (lock->semaphore.value == 0);

  old_level = intr_disable ();
  /* At this stage, the current thread has not been blocked, so it will become
     the owner of the lock. */
  lock->holder = current_thread;
  current_thread->lock_to_wait = NULL;
  /* Since there are initially no threads waiting for the lock, no donation
     occurs. */
  lock->max_priority = PRI_MIN;
  list_push_back (&current_thread->locks_acquired, &lock->elem);

  intr_set_level (old_level);
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success)
    lock->holder = thread_current ();
  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) 
{
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));

  list_remove (&lock->elem);
  lock->holder = NULL;
  sema_up (&lock->semaphore);
}

static void
lock_update_lower_max_priority (struct lock *lock)
{
  int max_priority = PRI_MIN;
  struct list_elem *maximal_elem;
  if (!list_empty (lock_donors (lock))) {
    maximal_elem = list_max (lock_donors (lock), thread_lower_priority, NULL);
    ASSERT (maximal_elem != list_end (lock_donors (lock)));
    max_priority = list_entry (maximal_elem, struct thread, elem)->priority;
  }
  lock->max_priority = max_priority;
}

static void
thread_update_lower_donation (struct thread *donee)
{
  if (!list_empty (&donee->locks_acquired)) {
    struct list_elem *maximal_lock_elem = list_max (
      &donee->locks_acquired,
      lock_lower_priority,
      NULL
    );
    int maximum_priority = list_entry (
      maximal_lock_elem,
      struct lock,
      elem
    )->max_priority;
    /* Reset the thread's priority to this maximum,
       if it is greater than the default. */
    donee->priority = donee->original_priority;
    if (maximum_priority > donee->priority) {
      donee->priority = maximum_priority;
    }
    if (donee->status == THREAD_READY) {
      ready_list_reinsert(donee);
    }
  } else {
    /* There are no locks, so set the thread's priority to the default. */
    donee->priority = donee->original_priority;
  }
}

/**
 * Revokes the donation from thread DONOR to the current thread, updating the
 * maximum priority from donation in all lock owners it donates to.
 * When this function is called, DONOR is the thread that was previously in
 * the list of waiters held by the LOCK and had the highest effective priority.
 * The top-level call has the lock just released by the current thread,
 * and if the DONOR has a higher priority than it, the DONOR will preempt the
 * running thread.
 * Recursive calls will update the donation from any locks the donee is waiting
 * for.
 * @param lock the lock from which DONOR was previously waiting.
 * @param donor the thread that has been unblocked by the LOCK's semaphore.
 */
static void
lock_revoke_donation (struct lock *lock, struct thread *donor)
{
  if (lock == NULL)
    return;
  /* Update the maximum priority of the waiter list. */
  lock_update_lower_max_priority (lock);
  ASSERT (lock->max_priority <= donor->priority);
  /* Update the priority of the lock's owner; if the owner is NULL, then this
     means the lock was just now released by the current thread. */
  struct thread *donee = lock->holder;
  if (donee == NULL)
    donee = thread_current();
  /* Revoke the donation on the donee's side by finding the new maximum
     priority across all locks owned by the donee's thread. */
  thread_update_lower_donation (donee);
  /* Recurse up the tree of locks to revoke their donation upwards. */
  lock_revoke_donation (donee->lock_to_wait, donee);
}

/**
 * Adds donation from thread DONOR to the current thread, updating the
 * maximum priority from donation in all lock owners it donates to.
 * When this function is called, DONOR is about to be added in the list of
 * waiters held by the LOCK.
 * The top-level call has the lock about to block the current thread.
 * Recursive calls will update the donation from any locks the donee is waiting
 * for.
 * @param lock the lock from which DONOR will be waiting.
 * @param donor the thread that will be blocked by the LOCK's semaphore.
 */
static void
lock_add_donation (struct lock *lock, struct thread *donor)
{
  if (lock == NULL)
    return;
  /* Increase the maximum priority of the waiter list. */
  if (lock->max_priority < donor->priority)
    lock->max_priority = donor->priority;
  ASSERT (lock->max_priority <= donor->priority);
  /* Increase the priority of the lock's owner; if the owner is NULL, then this
     means the lock was just now released by the current thread. */
  struct thread *donee = lock->holder;
  if (donee == NULL)
    return;
  /* Increase the donation on the donee's side by setting the new maximum
     priority across all locks owned by the donee's thread. */
  if (donee->priority < donor->priority) {
    donee->priority = donor->priority;
    if (donee->status == THREAD_READY) {
      ready_list_reinsert(donee);
    }
  }
  /* Recurse up the tree of locks to add their donation upwards. */
  lock_add_donation (donee->lock_to_wait, donee);
}

void thread_update_priority
(int priority)
{
  enum intr_level old_level = intr_disable ();
  struct thread *current_thread = thread_current ();
  int prev_priority = current_thread->priority;
  struct lock *lock_to_wait = current_thread->lock_to_wait;
  /* Update any existing lock's donation values. */
  current_thread->priority = priority;
  if (prev_priority < priority) {
    lock_add_donation (lock_to_wait, current_thread);
  }
  else if (prev_priority > priority) {
    lock_revoke_donation (lock_to_wait, current_thread);
  }
  intr_set_level (old_level);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) 
{
  ASSERT (lock != NULL);

  return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem 
  {
    struct list_elem elem;              /* List element. */
    struct semaphore semaphore;         /* This semaphore. */
  };

/**
 * Determines whether one semaphore has a thread that has 
 * lower priority than another semaphore's thread.
 * @param a The first semaphore.
 * @param b The second semaphore.
 * @param aux (Unused).
 * @return `true` iff thread `a` has lower priority than thread `b`
 */
static bool sema_lower_priority(
    const struct list_elem *a,
    const struct list_elem *b,
    void *aux UNUSED
) {
  struct semaphore_elem *a_sema = list_entry(a, struct semaphore_elem, elem);
  struct semaphore_elem *b_sema = list_entry(b, struct semaphore_elem, elem);
  struct list_elem *a_thread = list_front(&a_sema->semaphore.waiters);
  struct list_elem *b_thread = list_front(&b_sema->semaphore.waiters);
  uint64_t a_priority = list_entry(a_thread, struct thread, elem)->priority;
  uint64_t b_priority = list_entry(b_thread, struct thread, elem)->priority;
  return a_priority < b_priority;
}


/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) 
{
  struct semaphore_elem waiter;

  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));
  
  sema_init (&waiter.semaphore, 0);
  list_push_back (&cond->waiters, &waiter.elem);
  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  if (!list_empty (&cond->waiters)) 
  {
    list_sort (&cond->waiters, sema_lower_priority, NULL);
    sema_up (&list_entry (list_pop_back (&cond->waiters),
                          struct semaphore_elem, elem)->semaphore);
  }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);

  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}
