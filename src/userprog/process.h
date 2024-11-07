#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include "threads/thread.h"
#include <hash.h>

/// The maximum length of a file that can be opened.
#define MAX_FILENAME_LENGTH 14

struct process_status {
  tid_t tid;
  struct semaphore sema;
  int status;
  struct hash_elem elem;
};

struct process_tid {
  tid_t tid;
  struct list_elem elem;
};

struct hash user_processes;
struct lock user_processes_lock;

void user_process_hashmap_init(void);
void register_user_process(tid_t tid);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
