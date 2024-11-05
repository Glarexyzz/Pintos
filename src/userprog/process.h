#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct process_status {
  tid_t tid;
  struct semaphore sema;
  int status;
  struct hash_elem elem;
}

void user_process_hashmap_init();
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
