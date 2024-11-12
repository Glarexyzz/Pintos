#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include "threads/thread.h"
#include <hash.h>

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

struct fd_entry {
  int fd;
  struct file *file;
  struct hash_elem elem;
};

struct hash user_processes;
struct lock user_processes_lock;

struct lock file_system_lock;

void user_process_hashmap_init(void);
void register_user_process(tid_t tid);
tid_t process_execute (const char *file_name);
void file_system_lock_init(void);
int process_wait (tid_t);
void close_file(struct hash_elem *element, void *aux UNUSED);
void exit_user_process(int status) NO_RETURN;
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
