#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include "threads/thread.h"
#include <hash.h>

/// The exit code for a process which errors
#define ERROR_STATUS_CODE -1

/// Type of a process identifier.
typedef tid_t pid_t;

/// Used as an entry in the `user_processes` hashmap.
struct process_status {
  pid_t pid;             // The pid of the process
  struct semaphore sema; // The semaphore which parents use to wait for the
                         // process
  int status;            // The exit status of the process
  struct hash_elem elem; // Used to insert the element into `user_processes`
};

/// Used in lists on threads to store child processes of that thread
struct process_pid {
  pid_t pid;             // The pid of the child process
  struct list_elem elem; // Used to insert the element into the parent's
                         // `child_pids` list
};

/// Represents a file descriptor
struct fd_entry {
  int fd;                // The file descriptor number
  struct file *file;     // The file which it describes
  struct hash_elem elem; // Used to insert the element into the FD hash table
};

struct hash user_processes;
struct lock user_processes_lock;

struct lock file_system_lock;

void user_process_hashmap_init(void);
pid_t process_execute (const char *file_name);
void file_system_lock_init(void);
int process_wait (pid_t);
void close_file(struct hash_elem *element, void *aux UNUSED);
void exit_user_process(int status) NO_RETURN;
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
