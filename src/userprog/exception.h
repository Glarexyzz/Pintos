#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

#include "vm/page.h"

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

void exception_init (void);
void exception_print_stats (void);
bool process_spt_entry(struct spt_entry *entry);

/// The maximum size of the stack in bytes.
#define STACK_MAX 0x00400000 // 2^22 = 4MB

#endif /* userprog/exception.h */
