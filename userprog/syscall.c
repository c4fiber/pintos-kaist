#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	/*
	 * get argument from f
	 * %rax: system call number
	 * argumnets: %rdi, %rsi, %rdx, %r10, %r8, %r9
	 * return value: %rax
	 */

	// get system call number
	uint64_t syscall_num = f->R.rax;
	char *argv[6];
	memset(argv, 0, sizeof(argv));
	int argc = 0;

	// get arguments
	argv[0] = f->R.rdi;
	argv[1] = f->R.rsi;
	argv[2] = f->R.rdx;
	argv[3] = f->R.r10;
	argv[4] = f->R.r8;
	argv[5] = f->R.r9;

	// get argc
	while (argv[argc] != NULL) {
		argc++;
	}

	// call system call
	switch (syscall_num) {
	case SYS_HALT:
		power_off();
		break;
	case SYS_EXIT:
		// print exit message thread_name: exit(status_code)
		// TODO 수정 필요함
		printf("%s: exit(%d)\n", thread_current()->name, argv[0]);
		thread_exit();
		f->R.rax = argv[0];
		break;
	case SYS_FORK:
		// TODO f->R.rax = fork(argv[0]);
		break;
	case SYS_EXEC:
		// TODO 
		// thread_create(argv[0], PRI_DEFAULT, argv[0], 0);
		break;
	case SYS_WAIT:
		//f->R.rax = wait(argv[0]);
		break;
	case SYS_CREATE:
		//f->R.rax = create(argv[0], argv[1]);
		break;
	case SYS_REMOVE:
		//f->R.rax = remove(argv[0]);
		break;
	case SYS_OPEN:
		//f->R.rax = open(argv[0]);
		break;
	case SYS_FILESIZE:
		//f->R.rax = filesize(argv[0]);
		break;
	case SYS_READ:
		//f->R.rax = read(argv[0], argv[1], argv[2]);
		break;
	case SYS_WRITE:
		// f->R.rax = write(argv[0], argv[1], argv[2]);
		putbuf(f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		//seek(argv[0], argv[1]);
		break;
	case SYS_TELL:
		//f->R.rax = tell(argv[0]);
		break;
	case SYS_CLOSE:
		//close(argv[0]);
		break;
	}
	// printf ("system call!\n");
	// thread_exit ();
}
