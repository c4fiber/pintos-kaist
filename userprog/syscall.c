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

//project 2. user memory
void check_address (const uint64_t *addr){
	struct thread *cur = thread_current ();
		if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(cur -> pml4, addr) == NULL) {
			exit (-1);
		}
};

void exit(int status) {
	struct thread *cur = thread_current();
	// 프로그램이 정상적으로 종료되었는지 확인(정상적 종료 시 0)
    cur->exit_status = status;		
	// 종료 시 Process Termination Message 출력
	printf("%s: exit(%d)\n", cur -> name, status); 	
	// 스레드 종료
	thread_exit();		
}

int exec (char *file_name) {
	check_address(file_name);

	int file_size = strlen(file_name) + 1;
	//PAL_ZERO: palloc.h의 열거형 palloc_flags 의 값 중 하나. 002 means Zero page contents.
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL) {
		exit (-1); 
	}
	strcpy(fn_copy, file_name, file_size);
	if (process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();
	return 0;
}

bool create (char *file, unsigned initial_size) {
	check_address(file);
	//filesys/filesys.c의 filesys_create() 함수: name과 initial size로 file을 만드는 함수, 성공 여부를 true/false로 리턴함
	if (filesys_create(file, initial_size)) {
		return true;
	} else {
		return false;
	}
}

bool remove (char *file) {
	check_address(file);
	//filesys/filesys.c의 filesys_remove() 함수: file 의 name으로 file을 지우는 함수, 성공하면 true, 실패하면 false
	if(filesys_remove(file)) {
		return true;
	} else {
		return false;
	}
}

int add_file_to_fdt(struct file *file) {
	struct thread *cur = thread_current ();
	struct file **fdt = cur -> fd_table;

	//fd의 위치가 제한 범위를 넘지 않고, fd table의 인덱스 위치와 일치한다면
	while (cur -> fd_idx < FDCOUNT_LIMIT && fdt[cur -> fd_idx]) {
		cur -> fd_idx ++;
	}

	//fdt가 가득 찼다면
	if (cur -> fd_idx >= FDCOUNT_LIMIT) {
		return -1;
	}

	fdt[cur ->fd_idx] = file;
	return cur -> fd_idx;
}

int open (char *file) {
	check_address(file);
	struct file *open_file = filesys_open(file);

	if(open_file == NULL) {
		return -1;
	}

	int fd = add_file_to_fdt(open_file);

	//fd table이 가득 찼다면
	if(fd == -1) {
		file_close(open_file);
	}

	return fd;
}

static struct file *find_file_by_fd (int fd) {
	struct thread *cur = thread_current ();

	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
			return NULL;
		}
		return cur -> fd_table[fd]
}

int filesize(int fd) {
	struct file *open_file = find_file_by_fd(fd);
	if (open_file == NULL) {
		return -1;
	}
	return file_length(open_file);
	
}

void seek (int fd, unsigned position) {
	struct file *seek_file = find_file_by_fd(fd);
	//fd table 의 0, 1, 2는 이미 정의되어 있다.
	//0 = STDIN - keyboard file object
	//1 = STDOUT - monitor file object
	//2 = STDERR - monitor file object
	if (seek_file <= 2) {
		return;
	}

	seek_file->pos = position;
}
//project 2. user memory

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
		exit(argv[0]);
		break;
	case SYS_FORK:
		// TODO f->R.rax = fork(argv[0]);
		__pid_t child = process_fork(argv[0]);
		f->R.rax = child;
		break;
	case SYS_EXEC:
		// TODO 
		if (exec(argv[0]) == -1) {
			exit (-1);
		}
		break;
	case SYS_WAIT:
		//f->R.rax = wait(argv[0]);
		break;
	case SYS_CREATE:
		f->R.rax = create(argv[0], argv[1]);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(argv[0]);
		break;
	case SYS_OPEN:
		f->R.rax = open(argv[0]);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(argv[0]);
		break;
	case SYS_READ:
		//f->R.rax = read(argv[0], argv[1], argv[2]);
		break;
	case SYS_WRITE:
		// f->R.rax = write(argv[0], argv[1], argv[2]);
		putbuf(f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(argv[0], argv[1]);
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
	

	//project 2. user memory
}
