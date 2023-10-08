#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"

//project 2. system call
void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork(const char *thread_name, struct intr_frame *f);
int exec(const char *cmd_line);
int wait(int pid);
//project 2. system call

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

//project 2. system call

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
	lock_init(&filesys_lock);
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
		halt();
		break;
	case SYS_EXIT:
		exit(argv[0]);
		break;
	case SYS_FORK:
		// f->R.rax = fork(argv[0], f);
		break;
	case SYS_EXEC:
		f->R.rax = exec(argv[0]);
		break;
	case SYS_WAIT:
		// f->R.rax = wait(argv[0]);
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
		f->R.rax = read(argv[0], argv[1], argv[2]);
		break;
	case SYS_WRITE:
		f->R.rax = write(argv[0], argv[1], argv[2]);
		// putbuf(f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(argv[0], argv[1]);
		break;
	case SYS_TELL:
		f->R.rax = tell(argv[0]);
		break;
	case SYS_CLOSE:
		close(argv[0]);
		break;

	}

	// printf ("system call!\n");
	// thread_exit ();
	
}

//helper functions
//project 2. user memory
void check_address (void *addr){
	struct thread *cur = thread_current ();
		if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(cur -> pml4, addr) == NULL) {
			exit (-1);
		}
}
//project 2. user memory

//system call functions
void halt (void) {
	power_off ();
}

void exit(int status) {
	struct thread *cur = thread_current();
	// 프로그램이 정상적으로 종료되었는지 확인(정상적 종료 시 0)
    cur->exit_status = status;		
	// 종료 시 Process Termination Message 출력
	printf("%s: exit(%d)\n", cur -> name, status); 	
	// 스레드 종료
	thread_exit();		
}

int exec (const char *file_name) {
	check_address(file_name);
	// process.c 파일의 process_create_initd 함수와 유사하다.
	// 단, 스레드를 새로 생성하는 건 fork에서 수행하므로
	// 이 함수에서는 새 스레드를 생성하지 않고 process_exec을 호출한다.
	
	// process_exec 함수 안에서 filename을 변경해야 하므로
	// 커널 메모리 공간에 cmd_line의 복사본을 만든다.
	// (현재는 const char* 형식이기 때문에 수정할 수 없다.)
	int file_size = strlen(file_name) + 1;
	//PAL_ZERO: palloc.h의 열거형 palloc_flags 의 값 중 하나. 002 means Zero page contents.
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL) {
		//할당 실패시 -1 exit
		exit (-1); 
	}
	strlcpy(fn_copy, file_name, file_size);
	if (process_exec(fn_copy) == -1) {
		exit(-1);
	}
}

bool create (const char *file, unsigned initial_size) {
	lock_acquire(&filesys_lock);
	check_address(file);
	//filesys/filesys.c의 filesys_create() 함수: name과 initial size로 file을 만드는 함수, 성공 여부를 true/false로 리턴함
	bool success = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return success;
}

bool remove (const char *file) {
	check_address(file);
	//filesys/filesys.c의 filesys_remove() 함수: file 의 name으로 file을 지우는 함수, 성공하면 true, 실패하면 false
	return filesys_remove(file);
}

int open (const char *file_name) {
	check_address(file_name);
	lock_acquire(&filesys_lock);
	struct file *open_file = filesys_open(file_name);

	if(open_file == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	//fd table에 file 추가하기
	int fd = process_add_file(open_file);

	//fd table이 가득 찼다면
	if(fd == -1) {
		file_close(open_file);
	}
	lock_release(&filesys_lock);
	return fd;
}

int filesize(int fd) {
	struct file *open_file = process_get_file(fd);
	if (open_file == NULL) {
		return -1;
	}
	return file_length(open_file);
	
}

void seek(int fd, unsigned position) {
	struct file *seek_file = process_get_file(fd);
	//fd table 의 0, 1은 이미 정의되어 있다.
	//0 = STDIN - keyboard file object
	//1 = STDOUT - monitor file object

	if (seek_file == NULL) {
		return -1;
	}
	file_seek(seek_file, position);
}

tid_t fork (const char *thread_name, struct intr_frame *f) {
	return process_fork (thread_name, f);
}

int read (int fd, void *buffer, unsigned size) {
	check_address (buffer);
	int bytes_read = 0;
	char *ptr = (char *) buffer;
	lock_acquire(&filesys_lock);

	//fd == STDIN
	if (fd == 0) {

		for (int i = 0; i < size; i++)
		{
			*ptr++ = input_getc();
			bytes_read++;
		}
		lock_release(&filesys_lock);

	} else {

		if (fd < 2) {
			lock_release(&filesys_lock);
			return -1;
		}

		struct file *read_file = process_get_file(fd);

		if (read_file == NULL) {
			lock_release(&filesys_lock);
			return -1;
		}
		struct page *page = spt_find_page(&thread_current()->spt, buffer);
		if (page && !page->writable)
		{
			lock_release(&filesys_lock);
			exit(-1);
		}
		bytes_read = file_read(read_file, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_read;
}

unsigned tell (int fd) {
	struct file *tell_file = process_get_file(fd);
	
	if (tell_file == NULL) {
		return;
	}

	return file_tell(tell_file);
}

void close (int fd) {
	struct file *close_file = process_get_file(fd);
	
	if (close_file == NULL) {
		return;
	}
	file_close (close_file);
	process_close_file(fd);
}

int write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	int bytes_write = 0;
	//STDOUT
	if (fd == 1)
	{
		putbuf(buffer, size);
		bytes_write = size;
	}
	else
	{
		if (fd < 2)
			return -1;
		struct file *file = process_get_file(fd);
		if (file == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		bytes_write = file_write(file, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_write;

}

//project 2. system call