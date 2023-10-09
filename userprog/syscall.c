#include "userprog/syscall.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include <stdio.h>
#include <syscall-nr.h>

typedef int pid_t;

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* Projects 2 and later. */
void check_address(void *addr);
void halt(void) NO_RETURN;
void exit(int status) NO_RETURN;
pid_t fork(const char *thread_name, struct intr_frame *);
int exec(const char *file);
int wait(pid_t);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

int dup2(int oldfd, int newfd);

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

void syscall_init(void) {
    write_msr(MSR_STAR,
              ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
    // TODO: Your implementation goes here.
    /**
     * get argument from f
     * system call number: %rax
     * argumnets:
     *   argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]
     *   %rdi,    %rsi,    %rdx,    %r10,    %r8,     %r9
     *
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

    /* call system call */
    switch (syscall_num) {
    case SYS_HALT:
        power_off();
        break;
    case SYS_EXIT:
        exit(argv[0]);
        break;
    case SYS_FORK:
        f->R.rax = fork(argv[0], f);
        break;
    case SYS_EXEC:
        // TODO Please note that file descriptors remain open across an exec
        // call. If any of these descriptors is writable, it must be closed
        f->R.rax = exec(argv[0]);
        break;
    case SYS_WAIT:
        f->R.rax = wait(argv[0]);
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
        break;
    case SYS_SEEK:
        seek(argv[0], argv[1]); // no return value
        break;
    case SYS_TELL:
        f->R.rax = tell(argv[0]);
        break;
    case SYS_CLOSE:
        close(argv[0]); // no return value
        break;
    }

    // printf ("system call!\n");
    // thread_exit ();
}

//project 2. user memory
void check_address(void *addr)
{
	if (addr == NULL)
		exit(-1);
	if (!is_user_vaddr(addr))
		exit(-1);
	if (pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}
//project 2. user memory
/* Halt */
void halt(void) { power_off(); }

/* Exit */
void exit(int status) {
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}

/* Fork */
pid_t fork(const char *thread_name, struct intr_frame *f) {
    // child process의 반환값(rax)은 이때 반환하는 값이다.
    return process_fork(thread_name, f);
}

/* Exec */
int exec(const char *file) { return process_exec(file); }

/* Wait */
int wait(pid_t pid) { return process_wait(pid); }

/* Create */
bool create(const char *file, unsigned initial_size) {
	check_address(file);
    return filesys_create(file, initial_size);
}

/* Remove */
bool remove(const char *file) { return filesys_remove(file); }

/* Open */
int open(const char *file_name) {
	check_address(file_name);
    struct file *file = filesys_open(file_name);
    if (file == NULL) {
        return -1;
    }

    thread_current()->fd_table[thread_current()->fd_count] = file;
    return thread_current()->fd_count++;
}

/* Filesize */
int filesize(int fd) {
    struct file *file = thread_current()->fd_table[fd - 4]; // except 0,1,2
    if (file == NULL) {
        return -1;
    }
    return file_length(file);
}

/* Read */
int read(int fd, void *buffer, unsigned length) {
    // invalid fd
    if (fd == 1 || fd == 2 || fd < 0 || fd >= FDTABLE_SIZE) {
        return -1;
    }

    // current thread does not have fd
    if (fd >= thread_current()->fd_count) {
        return -1;
    }

    void *file = thread_current()->fd_table[fd];
    if (fd == 0) {
        int i;
        for (i = 0; i < length; i++) {
            ((char *)buffer)[i] = input_getc();
        }
        return length;
    } else {
        return file_read(file, buffer, length);
    }
    return -1;
}

/* Write */
int write(int fd, const void *buffer, unsigned length) {
    // invalid fd
    if (fd == 0 || fd < 0 || fd >= FDTABLE_SIZE) {
        return -1;
    }

    // current thread does not have fd
    if (fd >= thread_current()->fd_count) {
        return -1;
    }

    void *file = thread_current()->fd_table[fd];
    if (fd == 1) {
        putbuf(buffer, length);
        return length;
    } else {
        return file_write(file, buffer, length);
    }
    return -1;
}

/* Seek */
void seek(int fd, unsigned position) {
    struct file *file = thread_current()->fd_table[fd];
    if (file == NULL) {
        return;
    }
    file_seek(file, position);
}

/* tell */
unsigned tell(int fd) {
    struct file *file = thread_current()->fd_table[fd];
    if (file == NULL) {
        return -1;
    }
    return file_tell(file);
}


/* close */
void close(int fd) {
    if (fd >= thread_current() -> fd_count ) {
        return;
    }
    struct file *file = thread_current()->fd_table[fd];
    if (file == NULL) {
        return;
    }
    //file_close(file);
    thread_current()->fd_table[fd] = NULL;
}

/* dup2 */
int dup2(int oldfd, int newfd) {
    if (oldfd == newfd) {
        return newfd;
    }
    if (oldfd < 0 || oldfd >= FDTABLE_SIZE) {
        return -1;
    }
    if (newfd < 0 || newfd >= FDTABLE_SIZE) {
        return -1;
    }
    if (thread_current()->fd_table[oldfd] == NULL) {
        return -1;
    }
    if (thread_current()->fd_table[newfd] != NULL) {
        close(newfd);
    }
    thread_current()->fd_table[newfd] = thread_current()->fd_table[oldfd];
    return newfd;
}
