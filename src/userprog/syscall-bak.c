#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"
#include "pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"


struct child_element* get_child(tid_t tid,struct list *mylist);
void check_valid_ptr (const void *pointer);
static void syscall_handler (struct intr_frame *);
struct fd_element* get_fd(int fd);
int write (int fd, const void *buffer_, unsigned size);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
tid_t exec (const char *cmdline);
void exit (int status);

void check_valid_ptr (const void *pointer)
{
    if (!is_user_vaddr(pointer))
    {
        exit(-1);
    }

    void *check = pagedir_get_page(thread_current()->pagedir, pointer);
    if (check == NULL)
    {
        exit(-1);
    }
}

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f )
{
    int syscall_type = 0;
    check_valid_ptr((const void*) f -> esp);
    void *args = f -> esp;
    syscall_type = *( (int *) f -> esp);
    args += 4;
    check_valid_ptr((const void*) args);

    if (syscall_type == SYS_HALT) {                  	
        /* Halt the operating system. */
        halt();
    }
    
    else if (syscall_type == SYS_EXIT) {                   
        /* Terminate this process. */
        int argv = *((int*) args);
        args += 4;
        exit(argv);
    }
    else if (syscall_type == SYS_EXEC){                   
        /* Start another process. */
        int argv = *((int*) args);
        args += 4;
        check_valid_ptr((const void*) argv);
        f -> eax = exec((const char *)argv);
    }
    else if (syscall_type == SYS_WAIT){                   
        /* Wait for a child process to die. */
        int argv = *((int*) args);
        args += 4;
        f -> eax = wait(argv);
    }
    else if (syscall_type == SYS_CREATE){                 
        /* Create a file. */
        int argv = *((int*) args);
        args += 4;
        int argv_1 = *((int*) args);
        args += 4;     
        check_valid_ptr((const void*) argv);
        f -> eax = create((const char *) argv, (unsigned) argv_1);
    }
    else if (syscall_type == SYS_REMOVE){                 
        /* Delete a file. */
        int argv = *((int*) args);
        args += 4;
        check_valid_ptr((const void*) argv);
        f -> eax = remove((const char *) argv);
    }
    else if (syscall_type == SYS_OPEN){                   
        /* Open a file. */
        int argv = *((int*) args);
        args += 4;
        check_valid_ptr((const void*) argv);
        f -> eax = open((const char *) argv);
    }
    else if (syscall_type == SYS_FILESIZE){               
        /* Obtain a file's size. */
        int argv = *((int*) args);
        args += 4;
        f -> eax = filesize(argv);
    }
    else if (syscall_type == SYS_READ){                   
        /* Read from a file. */
        int argv = *((int*) args);
        args += 4;
        int argv_1 = *((int*) args);
        args += 4;
        int argv_2 = *((int*) args);
        args += 4;
        f->eax = read (argv,(void *) argv_1, (unsigned) argv_2);
    }
    else if (syscall_type == SYS_WRITE){                  
        /* Write to a file. */
        int argv = *((int*) args);
        args += 4;
        int argv_1 = *((int*) args);
        args += 4;
        int argv_2 = *((int*) args);
        args += 4;
        f->eax = write (argv,(void *) argv_1,(unsigned) argv_2);    
    }
    else if (syscall_type == SYS_SEEK){
        /* Change position in a file. */
        int argv = *((int*) args);
        args += 4;
        int argv_1 = *((int*) args);
        args += 4;                   
        seek(argv, (unsigned)argv_1);
    }
    else if (syscall_type == SYS_TELL){                   
        /* Report current position in a file. */
        int argv = *((int*) args);
        args += 4;
        f -> eax = tell(argv);
    }
    else if (syscall_type == SYS_CLOSE){                  
        /* Close a file. */
        int argv = *((int*) args);
        args += 4;
        close(argv);
    }
    else {
        exit(-1);
    }
}

void halt (void)
{
    shutdown_power_off();
}


void exit (int status)
{
    struct thread *cur = thread_current();
    printf ("%s: exit(%d)\n", cur -> name, status);

    // Get the child element corresponding to the current thread
    struct child_element *child = get_child(cur->tid, &cur -> parent -> child_list);
    // Set the exit status of the child
    child -> exit_status = status;
    // Mark the current status of the child
    if (status == -1)
    {
        child -> cur_status = WAS_KILLED;
    }
    else
    {
        child -> cur_status = HAD_EXITED;
    }
    // Exit the current thread
    thread_exit();
}

tid_t
exec (const char *cmd_line)
{
    // Get the current running thread
    struct thread *parent = thread_current();
    tid_t pid = -1;

    // Create child process to execute the command line
    pid = process_execute(cmd_line);

    // Get the created child process
    struct child_element *child = get_child(pid, &parent->child_list);
    // Wait for this child process to finish loading
    sema_down(&child->real_child->sema_exec);
    // After waking up, check if the child process was loaded successfully
    if (!child->loaded_success) {
        // Failed to load
        return -1;
    }

    // Return the process ID of the child process
    return pid;
}

int wait (tid_t pid)
{
    return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{
    lock_acquire(&file_lock);
    bool ret = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return ret;
}

bool remove (const char *file)
{
    lock_acquire(&file_lock);
    bool ret = filesys_remove(file);
    lock_release(&file_lock);
    return ret;
}

int open (const char *file)
{
    int ret = -1;
    lock_acquire(&file_lock);
    struct thread *cur = thread_current ();
    struct file * opened_file = filesys_open(file);
    lock_release(&file_lock);
    if(opened_file != NULL)
    {
        cur->fd_size = cur->fd_size + 1;
        ret = cur->fd_size;
        /* Create and init new fd_element */
        struct fd_element *file_d = (struct fd_element*) malloc(sizeof(struct fd_element));
        file_d->fd = ret;
        file_d->myfile = opened_file;
        /* Add this fd_element to this thread fd_list */
        list_push_back(&cur->fd_list, &file_d->element);
    }
    return ret;
}

int filesize (int fd)
{
    struct file *myfile = get_fd(fd)->myfile;
    lock_acquire(&file_lock);
    int ret = file_length(myfile);
    lock_release(&file_lock);
    return ret;
}

int read (int fd, void *buffer, unsigned size)
{
    int ret = -1;
    if(fd == 0)
    {
        // Read from keyboard
        ret = input_getc();
    }
    else if(fd > 0)
    {
        // Read from file
        // Get the fd_element
        struct fd_element *fd_elem = get_fd(fd);
        if(fd_elem == NULL || buffer == NULL)
        {
            return -1;
        }
        // Get the file
        struct file *myfile = fd_elem->myfile;
        lock_acquire(&file_lock);
        ret = file_read(myfile, buffer, size);
        lock_release(&file_lock);
        if(ret < (int)size && ret != 0)
        {
            // Error occured
            ret = -1;
        }
    }
    return ret;
}

int write (int fd, const void *buffer_, unsigned size)
{
    uint8_t * buffer = (uint8_t *) buffer_;
    int ret = -1;
    if (fd == 1)
    {
        // Write in the console
        putbuf( (char *)buffer, size);
        return (int)size;
    }
    else
    {
        // Write in file
        // Get the fd_element
        struct fd_element *fd_elem = get_fd(fd);
        if(fd_elem == NULL || buffer_ == NULL )
        {
            return -1;
        }
        // Get the file
        struct file *myfile = fd_elem->myfile;
        lock_acquire(&file_lock);
        ret = file_write(myfile, buffer_, size);
        lock_release(&file_lock);
    }
    return ret;
}


void seek (int fd, unsigned position)
{
    struct fd_element *fd_elem = get_fd(fd);
    if(fd_elem == NULL)
    {
        return;
    }
    struct file *myfile = fd_elem->myfile;
    lock_acquire(&file_lock);
    file_seek(myfile,position);
    lock_release(&file_lock);
}

unsigned tell (int fd)
{
    struct fd_element *fd_elem = get_fd(fd);
    if(fd_elem == NULL)
    {
        return -1;
    }
    struct file *myfile = fd_elem->myfile;
    lock_acquire(&file_lock);
    unsigned ret = file_tell(myfile);
    lock_release(&file_lock);
    return ret;
}

void close (int fd)
{
    struct fd_element *fd_elem = get_fd(fd);
    if(fd_elem == NULL)
    {
        return;
    }
    struct file *myfile = fd_elem->myfile;
    lock_acquire(&file_lock);
    file_close(myfile);
    lock_release(&file_lock);
}

/**
 Close and free all files of the current thread
*/
void close_all(struct list *fd_list)
{
    struct list_elem *e;
    while(!list_empty(fd_list))
    {
        e = list_pop_front(fd_list);
        struct fd_element *fd_elem = list_entry (e, struct fd_element, element);
        file_close(fd_elem->myfile);
        list_remove(e);
        free(fd_elem);
    }
}

/**
 * Iterate on the fd_list of the current thread and get the file which
 * has the same fd
 * If not found return NULL
 * */
struct fd_element*
get_fd(int fd)
{
    struct list_elem *e;
    for (e = list_begin (&thread_current()->fd_list); e != list_end (&thread_current()->fd_list);
            e = list_next (e))
    {
        struct fd_element *fd_elem = list_entry (e, struct fd_element, element);
        if(fd_elem->fd == fd)
        {
            return fd_elem;
        }
    }
    return NULL;
}


/**
Iterate mylist and return the child with the tid
*/
struct child_element*
get_child(tid_t tid, struct list *mylist)
{
    struct list_elem* e;
    for (e = list_begin (mylist); e != list_end (mylist); e = list_next (e))
    {
        struct child_element *child = list_entry (e, struct child_element, child_elem);
        if(child -> child_pid == tid)
        {
            return child;
        }
    }
}
