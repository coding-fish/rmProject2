// #include "userprog/process.h"
// #include <debug.h>
// #include <inttypes.h>
// #include <round.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include "userprog/gdt.h"
// #include "userprog/pagedir.h"
// #include "userprog/tss.h"
// #include "userprog/syscall.h"//
// #include "filesys/directory.h"
// #include "filesys/file.h"
// #include "filesys/filesys.h"
// #include "threads/flags.h"
// #include "threads/init.h"
// #include "threads/interrupt.h"
// #include "threads/palloc.h"
// #include "threads/thread.h"
// #include "threads/vaddr.h"
// #include "threads/synch.h"//
// #include "threads/malloc.h"//
// #include "lib/string.h"       //需要调用字符串分离函数
// #define MAX_ARGC 200          //假设一个命令行最多有200个参数

// static thread_func start_process NO_RETURN;
// static bool load (const char *cmdline, void (**eip) (void), void **esp);

// /* the list save all elem ready to read */
// static struct list read_list;
// /* the list to save all read request */
// static struct list wait_list;

// struct read_elem{
//   int pid;
//   enum action action;
//   struct list_elem elem;
//   int value;
// };

// struct wait_elem{
//   int pid;
//   enum action action;
//   struct list_elem elem;
//   struct semaphore sema;
// };

// void pipe_init(){
//   list_init(&read_list);
//   list_init(&wait_list);
// }

// /*
// add an elem to read list
// */
// void write_pipe(int pid,enum action action,int value){
//   enum intr_level old_level = intr_disable ();
//   // printf("%d write pipe %d, %d, %d\n",thread_tid(),pid, action, value);
//   /*
//   create a elem in read_list
//   */
//   struct read_elem* read = malloc(sizeof(struct read_elem));
//   read->pid = pid;
//   read->action = action;
//   read->value = value;
//   list_push_back(&read_list,&read->elem);

//   /*
//   wake up the read request if necessary
//   */
//   struct list_elem *e;
//   for(e=list_begin(&wait_list);e!=list_end(&wait_list);e=list_next(e)){
//     struct wait_elem *we = list_entry(e,struct wait_elem,elem);
//     if(we->pid == pid && we->action == action)
//       sema_up(&we->sema);
//   }
//   intr_set_level(old_level);
// }



// /*
// read the value in read list.
// create a read request if what the request want is not in read_list yet.
// */
// int read_pipe(int pid,enum action action){
//   enum intr_level old_level = intr_disable ();
//   // printf("%d read pipe %d, %d\n",thread_tid(),pid, action);
//   for(;;){
//     /*
//     check if what reader want already ready
//     */
//   struct list_elem *e;
//   for(e = list_begin(&read_list); e != list_end(&read_list); e = list_next(e) ){
//     struct read_elem *re = list_entry(e,struct read_elem, elem);
//     if(re->pid == pid && re->action == action){
//       list_remove(e);
//       int value = re->value;
//       free(re);
//       return value;
//     }
//     intr_set_level(old_level);
//   }
//   /*
//   what reader want is not in read_list, create a wait request
//   */
//   struct wait_elem *we = malloc(sizeof(struct wait_elem));
//   sema_init(&we->sema,0);
//   we->pid = pid;
//   we->action = action;
//   list_push_back(&wait_list,&we->elem);
//   sema_down(&we->sema);
//   /*
//   a writer has write something this reader want, the reader was unblocked and
//   clean the request and go to beginning
//   */
//   list_remove(&we->elem);
//   free(we);
// }
// }

// // call at init.c
// void process_init(){
//   pipe_init();
//   // init root process
//   list_init(&thread_current()->children);
// }

// /* Starts a new thread running a user program loaded from
//    FILENAME.  The new thread may be scheduled (and may even exit)
//    before process_execute() returns.  Returns the new process's
//    thread id, or TID_ERROR if the thread cannot be created. */
// tid_t
// process_execute (const char *file_name) 
// {
//   char *fn_copy;
//   tid_t tid;

//   /* Make a copy of FILE_NAME.
//      Otherwise there's a race between the caller and load(). */
//   fn_copy = palloc_get_page (0);
//   if (fn_copy == NULL)
//     return TID_ERROR;
//   strlcpy (fn_copy, file_name, PGSIZE);//但这里仍然用file_name

//   char *file_part, *save_ptr;//传入file_name实际是文件名和后面的参数，需要把文件名分离出来
//   file_part = strtok_r(file_name, " ", &save_ptr);//实际的文件名叫file_part

//   /* Create a new thread to execute FILE_NAME. */
//   tid = thread_create (file_part, PRI_DEFAULT, start_process, fn_copy);
//   // read information from pipe
//   tid = read_pipe(tid, EXEC);// 还没实现
//   if (tid == TID_ERROR)
//   {
//     palloc_free_page (fn_copy);
//     return TID_ERROR;
//   }

//   // 还没有实现
//   /*
//   add this thread to children, make shure that the thread start correctly
//   */
//   enum intr_level old_level = intr_disable ();
//   struct thread *child = get_thread_by_tid(tid);
//   child->parent_id = thread_current()->tid;

//   struct process *p = malloc(sizeof(struct process));
//   if(p==NULL)
//   {
//     return TID_ERROR;
//   }
//   p->thread = child->tid;

//   list_push_back(&thread_current()->children, &p->elem);
//   intr_set_level (old_level);

//   return tid;
// }

// /* A thread function that loads a user process and starts it
//    running. */
// static void
// start_process (void *file_name_)
// {
//   char *file_name = file_name_;
//   struct intr_frame if_;
//   bool success;

//   /* Initialize interrupt frame and load executable. */
//   memset (&if_, 0, sizeof if_);
//   if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
//   if_.cs = SEL_UCSEG;
//   if_.eflags = FLAG_IF | FLAG_MBS;

//   /* 由于后面要用到命令行中的参数，因此这里将所有子串都分离出来 */
//   int argc = 0;                   //参数个数
//   char * argv[MAX_ARGC];          //存每个参数
//   char * save_ptr = NULL;
//   int i = 0;
//   for (argv[i] = strtok_r (file_name, " ", &save_ptr); argv[i] != NULL;
//           argv[i] = strtok_r (NULL, " ", &save_ptr))
//   {
//     i++;
//     // printf ("'%s'\n", argv[i]);
//   }
//   argc = i;

//   success = load (argv[0], &if_.eip, 
//       &if_.esp);//文件名放在argv[0]中，传给load()，再间接传给load()中的setup_stack()

//   /* If load failed, quit. */
//   if (!success){
//     // load fail set exit status
//     write_pipe(thread_current()->tid, EXEC, TID_ERROR);// 还没实现   
//     exit(-1);
//     // thread_exit ();// 原来的
//   }
//   //TODO :: why
//   // PASS ARG-ONCE HERE WHY!!!
//   // success
//   int id = thread_current()->tid;
//   write_pipe(id, EXEC, id);// 还没实现

//   // 此时已经执行了load()，完成了栈的初始化setup_stack()
//   /* Start the user process by simulating a return from an
//      interrupt, implemented by intr_exit (in
//      threads/intr-stubs.S).  Because intr_exit takes all of its
//      arguments on the stack in the form of a `struct intr_frame',
//      we just point the stack pointer (%esp) to our stack frame
//      and jump to it. */
//   /* 下面完成参数传递 */
//   char* stack_pos[MAX_ARGC];    //存每个参数在栈上的位置
//   char* esp = (char*)if_.esp;       //以字节为单位移动，因此用char指针
//   for (i = argc-1; i >= 0; i--)
//   {
//     esp -= strlen(argv[i])+1;//有一个'\0'
//     memcpy(esp, argv[i], argv[i]+1);
//     stack_pos[i] = esp;             //存参数位置
//   }
//   while ((int)esp % 4)              //对齐
//     esp--;
//   esp -= 4;
//   *esp = 0;                         //argv[argc]
//   for (i = argc-1; i >= 0; i--)
//   {
//     esp -= 4;
//     *esp = (int*)stack_pos[i];      //每个地址是4字节
//   }
//   esp -= 4;
//   *esp = esp+4;                     //argv栈上地址
//   esp -= 4;
//   *esp = argc;                      //argc
//   esp -= 4;
//   *esp = 0;                         //return address

//   if_.esp = esp;                    //更新栈指针
//   /* 释放内存 */
//   free(argv);
//   palloc_free_page(file_name);

//   /* Start the user process by simulating a return from an
//      interrupt, implemented by intr_exit (in
//      threads/intr-stubs.S).  Because intr_exit takes all of its
//      arguments on the stack in the form of a `struct intr_frame',
//      we just point the stack pointer (%esp) to our stack frame
//      and jump to it. */
//   asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
//   NOT_REACHED ();
// }

// /*
// return true if tid is a child of current theread
// if delete flag is set, also remove the child
// notice that if the child is removed but it is not terminated, the
// current thread still is this process's parent. it is recoread in
// the thread's parent_id.
// */
// bool is_child(tid_t tid,bool delete){
//   struct thread *cur = thread_current();
//   struct list_elem *e;

//   for(e = list_begin(&cur->children); e != list_end(&cur->children);e = list_next(e)){
//     // TODO: thread was freed!
//     // struct thread *t = list_entry(e,struct process,elem)->thread;
//     int child_tid = list_entry(e,struct process,elem)->thread;
//     // printf("%d has children %d\n",thread_tid(),child_tid);
//     if(tid == child_tid){
//       if(delete){
//         list_remove(e);
//         free(list_entry(e,struct process,elem));
//       }
//       return true;
//     }
//   }
//   return false;
// }

// /*
// return true if current can wait this process
// */
// bool can_wait(tid_t tid){
//   //TODO : if -1 return false
//   return is_child(tid,true);
// }

// /* Waits for thread TID to die and returns its exit status.  If
//    it was terminated by the kernel (i.e. killed due to an
//    exception), returns -1.  If TID is invalid or if it was not a
//    child of the calling process, or if process_wait() has already
//    been successfully called for the given TID, returns -1
//    immediately, without waiting.

//    This function will be implemented in problem 2-2.  For now, it
//    does nothing. */
// int
// process_wait (tid_t child_tid)
// {
//   /*
//     check whether child_tid is a child of current thread.
//     if so, remove it from children list
//   */
//   if(!can_wait(child_tid))
//   {
//     return -1;
//   }
//   return read_pipe(child_tid, WAIT);
// }

// /*
// remove all signals write by current thread
// */
// void remove_child_signal(){
//   struct list_elem *e;
//   for(e = list_begin(&read_list);e != list_end(&read_list); e = list_next(e)){
//     struct read_elem *re = list_entry(e,struct read_elem, elem);
//     if(is_child(re->pid,false)){
//         list_remove(e);
//         free(re);
//     }
//   }
// }

// /*
// remove wait request
// */
// void remove_wait_request(){
//   struct list_elem *e;
//   for(e = list_begin(&wait_list); e!=list_end(&wait_list);e = list_next(e)){
//     struct wait_elem *we = list_entry(e,struct wait_elem, elem);
//     if(is_child(we->pid,false)){
//       list_remove(e);
//       sema_up(&we->sema);
//       free(we);
//     }
//   }

// }

// void free_children(){
//   struct list *children = &thread_current()->children;
//   struct list_elem *e;

//   for(e =list_begin(children); e!=list_end(children);e = list_next(e)){
//     list_remove(e);
//     free(list_entry(e,struct process, elem));
//   }
// }

// /* Free the current process's resources. */
// void
// process_exit (void)
// {
//   struct thread *cur = thread_current ();
//   uint32_t *pd;

//   // 还没有实现write_pipe和file_close
//   printf("%s: exit(%d)\n", cur->name, cur->exit_status);
//   write_pipe(cur->tid,WAIT,cur->exit_status);
//   file_close(cur->executable);

//   /*
//   don't exit kernel难道是这里？
//   */
//   if(cur->tid==1){
//     return;
//   }
//   /* Destroy the current process's page directory and switch back
//      to the kernel-only page directory. */
//   pd = cur->pagedir;
//   if (pd != NULL) // 说明是用户级进程
//     {
//       /* Correct ordering here is crucial.  We must set
//          cur->pagedir to NULL before switching page directories,
//          so that a timer interrupt can't switch back to the
//          process page directory.  We must activate the base page
//          directory before destroying the process's page
//          directory, or our active page directory will be one
//          that's been freed (and cleared). */
//       cur->pagedir = NULL;
//       pagedir_activate (NULL);
//       pagedir_destroy (pd);
//       //这个打印应该是在bochs的标准输出?
//       // printf("%s: exit(%d)\n", cur->name, cur->exit_status);//打印用户级进程返回值
//     }
// }

// /* Sets up the CPU for running user code in the current
//    thread.
//    This function is called on every context switch. */
// void
// process_activate (void)
// {
//   struct thread *t = thread_current ();

//   /* Activate thread's page tables. */
//   pagedir_activate (t->pagedir);

//   /* Set thread's kernel stack for use in processing
//      interrupts. */
//   tss_update ();
// }
// 
// /* We load ELF binaries.  The following definitions are taken
//    from the ELF specification, [ELF1], more-or-less verbatim.  */

// /* ELF types.  See [ELF1] 1-2. */
// typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
// typedef uint16_t Elf32_Half;

// /* For use with ELF types in printf(). */
// #define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
// #define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
// #define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
// #define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

// /* Executable header.  See [ELF1] 1-4 to 1-8.
//    This appears at the very beginning of an ELF binary. */
// struct Elf32_Ehdr
//   {
//     unsigned char e_ident[16];
//     Elf32_Half    e_type;
//     Elf32_Half    e_machine;
//     Elf32_Word    e_version;
//     Elf32_Addr    e_entry;
//     Elf32_Off     e_phoff;
//     Elf32_Off     e_shoff;
//     Elf32_Word    e_flags;
//     Elf32_Half    e_ehsize;
//     Elf32_Half    e_phentsize;
//     Elf32_Half    e_phnum;
//     Elf32_Half    e_shentsize;
//     Elf32_Half    e_shnum;
//     Elf32_Half    e_shstrndx;
//   };

// /* Program header.  See [ELF1] 2-2 to 2-4.
//    There are e_phnum of these, starting at file offset e_phoff
//    (see [ELF1] 1-6). */
// struct Elf32_Phdr
//   {
//     Elf32_Word p_type;
//     Elf32_Off  p_offset;
//     Elf32_Addr p_vaddr;
//     Elf32_Addr p_paddr;
//     Elf32_Word p_filesz;
//     Elf32_Word p_memsz;
//     Elf32_Word p_flags;
//     Elf32_Word p_align;
//   };

// /* Values for p_type.  See [ELF1] 2-3. */
// #define PT_NULL    0            /* Ignore. */
// #define PT_LOAD    1            /* Loadable segment. */
// #define PT_DYNAMIC 2            /* Dynamic linking info. */
// #define PT_INTERP  3            /* Name of dynamic loader. */
// #define PT_NOTE    4            /* Auxiliary info. */
// #define PT_SHLIB   5            /* Reserved. */
// #define PT_PHDR    6            /* Program header table. */
// #define PT_STACK   0x6474e551   /* Stack segment. */

// /* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
// #define PF_X 1          /* Executable. */
// #define PF_W 2          /* Writable. */
// #define PF_R 4          /* Readable. */

// static bool setup_stack (void **esp);
// static bool validate_segment (const struct Elf32_Phdr *, struct file *);
// static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
//                           uint32_t read_bytes, uint32_t zero_bytes,
//                           bool writable);

// /* Loads an ELF executable from FILE_NAME into the current thread.
//    Stores the executable's entry point into *EIP
//    and its initial stack pointer into *ESP.
//    Returns true if successful, false otherwise. */
// bool
// load (const char *file_name, void (**eip) (void), void **esp) 
// {
//   struct thread *t = thread_current ();
//   struct Elf32_Ehdr ehdr;
//   struct file *file = NULL;
//   off_t file_ofs;
//   bool success = false;
//   int i;

//   /* Allocate and activate page directory. */
//   t->pagedir = pagedir_create ();
//   if (t->pagedir == NULL) 
//     goto done;
//   process_activate ();

//   /* Open executable file. */
//   file = filesys_open (file_name);
//   if (file == NULL) 
//     {
//       printf ("load: %s: open failed\n", file_name);
//       goto done; 
//     }

//   /* Read and verify executable header. */
//   if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
//       || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
//       || ehdr.e_type != 2
//       || ehdr.e_machine != 3
//       || ehdr.e_version != 1
//       || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
//       || ehdr.e_phnum > 1024) 
//     {
//       printf ("load: %s: error loading executable\n", file_name);
//       goto done; 
//     }

//   /* Read program headers. */
//   file_ofs = ehdr.e_phoff;
//   for (i = 0; i < ehdr.e_phnum; i++) 
//     {
//       struct Elf32_Phdr phdr;

//       if (file_ofs < 0 || file_ofs > file_length (file))
//         goto done;
//       file_seek (file, file_ofs);

//       if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
//         goto done;
//       file_ofs += sizeof phdr;
//       switch (phdr.p_type) 
//         {
//         case PT_NULL:
//         case PT_NOTE:
//         case PT_PHDR:
//         case PT_STACK:
//         default:
//           /* Ignore this segment. */
//           break;
//         case PT_DYNAMIC:
//         case PT_INTERP:
//         case PT_SHLIB:
//           goto done;
//         case PT_LOAD:
//           if (validate_segment (&phdr, file)) 
//             {
//               bool writable = (phdr.p_flags & PF_W) != 0;
//               uint32_t file_page = phdr.p_offset & ~PGMASK;
//               uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
//               uint32_t page_offset = phdr.p_vaddr & PGMASK;
//               uint32_t read_bytes, zero_bytes;
//               if (phdr.p_filesz > 0)
//                 {
//                   /* Normal segment.
//                      Read initial part from disk and zero the rest. */
//                   read_bytes = page_offset + phdr.p_filesz;
//                   zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
//                                 - read_bytes);
//                 }
//               else 
//                 {
//                   /* Entirely zero.
//                      Don't read anything from disk. */
//                   read_bytes = 0;
//                   zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
//                 }
//               if (!load_segment (file, file_page, (void *) mem_page,
//                                  read_bytes, zero_bytes, writable))
//                 goto done;
//             }
//           else
//             goto done;
//           break;
//         }
//     }

//   /* Set up stack. */
//   if (!setup_stack (esp))         //这里调用了setup_stack()
//     goto done;

//   /* Start address. */
//   *eip = (void (*) (void)) ehdr.e_entry;

//   success = true;

//  done:
//   /* We arrive here whether the load is successful or not. */
//   if (success)
//   {
//     // 还没有实现？
//     t->executable = file;// woc是这里？
//     file_deny_write(file);
//   }
//   else
//   // when the process exit, the executable will be closed.
//   {
//     file_close (file);
//   }
//   return success;
// }
// 
// /* load() helpers. */

// static bool install_page (void *upage, void *kpage, bool writable);

// /* Checks whether PHDR describes a valid, loadable segment in
//    FILE and returns true if so, false otherwise. */
// static bool
// validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
// {
//   /* p_offset and p_vaddr must have the same page offset. */
//   if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
//     return false; 

//   /* p_offset must point within FILE. */
//   if (phdr->p_offset > (Elf32_Off) file_length (file)) 
//     return false;

//   /* p_memsz must be at least as big as p_filesz. */
//   if (phdr->p_memsz < phdr->p_filesz) 
//     return false; 

//   /* The segment must not be empty. */
//   if (phdr->p_memsz == 0)
//     return false;
  
//   /* The virtual memory region must both start and end within the
//      user address space range. */
//   if (!is_user_vaddr ((void *) phdr->p_vaddr))
//     return false;
//   if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
//     return false;

//   /* The region cannot "wrap around" across the kernel virtual
//      address space. */
//   if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
//     return false;

//   /* Disallow mapping page 0.
//      Not only is it a bad idea to map page 0, but if we allowed
//      it then user code that passed a null pointer to system calls
//      could quite likely panic the kernel by way of null pointer
//      assertions in memcpy(), etc. */
//   if (phdr->p_vaddr < PGSIZE)
//     return false;

//   /* It's okay. */
//   return true;
// }

// /* Loads a segment starting at offset OFS in FILE at address
//    UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
//    memory are initialized, as follows:

//         - READ_BYTES bytes at UPAGE must be read from FILE
//           starting at offset OFS.

//         - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

//    The pages initialized by this function must be writable by the
//    user process if WRITABLE is true, read-only otherwise.

//    Return true if successful, false if a memory allocation error
//    or disk read error occurs. */
// static bool
// load_segment (struct file *file, off_t ofs, uint8_t *upage,
//               uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
// {
//   ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
//   ASSERT (pg_ofs (upage) == 0);
//   ASSERT (ofs % PGSIZE == 0);

//   file_seek (file, ofs);
//   while (read_bytes > 0 || zero_bytes > 0) 
//     {
//       /* Calculate how to fill this page.
//          We will read PAGE_READ_BYTES bytes from FILE
//          and zero the final PAGE_ZERO_BYTES bytes. */
//       size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
//       size_t page_zero_bytes = PGSIZE - page_read_bytes;

//       /* Get a page of memory. */
//       uint8_t *kpage = palloc_get_page (PAL_USER);
//       if (kpage == NULL)
//         return false;

//       /* Load this page. */
//       if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
//         {
//           palloc_free_page (kpage);
//           return false; 
//         }
//       memset (kpage + page_read_bytes, 0, page_zero_bytes);

//       /* Add the page to the process's address space. */
//       if (!install_page (upage, kpage, writable)) 
//         {
//           palloc_free_page (kpage);
//           return false; 
//         }

//       /* Advance. */
//       read_bytes -= page_read_bytes;
//       zero_bytes -= page_zero_bytes;
//       upage += PGSIZE;
//     }
//   return true;
// }

// /* Create a minimal stack by mapping a zeroed page at the top of
//    user virtual memory. */
// static bool
// setup_stack (void **esp) 
// {
//   uint8_t *kpage;
//   bool success = false;

//   kpage = palloc_get_page (PAL_USER | PAL_ZERO);
//   if (kpage != NULL) 
//     {
//       success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
//       if (success)
//         *esp = PHYS_BASE;
//       else
//         palloc_free_page (kpage);
//     }
//   return success;
// }

// /* Adds a mapping from user virtual address UPAGE to kernel
//    virtual address KPAGE to the page table.
//    If WRITABLE is true, the user process may modify the page;
//    otherwise, it is read-only.
//    UPAGE must not already be mapped.
//    KPAGE should probably be a page obtained from the user pool
//    with palloc_get_page().
//    Returns true on success, false if UPAGE is already mapped or
//    if memory allocation fails. */
// static bool
// install_page (void *upage, void *kpage, bool writable)
// {
//   struct thread *t = thread_current ();

//   /* Verify that there's not already a page at that virtual
//      address, then map our page there. */
//   return (pagedir_get_page (t->pagedir, upage) == NULL
//           && pagedir_set_page (t->pagedir, upage, kpage, writable));
// }
#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

char* extract_command(char* command,char* argv[],int* argc);


/*
the list save all elem ready to read
*/
static struct list read_list;
/**
the list to save all read request
*/
static struct list wait_list;

struct read_elem{
  int pid;
  enum action action;
  struct list_elem elem;
  int value;
};

struct wait_elem{
  int pid;
  enum action action;
  struct list_elem elem;
  struct semaphore sema;
};

void pipe_init(){
  list_init(&read_list);
  list_init(&wait_list);
}

/*
add an elem to read list
*/
void write_pipe(int pid,enum action action,int value){
  enum intr_level old_level = intr_disable ();
  // printf("%d write pipe %d, %d, %d\n",thread_tid(),pid, action, value);
  /*
  create a elem in read_list
  */
  struct read_elem* read = malloc(sizeof(struct read_elem));
  read->pid = pid;
  read->action = action;
  read->value = value;
  list_push_back(&read_list,&read->elem);

  /*
  wake up the read request if necessary
  */
  struct list_elem *e;
  for(e=list_begin(&wait_list);e!=list_end(&wait_list);e=list_next(e)){
    struct wait_elem *we = list_entry(e,struct wait_elem,elem);
    if(we->pid == pid && we->action == action)
      sema_up(&we->sema);
  }
  intr_set_level(old_level);
}



/*
read the value in read list.
create a read request if what the request want is not in read_list yet.
*/
int read_pipe(int pid,enum action action){
  enum intr_level old_level = intr_disable ();
  // printf("%d read pipe %d, %d\n",thread_tid(),pid, action);
  for(;;){
    /*
    check if what reader want already ready
    */
  struct list_elem *e;
  for(e = list_begin(&read_list); e != list_end(&read_list); e = list_next(e) ){
    struct read_elem *re = list_entry(e,struct read_elem, elem);
    if(re->pid == pid && re->action == action){
      list_remove(e);
      int value = re->value;
      free(re);
      return value;
    }
    intr_set_level(old_level);
  }
  /*
  what reader want is not in read_list, create a wait request
  */
  struct wait_elem *we = malloc(sizeof(struct wait_elem));
  sema_init(&we->sema,0);
  we->pid = pid;
  we->action = action;
  list_push_back(&wait_list,&we->elem);
  sema_down(&we->sema);
  /*
  a writer has write something this reader want, the reader was unblocked and
  clean the request and go to beginning
  */
  list_remove(&we->elem);
  free(we);
}
}





// call at init.c
void process_init(){
  pipe_init();
  // init root process
  list_init(&thread_current()->children);
}
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

   /*
   wait child to start and get correct tid
   */
tid_t
process_execute (const char *file_name)
{
  // printf("process execute :%s\n",file_name );
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
     // can not over 2KB(PGSIZE)
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */

  // thread name: file_name(with arguments)
  // start_process arguments: fn_copy
  char *argv[MAX_ARGC];
  int argc;
  char* command_bak = extract_command(file_name,argv,&argc);
  // thread->name max 16

  tid = thread_create (argv[0], PRI_DEFAULT, start_process, fn_copy);

  tid = read_pipe(tid,EXEC);
  if (tid == TID_ERROR){
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }



  /*
  add this thread to children, make shure that the thread start correctly
  */
   enum intr_level old_level = intr_disable ();
  struct thread *child = get_thread_by_tid(tid);
  child->parent_id = thread_current()->tid;


  struct process *p = malloc(sizeof(struct process));
  if(p==NULL){

    return TID_ERROR;
  }
  p->thread = child->tid;

  list_push_back(&thread_current()->children,&p->elem);
  intr_set_level (old_level);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  // load name const char* Executable file name
  char *argv[MAX_ARGC];
  int argc;
  char* command_bak = extract_command(file_name,argv,&argc);
  // eip: The address of the next instruction to be executed by the interrupted thread.
  // esp: The interrupted thread’s stack pointer.
  success = load (argv[0], &if_.eip, &if_.esp);
  if (!success){
    // load fial set exit status
    // free(command_bak);
    write_pipe(thread_current()->tid,EXEC,TID_ERROR);
    // thread_current()->exit_status = -1;
    // thread_exit ();
    exit(-1);
  }
  //TODO :: why
  // PASS ARG-ONCE HERE WHY!!!
  int id = thread_current()->tid;
  write_pipe(id,EXEC,id);
  //put arguments into stack;
  int i=argc;
  char * addr_arr[argc];
  //printf("%s\n","try to put args" );
  //printf("Address\t         Nmae\t        Data\n");
  while(--i>=0){
    if_.esp = if_.esp - sizeof(char)*(strlen(argv[i])+1); //+1: extra \0

    addr_arr[i]=(char *)if_.esp;
    memcpy(if_.esp,argv[i],strlen(argv[i])+1);
    //strlcpy(if_.esp,argv[i],strlen(argv[i])+1);
    //printf("%d\targv[%d][...]\t'%s'\n",if_.esp,i,(char*)if_.esp);

  }

  // 4k  对齐
  //world-align
  while ((int)if_.esp%4!=0) {
    if_.esp--;
  }
  //printf("%d\tworld-align\t0\n", if_.esp);

  i=argc;
  if_.esp = if_.esp-4;
  (*(int *)if_.esp)=0;
  //printf("%d\targv[%d]\t%d\n",if_.esp,i,*((int *)if_.esp));
  while (--i>=0) {

    if_.esp = if_.esp-4;//sizeof()
    (*(char **)if_.esp) = addr_arr[i]; // if_.esp a pointer to uint32_t*
    //printf("%d\targv[%d]\t%d\n",if_.esp,i,(*(char **)if_.esp));
  }

  if_.esp = if_.esp-4;
  (*(char **)if_.esp)=if_.esp+4;
  //printf("%d\targv\t%d\n",if_.esp,(*(char **)if_.esp));

  //put argc
  if_.esp = if_.esp-4;
  (*(int *)if_.esp)=argc;
  //printf("%d\targc\t%d\n",if_.esp,(*(int *)if_.esp));

  //put return address 0
  if_.esp = if_.esp-4;
  (*(int *)if_.esp)=0;
  //printf("%d\treturn address\t%d\n",if_.esp,(*(int *)if_.esp));

  /* If load failed, quit. */
  free(command_bak);
  palloc_free_page (file_name);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/*
split command by " ", return argc
argv should have enough length.
example: ls -l
@param command
@param argv[]
@param argc

@return
command ls -l
argc 2
argv[0] ls
argv[1] -l
*/
char* extract_command(char* command,char* argv[],int* argc){
  char* command_bak = NULL;
  *argc=0;
  command_bak = malloc(strlen(command)+1);
  char* save = NULL;
  char* temp = NULL;

  // to command_bak, from command
  strlcpy(command_bak,command,PGSIZE);


  temp = strtok_r(command_bak," ",&save);
  argv[*argc] = temp;

  while (temp != NULL) {
    (*argc)++; //will cause extra +1, need it!
    temp = strtok_r(NULL," ",&save);
    argv[*argc] = temp;
  }
  return command_bak;
}

/*
return true if tid is a child of current theread
if delete flag is set, also remove the child

notice that if the child is removed but it is not terminated, the
current thread still is this process's parent. it is recoread in
the thread's parent_id.
*/
bool is_child(tid_t tid,bool delete){
  struct thread *cur = thread_current();
  struct list_elem *e;

  for(e = list_begin(&cur->children); e != list_end(&cur->children);e = list_next(e)){
    // TODO: thread was freed!
    // struct thread *t = list_entry(e,struct process,elem)->thread;
    int child_tid = list_entry(e,struct process,elem)->thread;
    // printf("%d has children %d\n",thread_tid(),child_tid);
    if(tid == child_tid){
      if(delete){
        list_remove(e);
        free(list_entry(e,struct process,elem));
      }
      return true;
    }
  }
  return false;
}

/*
return true if current can wait this process
*/
bool can_wait(tid_t tid){
  //TODO : if -1 return false
  return is_child(tid,true);
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  // printf("process %d wait %d \n",thread_tid(),child_tid);
  if(!can_wait(child_tid)){
    // printf("%d can't wait tid %d\n",thread_tid(),child_tid);
    return -1;
  }
  return read_pipe(child_tid,WAIT);
  //printf("process wait done\n");
  // return -1;
}

/*
remove all signals write by current thread
*/
void remove_child_signal(){
  struct list_elem *e;
  for(e = list_begin(&read_list);e != list_end(&read_list); e = list_next(e)){
    struct read_elem *re = list_entry(e,struct read_elem, elem);
    if(is_child(re->pid,false)){
        list_remove(e);
        free(re);
    }
  }
}

/*
remove wait request
*/
void remove_wait_request(){
  struct list_elem *e;
  for(e = list_begin(&wait_list); e!=list_end(&wait_list);e = list_next(e)){
    struct wait_elem *we = list_entry(e,struct wait_elem, elem);
    if(is_child(we->pid,false)){
      list_remove(e);
      sema_up(&we->sema);
      free(we);
    }
  }

}



void free_children(){
  struct list *children = &thread_current()->children;
  struct list_elem *e;

  for(e =list_begin(children); e!=list_end(children);e = list_next(e)){
    list_remove(e);
    free(list_entry(e,struct process, elem));
  }
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  printf("%s: exit(%d)\n", cur->name, cur->exit_status);
  write_pipe(cur->tid,WAIT,cur->exit_status);
  file_close(cur->executable);
  // printf("write pipe %s, WAIT, %d\n", cur->name,cur->exit_status);

  // TODO: free these
  // // printf("remove child signal\n");
  // // remove all child single or let them be a child of main process
  // remove_child_signal();
  //
  // // printf("close open files\n");
  // // close all files it opend.
  // remove_wait_request();
  //
  // // printf("free children\n");
  // free_children();
  // // printf("free children done\n");

  /*

  free all children
  */


  /*
  don't exit kernel
  */
  if(cur->tid==1){
    return;
  }
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL); // set to init_page_dir
      pagedir_destroy (pd);
    }

    /*
    write to pipe "notify" father
    */



}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if(success){
    t->executable = file;
    file_deny_write(file);
  }
  else
  // when the process exit, the executable will be closed.
  {
    file_close (file);
  }
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
