# ASLR

有点硬核，打*的先不看

ASLR就是地址空间布局随机化，当ASLR开启时，程序每次运行时的内存布局都是相同的；打开后每次运行时的内存布局都会发生变化

> - 0：完全关闭
> - 1：部分开启（堆、栈、MMAP、动态链接库）
> - 2：完全开启（BRK、堆、栈、MMAP、动态链接库）

## 1 实现原理

程序加载到内存中的内存布局是由操作系统决定的，通过上面的ASLR开关方式可以知道，用户空间可以借助内核提供的`proc`虚文件对ASLR控制



### *1.1 虚文件系统

Linux为了避免用户空间程序操作文件时仍需要考虑不同文件系统带来的差异问题，Linux提供了一个统一的接口供用户空间使用，叫做`VFS(虚拟文件系统)`

`VFS`为了支持各种文件系统，它定义一套所有文件系统都支持的接口和数据结构，用于支持各类文件系统和VFS协同工作

> ```c
> struct file_system_type {
>     const char *name;
>     int fs_flags;
> #define FS_REQUIRES_DEV     1
> #define FS_BINARY_MOUNTDATA 2
> #define FS_HAS_SUBTYPE      4
> #define FS_USERNS_MOUNT     8   /* Can be mounted by userns root */
> #define FS_DISALLOW_NOTIFY_PERM 16  /* Disable fanotify permission events */
> #define FS_ALLOW_IDMAP         32      /* FS has been updated to handle vfs idmappings. */
> #define FS_RENAME_DOES_D_MOVE   32768   /* FS will handle d_move() during rename() internally. */
>     int (*init_fs_context)(struct fs_context *);
>     const struct fs_parameter_spec *parameters;
>     struct dentry *(*mount) (struct file_system_type *, int,
>                const char *, void *);
>     void (*kill_sb) (struct super_block *);
>     struct module *owner;
>     struct file_system_type * next;
>     struct hlist_head fs_supers;
>  
>     struct lock_class_key s_lock_key;
>     struct lock_class_key s_umount_key;
>     struct lock_class_key s_vfs_rename_key;
>     struct lock_class_key s_writers_key[SB_FREEZE_LEVELS];
>  
>     struct lock_class_key i_lock_key;
>     struct lock_class_key i_mutex_key;
>     struct lock_class_key invalidate_lock_key;
>     struct lock_class_key i_mutex_dir_key;
> };
> ```

Linux内文件系统需要设置`file_system_type`信息，然后将设置好的信息提交给`register_filesystem`函数进行注册，只有完成注册的文件系统才能被VFS操控

```c
extern int register_filesystem (struct file_system_type *);
```

`file_system_type`本身比较简单，主要就是定义获取和删除`super_block`的接口及属性信息，不同文件系统间的`file_system_type`之间通过链接进行管理

> `super_block`是一个更加复杂的结构体，它定义了文件系统的具体信息和对应文件系统的操作接口，是实际管理文件系统的数据结构
>
> ```c
> struct super_block {
>     struct list_head    s_list;     /* Keep this first */
>     dev_t           s_dev;      /* search index; _not_ kdev_t */
>     unsigned char       s_blocksize_bits;
>     unsigned long       s_blocksize;
>     loff_t          s_maxbytes; /* Max file size */
>     struct file_system_type *s_type;
>     const struct super_operations   *s_op;
>     const struct dquot_operations   *dq_op;
>     const struct quotactl_ops   *s_qcop;
>     const struct export_operations *s_export_op;
>     unsigned long       s_flags;
>     unsigned long       s_iflags;   /* internal SB_I_* flags */
>     unsigned long       s_magic;
>     struct dentry       *s_root;
>     struct rw_semaphore s_umount;
>     int         s_count;
>     atomic_t        s_active;
>     ......
>     spinlock_t      s_inode_wblist_lock;
>     struct list_head    s_inodes_wb;    /* writeback inodes */
> } __randomize_layout;
> ```

而下面展示了`proc`文件系统的注册过程

> ```c
> static struct file_system_type proc_fs_type = {
>     .name           = "proc",
>     .init_fs_context    = proc_init_fs_context,
>     .parameters     = proc_fs_parameters,
>     .kill_sb        = proc_kill_sb,
>     .fs_flags       = FS_USERNS_MOUNT | FS_DISALLOW_NOTIFY_PERM,
> };
>  
> void __init proc_root_init(void)
> {
>     ......
>     register_filesystem(&proc_fs_type);
> }
> ```

`proc`是进程文件系统，属于Linux中伪文件系统中的一种，它没有对应真实的磁盘或硬盘，而是提供给用户空间便利的使用Linux系统资源的接口。常见的伪文件系统有`proc`,`sys`,`dev`等。`proc`可以方便的查看进程信息，比如进程的内存布局，CPU信息等

### *1.2 proc

进行Linux驱动开发时，可以借助`proc_ops`结构体，`proc_create`接口、`proc_remove`接口对`proc`进行创建和控制。

`prco_ops`结构体中有两个较为重要的成员，即`proc_read`和`proc_write`，它们分别会响应虚文件被用户空间读写时的操作。下面给出了创建`proc`虚文件的示例代码

> ```c
> #include <linux/proc_fs.h>
>  
> static struct proc_dir_entry* lde_proc_entry = NULL;
>  
> static ssize_t lde_proc_read(struct file* file, char __user* ubuf, size_t count, loff_t* data)
> {
>     printk(KERN_INFO "%s called file 0x%px, buffer 0x%px count 0x%lx off 0x%llx\n",
>         __func__, file, ubuf, count, *data);
>  
>     return 0;
> }
>  
> static ssize_t lde_proc_write(struct file* file, const char __user* ubuf, size_t count, loff_t* data)
> {
>     printk(KERN_INFO "%s called legnth 0x%lx, 0x%px\n",
>         __func__, count, ubuf);
>  
>     return count;
> }
>  
> static struct proc_ops lde_proc_ops = {
>     .proc_read = lde_proc_read,
>     .proc_write = lde_proc_write
> };
>  
> int lde_proc_create(void)
> {
>     int ret;
>  
>     ret = SUCCEED;
>  
>     lde_proc_entry = proc_create("lde_proc", 0, NULL, &lde_proc_ops);
>     if (!lde_proc_entry) {
>         printk(KERN_ERR "%s create proc entry failed\n", __func__);
>  
>         ret = PROC_CREATE_FAILED;
>     }
>  
>     return ret;
> }
>  
> void lde_proc_remove(void)
> {
>     if (lde_proc_entry == NULL) {
>         printk(KERN_INFO "%s proc not exists\n", __func__);
>         goto TAG_RETURN;
>     }
>  
>     proc_remove(lde_proc_entry);
>  
> TAG_RETURN:
>     return;
> }
> ```

通过读写虚文件，可以在`dmesg`中看到相关的打印信息

> ```shell
> cat /proc/lde_proc
> echo test | sudo tee -a /proc/lde_proc
>  
> [  440.396298] starting from 0xffffffffc0af6090 ...
> [  446.024481] lde_proc_read called file 0xffff9626c2931400, buffer 0x000077aeb6db8000 count 0x40000 off 0x0
> [  459.392387] lde_proc_write called legnth 0x5, 0x00007fff783f3090
> [  476.345011] exiting from 0xffffffffc0af60f0 ...
> ```

### *1.3 randomize_va_space变量的设置

`proc`除了支持访问进程信息外，它还支持在Linux内核运行时对内核参数进行修改，该机制也被叫做`sysctl`

`proc/sys/kernel/`中的虚文件会通过`kern_table`进行定义，每个模块都会定义一个处理函数贺数据对象，处理函数会负责处理虚文件被读写时进行的操作，而数据对象则是被操作的数值。`randomize_va_space`指定的处理函数史`proc_dointvec`，其作用是读取整数值或写入整数值，待处理的数据对象是`randomize_va_space`，它是一个整型的全局变量

当向`proc/sys/kernel/randomize_va_space`写入数值时，`randomize_va_space`变量的数值就会被`proc_dointvec`函数修改

> ```c
> static struct ctl_table kern_table[] = {
> ......
> #if defined(CONFIG_MMU)
>     {
>         .procname   = "randomize_va_space",
>         .data       = &randomize_va_space,
>         .maxlen     = sizeof(int),
>         .mode       = 0644,
>         .proc_handler   = proc_dointvec,
>     },
> #endif
> ......
> }
> ```

### 1.4 内存布局的随机化设置

当程序启动时，负责加载ELF文件的`load_elf_binary`函数会根据`randomize_va_space`变量设置标志位，当标志位完成设置后，才会正式开始BRK、MMAP、堆、栈、动态链接库、vDSO的地址随机化，随机化的主要操作就是根据随机值堆地址进行偏移

>```c
>static int load_elf_binary(struct linux_binprm *bprm)
>{
>    ......
>    if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
>		current->flags |= PF_RANDOMIZE;
>    setup_new_exec(bprm);
> 
>/* Do this so that we can load the interpreter, if need be.  We will
>   change some of these later */
>retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
>             executable_stack);
>......
>mm = current->mm;
>mm->end_code = end_code;
>mm->start_code = start_code;
>mm->start_data = start_data;
>mm->end_data = end_data;
>mm->start_stack = bprm->p;
> 
>......
> 
>if (!first_pt_load) {
>        elf_flags |= MAP_FIXED;
>    } else if (elf_ex->e_type == ET_EXEC) {
>        elf_flags |= MAP_FIXED_NOREPLACE;
>    } else if (elf_ex->e_type == ET_DYN) {
>        if (interpreter) {
>            load_bias = ELF_ET_DYN_BASE;
>            if (current->flags & PF_RANDOMIZE)
>                load_bias += arch_mmap_rnd();
>            alignment = maximum_alignment(elf_phdata, elf_ex->e_phnum);
>            if (alignment)
>                load_bias &= ~(alignment - 1);
>            elf_flags |= MAP_FIXED_NOREPLACE;
>        } else
>            load_bias = 0;
>......
>}
> 
>......
> 
>if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
>    /*
>     * For architectures with ELF randomization, when executing
>     * a loader directly (i.e. no interpreter listed in ELF
>     * headers), move the brk area out of the mmap region
>     * (since it grows up, and may collide early with the stack
>     * growing down), and into the unused ELF_ET_DYN_BASE region.
>     */
>    if (IS_ENABLED(CONFIG_ARCH_HAS_ELF_RANDOMIZE) && elf_ex->e_type == ET_DYN && !interpreter) 
>    {
>        mm->brk = mm->start_brk = ELF_ET_DYN_BASE;
>    }
>    mm->brk = mm->start_brk = arch_randomize_brk(mm);
>    #ifdef compat_brk_randomized
>current->brk_randomized = 1;
>#endif
>}
>......
>}
>```

*看不懂没事，因为看不懂也能做题*

#### 1.4.1 mmap随机化

内核会通过`arch_pick_mmap_layout`函数对MMAP进行随机化，当检测到标志位开启时，就会提供随机值给MMAP，否则会提供0，MMAP会根据该数值对地址空间进行设置

> ```c
> void setup_new_exec(struct linux_binprm * bprm)
> {
>     ......
>     arch_pick_mmap_layout(me->mm, &bprm->rlim_stack);
>     ......
> }
> EXPORT_SYMBOL(setup_new_exec);
>  
> void arch_pick_mmap_layout(struct mm_struct *mm, struct rlimit *rlim_stack)
> {
>     ......
>     arch_pick_mmap_base(&mm->mmap_base, &mm->mmap_legacy_base,
>             arch_rnd(mmap64_rnd_bits), task_size_64bit(0),
>             rlim_stack);
>     ......
> }
>  
> static unsigned long arch_rnd(unsigned int rndbits)
> {
>     if (!(current->flags & PF_RANDOMIZE))
>         return 0;
>     return (get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT;
> }
> ```

#### 1.4.2 栈的随机化

`load_elf_binary`函数会先通过`setup_arg_page`函数设置栈空间。栈空间的偏移值由`randomize_stack_top`的结果决定，当标志位中存在`PF_RANDOMIZE`时，`randomize_stack_top`将地址根据随机值进行偏移，否则就不会进行偏移

>```c
>unsigned long randomize_stack_top(unsigned long stack_top)
>{
>    unsigned long random_variable = 0;
> 
>    if (current->flags & PF_RANDOMIZE) {
>        random_variable = get_random_long();
>        random_variable &= STACK_RND_MASK;
>        random_variable <<= PAGE_SHIFT;
>    }
>#ifdef CONFIG_STACK_GROWSUP
>    return PAGE_ALIGN(stack_top) + random_variable;
>#else
>    return PAGE_ALIGN(stack_top) - random_variable;
>#endif
>}
> 
>int setup_arg_pages(struct linux_binprm *bprm,
>            unsigned long stack_top,
>            int executable_stack)
>{
>    ......
>#ifdef CONFIG_STACK_GROWSUP
>    /* Limit stack size */
>    stack_base = bprm->rlim_stack.rlim_max;
> 
>    stack_base = calc_max_stack_size(stack_base);
> 
>    /* Add space for stack randomization. */
>    stack_base += (STACK_RND_MASK << PAGE_SHIFT);
> 
>    /* Make sure we didn't let the argument array grow too large. */
>    if (vma->vm_end - vma->vm_start > stack_base)
>        return -ENOMEM;
> 
>    stack_base = PAGE_ALIGN(stack_top - stack_base);
> 
>    stack_shift = vma->vm_start - stack_base;
>    mm->arg_start = bprm->p - stack_shift;
>    bprm->p = vma->vm_end - stack_shift;
>#else
>    stack_top = arch_align_stack(stack_top);
>    stack_top = PAGE_ALIGN(stack_top);
> 
>    if (unlikely(stack_top < mmap_min_addr) ||
>        unlikely(vma->vm_end - vma->vm_start >= stack_top - mmap_min_addr))
>        return -ENOMEM;
> 
>    stack_shift = vma->vm_end - stack_top;
> 
>    bprm->p -= stack_shift;
>    mm->arg_start = bprm->p;
>#endif
>    ......
>}
>```

一般来说，栈是向下增长的，如果支持栈向上增长，那么可以通过`CONFIG_STACK_GROWSUP`对内核进行配置。处理栈空间的地址时，如果不使用`CONFIG_STACK_GROWSUP`功能，那么栈顶地址会通过`arch_align_stack`再次进行偏移，然后将低4比特设置为0，进行对齐。

> ```c
> unsigned long arch_align_stack(unsigned long sp)
> {
>     if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
>         sp -= prandom_u32_max(8192);
>     return sp & ~0xf;
> }

#### 1.4.3 动态链接的随机化

当`load_elf_binary`函数处理动态链接库时，它会根据标志位决定是否给动态链接库的加载地址设置偏移值，偏移值的数值由`arch_rnd`获取。

> ```c
> static unsigned long arch_rnd(unsigned int rndbits)
> {
>     if (!(current->flags & PF_RANDOMIZE))
>         return 0;
>     return (get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT;
> }
>  
> unsigned long arch_mmap_rnd(void)
> {
>     return arch_rnd(mmap_is_ia32() ? mmap32_rnd_bits : mmap64_rnd_bits);
> }
>  
> load_elf_binary{
>     ......
>     if (!first_pt_load) {
>         elf_flags |= MAP_FIXED;
>     } else if (elf_ex->e_type == ET_EXEC) {
>         elf_flags |= MAP_FIXED_NOREPLACE;
>     } else if (elf_ex->e_type == ET_DYN) {
>         if (interpreter) {
>             load_bias = ELF_ET_DYN_BASE;
>             if (current->flags & PF_RANDOMIZE)
>                 load_bias += arch_mmap_rnd();
>             alignment = maximum_alignment(elf_phdata, elf_ex->e_phnum);
>             if (alignment)
>                 load_bias &= ~(alignment - 1);
>             elf_flags |= MAP_FIXED_NOREPLACE;
>         } else
>             load_bias = 0;
>         ......
>     }
>     ......
> }
> ```

### 1.5 随机化总结

上面已经描述了需要随机化的地址空间（BRK、堆、栈、MMAP、动态链接库、vDSO）是如何及何时进行随机化的，由于随机化的操作是程序运行开始阶段处理的，**所以随机化选项的变更并不会影响已经运行的程序。**

尽管不同地址空间的随机化方式都是根据随机值进行偏移，但是也可以明显的看到，不同地址空间随机化取值的方式总体上是类似的，先是通过`get_random_long`函数获取随机值，然后根据某数值进行运算，最后根据页偏移进行对齐。

下面对为什么使用不同数值计算的原因进行了解释。

> ```c
> #define PAGE_SHIFT      12
>  
> static inline unsigned long get_random_long(void)
> {
> #if BITS_PER_LONG == 64
>     return get_random_u64();
> #else
>     return get_random_u32();
> #endif
> }
> ```

mmap、动态链接库的解释

> ```c
> rndbits = mmap64_rnd_bit = mmap_rnd_bits = CONFIG_ARCH_MMAP_RND_BITS = 32
>  
> (get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT
> ```
>
> 作用：将随机值跟页大小对齐（4kb，0x1000）；1向右移动32位比特，减1后变为32位比特空间内的最大值，特点是所有比特位全为1，当随机值和它进行与运算后，随机值会被保留下来，最后根据页大小向右移动12位，跟页大小对齐。由于运算时比特位自动扩充的原因，`((1UL << rndbits) -  1)`可以保障数值占用的比特位数量在32内，在64位系统中，用户空间一般会占用48位空间，考虑到高4位会被用于区分不同的ELF文件（比如动态链接库一般是0x7xxx打头，执行文件一般0x5xxx、0x6xxx打头等等），所以系统会对低48位（32位随机值+12位页对齐值）进行设置，并不会触及高4个比特位

栈的解释：

> ```c
> #define __STACK_RND_MASK(is32bit) ((is32bit) ? 0x7ff : 0x3fffff)
> #define STACK_RND_MASK __STACK_RND_MASK(mmap_is_ia32())
>  
> random_variable = get_random_long();
> random_variable &= STACK_RND_MASK;
> random_variable <<= PAGE_SHIFT;
> ```
>
> 作用：设置随机值后跟页大小对齐（4kb，0x1000）；原数值和0x3fffff与运算时，只有低22个比特位会被保留下来，当跟页大小对齐后，数值大小会被扩充到34个比特位，在Linux当中，栈地址会以0x7ffx打头，占用14个比特位，所以会对低34个比特位设置。

## 2 绕过思路

下面会以程序中存在泄露地址的情况为前提进行讨论。

即使开启了ASLR，导致程序使用的内存地址在不断的变化，但是变化的只是基地址，程序内容的地址仍然靠基地址加文件内偏移的组合进行定位，因此程序同一元素即使每次每次运行时的地址都不一样，**但它减去起始地址的偏移值永远都是固定的。**

当我们可以稳定泄露程序内某元素的地址时，就可以先借助起始地址手工计算偏移值，等到下次运行时，就可以直接通过元素的随机地址减偏移值得到随机的起始地址（比如可泄露元素的地址是Libc中，那么就相当于稳定获取Libc的基地址，进而对整个Libc进行利用）