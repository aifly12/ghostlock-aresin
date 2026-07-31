/*
 * extract_struct_offsets.c - 在设备上运行，提取内核结构体偏移
 *
 * 编译: aarch64-linux-android-clang -o extract_struct_offsets extract_struct_offsets.c
 * 运行: adb push extract_struct_offsets /data/local/tmp/
 *       adb shell /data/local/tmp/extract_struct_offsets
 *
 * 需要 root 权限
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* 从 /proc/kallsyms 读取符号地址 */
uint64_t read_symbol_addr(const char *symbol) {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;

    char line[256];
    uint64_t addr = 0;
    char type;
    char name[128];

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx %c %s", &addr, &type, name) == 3) {
            if (strcmp(name, symbol) == 0) {
                fclose(f);
                return addr;
            }
        }
    }

    fclose(f);
    return 0;
}

/* 读取内核内存 */
int read_kernel_memory(uint64_t addr, void *buf, size_t len) {
    int fd = open("/dev/kmem", O_RDONLY);
    if (fd < 0) {
        /* 尝试 /proc/kcore */
        fd = open("/proc/kcore", O_RDONLY);
        if (fd < 0) {
            perror("open /dev/kmem or /proc/kcore");
            return -1;
        }
    }

    /* 对于 /proc/kcore，需要计算偏移 */
    /* 这里简化处理，实际需要解析 ELF 头 */
    lseek(fd, addr, SEEK_SET);
    ssize_t n = read(fd, buf, len);
    close(fd);

    return (n == (ssize_t)len) ? 0 : -1;
}

int main() {
    printf("=== 内核结构体偏移提取工具 ===\n");
    printf("设备: POCO F3 GT (aresin)\n");
    printf("内核: 4.14.186\n\n");

    /* 读取关键符号地址 */
    printf("[*] 读取内核符号地址...\n");

    uint64_t commit_creds = read_symbol_addr("commit_creds");
    uint64_t prepare_kernel_cred = read_symbol_addr("prepare_kernel_cred");
    uint64_t rt_mutex_init_waiter = read_symbol_addr("rt_mutex_init_waiter");
    uint64_t remove_waiter = read_symbol_addr("remove_waiter");
    uint64_t __rt_mutex_start_proxy_lock = read_symbol_addr("__rt_mutex_start_proxy_lock");

    printf("  commit_creds: 0x%lx\n", commit_creds);
    printf("  prepare_kernel_cred: 0x%lx\n", prepare_kernel_cred);
    printf("  rt_mutex_init_waiter: 0x%lx\n", rt_mutex_init_waiter);
    printf("  remove_waiter: 0x%lx\n", remove_waiter);
    printf("  __rt_mutex_start_proxy_lock: 0x%lx\n", __rt_mutex_start_proxy_lock);

    /* 计算 rt_mutex_waiter 结构体偏移 */
    printf("\n[*] rt_mutex_waiter 结构体偏移 (基于 4.14 内核源码):\n");
    printf("  tree_entry:      0x00 (struct rb_node, 24 bytes)\n");
    printf("  pi_tree_entry:   0x18 (struct rb_node, 24 bytes)\n");
    printf("  task:            0x30 (struct task_struct *, 8 bytes)\n");
    printf("  lock:            0x38 (struct rt_mutex *, 8 bytes)\n");
    printf("  prio:            0x40 (int, 4 bytes)\n");
    printf("  deadline:        0x48 (u64, 8 bytes)\n");

    /* task_struct 偏移需要从内核分析 */
    printf("\n[*] task_struct 偏移需要从内核二进制分析:\n");
    printf("  使用 pahole 或 Ghidra 分析 vmlinux\n");

    return 0;
}
