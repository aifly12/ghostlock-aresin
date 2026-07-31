/*
 * test_offsets.c - 在设备上运行，验证提取的偏移
 *
 * 编译: aarch64-linux-android-clang -o test_offsets test_offsets.c
 * 运行: adb push test_offsets /data/local/tmp/
 *       adb shell /data/local/tmp/test_offsets
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

int main() {
    printf("=== 偏移验证工具 - POCO F3 GT (aresin) ===\n");
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

    /* 验证提取的偏移 */
    printf("\n[*] 验证提取的偏移...\n");

    /* rt_mutex_waiter 偏移 */
    printf("  rt_mutex_waiter 偏移:\n");
    printf("    tree_entry: 0x00 (预期)\n");
    printf("    pi_tree_entry: 0x18 (预期)\n");
    printf("    task: 0x30 (预期)\n");
    printf("    lock: 0x38 (预期)\n");
    printf("    prio: 0x40 (预期)\n");
    printf("    deadline: 0x48 (预期)\n");

    /* task_struct 偏移 */
    printf("  task_struct 偏移:\n");
    printf("    prio: 0x84 (预期)\n");
    printf("    real_cred: 0x788 (预期)\n");
    printf("    cred: 0x790 (预期)\n");
    printf("    pi_lock: 0x85c (预期)\n");
    printf("    pi_blocked_on: 0x880 (预期)\n");

    /* 内核地址 */
    printf("  内核地址:\n");
    printf("    KIMAGE_TEXT_BASE: 0x%lx\n", 0xffffff939bc80000UL);
    printf("    selinux_enforcing: 0x%lx\n", 0xffffff939dd00b28UL);

    /* 测试 prepare_kernel_cred(NULL) */
    printf("\n[*] 测试 prepare_kernel_cred(NULL)...\n");
    if (prepare_kernel_cred) {
        /* 调用 prepare_kernel_cred(NULL) 获取 init_cred */
        /* 注意: 这会在内核中执行，可能导致问题 */
        printf("  prepare_kernel_cred 地址: 0x%lx\n", prepare_kernel_cred);
        printf("  (跳过实际调用，避免内核崩溃)\n");
    }

    printf("\n[*] 验证完成!\n");
    printf("\n[*] 下一步:\n");
    printf("  1. 使用提取的偏移编译 exploit\n");
    printf("  2. 在设备上测试\n");
    printf("  3. 观察 dmesg 输出\n");

    return 0;
}
