// fill_offsets.c - 在 aresin 设备上运行，找未导出内核符号偏移并生成 target.h 片段
// 原理:
//   1. 通过 kallsyms 找已导出函数地址
//   2. 通过 mmap + /proc/self/mem 尝试读内核代码段
//   3. 通过 create_kmalloc_caches 反汇编找 kmalloc_caches
//   4. 通过安全相关函数找 selinux_blob_sizes / security_hook_heads
//   5. 通过 ashmem ioctl 找 ashmem_misc_fops
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf jmp_env;
static volatile int got_segv = 0;
static void segv_handler(int sig) { got_segv = 1; siglongjmp(jmp_env, 1); }

// 安全读取内核地址 (捕获 SIGSEGV)
static int safe_read64(uint64_t addr, uint64_t *out) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = segv_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old);
    got_segv = 0;
    if (sigsetjmp(jmp_env, 1) == 0) {
        *out = *(volatile uint64_t *)(uintptr_t)addr;
        sigaction(SIGSEGV, &old, NULL);
        return 1;
    }
    sigaction(SIGSEGV, &old, NULL);
    return 0;
}

static int safe_read32(uint64_t addr, uint32_t *out) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = segv_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old);
    got_segv = 0;
    if (sigsetjmp(jmp_env, 1) == 0) {
        *out = *(volatile uint32_t *)(uintptr_t)addr;
        sigaction(SIGSEGV, &old, NULL);
        return 1;
    }
    sigaction(SIGSEGV, &old, NULL);
    return 0;
}

static uint64_t ksym(const char *name) {
    FILE *fp = popen("cat /proc/kallsyms 2>/dev/null", "r");
    if (!fp) return 0;
    char line[512];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *sp1 = strchr(line, ' ');
        if (!sp1) continue;
        char *sp2 = strchr(sp1 + 1, ' ');
        if (!sp2) continue;
        char *nm = sp2 + 1;
        char *tab = strchr(nm, '\t');
        if (tab) *tab = 0;
        char *nl = strchr(nm, '\n');
        if (nl) *nl = 0;
        if (strcmp(nm, name) == 0) {
            addr = strtoull(line, NULL, 16);
            break;
        }
    }
    pclose(fp);
    return addr;
}

// ARM64 ADRP + ADD 解码
static uint64_t decode_adrp_add(uint32_t adrp, uint32_t add, uint64_t pc) {
    if ((adrp & 0x9f000000) != 0x90000000) return 0;
    if ((add  & 0xffc00000) != 0x91000000) return 0;
    int rd_adrp = adrp & 0x1f;
    int rd_add  = add & 0x1f;
    if (rd_adrp != rd_add) return 0;

    int32_t immhi = (int32_t)((adrp >> 5) & 0x7ffff);
    uint32_t immlo = (adrp >> 29) & 0x3;
    int64_t imm = ((int64_t)(immhi << 2) | immlo) << 12;
    if (imm & 0x100000000000LL) imm -= 0x200000000000LL;

    uint32_t imm12 = (add >> 10) & 0xfff;
    uint32_t sh = (add >> 22) & 0x3;
    if (sh == 1) imm12 <<= 12;

    return ((pc & ~0xfffULL) + imm + imm12);
}

// 扫描函数找 ADRP+ADD 引用
static int scan_func_adrp(uint64_t func_addr, int max_instr, uint64_t *results, int max_results) {
    int count = 0;
    for (int i = 0; i < max_instr && count < max_results; i++) {
        uint32_t instr;
        if (!safe_read32(func_addr + i * 4, &instr)) break;
        if ((instr & 0x9f000000) != 0x90000000) continue;
        uint32_t next;
        if (!safe_read32(func_addr + (i + 1) * 4, &next)) continue;
        uint64_t target = decode_adrp_add(instr, next, func_addr + i * 4);
        if (target > 0xffffff0000000000ULL) {
            results[count++] = target;
        }
    }
    return count;
}

// ADRP + LDR 解码 (用于找指针加载)
static uint64_t decode_adrp_ldr(uint32_t adrp, uint32_t ldr, uint64_t pc) {
    if ((adrp & 0x9f000000) != 0x90000000) return 0;
    if ((ldr & 0xffc00000) != 0xf9400000) return 0; // LDR X imm
    int rd_adrp = adrp & 0x1f;
    int rn_ldr = (ldr >> 5) & 0x1f;
    if (rd_adrp != rn_ldr) return 0;

    int32_t immhi = (int32_t)((adrp >> 5) & 0x7ffff);
    uint32_t immlo = (adrp >> 29) & 0x3;
    int64_t imm = ((int64_t)(immhi << 2) | immlo) << 12;
    if (imm & 0x100000000000LL) imm -= 0x200000000000LL;

    uint32_t imm12 = (ldr >> 10) & 0xfff;
    return ((pc & ~0xfffULL) + imm + imm12 * 8);
}

int main() {
    printf("=== aresin offset finder ===\n\n");

    uint64_t base = ksym("_text");
    printf("_text = 0x%lx\n", base);

    // ---- 1. kmalloc_caches ----
    // kmem_cache_alloc 引用 kmalloc_caches (ADRP+ADD 或 ADRP+LDR)
    uint64_t kca = ksym("kmem_cache_alloc");
    printf("[*] kmem_cache_alloc = 0x%lx\n", kca);
    if (kca) {
        // 扫描前 200 条指令找所有 ADRP+ADD 目标
        uint64_t targets[32];
        int n = scan_func_adrp(kca, 200, targets, 32);
        printf("  ADRP+ADD targets (%d):\n", n);
        for (int i = 0; i < n; i++) {
            uint64_t val = 0;
            safe_read64(targets[i], &val);
            printf("    [%d] 0x%lx -> 0x%lx\n", i, targets[i], val);
        }
        // kmalloc_caches 是一个全局数组，地址应该是 .data/.bss 段
        // 通常第一个 ADRP+ADD 就是它
        if (n > 0) {
            printf("  -> kmalloc_caches 可能 @ 0x%lx\n", targets[0]);
        }
    }

    // ---- 2. selinux_blob_sizes ----
    // security_task_alloc 或 selinux_cred_alloc 引用
    uint64_t sta = ksym("security_task_alloc");
    printf("\n[*] security_task_alloc = 0x%lx\n", sta);
    if (sta) {
        uint64_t targets[32];
        int n = scan_func_adrp(sta, 100, targets, 32);
        printf("  ADRP+ADD targets (%d):\n", n);
        for (int i = 0; i < n; i++) {
            uint64_t val = 0;
            safe_read64(targets[i], &val);
            printf("    [%d] 0x%lx -> 0x%lx\n", i, targets[i], val);
        }
    }

    // ---- 3. security_hook_heads ----
    // 通过 security_file_open 或类似函数
    uint64_t sfo = ksym("security_file_open");
    printf("\n[*] security_file_open = 0x%lx\n", sfo);
    if (sfo) {
        uint64_t targets[32];
        int n = scan_func_adrp(sfo, 100, targets, 32);
        printf("  ADRP+ADD targets (%d):\n", n);
        for (int i = 0; i < n; i++) {
            uint64_t val = 0;
            safe_read64(targets[i], &val);
            printf("    [%d] 0x%lx -> 0x%lx\n", i, targets[i], val);
        }
    }

    // ---- 4. ashmem_misc_fops ----
    // ashmem_mmap 引用 ashmem_misc_fops
    uint64_t am = ksym("ashmem_mmap");
    printf("\n[*] ashmem_mmap = 0x%lx\n", am);
    if (am) {
        uint64_t targets[32];
        int n = scan_func_adrp(am, 100, targets, 32);
        printf("  ADRP+ADD targets (%d):\n", n);
        for (int i = 0; i < n; i++) {
            uint64_t val = 0;
            safe_read64(targets[i], &val);
            printf("    [%d] 0x%lx -> 0x%lx\n", i, targets[i], val);
        }
    }

    // ---- 5. configfs_read_iter ----
    uint64_t cri = ksym("configfs_read_iter");
    printf("\n[*] configfs_read_iter = 0x%lx\n", cri);

    // ---- 6. copy_splice_read ----
    uint64_t csr = ksym("copy_splice_read");
    printf("[*] copy_splice_read = 0x%lx\n", csr);

    // ---- 7. noop_llseek ----
    uint64_t nl = ksym("noop_llseek");
    printf("[*] noop_llseek = 0x%lx\n", nl);

    // ---- 8. generic_pipe_buf_ops (通过 generic_pipe_buf_confirm 间接)
    uint64_t gpbc = ksym("generic_pipe_buf_confirm");
    uint64_t gpbr = ksym("generic_pipe_buf_release");
    printf("[*] generic_pipe_buf_confirm = 0x%lx\n", gpbc);
    printf("[*] generic_pipe_buf_release = 0x%lx\n", gpbr);
    // confirm 是 ops 的第一个函数指针，所以 ops 地址 = confirm 地址所在位置
    // 但我们需要找到指向 confirm 的指针位置，这更复杂

    printf("\n=== done ===\n");
    return 0;
}
