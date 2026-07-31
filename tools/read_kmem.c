// read_kmem.c - 以 root 读内核内存，找未导出符号
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf jump_buf;

static void segv_handler(int sig) {
    siglongjmp(jump_buf, 1);
}

uint64_t kallsyms_lookup(const char *name) {
    FILE *fp = popen("cat /proc/kallsyms 2>/dev/null", "r");
    if (!fp) return 0;
    char line[512];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = strchr(line, ' ');
        if (!p) continue;
        p++;
        char *t = strchr(p, ' ');
        if (!t) continue;
        t++;
        char *nl = strchr(t, '\n');
        if (nl) *nl = 0;
        char *tab = strchr(t, '\t');
        if (tab) *tab = 0;
        if (strcmp(t, name) == 0) {
            addr = strtoull(line, NULL, 16);
            break;
        }
    }
    pclose(fp);
    return addr;
}

// 安全读取内核内存 (捕获 SIGSEGV)
int safe_read(uint64_t addr, void *buf, int size) {
    struct sigaction sa, old_sa;
    sa.sa_handler = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_sa);

    if (sigsetjmp(jump_buf, 1) == 0) {
        memcpy(buf, (void *)addr, size);
        sigaction(SIGSEGV, &old_sa, NULL);
        return 1;
    }
    sigaction(SIGSEGV, &old_sa, NULL);
    return 0;
}

// 解码 ADRP+ADD，返回目标地址
uint64_t decode_adrp_add(uint32_t *code, uint64_t pc) {
    uint32_t instr = code[0];
    if ((instr & 0x9f000000) != 0x90000000) return 0;

    int rd = instr & 0x1f;
    int32_t immhi = (int32_t)((instr >> 5) & 0x7ffff);
    uint32_t immlo = (instr >> 29) & 0x3;
    int64_t imm = ((int64_t)(immhi << 2) | immlo) << 12;
    if (imm & 0x100000000000LL) imm -= 0x200000000000LL;

    uint32_t next = code[1];
    if ((next & 0xffc00000) != 0x91000000) return 0;
    int rd2 = next & 0x1f;
    if (rd != rd2) return 0;

    uint32_t imm12 = (next >> 10) & 0xfff;
    uint32_t sh = (next >> 22) & 0x3;
    if (sh == 1) imm12 <<= 12;

    return ((pc & ~0xfffLL) + imm + imm12);
}

int main() {
    printf("=== 内存扫描找未导出符号 ===\n\n");

    // 读取函数代码并解码
    struct {
        const char *func_name;
        const char *target_name;
    } funcs[] = {
        {"kmem_cache_alloc", "kmalloc_caches"},
        {"security_task_alloc", "security_hook_heads"},
        {"selinux_task_alloc", "selinux_blob_sizes"},
        {"ashmem_mmap", "ashmem_misc_fops"},
        {NULL, NULL}
    };

    for (int f = 0; funcs[f].func_name; f++) {
        uint64_t addr = kallsyms_lookup(funcs[f].func_name);
        if (!addr) {
            printf("[-] %s 未找到\n", funcs[f].func_name);
            continue;
        }
        printf("[*] %s @ 0x%lx, 搜索 %s\n", funcs[f].func_name, addr, funcs[f].target_name);

        uint32_t code[512];
        if (!safe_read(addr, code, sizeof(code))) {
            printf("  [-] 无法读取代码\n");
            continue;
        }

        int found = 0;
        for (int i = 0; i < 400; i++) {
            uint64_t target = decode_adrp_add(&code[i], addr + i * 4);
            if (target > 0xffffff0000000000ULL) {
                // 读取目标地址的值
                uint64_t val = 0;
                safe_read(target, &val, sizeof(val));
                printf("  [+] +%d: ADRP+ADD -> 0x%lx [值=0x%lx]\n", i * 4, target, val);
                found++;
            }
        }
        if (!found) printf("  [-] 未找到 ADRP+ADD 引用\n");
    }

    printf("\n=== 完成 ===\n");
    return 0;
}
