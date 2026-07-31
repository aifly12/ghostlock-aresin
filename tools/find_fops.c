// find_fops.c - 通过打开 /dev/ashmem 找 ashmem_misc_fops 地址
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf jump_buf;
static void segv_handler(int sig) { siglongjmp(jump_buf, 1); }

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

int main() {
    printf("=== 通过 /dev/ashmem 找 ashmem_misc_fops ===\n\n");

    // 打开 /dev/ashmem
    int fd = open("/dev/ashmem", O_RDWR);
    if (fd < 0) {
        printf("[-] 无法打开 /dev/ashmem\n");
        return 1;
    }
    printf("[+] /dev/ashmem fd = %d\n", fd);

    // 读取 /proc/self/fdinfo/N 找 file 结构体地址
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    FILE *fp = fopen(path, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            printf("  fdinfo: %s", line);
        }
        fclose(fp);
    }

    // 通过 /proc/self/fd/ 符号链接找 file 结构体
    char link[256];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(path, link, sizeof(link)-1);
    if (n > 0) {
        link[n] = 0;
        printf("[+] fd symlink: %s\n", link);
    }

    // 尝试通过 /proc/self/maps 找内核地址映射
    fp = fopen("/proc/self/maps", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "vdso") || strstr(line, "vvar")) {
                printf("  maps: %s", line);
            }
        }
        fclose(fp);
    }

    close(fd);

    // 尝试直接读取 ashmem_misc_fops
    // 从 kallsyms 找 ashmem_mmap
    uint64_t ashmem_mmap = kallsyms_lookup("ashmem_mmap");
    printf("\n[*] ashmem_mmap @ 0x%lx\n", ashmem_mmap);

    if (ashmem_mmap) {
        // 读取 ashmem_mmap 函数代码
        uint32_t code[256];
        if (safe_read(ashmem_mmap, code, sizeof(code))) {
            // 搜索 ADRP+ADD 模式找引用
            for (int i = 0; i < 200; i++) {
                uint32_t instr = code[i];
                if ((instr & 0x9f000000) == 0x90000000) {
                    int rd = instr & 0x1f;
                    int32_t immhi = (int32_t)((instr >> 5) & 0x7ffff);
                    uint32_t immlo = (instr >> 29) & 0x3;
                    int64_t imm = ((int64_t)(immhi << 2) | immlo) << 12;
                    if (imm & 0x100000000000LL) imm -= 0x200000000000LL;

                    uint32_t next = code[i+1];
                    if ((next & 0xffc00000) == 0x91000000) {
                        int rd2 = next & 0x1f;
                        if (rd == rd2) {
                            uint32_t imm12 = (next >> 10) & 0xfff;
                            uint64_t target = ((ashmem_mmap + i*4) & ~0xfffLL) + imm + imm12;
                            if (target > 0xffffff0000000000ULL) {
                                uint64_t val = 0;
                                safe_read(target, &val, sizeof(val));
                                printf("  [+%d] ADRP+ADD -> 0x%lx [值=0x%lx]\n", i*4, target, val);
                            }
                        }
                    }
                }
            }
        } else {
            printf("[-] 无法读取 ashmem_mmap 代码\n");
        }
    }

    printf("\n=== 完成 ===\n");
    return 0;
}
