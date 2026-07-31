// find_kmalloc.c - 通过反汇编 create_kmalloc_caches 找 kmalloc_caches 地址
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

uint64_t kallsyms_lookup(const char *name) {
    FILE *fp = popen("cat /proc/kallsyms 2>/dev/null", "r");
    if (!fp) return 0;
    char line[512];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *space1 = strchr(line, ' ');
        if (!space1) continue;
        char *space2 = strchr(space1 + 1, ' ');
        if (!space2) continue;
        char *sym_name = space2 + 1;
        char *tab = strchr(sym_name, '\t');
        if (tab) *tab = 0;
        char *nl = strchr(sym_name, '\n');
        if (nl) *nl = 0;
        if (strcmp(sym_name, name) == 0) {
            addr = strtoull(line, NULL, 16);
            break;
        }
    }
    pclose(fp);
    return addr;
}

// 读取内核内存 (通过 /proc/pid/mem)
int read_kernel_mem(uint64_t addr, void *buf, size_t size) {
    // 使用 init 进程 (pid 1) 的 /proc/1/mem
    int fd = open("/proc/1/mem", O_RDONLY);
    if (fd < 0) return -1;
    lseek(fd, (off_t)addr, SEEK_SET);
    int n = read(fd, buf, size);
    close(fd);
    return n;
}

int main() {
    printf("=== kmalloc_caches 查找器 ===\n\n");

    uint64_t create_km = kallsyms_lookup("create_kmalloc_caches");
    if (!create_km) {
        printf("错误: 找不到 create_kmalloc_caches\n");
        return 1;
    }

    printf("create_kmalloc_caches @ 0x%lx\n", create_km);

    // 读取 create_kmalloc_caches 函数的前 256 字节
    uint8_t code[256];
    if (read_kernel_mem(create_km, code, sizeof(code)) != sizeof(code)) {
        printf("错误: 无法读取内核内存\n");
        return 1;
    }

    printf("读取了 %lu 字节的函数代码\n", sizeof(code));

    // ARM64 ADRP+ADD 模式找 kmalloc_caches 地址
    // ADRP: 10000000 + immlo(2) + 1 + immhi(19) + Rd(5)
    // ADD:  10010000 + shift(2) + imm12(12) + Rn(5) + Rd(5)

    for (int i = 0; i < sizeof(code) - 8; i += 4) {
        uint32_t instr = *(uint32_t *)(code + i);

        // 检查 ADRP 指令
        if ((instr & 0x9f000000) == 0x90000000) {
            int rd = instr & 0x1f;
            int32_t immhi = (int32_t)(instr & 0xffffe0) >> 3;
            uint32_t next = *(uint32_t *)(code + i + 4);

            // 检查下一条是否是 ADD
            if ((next & 0xffc00000) == 0x91000000) {
                int rd2 = next & 0x1f;
                if (rd == rd2) {
                    uint32_t imm12 = (next >> 10) & 0xfff;
                    uint64_t page = (create_km + i) & ~0xfffULL;
                    int32_t adrp_imm = (immhi | ((instr >> 29) & 3)) << 2;
                    if (adrp_imm & 0x100000) adrp_imm -= 0x200000; // 符号扩展
                    page += adrp_imm;
                    uint64_t target = page + imm12;

                    // 检查是否是合理的内核地址
                    if (target > 0xffffff0000000000ULL) {
                        printf("\n发现 ADRP+ADD 模式 @ offset %d:\n", i);
                        printf("  指令: 0x%08x 0x%08x\n", instr, next);
                        printf("  目标地址: 0x%lx\n", target);
                        printf("  寄存器: x%d\n", rd);

                        // 读取目标地址的值
                        uint64_t val;
                        if (read_kernel_mem(target, &val, sizeof(val)) == sizeof(val)) {
                            printf("  [0x%lx] = 0x%lx\n", target, val);
                        }

                        // 如果这个地址看起来像 slab cache 指针，可能是 kmalloc_caches
                        if (target > 0xffffff0000000000ULL && target < 0xffffffffffffffffULL) {
                            printf("  *** 可能是 kmalloc_caches @ 0x%lx ***\n", target);
                        }
                    }
                }
            }
        }
    }

    printf("\n=== 完成 ===\n");
    return 0;
}
