// find_syms_via_disasm.c - 通过反汇编已导出函数找未导出符号地址
// 原理: kmem_cache_alloc 内部引用 kmalloc_caches (ADRP+ADD)
//        security_task_alloc 内部引用 security_hook_heads
//        ashmem_mmap 内部引用 ashmem_misc_fops
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

// 获取符号大小 (从 kallsyms 的下一个符号推算)
uint64_t kallsyms_get_size(const char *name) {
    // 简化: 返回固定大小 4096 字节
    return 4096;
}

// 读取内核内存 - 通过 /proc/self/mem (以 root 运行时可读内核地址)
int read_kernel_mem(uint64_t addr, void *buf, size_t size) {
    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, size, (off_t)addr);
    close(fd);
    return (int)n;
}

// 解码 ARM64 ADRP 指令
// ADRP: 1_0000_hi:immlo_1_immhi:19_Rd:5
int decode_adrp(uint32_t instr, uint64_t pc, int64_t *target_page) {
    if ((instr & 0x9f000000) != 0x90000000) return 0;
    int rd = instr & 0x1f;
    int32_t immhi = (int32_t)((instr >> 5) & 0x7ffff);
    uint32_t immlo = (instr >> 29) & 0x3;
    int64_t imm = ((int64_t)(immhi << 2) | immlo) << 12;
    if (imm & 0x100000000000LL) imm -= 0x200000000000LL; // 符号扩展 (48-bit)
    *target_page = (pc & ~0xfffLL) + imm;
    return rd;
}

// 解码 ARM64 ADD (immediate) 指令
// ADD: 1_001000_0_sh:2_imm12:12_Rn:5_Rd:5
int decode_add_imm(uint32_t instr, int expected_rn, uint64_t *imm12_out) {
    if ((instr & 0xffc00000) != 0x91000000) return 0;
    int rd = instr & 0x1f;
    int rn = (instr >> 5) & 0x1f;
    if (rn != expected_rn) return 0;
    uint32_t sh = (instr >> 22) & 0x3;
    uint32_t imm12 = (instr >> 10) & 0xfff;
    if (sh == 1) imm12 <<= 12;
    *imm12_out = imm12;
    return 1;
}

// 解码 ARM64 LDR (immediate, unsigned offset) 指令
// LDR X: 1_1111_01_001_imm12:12_Rn:5_Rt:5
int decode_ldr_imm(uint32_t instr, int expected_rn, uint64_t *offset_out) {
    if ((instr & 0xffc00000) != 0xf9400000) return 0;
    int rt = instr & 0x1f;
    int rn = (instr >> 5) & 0x1f;
    if (rn != expected_rn) return 0;
    uint32_t imm12 = (instr >> 10) & 0xfff;
    *offset_out = (uint64_t)imm12 * 8; // 每单位 8 字节 (X 寄存器)
    return 1;
}

void analyze_function(const char *func_name, uint64_t func_addr, const char *target_desc) {
    printf("\n=== 分析 %s (0x%lx) ===\n", func_name, func_addr);
    printf("目标: 找 %s\n", target_desc);

    uint8_t code[4096];
    if (read_kernel_mem(func_addr, code, sizeof(code)) != sizeof(code)) {
        printf("错误: 无法读取函数代码\n");
        return;
    }

    int found = 0;
    for (int i = 0; i < sizeof(code) - 8; i += 4) {
        uint32_t instr = *(uint32_t *)(code + i);
        int64_t target_page = 0;
        int rd = decode_adrp(instr, func_addr + i, &target_page);
        if (rd < 0) continue;

        // 检查下一条是否是 ADD
        uint32_t next = *(uint32_t *)(code + i + 4);
        uint64_t imm12 = 0;
        if (decode_add_imm(next, rd, &imm12)) {
            uint64_t target = target_page + imm12;
            if (target > 0xffffff0000000000ULL) {
                printf("  ADRP+ADD @ +%d: 目标=0x%lx\n", i, target);
                found++;
            }
        }

        // 检查下一条是否是 LDR (从目标页加载)
        uint32_t next2 = *(uint32_t *)(code + i + 4);
        uint64_t ldr_off = 0;
        if (decode_ldr_imm(next2, rd, &ldr_off)) {
            uint64_t target = target_page + ldr_off;
            if (target > 0xffffff0000000000ULL) {
                printf("  ADRP+LDR @ +%d: 目标=0x%lx (读取值)\n", i, target);
                found++;
            }
        }
    }

    if (!found) {
        printf("  未找到 ADRP 引用\n");
    }
}

int main() {
    printf("=== 通过反汇编找未导出符号 ===\n\n");

    // 1. 找 kmalloc_caches (通过 kmem_cache_alloc)
    uint64_t kmem_cache_alloc_addr = kallsyms_lookup("kmem_cache_alloc");
    if (kmem_cache_alloc_addr) {
        analyze_function("kmem_cache_alloc", kmem_cache_alloc_addr, "kmalloc_caches");
    }

    // 2. 找 security_hook_heads (通过 security_task_alloc)
    uint64_t security_task_alloc_addr = kallsyms_lookup("security_task_alloc");
    if (security_task_alloc_addr) {
        analyze_function("security_task_alloc", security_task_alloc_addr, "security_hook_heads");
    }

    // 3. 找 ashmem_misc_fops (通过 ashmem_mmap)
    uint64_t ashmem_mmap_addr = kallsyms_lookup("ashmem_mmap");
    if (ashmem_mmap_addr) {
        analyze_function("ashmem_mmap", ashmem_mmap_addr, "ashmem_misc_fops");
    }

    // 4. 找 selinux_blob_sizes (通过 selinux_cred_alloc)
    uint64_t selinux_cred_alloc_addr = kallsyms_lookup("selinux_cred_alloc");
    if (selinux_cred_alloc_addr) {
        analyze_function("selinux_cred_alloc", selinux_cred_alloc_addr, "selinux_blob_sizes");
    } else {
        printf("\n=== selinux_cred_alloc 未找到，尝试其他函数 ===\n");
        uint64_t selinux_task_alloc = kallsyms_lookup("selinux_task_alloc");
        if (selinux_task_alloc) {
            analyze_function("selinux_task_alloc", selinux_task_alloc, "selinux_blob_sizes");
        }
    }

    printf("\n=== 完成 ===\n");
    return 0;
}
