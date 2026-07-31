// find_offsets.c - 在设备上运行，通过 /proc/kallsyms 和暴力搜索找内核符号偏移
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

// 从 kallsyms 读取符号地址
uint64_t kallsyms_lookup(const char *name) {
    FILE *fp = popen("cat /proc/kallsyms 2>/dev/null", "r");
    if (!fp) return 0;

    char line[512];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        // Format: "addr type name\t[module]"
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

int main() {
    printf("=== GhostLock Offset Finder ===\n");
    printf("Device: aresin (MT6893, 4.14.186)\n\n");

    // 已知符号
    uint64_t noop_llseek = kallsyms_lookup("noop_llseek");
    uint64_t confirm = kallsyms_lookup("generic_pipe_buf_confirm");
    uint64_t release = kallsyms_lookup("generic_pipe_buf_release");
    uint64_t steal = kallsyms_lookup("generic_pipe_buf_steal");
    uint64_t get = kallsyms_lookup("generic_pipe_buf_get");
    uint64_t nosteal = kallsyms_lookup("generic_pipe_buf_nosteal");

    printf("已解析符号:\n");
    printf("  noop_llseek:              0x%lx\n", noop_llseek);
    printf("  generic_pipe_buf_confirm: 0x%lx\n", confirm);
    printf("  generic_pipe_buf_release: 0x%lx\n", release);
    printf("  generic_pipe_buf_steal:   0x%lx\n", steal);
    printf("  generic_pipe_buf_get:     0x%lx\n", get);
    printf("  generic_pipe_buf_nosteal: 0x%lx\n", nosteal);

    if (confirm && release && steal && get) {
        printf("\ngeneric_pipe_buf_ops 结构体布局:\n");
        printf("  confirm @ offset 0x00: 0x%lx\n", confirm);
        printf("  release @ offset 0x08: 0x%lx\n", release);
        printf("  steal   @ offset 0x10: 0x%lx\n", steal);
        printf("  get     @ offset 0x18: 0x%lx\n", get);
    }

    // 尝试通过 create_kmalloc_caches 找 kmalloc_caches
    uint64_t create_km = kallsyms_lookup("create_kmalloc_caches");
    printf("\ncreate_kmalloc_caches: 0x%lx\n", create_km);

    // 尝试找其他相关符号
    uint64_t kmalloc_info = kallsyms_lookup("kmalloc_info");
    uint64_t kmem_cache_alloc = kallsyms_lookup("kmem_cache_alloc");
    printf("kmalloc_info: 0x%lx\n", kmalloc_info);
    printf("kmem_cache_alloc: 0x%lx\n", kmem_cache_alloc);

    printf("\n=== 完成 ===\n");
    printf("注意: kmalloc_caches, selinux_blob_sizes, security_hook_heads, ashmem_misc_fops\n");
    printf("是未导出符号，不在 kallsyms 中。需要从 vmlinux 分析或内核内存读取。\n");

    return 0;
}
