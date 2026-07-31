// rt_offsets.c - 运行时找未导出内核符号偏移
// 策略:
//   1. kmalloc_caches: 通过 /sys/kernel/slab/ 找 slab cache 地址
//   2. ashmem_misc_fops: 通过 /proc/self/fdinfo 找 file 结构体
//   3. security_hook_heads: 通过 /proc/self/attr 找安全钩子
//   4. selinux_blob_sizes: 通过 SELinux 相关操作找
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/ioctl.h>

uint64_t ksym(const char *name) {
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

int main() {
    printf("=== Runtime Offset Finder ===\n\n");

    uint64_t _stext = ksym("_stext");
    printf("_stext = 0x%lx\n\n", _stext);

    // ---- 1. 找 kmalloc_caches ----
    // 方法: 读 /sys/kernel/slab/*/cpu_slabs 找 slab cache 地址
    // 实际上 /sys/kernel/slab/ 不直接暴露地址
    // 但我们可以用 kmem_cache_alloc 的返回值来推算

    // ---- 2. 找 ashmem_misc_fops ----
    // 方法: 打开 /dev/ashmem，通过 /proc/self/fdinfo 找 file 结构体
    printf("=== ashmem_misc_fops ===\n");
    int fd = open("/dev/ashmem", O_RDWR);
    if (fd >= 0) {
        // 读 /proc/self/fdinfo/fd
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
        close(fd);
    }

    // ---- 3. 找 security_hook_heads ----
    // 方法: 读 /proc/self/attr/current 触发安全钩子
    printf("\n=== security_hook_heads ===\n");
    FILE *fp = fopen("/proc/self/attr/current", "r");
    if (fp) {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp)) {
            printf("  current attr: %s", buf);
        }
        fclose(fp);
    }

    // ---- 4. 找 selinux_blob_sizes ----
    printf("\n=== selinux_blob_sizes ===\n");
    fp = fopen("/sys/fs/selinux/status", "r");
    if (fp) {
        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) {
            printf("  selinux status: %s", buf);
        }
        fclose(fp);
    }

    // ---- 5. 尝试通过 /proc/slabinfo 找 kmalloc_caches ----
    printf("\n=== /proc/slabinfo ===\n");
    fp = fopen("/proc/slabinfo", "r");
    if (fp) {
        char line[512];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 20) {
            if (strstr(line, "kmalloc") || strstr(line, "size") || strstr(line, "#")) {
                printf("  %s", line);
            }
            count++;
        }
        fclose(fp);
    } else {
        printf("  /proc/slabinfo not available\n");
    }

    // ---- 6. 尝试通过 /proc/vmallocinfo 找内核地址 ----
    printf("\n=== /proc/vmallocinfo (first 5 lines) ===\n");
    fp = fopen("/proc/vmallocinfo", "r");
    if (fp) {
        char line[512];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 5) {
            printf("  %s", line);
            count++;
        }
        fclose(fp);
    }

    printf("\n=== Done ===\n");
    return 0;
}
