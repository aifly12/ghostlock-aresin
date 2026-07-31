// extract_via_proc.c - 通过 /proc 接口提取未导出内核符号偏移
// 策略:
//   1. kmalloc_caches: 通过 /proc/slabinfo 或 /sys/kernel/slab/ 获取
//   2. ashmem_misc_fops: 通过 /proc/self/fdinfo 获取 file 结构体
//   3. security_hook_heads: 通过 /proc/self/attr 获取
//   4. selinux_blob_sizes: 通过 /proc/self/attr 获取
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
    printf("=== /proc 偏移提取 ===\n\n");

    uint64_t _stext = ksym("_stext");
    printf("_stext = 0x%lx\n\n", _stext);

    // ---- 1. 通过 /sys/kernel/slab/ 找 kmalloc_caches ----
    printf("=== /sys/kernel/slab/ ===\n");
    DIR *dir = opendir("/sys/kernel/slab");
    if (dir) {
        struct dirent *ent;
        int count = 0;
        while ((ent = readdir(dir)) != NULL && count < 20) {
            if (ent->d_name[0] == '.') continue;
            // 读取 object_size
            char path[512];
            snprintf(path, sizeof(path), "/sys/kernel/slab/%s/object_size", ent->d_name);
            FILE *fp = fopen(path, "r");
            if (fp) {
                char buf[64];
                if (fgets(buf, sizeof(buf), fp)) {
                    int size = atoi(buf);
                    if (size > 0 && size <= 8192) {
                        printf("  %s: object_size=%d\n", ent->d_name, size);
                    }
                }
                fclose(fp);
                count++;
            }
        }
        closedir(dir);
    }

    // ---- 2. 通过 /proc/slabinfo 找 kmalloc_caches ----
    printf("\n=== /proc/slabinfo ===\n");
    FILE *fp = fopen("/proc/slabinfo", "r");
    if (fp) {
        char line[512];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 30) {
            if (strstr(line, "kmalloc") || strstr(line, "size-") || strstr(line, "#")) {
                printf("  %s", line);
            }
            count++;
        }
        fclose(fp);
    } else {
        printf("  not available\n");
    }

    // ---- 3. 通过 /proc/vmallocinfo 找内核地址 ----
    printf("\n=== /proc/vmallocinfo ===\n");
    fp = fopen("/proc/vmallocinfo", "r");
    if (fp) {
        char line[512];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 10) {
            printf("  %s", line);
            count++;
        }
        fclose(fp);
    }

    // ---- 4. 通过 /proc/kallsyms 找已导出的安全符号 ----
    printf("\n=== 安全相关符号 ===\n");
    const char *syms[] = {
        "security_file_open", "security_task_alloc", "security_cred_alloc",
        "selinux_cred_alloc", "selinux_task_alloc", "selinux_file_open",
        "ashmem_mmap", "ashmem_ioctl", "ashmem_open", "ashmem_release",
        NULL
    };
    for (int i = 0; syms[i]; i++) {
        uint64_t addr = ksym(syms[i]);
        if (addr) {
            printf("  %s = 0x%lx (offset 0x%lx)\n", syms[i], addr, addr - _stext);
        }
    }

    // ---- 5. 通过 /proc/self/fdinfo 找 file 结构体 ----
    printf("\n=== /proc/self/fdinfo ===\n");
    int fd = open("/dev/ashmem", O_RDWR);
    if (fd >= 0) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
        fp = fopen(path, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                printf("  %s", line);
            }
            fclose(fp);
        }
        close(fd);
    }

    // ---- 6. 通过 /proc/self/attr 找 SELinux 信息 ----
    printf("\n=== /proc/self/attr ===\n");
    const char *attrs[] = {"current", "exec", "fscreate", "keycreate", "sockcreate"};
    for (int i = 0; i < 5; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/attr/%s", attrs[i]);
        fp = fopen(path, "r");
        if (fp) {
            char buf[256];
            if (fgets(buf, sizeof(buf), fp)) {
                printf("  %s: %s", attrs[i], buf);
            }
            fclose(fp);
        }
    }

    printf("\n=== 完成 ===\n");
    return 0;
}
