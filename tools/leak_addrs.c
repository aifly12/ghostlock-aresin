// leak_addrs.c - 通过内核接口泄漏未导出符号地址
// 策略:
//   1. kmalloc_caches: 通过 pipe + /proc/self/pagemap 找 slab 地址
//   2. ashmem_misc_fops: 通过 ioctl(ASHMEM_GET_NAME) 触发 fops 调用
//   3. security_hook_heads: 通过 prctl 找安全钩子
//   4. selinux_blob_sizes: 通过 /proc/self/attr 找
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>

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
    printf("=== Leak Addresses ===\n\n");

    uint64_t _stext = ksym("_stext");
    printf("_stext = 0x%lx\n", _stext);

    // ---- 方法1: 通过 pipe 找 kmalloc_caches ----
    // 创建 pipe，pipe 的 buffer 是通过 kmalloc 分配的
    // 我们可以通过 /proc/self/pagemap 找到物理地址
    printf("\n=== pipe buffer leak ===\n");
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        // 写入一些数据到 pipe
        write(pipefd[1], "AAAAAAAA", 8);

        // 读取 /proc/self/pagemap 找物理地址
        int pm_fd = open("/proc/self/pagemap", O_RDONLY);
        if (pm_fd >= 0) {
            // 获取 pipe buffer 的虚拟地址
            // 通过 fcntl F_GETPIPE_BUFSIZE 获取 pipe buffer 大小
            int bufsize = fcntl(pipefd[0], F_GETPIPE_SZ);
            printf("  pipe buffer size: %d\n", bufsize);

            // 读取 pipe buffer 的内容
            char buf[64];
            read(pipefd[0], buf, 8);
            printf("  pipe buffer content: %.*s\n", 8, buf);

            close(pm_fd);
        }
        close(pipefd[0]);
        close(pipefd[1]);
    }

    // ---- 方法2: 通过 ashmem ioctl 找 ashmem_misc_fops ----
    printf("\n=== ashmem ioctl leak ===\n");
    int ashfd = open("/dev/ashmem", O_RDWR);
    if (ashfd >= 0) {
        // ASHMEM_GET_NAME
        char name[256] = {0};
        // 定义 ASHMEM_GET_NAME ioctl
        #define ASHMEM_GET_NAME 0x00007703  // _IOR(__ASHMEMIOC, 3, char[ASHMEM_NAME_LEN])
        int ret = ioctl(ashfd, ASHMEM_GET_NAME, name);
        printf("  ASHMEM_GET_NAME: ret=%d name='%s'\n", ret, name);

        // ASHMEM_SET_NAME
        #define ASHMEM_SET_NAME 0x40007701  // _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
        ret = ioctl(ashfd, ASHMEM_SET_NAME, "test_ashmem");
        printf("  ASHMEM_SET_NAME: ret=%d\n", ret);

        // ASHMEM_GET_SIZE
        #define ASHMEM_GET_SIZE 0x00007704  // _IO(__ASHMEMIOC, 4)
        int size = ioctl(ashfd, ASHMEM_GET_SIZE);
        printf("  ASHMEM_GET_SIZE: %d\n", size);

        close(ashfd);
    }

    // ---- 方法3: 通过 prctl 找 security_hook_heads ----
    printf("\n=== prctl leak ===\n");
    // prctl(PR_GET_NAME) 触发 security_task_alloc
    char comm[16];
    int ret = prctl(PR_GET_NAME, comm, 0, 0, 0);
    printf("  PR_GET_NAME: ret=%d comm='%s'\n", ret, comm);

    // prctl(PR_GET_SECCOMP) 触发安全检查
    int seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    printf("  PR_GET_SECCOMP: %d\n", seccomp);

    // ---- 方法4: 通过 /proc/self/attr 找 selinux ----
    printf("\n=== selinux leak ===\n");
    FILE *fp = fopen("/proc/self/attr/current", "r");
    if (fp) {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp)) {
            printf("  current: %s", buf);
        }
        fclose(fp);
    }

    fp = fopen("/proc/self/attr/exec", "r");
    if (fp) {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp)) {
            printf("  exec: %s", buf);
        }
        fclose(fp);
    }

    // ---- 方法5: 通过 /sys/kernel/slab 找 kmalloc_caches ----
    printf("\n=== /sys/kernel/slab ===\n");
    // 读取 kmalloc-8 的信息
    fp = fopen("/sys/kernel/slab/kmalloc-8/object_size", "r");
    if (fp) {
        char buf[64];
        if (fgets(buf, sizeof(buf), fp)) {
            printf("  kmalloc-8 object_size: %s", buf);
        }
        fclose(fp);
    }

    fp = fopen("/sys/kernel/slab/kmalloc-16/object_size", "r");
    if (fp) {
        char buf[64];
        if (fgets(buf, sizeof(buf), fp)) {
            printf("  kmalloc-16 object_size: %s", buf);
        }
        fclose(fp);
    }

    printf("\n=== Done ===\n");
    return 0;
}
