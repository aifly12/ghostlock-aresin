#!/system/bin/sh
# find_via_device.sh - 在设备上运行，提取内核符号地址
# 需要 root 权限

echo "============================================"
echo "  内核符号地址提取 - POCO F3 GT (aresin)"
echo "============================================"
echo ""

# 确保 kptr_restrict=0
echo "0" > /proc/sys/kernel/kptr_restrict

echo "[*] 关键函数地址:"
echo "----------------------------------------"
grep -E "commit_creds|prepare_kernel_cred|rt_mutex_init_waiter|remove_waiter" /proc/kallsyms | head -10
echo ""

echo "[*] 搜索 init_task 相关符号:"
echo "----------------------------------------"
grep -E "init_task|idle_task|fork_init" /proc/kallsyms | head -20
echo ""

echo "[*] 搜索 init_cred 相关符号:"
echo "----------------------------------------"
grep -E "init_cred|prepare_kernel_cred|commit_creds" /proc/kallsyms | head -20
echo ""

echo "[*] 搜索 selinux 相关符号:"
echo "----------------------------------------"
grep -E "selinux_enforcing|selinux_state|enforcing_setup" /proc/kallsyms | head -10
echo ""

echo "[*] 搜索 per_cpu 相关符号:"
echo "----------------------------------------"
grep -E "__per_cpu_offset|per_cpu__" /proc/kallsyms | head -10
echo ""

echo "[*] 搜索 task_group 相关符号:"
echo "----------------------------------------"
grep -E "root_task_group|task_group" /proc/kallsyms | head -10
echo ""

echo "[*] 尝试从 prepare_kernel_cred 读取 init_cred 指针:"
echo "----------------------------------------"
# prepare_kernel_cred @ 0xffffff939bce4578
# ADRP+LDR at +0x10/+0x18 loads from 0xffffff939dae3850
echo "prepare_kernel_cred loads init_cred from pointer at 0xffffff939dae3850"
echo "Reading the pointer value..."
# Try to read from /proc/kcore
if [ -r /proc/kcore ]; then
    # Calculate file offset for /proc/kcore
    # /proc/kcore is an ELF file, the data starts at offset 0x1000 typically
    # But the virtual address mapping is different
    echo "  /proc/kcore is readable"
    # Use dd to read 8 bytes at the virtual address
    # This might not work directly, but worth trying
    dd if=/proc/kcore bs=1 count=8 skip=$((0xffffff939dae3850)) 2>/dev/null | xxd
else
    echo "  /proc/kcore not readable"
fi
echo ""

echo "[*] 尝试通过 kallsyms 查找 init_task:"
echo "----------------------------------------"
# init_task is typically referenced by many functions
# Let's look for functions that explicitly reference it
grep -E "T idle_threads$|D init_task$|D init_cred$" /proc/kallsyms
echo ""

echo "[*] 查找 swapper/0 相关:"
echo "----------------------------------------"
grep "swapper" /proc/kallsyms | head -5
echo ""

echo "============================================"
echo "[*] 提取完成!"
echo "============================================"
