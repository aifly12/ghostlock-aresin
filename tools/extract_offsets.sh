#!/system/bin/sh
# extract_offsets.sh - 在设备上运行，提取 GhostLock 所需偏移
# 用法: adb push tools/extract_offsets.sh /data/local/tmp/ && adb shell sh /data/local/tmp/extract_offsets.sh
#
# 注意: 部分提取需要 root (Magisk)，无 root 时只提取 /proc/kallsyms 可见内容

echo "============================================"
echo "  GhostLock 偏移提取工具 - POCO F3 GT (aresin)"
echo "  Kernel: $(uname -r)"
echo "============================================"
echo ""

OUTPUT="/data/local/tmp/ghostlock_offsets.txt"

echo "[*] 基础设备信息" | tee $OUTPUT
echo "----------------------------------------" | tee -a $OUTPUT
echo "Model: $(getprop ro.product.model)" | tee -a $OUTPUT
echo "Device: $(getprop ro.product.device)" | tee -a $OUTPUT
echo "Platform: $(getprop ro.board.platform)" | tee -a $OUTPUT
echo "Android: $(getprop ro.build.version.release)" | tee -a $OUTPUT
echo "Build: $(getprop ro.build.display.id)" | tee -a $OUTPUT
echo "Kernel: $(uname -r)" | tee -a $OUTPUT
echo "Arch: $(uname -m)" | tee -a $OUTPUT
echo "" | tee -a $OUTPUT

echo "[*] 内核配置检查" | tee -a $OUTPUT
echo "----------------------------------------" | tee -a $OUTPUT
if [ -f /proc/config.gz ]; then
    zcat /proc/config.gz | grep -E "CONFIG_FUTEX_PI|CONFIG_RT_MUTEXES|CONFIG_PREEMPT|CONFIG_RANDOMIZE_KSTACK|CONFIG_KASLR" | tee -a $OUTPUT
else
    echo "[!] /proc/config.gz 不可用，需要 root 或从 boot.img 提取" | tee -a $OUTPUT
fi
echo "" | tee -a $OUTPUT

echo "[*] 从 /proc/kallsyms 提取内核符号地址" | tee -a $OUTPUT
echo "----------------------------------------" | tee -a $OUTPUT
echo "[!] 注意: Android 内核通常对非 root 进程隐藏 kallsyms" | tee -a $OUTPUT
echo "[!] 如果全部显示 0，需要 root 或从 vmlinux 提取" | tee -a $OUTPUT
echo "" | tee -a $OUTPUT

# 关键符号提取
for sym in init_task init_cred entry_task __per_cpu_offset root_task_group selinux_enforcing; do
    addr=$(cat /proc/kallsyms 2>/dev/null | grep -w "$sym" | head -1 | awk '{print $1}')
    if [ -n "$addr" ] && [ "$addr" != "0000000000000000" ]; then
        echo "  $sym = 0x$addr" | tee -a $OUTPUT
    else
        echo "  $sym = [需要 root 或 vmlinux 提取]" | tee -a $OUTPUT
    fi
done
echo "" | tee -a $OUTPUT

echo "[*] rt_mutex_waiter 结构体信息" | tee -a $OUTPUT
echo "----------------------------------------" | tee -a $OUTPUT
echo "[!] 以下需要从 vmlinux 提取 (pahole 或 Ghidra)" | tee -a $OUTPUT
echo "" | tee -a $OUTPUT

echo "[*] task_struct 关键字段偏移" | tee -a $OUTPUT
echo "----------------------------------------" | tee -a $OUTPUT
echo "[!] 以下需要从 vmlinux 提取" | tee -a $OUTPUT
echo "" | tee -a $OUTPUT

echo "[*] 内核漏洞检测" | tee -a $OUTPUT
echo "----------------------------------------" | tee -a $OUTPUT
echo "Kernel version: $(uname -r)" | tee -a $OUTPUT
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
KERNEL_PATCH=$(uname -r | cut -d. -f3 | cut -d- -f1)
echo "Parsed: $KERNEL_MAJOR.$KERNEL_MINOR.$KERNEL_PATCH" | tee -a $OUTPUT

if [ "$KERNEL_MAJOR" -le 2 ] || ([ "$KERNEL_MAJOR" -eq 3 ] && [ "$KERNEL_MINOR" -eq 0 ]); then
    echo "[!] 内核版本过旧，可能不受影响" | tee -a $OUTPUT
elif [ "$KERNEL_MAJOR" -ge 8 ]; then
    echo "[!] 内核版本 >= 8.x，已修复" | tee -a $OUTPUT
else
    echo "[+] 内核版本在受影响范围内 (2.6.39 ~ 7.0.4)" | tee -a $OUTPUT
fi
echo "" | tee -a $OUTPUT

echo "============================================" | tee -a $OUTPUT
echo "[*] 提取完成! 结果保存到: $OUTPUT" | tee -a $OUTPUT
echo "============================================" | tee -a $OUTPUT
echo "" | tee -a $OUTPUT
echo "[*] 下一步:" | tee -a $OUTPUT
echo "  1. adb pull $OUTPUT" | tee -a $OUTPUT
echo "  2. 从 boot.img 提取 vmlinux (用 magiskboot unpack)" | tee -a $OUTPUT
echo "  3. 用 pahole 提取 rt_mutex_waiter 和 task_struct 偏移" | tee -a $OUTPUT
echo "  4. 填入 target.h" | tee -a $OUTPUT
