import struct
import os

kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# Verify selinux_enforcing
selinux_addr = 0xffffff939dd00b28
selinux_off = selinux_addr - base
print("=== selinux_enforcing @ 0x%x ===" % selinux_addr)
if 0 <= selinux_off + 4 <= len(kernel):
    val = struct.unpack('<I', kernel[selinux_off:selinux_off+4])[0]
    print("  Value: %d" % val)

# Also check the selinux_state structure
selinux_state_addr = 0xffffff939d8cdac8
selinux_state_off = selinux_state_addr - base
print("\n=== selinux_state @ 0x%x ===" % selinux_state_addr)
if 0 <= selinux_state_off + 16 <= len(kernel):
    for j in range(16):
        b = kernel[selinux_state_off + j]
        print("  +0x%x: 0x%02x (%d)" % (j, b, b))

# Check if init_task is near the data section
# Search for the pattern of init_task (task_struct starts with thread_info)
# thread_info has: flags, preempt_count, addr_limit
# On ARM64: flags = 0, preempt_count varies
print("\n=== Searching for init_task ===")
# Search for swapper comm in the data section
for i in range(0, len(kernel) - 16, 4):
    if kernel[i:i+10] == b'swapper/0\x00':
        comm_addr = base + i
        # comm is typically at offset 0x5c0 in task_struct for 4.14
        for comm_off in [0x5c0, 0x5d0, 0x5e0, 0x5f0, 0x600]:
            init_task_addr = comm_addr - comm_off
            init_task_off = i - comm_off
            if 0 <= init_task_off:
                print("  Found 'swapper/0' at 0x%x" % comm_addr)
                print("  Potential init_task @ 0x%x (comm_off=0x%x)" % (init_task_addr, comm_off))
                # Read first few bytes
                if 0 <= init_task_off + 32 <= len(kernel):
                    print("    First 32 bytes:")
                    for j in range(0, 32, 8):
                        val = struct.unpack('<Q', kernel[init_task_off+j:init_task_off+j+8])[0]
                        print("      +0x%x: 0x%016x" % (j, val))
        break

# Summary of all found offsets
print("\n" + "="*60)
print("SUMMARY OF EXTRACTED OFFSETS")
print("="*60)
print()
print("=== rt_mutex_waiter (4.14.186 ARM64) ===")
print("  tree_entry:      0x00")
print("  pi_tree_entry:   0x18")
print("  task:            0x30")
print("  lock:            0x38")
print("  prio:            0x40")
print("  deadline:        0x48")
print()
print("=== task_struct (4.14.186 MT6893) ===")
print("  prio:            0x84")
print("  real_cred:       0x788")
print("  cred:            0x790")
print("  deadline:        0x388")
print("  pi_lock:         0x85c")
print("  pi_waiters:      0x868")
print("  pi_top_task:     0x870")
print("  pi_blocked_on:   0x880")
print()
print("=== Kernel addresses ===")
print("  KIMAGE_TEXT_BASE: 0x%x" % base)
print("  commit_creds:     0x%x" % 0xffffff939bce41e0)
print("  prepare_kernel_cred: 0x%x" % 0xffffff939bce4578)
print("  selinux_enforcing: 0x%x" % selinux_addr)
print()
print("=== Memory layout ===")
print("  CONFIG_ARM64_VA_BITS=39")
print("  PAGE_OFFSET: 0xffffff8000000000")
print("  PHYS_OFFSET: 0x40000000")
