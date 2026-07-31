import struct
import os

kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# Read value at the potential selinux_enforcing address
selinux_addr = 0xffffff939d8cdac8
selinux_off = selinux_addr - base

print("=== Potential selinux_enforcing at 0x%x ===" % selinux_addr)
if 0 <= selinux_off + 8 <= len(kernel):
    val = struct.unpack('<Q', kernel[selinux_off:selinux_off+8])[0]
    print("  Value: 0x%x (%d)" % (val, val))

# Also check the nearby area
for offset in range(-32, 32, 4):
    off = selinux_off + offset
    if 0 <= off + 8 <= len(kernel):
        val = struct.unpack('<Q', kernel[off:off+8])[0]
        if val <= 1:
            print("  +0x%x: 0x%x (potential bool/flag)" % (offset, val))

# Check the string at 0xffffff939d18ace1 (might help identify the context)
str_addr = 0xffffff939d18ace1
str_off = str_addr - base
print("\n=== String at 0x%x ===" % str_addr)
if 0 <= str_off < len(kernel):
    s = kernel[str_off:str_off+64]
    # Find null terminator
    end = s.find(b'\x00')
    if end >= 0:
        s = s[:end]
    try:
        print("  '%s'" % s.decode('ascii', errors='replace'))
    except:
        print("  (binary)")

# Now let's find the kernel base page_offset for physmap
# CONFIG_ARM64_VA_BITS=39 means:
# PAGE_OFFSET = 0xffffff8000000000 (with 39-bit VA)
# PHYS_OFFSET = 0x40000000 (typical for MT6893)
print("\n=== Memory layout ===")
print("CONFIG_ARM64_VA_BITS=39")
print("PAGE_OFFSET = 0xffffff8000000000")
print("PHYS_OFFSET = 0x40000000 (typical for MT6893)")
print("KIMAGE_TEXT_BASE = 0x%x" % base)

# Try to find init_task by scanning for the task_struct pattern
# init_task is typically aligned to a page boundary and has specific patterns
# The comm field should contain "swapper" or similar
print("\n=== Searching for init_task (swapper/0) ===")
search_str = b'swapper/0\x00'
for i in range(0, len(kernel) - len(search_str), 4):
    if kernel[i:i+len(search_str)] == search_str:
        # Found "swapper/0" string
        # init_task.comm is typically at offset 0x5c0-0x600 in task_struct
        # So init_task = address - comm_offset
        print("  Found 'swapper/0' at file offset 0x%x" % i)
        print("  Kernel address: 0x%x" % (base + i))
        # Check surrounding area
        for comm_off in [0x5c0, 0x5d0, 0x5e0, 0x5f0, 0x600]:
            init_task_addr = base + i - comm_off
            init_task_off = i - comm_off
            if 0 <= init_task_off + 8 <= len(kernel):
                val = struct.unpack('<Q', kernel[init_task_off:init_task_off+8])[0]
                print("    init_task @ 0x%x (comm_off=0x%x): first 8 bytes = 0x%x" % (init_task_addr, comm_off, val))

# Search for init_cred
# init_cred starts with: uid={0}, gid={0}, suid={0}, sgid={0}, euid={0}, egid={0}
# On 4.14: kuid_t = {uid_t val} = 4 bytes, kgid_t = {gid_t val} = 4 bytes
# So init_cred starts with 24 bytes of zeros (6 * 4 bytes for uid/gid/suid/sgid/euid/egid)
print("\n=== Searching for init_cred ===")
# Search for long runs of zeros followed by specific patterns
# init_cred is in .data section, typically after init_task
# The cred struct has:
#   atomic_t usage (4 bytes)
#   kuid_t uid, gid, suid, sgid, euid, egid (24 bytes)
#   kgid_t sgid (4 bytes)
#   ...
# init_cred: usage = 1 (or higher), then 6 zeros for uid fields

for i in range(0, len(kernel) - 32, 4):
    # Check for pattern: atomic usage (non-zero), then 6 zero uid/gid fields
    usage = struct.unpack('<I', kernel[i:i+4])[0]
    if usage > 0 and usage < 100:
        zeros = struct.unpack('<QQQ', kernel[i+4:i+28])
        if zeros == (0, 0, 0):
            # This could be init_cred
            init_cred_addr = base + i
            print("  Potential init_cred at 0x%x (usage=%d)" % (init_cred_addr, usage))
            # Read more fields
            print("    uid=0x%x gid=0x%x suid=0x%x sgid=0x%x euid=0x%x egid=0x%x" % (
                struct.unpack('<6I', kernel[i+4:i+28])))
            break

# Also look at __init_begin which is near init_task
print("\n=== __init_begin @ 0x%x ===" % 0xffffff939d300000)
# init_task is typically before __init_begin
# Search backwards from __init_begin for the swapper comm
init_begin_off = 0xffffff939d300000 - base
# Search for swapper in the range before __init_begin
for i in range(max(0, init_begin_off - 0x100000), init_begin_off, 4):
    if kernel[i:i+10] == b'swapper/0\x00':
        print("  Found 'swapper/0' at 0x%x" % (base + i))
        break
