import struct
import os

kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# Verify init_task candidates
print("=" * 60)
print("VERIFYING init_task CANDIDATES")
print("=" * 60)

swapper_addr = 0xffffff939d8dc658
swapper_off = swapper_addr - base

# For 4.14, comm offset is typically around 0x5c0-0x620
# Let's check each candidate
for comm_off in [0x5c0, 0x5d0, 0x5e0, 0x5f0, 0x600, 0x610, 0x620]:
    task_addr = swapper_addr - comm_off
    task_off = swapper_off - comm_off

    if task_off < 0 or task_off + 0x800 > len(kernel):
        continue

    print("\n--- Candidate: init_task @ 0x%x (comm_off=0x%x) ---" % (task_addr, comm_off))

    # Read first 64 bytes (thread_info area)
    print("  First 64 bytes (thread_info / task start):")
    for j in range(0, 64, 8):
        val = struct.unpack('<Q', kernel[task_off+j:task_off+j+8])[0]
        print("    +0x%02x: 0x%016x" % (j, val))

    # Read around the cred pointers (offset 0x788 and 0x790)
    print("  Cred area (offset 0x788-0x798):")
    for j in range(0x788, 0x7a0, 8):
        val = struct.unpack('<Q', kernel[task_off+j:task_off+j+8])[0]
        print("    +0x%03x: 0x%016x" % (j, val))

    # Read around pi_lock (offset 0x85c)
    print("  PI area (offset 0x85c-0x890):")
    for j in range(0x85c, 0x890, 8):
        val = struct.unpack('<Q', kernel[task_off+j:task_off+j+8])[0]
        print("    +0x%03x: 0x%016x" % (j, val))

    # Read comm field
    print("  Comm field (offset 0x%x):" % comm_off)
    comm_bytes = kernel[task_off+comm_off:task_off+comm_off+16]
    print("    '%s'" % comm_bytes.decode('ascii', errors='replace'))

    # Validate: init_task should have:
    # - usage > 0 (atomic_t at some offset)
    # - state = TASK_RUNNING (0)
    # - comm = "swapper/0"
    # - cred pointing to init_cred

# Also check the __switch_to reference
print("\n" + "=" * 60)
print("VERIFYING __switch_to REFERENCE (potential entry_task)")
print("=" * 60)

# __switch_to @ 0xffffff939bc8853c
# The ADRP+ADD at +09c points to 0xffffff939d404070
entry_task_candidate = 0xffffff939d404070
entry_task_off = entry_task_candidate - base

if 0 <= entry_task_off + 8 <= len(kernel):
    val = struct.unpack('<Q', kernel[entry_task_off:entry_task_off+8])[0]
    print("  Value at 0x%x: 0x%016x" % (entry_task_candidate, val))
    if val == 0:
        print("  (Zero - might be uninitialized or per-CPU)")
    elif val > 0xffffff0000000000:
        print("  (Looks like a kernel pointer)")
    else:
        print("  (Non-zero value)")

# Check the surrounding area
print("  Surrounding area:")
for j in range(-16, 32, 8):
    off = entry_task_off + j
    if 0 <= off + 8 <= len(kernel):
        val = struct.unpack('<Q', kernel[off:off+8])[0]
        print("    +0x%x: 0x%016x" % (j, val))

# Try to find init_cred by looking at prepare_kernel_cred more carefully
print("\n" + "=" * 60)
print("ANALYZING prepare_kernel_cred FOR init_cred")
print("=" * 60)

# prepare_kernel_cred @ 0xffffff939bce4578
# The function loads init_cred from a global pointer
# We need to find where init_cred is stored

pc_addr = 0xffffff939bce4578
pc_off = pc_addr - base

# Look for the ADRP that loads the init_cred pointer
for i in range(0, 128, 4):
    off = pc_off + i
    if off + 4 > len(kernel):
        break
    insn = struct.unpack('<I', kernel[off:off+4])[0]

    # ADRP
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page_off = imm << 12
        pc_page = (base + off) & ~0xfff
        target = (pc_page + page_off) & 0xffffffffffffffff

        # Check next instruction for LDR
        if off + 4 < len(kernel):
            next_insn = struct.unpack('<I', kernel[off+4:off+8])[0]
            if (next_insn & 0xffc00000) == 0xf9400000:  # LDR
                ldr_imm = ((next_insn >> 10) & 0xfff) * 8
                final = target + ldr_imm
                print("  ADRP+LDR at +%03x: loads from 0x%x" % (i, final))
                file_off = final - base
                if 0 <= file_off + 8 <= len(kernel):
                    val = struct.unpack('<Q', kernel[file_off:file_off+8])[0]
                    print("    Value: 0x%016x" % val)
                    if val > 0xffffff0000000000:
                        print("    (Looks like a kernel pointer - potential init_cred)")
                else:
                    print("    (Outside image - in BSS)")

    if insn == 0xd65f03c0 and i > 20:
        break

# Also look for init_cred by searching for cred structure patterns
print("\n" + "=" * 60)
print("SEARCHING FOR init_cred IN DATA SECTION")
print("=" * 60)

# init_cred is a const struct cred, so it should be in .rodata or .data
# It has a specific pattern: usage (atomic_t) > 0, then uid/gid fields all 0
# After that, capabilities and security pointers

# Search more carefully
found_init_cred = False
for i in range(0, len(kernel) - 128, 4):
    usage = struct.unpack('<I', kernel[i:i+4])[0]

    # init_cred typically has usage around 1-3
    if usage < 1 or usage > 10:
        continue

    # Check uid/gid fields (6 * 4 bytes = 24 bytes)
    uid_fields = struct.unpack('<6I', kernel[i+4:i+28])
    if uid_fields != (0, 0, 0, 0, 0, 0):
        continue

    # Check securebits (should be 0 for init)
    securebits = struct.unpack('<I', kernel[i+28:i+32])[0]
    if securebits != 0:
        continue

    # Check capabilities (cap_struct has two __u32 arrays)
    # For init_cred, capabilities should be all 1s (full caps)
    cap_inheritable = struct.unpack('<2I', kernel[i+32:i+40])
    cap_permitted = struct.unpack('<2I', kernel[i+40:i+48])
    cap_effective = struct.unpack('<2I', kernel[i+48:i+56])

    # init_cred has all capabilities
    all_caps = (0xffffffff, 0xffffffff)
    if cap_inheritable == all_caps and cap_permitted == all_caps and cap_effective == all_caps:
        print("  FOUND init_cred @ 0x%x!" % (base + i))
        print("    usage: %d" % usage)
        print("    uid/gid: %s" % str(uid_fields))
        print("    securebits: %d" % securebits)
        print("    cap_inheritable: 0x%08x%08x" % (cap_inheritable[1], cap_inheritable[0]))
        print("    cap_permitted: 0x%08x%08x" % (cap_permitted[1], cap_permitted[0]))
        print("    cap_effective: 0x%08x%08x" % (cap_effective[1], cap_effective[0]))

        # Read more fields
        print("    Full first 128 bytes:")
        for j in range(0, 128, 8):
            val = struct.unpack('<Q', kernel[i+j:i+j+8])[0]
            print("      +0x%02x: 0x%016x" % (j, val))

        found_init_cred = True
        break

if not found_init_cred:
    print("  init_cred not found with full capabilities pattern")
    print("  (May be in BSS or have different capability values)")
