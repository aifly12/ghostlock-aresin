import struct
import os

kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# rest_init @ 0xffffff939ccde5c0
# This function creates the init task and references init_task
print("=" * 60)
print("ANALYZING rest_init @ 0x%x" % 0xffffff939ccde5c0)
print("=" * 60)

ri_off = 0xffffff939ccde5c0 - base

for i in range(0, 256, 4):
    off = ri_off + i
    if off + 4 > len(kernel):
        break
    insn = struct.unpack('<I', kernel[off:off+4])[0]

    comment = ""
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

        # Check next instruction
        if off + 4 < len(kernel):
            next_insn = struct.unpack('<I', kernel[off+4:off+8])[0]
            # ADD
            if (next_insn & 0xff000000) == 0x91000000:
                add_imm = (next_insn >> 10) & 0xfff
                final = target + add_imm
                comment = "ADRP+ADD => 0x%x" % final
            # LDR
            elif (next_insn & 0xffc00000) == 0xf9400000:
                ldr_imm = ((next_insn >> 10) & 0xfff) * 8
                final = target + ldr_imm
                comment = "ADRP+LDR => 0x%x" % final
            # LDRB
            elif (next_insn & 0xffc00000) == 0x39400000:
                ldr_imm = (next_insn >> 10) & 0xfff
                final = target + ldr_imm
                comment = "ADRP+LDRB => 0x%x" % final
            # STR
            elif (next_insn & 0xffc00000) == 0xf9000000:
                str_imm = ((next_insn >> 10) & 0xfff) * 8
                final = target + str_imm
                comment = "ADRP+STR => 0x%x" % final
            else:
                comment = "ADRP X%d, 0x%x" % (rd, target)
    elif (insn & 0xffc00000) == 0xf9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 8
        comment = "LDR X%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0xf9000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 8
        comment = "STR X%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xfc000000) == 0x94000000:
        imm = insn & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        target = base + off + imm * 4
        comment = "BL 0x%x" % target
    elif (insn & 0xff000000) == 0x91000000:
        rd = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "ADD X%d, X%d, #0x%x" % (rd, rn, imm)
    elif insn == 0xd65f03c0:
        comment = "RET"
    elif (insn & 0xffe0ffff) == 0xd5384024:
        rt = insn & 0x1f
        comment = "MRS X%d, TPIDR_EL1" % rt

    if comment:
        print("  +%03x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 20:
        break

# Also look at kernel_init which references init_task
print("\n" + "=" * 60)
print("ANALYZING kernel_init @ 0x%x" % 0xffffff939ccde69c)
print("=" * 60)

ki_off = 0xffffff939ccde69c - base

for i in range(0, 256, 4):
    off = ki_off + i
    if off + 4 > len(kernel):
        break
    insn = struct.unpack('<I', kernel[off:off+4])[0]

    comment = ""
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

        # Check next instruction
        if off + 4 < len(kernel):
            next_insn = struct.unpack('<I', kernel[off+4:off+8])[0]
            # ADD
            if (next_insn & 0xff000000) == 0x91000000:
                add_imm = (next_insn >> 10) & 0xfff
                final = target + add_imm
                comment = "ADRP+ADD => 0x%x" % final
            # LDR
            elif (next_insn & 0xffc00000) == 0xf9400000:
                ldr_imm = ((next_insn >> 10) & 0xfff) * 8
                final = target + ldr_imm
                comment = "ADRP+LDR => 0x%x" % final
            else:
                comment = "ADRP X%d, 0x%x" % (rd, target)
    elif (insn & 0xffc00000) == 0xf9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 8
        comment = "LDR X%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0xf9000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 8
        comment = "STR X%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xfc000000) == 0x94000000:
        imm = insn & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        target = base + off + imm * 4
        comment = "BL 0x%x" % target
    elif (insn & 0xff000000) == 0x91000000:
        rd = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "ADD X%d, X%d, #0x%x" % (rd, rn, imm)
    elif insn == 0xd65f03c0:
        comment = "RET"

    if comment:
        print("  +%03x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 20:
        break

# Try to find init_cred by looking at prepare_kernel_cred's data references
print("\n" + "=" * 60)
print("SEARCHING FOR init_cred POINTER IN prepare_kernel_cred")
print("=" * 60)

# prepare_kernel_cred loads init_cred from a global pointer
# The ADRP+LDR at +0x10/+0x18 loads from 0xffffff939dae3850
# This is in BSS, so the value is 0 in the image
# But we can find the address where init_cred is stored

init_cred_ptr_addr = 0xffffff939dae3850
print("  init_cred pointer stored at: 0x%x" % init_cred_ptr_addr)
print("  (This is in BSS, initialized at boot time)")

# For the exploit, we need the runtime value of init_cred
# We can get this by reading from the device
print("\n  To get runtime init_cred value:")
print("  adb shell su -c 'cat /proc/kallsyms | grep prepare_kernel_cred'")
print("  Then disassemble to find the ADRP+LDR and calculate the pointer address")
print("  Then read the pointer value from device memory")

# Let's also search for the actual init_cred value pattern in the image
# init_cred has: usage (atomic_t), then uid/gid fields all 0, then full capabilities
print("\n" + "=" * 60)
print("SEARCHING FOR init_cred IN KERNEL IMAGE")
print("=" * 60)

# More thorough search
for i in range(0, len(kernel) - 256, 4):
    usage = struct.unpack('<I', kernel[i:i+4])[0]

    # init_cred usage should be small
    if usage < 1 or usage > 100:
        continue

    # Check uid/gid fields
    uid_fields = struct.unpack('<6I', kernel[i+4:i+28])
    if uid_fields != (0, 0, 0, 0, 0, 0):
        continue

    # Check securebits
    securebits = struct.unpack('<I', kernel[i+28:i+32])[0]
    if securebits != 0:
        continue

    # Check capabilities - for init_cred, all capabilities should be set
    # cap_struct has two u32 arrays: effective and inheritable
    cap_data = struct.unpack('<6I', kernel[i+32:i+56])

    # For init_cred, capabilities should be all 0xffffffff
    all_caps = True
    for c in cap_data:
        if c != 0xffffffff:
            all_caps = False
            break

    if all_caps:
        print("  FOUND init_cred @ 0x%x!" % (base + i))
        print("    usage: %d" % usage)
        print("    uid/gid: %s" % str(uid_fields))
        print("    securebits: %d" % securebits)
        print("    capabilities: %s" % str(cap_data))
        break
    elif usage >= 1 and usage <= 10:
        # This might still be init_cred with different capability format
        print("  Potential init_cred @ 0x%x (usage=%d, caps=%s)" % (base + i, usage, str(cap_data)))
