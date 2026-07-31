import struct
import os

kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# enforcing_setup @ 0xffffff939d33047c
# This function sets selinux_enforcing based on boot parameter
print("=== enforcing_setup @ 0x%x ===" % 0xffffff939d33047c)
es_off = 0xffffff939d33047c - base

for i in range(0, 64, 4):
    off = es_off + i
    if off + 4 > len(kernel):
        break
    insn = struct.unpack('<I', kernel[off:off+4])[0]

    comment = ""
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
        comment = "ADRP X%d, 0x%x" % (rd, target)
    elif (insn & 0xff000000) == 0x91000000:
        rd = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "ADD X%d, X%d, #0x%x" % (rd, rn, imm)
    elif (insn & 0xffc00000) == 0xb9000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 4
        comment = "STR W%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0x39000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "STRB W%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0xb9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 4
        comment = "LDR W%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xfc000000) == 0x94000000:
        imm = insn & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        target = base + off + imm * 4
        comment = "BL 0x%x" % target
    elif insn == 0xd65f03c0:
        comment = "RET"
    elif insn == 0xd503201f:
        comment = "NOP"
    elif (insn & 0xffc00000) == 0xf9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 8
        comment = "LDR X%d, [X%d, #0x%x]" % (rt, rn, imm)

    if comment:
        print("  +%02x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%02x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 10:
        break

# Also look at selinux_complete_init which sets up the enforcing state
print("\n=== selinux_complete_init @ 0x%x ===" % 0xffffff939c048734)
sci_off = 0xffffff939c048734 - base

for i in range(0, 128, 4):
    off = sci_off + i
    if off + 4 > len(kernel):
        break
    insn = struct.unpack('<I', kernel[off:off+4])[0]

    comment = ""
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
        comment = "ADRP X%d, 0x%x" % (rd, target)
    elif (insn & 0xff000000) == 0x91000000:
        rd = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "ADD X%d, X%d, #0x%x" % (rd, rn, imm)
    elif (insn & 0xffc00000) == 0xb9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 4
        comment = "LDR W%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0xb9000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 4
        comment = "STR W%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0x39400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "LDRB W%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0x39000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "STRB W%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xfc000000) == 0x94000000:
        imm = insn & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        target = base + off + imm * 4
        comment = "BL 0x%x" % target
    elif insn == 0xd65f03c0:
        comment = "RET"
    elif (insn & 0xffc00000) == 0xf9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 8
        comment = "LDR X%d, [X%d, #0x%x]" % (rt, rn, imm)

    if comment:
        print("  +%02x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%02x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 10:
        break

# Read the potential selinux_state address as bytes
print("\n=== Byte-level read at potential selinux_state ===")
selinux_addr = 0xffffff939d8cdac8
selinux_off = selinux_addr - base
if 0 <= selinux_off + 16 <= len(kernel):
    for j in range(16):
        b = kernel[selinux_off + j]
        print("  +0x%x: 0x%02x (%d)" % (j, b, b))
