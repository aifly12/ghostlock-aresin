import struct

import os
kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
if not os.path.exists(kernel_path):
    kernel_path = os.path.expanduser('~/AppData/Local/Temp/kernel_raw')
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# prepare_kernel_cred @ 0xffffff939bce4578
# +010: ADRP X8, page    +018: LDR X0, [X8, #0x850]  => init_cred
pc_offset = 0xffffff939bce4578 - base

# Decode ADRP at offset +0x10
adrp_off = pc_offset + 0x10
adrp_insn = struct.unpack('<I', kernel[adrp_off:adrp_off+4])[0]

# ADRP: bit31=1, bit28:24=10000
immlo = (adrp_insn >> 29) & 0x3
immhi = (adrp_insn >> 5) & 0x7ffff
imm = (immhi << 2) | immlo
if imm & 0x100000:
    imm -= 0x200000
page_offset = imm << 12

adrp_pc = base + adrp_off
adrp_page = adrp_pc & ~0xfff
target_page = (adrp_page + page_offset) & 0xffffffffffffffff

# LDR at offset +0x18
ldr_off = pc_offset + 0x18
ldr_insn = struct.unpack('<I', kernel[ldr_off:ldr_off+4])[0]
ldr_imm = ((ldr_insn >> 10) & 0xfff) * 8  # unsigned offset

init_cred_ptr_addr = target_page + ldr_imm

print("=== prepare_kernel_cred analysis ===")
print("ADRP instruction: 0x%08x" % adrp_insn)
print("ADRP PC: 0x%x" % adrp_pc)
print("ADRP page target: 0x%x" % target_page)
print("LDR offset: 0x%x" % ldr_imm)
print("init_cred pointer at: 0x%x" % init_cred_ptr_addr)
print("init_cred pointer (file offset): 0x%x" % (init_cred_ptr_addr - base))

# Read the actual init_cred value from the kernel image
init_cred_file_off = init_cred_ptr_addr - base
if 0 <= init_cred_file_off + 8 <= len(kernel):
    init_cred_val = struct.unpack('<Q', kernel[init_cred_file_off:init_cred_file_off+8])[0]
    print("init_cred value: 0x%x" % init_cred_val)
else:
    print("init_cred pointer is outside the image (at 0x%x)" % init_cred_file_off)

# Now find selinux_enforcing by looking at selinux_status_update_setenforce
# selinux_status_update_setenforce @ 0xffffff939c066520
se_offset = 0xffffff939c066520 - base
print("\n=== selinux_status_update_setenforce @ 0x%x ===" % 0xffffff939c066520)
for i in range(0, 128, 4):
    off = se_offset + i
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
        comment = "ADRP X%d, 0x%x" % (rd, target)
    elif (insn & 0xffc00000) == 0xf9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 8
        comment = "LDR X%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0xb9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 4
        comment = "LDR W%d, [W%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0xb9000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 4
        comment = "STR W%d, [W%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xffc00000) == 0x39400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "LDRB W%d, [X%d, #0x%x]" % (rt, rn, imm)
    elif (insn & 0xff000000) == 0x71000000:
        rd = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "SUBS W%d, W%d, #0x%x" % (rd, rn, imm)
    elif insn == 0xd65f03c0:
        comment = "RET"
    elif (insn & 0xffc00000) == 0x39000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "STRB W%d, [X%d, #0x%x]" % (rt, rn, imm)

    if comment:
        print("  +%03x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 10:
        break

# Also search for task_struct field offsets
# commit_creds accesses current->real_cred and current->cred
print("\n=== commit_creds @ 0x%x (first 80 bytes) ===" % 0xffffff939bce41e0)
cc_offset = 0xffffff939bce41e0 - base
for i in range(0, 128, 4):
    off = cc_offset + i
    if off + 4 > len(kernel):
        break
    insn = struct.unpack('<I', kernel[off:off+4])[0]

    comment = ""
    # MRS Xn, TPIDR_EL1 (current task)
    if (insn & 0xffe0ffff) == 0xd5384024:
        rt = insn & 0x1f
        comment = "MRS X%d, TPIDR_EL1 (current)" % rt
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
    elif insn == 0xd65f03c0:
        comment = "RET"
    elif (insn & 0xfc000000) == 0x94000000:
        imm = insn & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        target = base + off + imm * 4
        comment = "BL 0x%x" % target
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
    elif (insn & 0xffc00000) == 0xa9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        rt2 = (insn >> 10) & 0x1f
        imm = ((insn >> 15) & 0x7f)
        if imm & 0x40: imm -= 0x80
        imm *= 8
        comment = "LDP X%d, X%d, [X%d, #%d]" % (rt, rt2, rn, imm)

    marker = ""
    if "MRS" in comment or "TPIDR" in comment:
        marker = " <== CURRENT"

    if comment:
        print("  +%03x: %08x  %s%s" % (i, insn, comment, marker))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 10:
        break
