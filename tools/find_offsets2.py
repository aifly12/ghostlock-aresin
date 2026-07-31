import struct
import os

kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
if not os.path.exists(kernel_path):
    kernel_path = os.path.expanduser('~/AppData/Local/Temp/kernel_raw')

with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# task_blocks_on_rt_mutex @ 0xffffff939bd352cc
# This function accesses task->pi_blocked_on, task->pi_lock, waiter->prio, etc.
tborm_addr = 0xffffff939bd352cc
tborm_off = tborm_addr - base

print("=== task_blocks_on_rt_mutex @ 0x%x ===" % tborm_addr)
print("  (accesses: task->pi_blocked_on, task->pi_lock, waiter->prio, waiter->lock)")

# MRS instructions access current task_struct
for i in range(0, 256, 4):
    off = tborm_off + i
    if off + 4 > len(kernel):
        break
    insn = struct.unpack('<I', kernel[off:off+4])[0]

    comment = ""
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
    elif (insn & 0xffc00000) == 0xa9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        rt2 = (insn >> 10) & 0x1f
        imm = ((insn >> 15) & 0x7f)
        if imm & 0x40: imm -= 0x80
        imm *= 8
        comment = "LDP X%d, X%d, [X%d, #%d]" % (rt, rt2, rn, imm)
    elif (insn & 0xffc00000) == 0xa9000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        rt2 = (insn >> 10) & 0x1f
        imm = ((insn >> 15) & 0x7f)
        if imm & 0x40: imm -= 0x80
        imm *= 8
        comment = "STP X%d, X%d, [X%d, #%d]" % (rt, rt2, rn, imm)
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
    elif (insn & 0xff000000) == 0x91000000:
        rd = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "ADD X%d, X%d, #0x%x" % (rd, rn, imm)
    elif (insn & 0xfc000000) == 0x94000000:
        imm = insn & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        target = base + off + imm * 4
        comment = "BL 0x%x" % target
    elif (insn & 0xff000010) == 0x54000000:
        cond = insn & 0xf
        imm = (insn >> 5) & 0x7ffff
        if imm & 0x40000:
            imm -= 0x80000
        target = base + off + imm * 4
        cond_names = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}
        comment = "B.%s 0x%x" % (cond_names.get(cond, '?'), target)
    elif insn == 0xd65f03c0:
        comment = "RET"
    # LDAXR / STXR patterns for spinlocks
    elif (insn & 0xffe00000) == 0x88000000:
        comment = "ST(L)XR (spinlock op)"
    elif (insn & 0xffe00000) == 0x88400000:
        comment = "LD(A)XR (spinlock op)"

    if comment:
        print("  +%03x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 20:
        break

# Also look at rt_mutex_setprio for task_struct prio/normal_prio offsets
print("\n=== rt_mutex_setprio @ 0x%x ===" % 0xffffff939bcf6278)
rmp_off = 0xffffff939bcf6278 - base
for i in range(0, 128, 4):
    off = rmp_off + i
    if off + 4 > len(kernel):
        break
    insn = struct.unpack('<I', kernel[off:off+4])[0]

    comment = ""
    if (insn & 0xffe0ffff) == 0xd5384024:
        rt = insn & 0x1f
        comment = "MRS X%d, TPIDR_EL1" % rt
    elif (insn & 0xffc00000) == 0xf9400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 8
        comment = "LDR X%d, [X%d, #0x%x]" % (rt, rn, imm)
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
    elif (insn & 0xff000000) == 0x91000000:
        rd = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = (insn >> 10) & 0xfff
        comment = "ADD X%d, X%d, #0x%x" % (rd, rn, imm)
    elif insn == 0xd65f03c0:
        comment = "RET"
    elif (insn & 0xfc000000) == 0x94000000:
        imm = insn & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        target = base + off + imm * 4
        comment = "BL 0x%x" % target

    if comment:
        print("  +%03x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 10:
        break

# Search for init_cred by scanning the data section for a pointer pattern
# init_cred is a struct cred, which starts with kuid_t uid = {0}
# In the kernel, init_cred is typically right after init_task
print("\n=== Searching for init_cred / selinux_enforcing ===")
print("Searching for commit_creds references to find init_cred...")
print("commit_creds @ 0x%x" % 0xffffff939bce41e0)
# The function at +08c has: B000e033 (ADRP X19, ...) followed by ADD X19, X19, #0x158
# This loads a data address
adrp_off2 = 0xffffff939bce41e0 - base + 0x8c
adrp2 = struct.unpack('<I', kernel[adrp_off2:adrp_off2+4])[0]
add_off2 = adrp_off2 + 4
add2 = struct.unpack('<I', kernel[add_off2:add_off2+4])[0]

if (adrp2 & 0x9f000000) == 0x90000000:
    immlo = (adrp2 >> 29) & 0x3
    immhi = (adrp2 >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    page_off = imm << 12
    pc_page = (base + adrp_off2) & ~0xfff
    target = (pc_page + page_off) & 0xffffffffffffffff

    if (add2 & 0xff000000) == 0x91000000:
        add_imm = (add2 >> 10) & 0xfff
        final = target + add_imm
        print("ADRP+ADD in commit_creds+0x8c: 0x%x" % final)
        # Check if this is in kernel image
        file_off = final - base
        if 0 <= file_off + 8 <= len(kernel):
            val = struct.unpack('<Q', kernel[file_off:file_off+8])[0]
            print("  Value at that address: 0x%x" % val)
        else:
            print("  Address 0x%x (file offset 0x%x) - outside image" % (final, file_off))
