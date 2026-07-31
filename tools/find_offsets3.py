import struct
import os

kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# From task_blocks_on_rt_mutex:
# - task->pi_lock = task + 0x85c
# - task->prio = task + 0x84
# - task->deadline = task + 0x388
#
# From commit_creds:
# - task->real_cred = task + 0x788
# - task->cred = task + 0x790
#
# Now we need: pi_blocked_on, pi_waiters, pi_top_task, selinux_enforcing
#
# rt_mutex_adjust_prio_chain accesses task->pi_blocked_on, task->pi_waiters, etc.
# @ 0xffffff939bd34830

print("=== rt_mutex_adjust_prio_chain @ 0x%x ===" % 0xffffff939bd34830)
rmapc_off = 0xffffff939bd34830 - base

# Disassemble first 400 bytes
for i in range(0, 400, 4):
    off = rmapc_off + i
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
    elif (insn & 0xffc00000) == 0xf9000000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm = ((insn >> 10) & 0xfff) * 8
        comment = "STR X%d, [X%d, #0x%x]" % (rt, rn, imm)
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
    elif insn == 0xd65f03c0:
        comment = "RET"

    if comment:
        print("  +%03x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 20:
        break

# Search for selinux_enforcing by looking at the selinux_set_mnt_opts function
# which accesses enforcing
print("\n=== Searching for selinux_enforcing in selinux_set_mnt_opts ===")
selinux_addr = 0xffffff939c048abc
selinux_off = selinux_addr - base

# Look for ADRP+ADD/LDR patterns that load selinux_enforcing
for i in range(0, 512, 4):
    off = selinux_off + i
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

        # Check next instruction for ADD or LDR
        if off + 4 < len(kernel):
            next_insn = struct.unpack('<I', kernel[off+4:off+8])[0]
            # ADD immediate
            if (next_insn & 0xff000000) == 0x91000000:
                add_imm = (next_insn >> 10) & 0xfff
                final = target + add_imm
                file_off = final - base
                if 0 <= file_off < len(kernel):
                    print("  +%03x: ADRP X%d, 0x%x + ADD #0x%x => 0x%x (in image)" % (i, rd, target, add_imm, final))
            # LDR unsigned
            elif (next_insn & 0xffc00000) == 0xf9400000:
                ldr_imm = ((next_insn >> 10) & 0xfff) * 8
                final = target + ldr_imm
                file_off = final - base
                if 0 <= file_off < len(kernel):
                    print("  +%03x: ADRP X%d, 0x%x + LDR #0x%x => 0x%x (in image)" % (i, rd, target, ldr_imm, final))

    if insn == 0xd65f03c0 and i > 20:
        break
