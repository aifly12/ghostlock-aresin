import struct
import sys

kernel_path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/kernel_raw'
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# Key functions to disassemble
functions = [
    ('rt_mutex_init_waiter', 0xffffff939bd34ebc, 80),
    ('remove_waiter', 0xffffff939bd35620, 400),
    ('prepare_kernel_cred', 0xffffff939bce4578, 200),
]

for fname, faddr, fsize in functions:
    offset = faddr - base
    print("\n=== %s @ 0x%x (file offset 0x%x) ===" % (fname, faddr, offset))

    for i in range(0, fsize, 4):
        off = offset + i
        if off + 4 > len(kernel):
            break
        insn = struct.unpack('<I', kernel[off:off+4])[0]
        comment = ""

        # LDR (immediate unsigned offset)
        if (insn & 0xffc00000) == 0xf9400000:
            rt = insn & 0x1f
            rn = (insn >> 5) & 0x1f
            imm = ((insn >> 10) & 0xfff) * 8
            comment = "LDR X%d, [X%d, #0x%x]" % (rt, rn, imm)
        elif (insn & 0xffc00000) == 0xf9000000:
            rt = insn & 0x1f
            rn = (insn >> 5) & 0x1f
            imm = ((insn >> 10) & 0xfff) * 8
            comment = "STR X%d, [X%d, #0x%x]" % (rt, rn, imm)
        elif (insn & 0xffe0ffe0) == 0xaa0003e0:
            rd = insn & 0x1f
            rm = (insn >> 16) & 0x1f
            comment = "MOV X%d, X%d" % (rd, rm)
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
        elif (insn & 0xffc00000) == 0xa9000000:
            rt = insn & 0x1f
            rn = (insn >> 5) & 0x1f
            rt2 = (insn >> 10) & 0x1f
            imm = ((insn >> 15) & 0x7f)
            if imm & 0x40: imm -= 0x80
            imm *= 8
            comment = "STP X%d, X%d, [X%d, #%d]" % (rt, rt2, rn, imm)
        elif (insn & 0xffc00000) == 0xa9400000:
            rt = insn & 0x1f
            rn = (insn >> 5) & 0x1f
            rt2 = (insn >> 10) & 0x1f
            imm = ((insn >> 15) & 0x7f)
            if imm & 0x40: imm -= 0x80
            imm *= 8
            comment = "LDP X%d, X%d, [X%d, #%d]" % (rt, rt2, rn, imm)
        elif insn == 0xd65f03c0:
            comment = "RET"
        elif insn == 0xd503201f:
            comment = "NOP"
        # MRS Xn, TPIDR_EL1 (current task)
        elif (insn & 0xffe0ffff) == 0xd5384024:
            rt = insn & 0x1f
            comment = "MRS X%d, TPIDR_EL1" % rt

        marker = ""
        if "[X0" in comment:
            marker = " <== WAITER"

        if comment:
            print("  +%03x: %08x  %s%s" % (i, insn, comment, marker))
        else:
            print("  +%03x: %08x" % (i, insn))

        if fname != 'rt_mutex_init_waiter' and insn == 0xd65f03c0 and i > 20:
            break
