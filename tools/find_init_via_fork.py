import struct
import os

kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# fork_init @ 0xffffff939d308c24
# This function initializes the fork subsystem and references init_task
print("=" * 60)
print("ANALYZING fork_init @ 0x%x" % 0xffffff939d308c24)
print("=" * 60)

fi_off = 0xffffff939d308c24 - base

for i in range(0, 256, 4):
    off = fi_off + i
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

    if comment:
        print("  +%03x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 20:
        break

# Also look at rest_init which creates the init task
print("\n" + "=" * 60)
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

    if comment:
        print("  +%03x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 20:
        break

# Summary
print("\n" + "=" * 60)
print("SUMMARY OF FINDINGS")
print("=" * 60)
print("""
Based on analysis:

1. init_task: The swapper/0 string is at 0xffffff939d8dc658
   - This is in the .data section
   - init_task is likely at 0xffffff939d8dc058 (comm_off=0x600)
   - But the data is all zeros in the boot image (initialized at boot)

2. init_cred: prepare_kernel_cred loads from pointer at 0xffffff939dae3850
   - This pointer is in BSS and initialized at boot time
   - The actual init_cred structure address is unknown from static analysis

3. For the exploit, we can use alternative approaches:
   - Use commit_creds/prepare_kernel_cred directly
   - Find init_cred at runtime by reading the pointer
   - Use KASLR slide detection to find the actual addresses

4. The remaining addresses (ENTRY_TASK, PER_CPU_OFFSET, ROOT_TASK_GROUP)
   are per-CPU variables that are initialized at boot time and cannot be
   determined from static analysis alone.
""")
