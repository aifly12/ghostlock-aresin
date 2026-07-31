import struct
import os

kernel_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'kernel_raw')
with open(kernel_path, 'rb') as f:
    kernel = f.read()

base = 0xffffff939bc80000

# idle_threads_init @ 0xffffff939d30aea4
# This function initializes idle threads and references init_task
print("=" * 60)
print("ANALYZING idle_threads_init @ 0x%x" % 0xffffff939d30aea4)
print("=" * 60)

iti_off = 0xffffff939d30aea4 - base

for i in range(0, 256, 4):
    off = iti_off + i
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

    if comment:
        print("  +%03x: %08x  %s" % (i, insn, comment))
    else:
        print("  +%03x: %08x" % (i, insn))

    if insn == 0xd65f03c0 and i > 20:
        break

# Also analyze fork_init which references init_task
print("\n" + "=" * 60)
print("SEARCHING FOR fork_init")
print("=" * 60)

# fork_init is typically called during boot and references init_task
# Let's search for it in the kernel binary
# It's usually near the init functions

# Look for functions that reference init_task by searching for ADRP+ADD patterns
# that point to the data section

# The swapper/0 string is at 0xffffff939d8dc658
# So init_task should be near there

# Let's search for functions that have ADRP+ADD pointing near the swapper string
print("  Searching for functions referencing address near swapper/0...")

# Check if there are any ADRP+ADD patterns pointing to the swapper area
swapper_page = 0xffffff939d8dc000  # page containing swapper/0

# Search for ADRP that loads this page
for i in range(0, len(kernel) - 4, 4):
    insn = struct.unpack('<I', kernel[i:i+4])[0]

    # ADRP
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page_off = imm << 12
        pc_page = (base + i) & ~0xfff
        target = (pc_page + page_off) & 0xffffffffffffffff

        # Check if target is near the swapper string
        if abs(target - swapper_page) < 0x10000:
            # Found a reference to the swapper area
            func_addr = base + i
            print("  Found ADRP to swapper area at 0x%x (target=0x%x)" % (func_addr, target))

            # Check next instruction for ADD
            if i + 4 < len(kernel):
                next_insn = struct.unpack('<I', kernel[i+4:i+8])[0]
                if (next_insn & 0xff000000) == 0x91000000:
                    add_imm = (next_insn >> 10) & 0xfff
                    final = target + add_imm
                    print("    ADD #0x%x => 0x%x" % (add_imm, final))

                    # This might be init_task or related
                    if final == swapper_page:
                        print("    -> Points to swapper page (likely init_task reference)")

# Also search for the init_cred pointer address
print("\n" + "=" * 60)
print("SEARCHING FOR init_cred POINTER REFERENCES")
print("=" * 60)

# prepare_kernel_cred loads from 0xffffff939dae3850
# Let's search for other references to this address
init_cred_ptr_page = 0xffffff939dae3000

for i in range(0, len(kernel) - 4, 4):
    insn = struct.unpack('<I', kernel[i:i+4])[0]

    # ADRP
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page_off = imm << 12
        pc_page = (base + i) & ~0xfff
        target = (pc_page + page_off) & 0xffffffffffffffff

        # Check if target is near the init_cred pointer
        if abs(target - init_cred_ptr_page) < 0x1000:
            # Found a reference
            func_addr = base + i
            print("  Found ADRP to init_cred area at 0x%x (target=0x%x)" % (func_addr, target))

            # Check next instruction for LDR
            if i + 4 < len(kernel):
                next_insn = struct.unpack('<I', kernel[i+4:i+8])[0]
                if (next_insn & 0xffc00000) == 0xf9400000:
                    ldr_imm = ((next_insn >> 10) & 0xfff) * 8
                    final = target + ldr_imm
                    print("    LDR #0x%x => 0x%x" % (ldr_imm, final))
