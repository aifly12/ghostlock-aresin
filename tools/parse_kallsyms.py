#!/usr/bin/env python3
"""
Parse compressed kallsyms from ARM64 kernel binary.
Extracts symbol addresses for unexported symbols.
"""

import struct
import sys

def find_token_table(data):
    """Find the kallsyms_token_table (256 null-terminated strings)"""
    # The token table is 256 null-terminated strings
    # It's typically near the end of the kallsyms data
    # Search for a sequence of short null-terminated strings

    # Try to find by looking for common token patterns
    # The first few tokens are usually single characters: \0, \n, space, etc.

    # Method: search for the kallsyms_markers array (one entry per 256 symbols)
    # then the token table follows

    return None

def parse_kallsyms_from_binary(data, kimage_base):
    """
    Try to parse the compressed kallsyms format from the kernel binary.

    Format (CONFIG_KALLSYMS_BASE_RELATIVE=y, common in ARM64):
    1. kallsyms_addresses: int32[] (offsets from kimage_base)
    2. kallsyms_num_syms: int32
    3. kallsyms_names: byte[] (length + token indices per symbol)
    4. kallsyms_markers: int32[] (one per 256 symbols)
    5. kallsyms_token_table: 256 null-terminated strings
    6. kallsyms_token_index: uint16[256]
    """

    # We know some symbol names and their approximate locations
    # Let's use a different approach: search for the symbol name in the
    # compressed name table

    # The name table stores each symbol as:
    # [length_byte] [token_index_0] [token_index_1] ... [token_index_{length-1}]

    # The token table maps each byte 0-255 to a string fragment
    # For standard kernels, the token table is:
    # 0x00 -> "\0"
    # 0x01 -> "\n"
    # 0x02 -> " "
    # etc.

    # Actually, let's try a simpler approach:
    # Search for the string "generic_pipe_buf_confirm" in the kallsyms name table
    # The name is stored as token indices, but if we can find the token table,
    # we can decode it

    # For now, let's try to find the kallsyms_addresses table by looking for
    # sorted sequences of addresses that match known kallsyms output

    # We know from the device (with kptr_restrict=0):
    # generic_pipe_buf_confirm = 0xffffff904187c950 (runtime, with KASLR)
    # generic_pipe_buf_release = 0xffffff904187c958
    # noop_llseek = 0xffffff904186f55c

    # The static addresses (without KASLR) would be:
    # KIMAGE_TEXT_BASE + offset
    # We need to find the offset

    # Let's search for the pattern of the function code
    # generic_pipe_buf_confirm: MOV W0, #0; RET (or MOV W0, WZR; RET)

    results = {}

    # Search for MOV W0, WZR; RET pattern
    # MOV W0, WZR = 0x2a1f03e0
    # RET = 0xd65f03c0
    pattern = struct.pack('<II', 0x2a1f03e0, 0xd65f03c0)

    candidates = []
    pos = 0x80000  # text start
    while pos < len(data) - 8:
        idx = data.find(pattern, pos)
        if idx < 0:
            break
        candidates.append(idx)
        pos = idx + 4

    print("Found %d MOV W0,WZR+RET candidates" % len(candidates))

    # For each candidate, check if it could be generic_pipe_buf_confirm
    # by looking for nearby functions (release, steal, get)

    # generic_pipe_buf_release typically calls put_page or page_ref_dec
    # It should be close to confirm (within 256 bytes)

    for conf_off in candidates:
        conf_va = kimage_base + conf_off

        # Look for a function prologue nearby (within 512 bytes)
        for delta in range(-512, 512, 4):
            check_off = conf_off + delta
            if check_off < 0x80000 or check_off >= len(data) - 4:
                continue

            instr = struct.unpack_from('<I', data, check_off)[0]
            # STP X29, X30, [SP, #-N]! (function prologue)
            if (instr & 0xffc003e0) == 0xa98003e0:
                # This is a function prologue near our confirm candidate
                # Check if it's a reasonable distance
                if abs(delta) < 256 and abs(delta) > 4:
                    # This could be generic_pipe_buf_release
                    release_va = kimage_base + check_off
                    results['generic_pipe_buf_confirm'] = conf_va
                    results['generic_pipe_buf_release'] = release_va
                    print("Candidate pair:")
                    print("  confirm: 0x%x (file 0x%x)" % (conf_va, conf_off))
                    print("  release: 0x%x (file 0x%x, delta=%d)" % (release_va, check_off, delta))
                    break
        else:
            continue
        break

    return results

def main():
    kernel_path = sys.argv[1] if len(sys.argv) > 1 else "boot/kernel_raw"
    kimage_base = 0xffffff939bc80000

    with open(kernel_path, 'rb') as f:
        data = f.read()

    print("Kernel size: %d bytes" % len(data))
    print("KIMAGE_TEXT_BASE: 0x%x" % kimage_base)
    print()

    results = parse_kallsyms_from_binary(data, kimage_base)

    if results:
        print("\nFound symbols:")
        for name, addr in sorted(results.items()):
            offset = addr - kimage_base
            print("  %s = 0x%x (offset 0x%x)" % (name, addr, offset))
    else:
        print("No symbols found")

if __name__ == "__main__":
    main()
