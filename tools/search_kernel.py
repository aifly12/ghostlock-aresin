#!/usr/bin/env python3
"""
Search kernel binary for specific strings and patterns.
This is a standalone Python script that doesn't require Ghidra.
"""

import sys

def search_kernel_binary(kernel_path, output_path):
    """Search kernel binary for specific strings and patterns."""
    
    targets = [
        b"kmalloc_caches",
        b"selinux_blob_sizes",
        b"security_hook_heads",
        b"ashmem_misc_fops",
        b"generic_pipe_buf_ops",
        b"anon_pipe_buf_ops",
        b"configfs_read_iter",
        b"configfs_bin_write_iter",
        b"copy_splice_read",
        b"noop_llseek",
        b"generic_pipe_buf_confirm",
        b"generic_pipe_buf_release"
    ]
    
    KIMAGE_BASE = 0xFFFFFF939BC80000
    TEXT_START = 0x80000
    
    print(f"Searching kernel binary: {kernel_path}")
    print(f"KIMAGE_TEXT_BASE: 0x{KIMAGE_BASE:X}")
    print()
    
    with open(kernel_path, 'rb') as f:
        data = f.read()
    
    results = []
    
    # Search for strings
    for target in targets:
        target_str = target.decode('ascii', errors='replace')
        idx = 0
        found = False
        while True:
            idx = data.find(target, idx)
            if idx < 0:
                break
            va = KIMAGE_BASE + idx
            results.append(f"FOUND: '{target_str}' @ file 0x{idx:X} (VA 0x{va:X})")
            print(f"FOUND: '{target_str}' @ file 0x{idx:X} (VA 0x{va:X})")
            found = True
            idx += 1
        
        if not found:
            results.append(f"NOT FOUND: '{target_str}'")
            print(f"NOT FOUND: '{target_str}'")
    
    # Search for code patterns
    print("\n=== Searching for code patterns ===")
    
    # Search for MOV W0, #0; RET (generic_pipe_buf_confirm)
    confirm_pattern = b'\x00\x00\x80\x52\xc0\x03\x5f\xd6'
    idx = 0
    count = 0
    while count < 10:
        idx = data.find(confirm_pattern, idx)
        if idx < 0:
            break
        va = KIMAGE_BASE + idx
        results.append(f"CODE: 'MOV W0,#0; RET' @ file 0x{idx:X} (VA 0x{va:X})")
        print(f"CODE: 'MOV W0,#0; RET' @ file 0x{idx:X} (VA 0x{va:X})")
        count += 1
        idx += 1
    
    # Write results to file
    with open(output_path, 'w') as f:
        f.write('\n'.join(results))
    
    print(f"\nResults saved to: {output_path}")

if __name__ == "__main__":
    kernel_path = "C:/Users/Lenovo/Desktop/adsadsd/ghostlock-aresin/boot/kernel_raw"
    output_path = "C:/Users/Lenovo/Desktop/adsadsd/ghostlock-aresin/tools/kernel_symbols.txt"
    search_kernel_binary(kernel_path, output_path)
