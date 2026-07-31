# Ghidra headless script to find missing kernel symbols
# Usage: analyzeHeadless ... -postScript find_symbols.py

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import Data
from ghidra.program.model.address import Address

def find_symbol_by_name(name):
    """Search for a symbol by name in the symbol table"""
    sym = currentProgram.getSymbolTable()
    symbols = sym.getSymbols(name)
    for s in symbols:
        return s
    return None

def find_data_at_address(addr_str):
    """Get data at a specific address"""
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr:
        listing = currentProgram.getListing()
        data = listing.getDataAt(addr)
        return data
    return None

def search_string_in_listing(search_str):
    """Search for a string in the listing"""
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    count = 0
    while data_iter.hasNext() and count < 100000:
        data = data_iter.next()
        if data.hasStringValue():
            val = data.getDefaultValueRepresentation()
            if search_str in val:
                print("Found string '%s' at %s" % (search_str, data.getAddress()))
                return data
        count += 1
    return None

# Main search
print("=" * 60)
print("Searching for missing kernel symbols...")
print("=" * 60)

# Search for symbols
targets = [
    "kmalloc_caches",
    "selinux_blob_sizes",
    "security_hook_heads",
    "ashmem_misc_fops",
    "generic_pipe_buf_ops",
    "anon_pipe_buf_ops",
    "configfs_read_iter",
    "configfs_bin_write_iter",
    "copy_splice_read",
]

for name in targets:
    sym = find_symbol_by_name(name)
    if sym:
        addr = sym.getAddress()
        print("FOUND: %s @ %s (0x%x)" % (name, addr, addr.getOffset()))
    else:
        print("NOT FOUND: %s" % name)

print("\nDone.")
