// Ghidra headless script to find missing kernel symbols
// Usage: analyzeHeadless ... -postScript FindSymbols.java

import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class FindSymbols extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] targets = {
            "kmalloc_caches",
            "selinux_blob_sizes",
            "security_hook_heads",
            "ashmem_misc_fops",
            "generic_pipe_buf_ops",
            "anon_pipe_buf_ops",
            "configfs_read_iter",
            "configfs_bin_write_iter",
            "copy_splice_read",
        };

        println("=== Searching for missing kernel symbols ===");
        println("Base address: " + currentProgram.getImageBase());

        // Search for strings in memory
        Memory memory = currentProgram.getMemory();

        for (String target : targets) {
            byte[] pattern = target.getBytes();
            Address[] found = findBytes(null, pattern);
            if (found != null && found.length > 0) {
                for (Address addr : found) {
                    long offset = addr.getOffset();
                    println("FOUND: '" + target + "' @ 0x" + Long.toHexString(offset));
                }
            } else {
                println("NOT FOUND: '" + target + "'");
            }
        }

        println("\n=== Done ===");
    }
}
