import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class RebaseAndSearch extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== GhostLock Kernel Symbol Search ===");
        println("Program: " + currentProgram.getName());
        println("Current Image Base: " + currentProgram.getImageBase());

        // Rebase to correct address
        long KIMAGE_BASE = 0xFFFFFF939BC80000L;
        Address newBase = getAddressFactory().getDefaultAddressSpace().getAddress(KIMAGE_BASE);
        
        println("Rebasing to: 0x" + Long.toHexString(KIMAGE_BASE));
        
        // Use setImageBase to rebase
        boolean relocated = currentProgram.setImageBase(newBase, true);
        println("Rebase result: " + relocated);
        println("New Image Base: " + currentProgram.getImageBase());

        // Search for strings in memory
        println("\n=== Searching for kernel strings ===");
        
        String[] searchStrings = {
            "kmalloc_caches",
            "selinux_blob_sizes", 
            "security_hook_heads",
            "ashmem_misc_fops",
            "generic_pipe_buf_ops",
            "anon_pipe_buf_ops",
            "configfs_read_iter",
            "configfs_bin_write_iter",
            "copy_splice_read",
            "noop_llseek",
            "generic_pipe_buf_confirm",
            "generic_pipe_buf_release"
        };

        Memory memory = currentProgram.getMemory();
        
        for (String target : searchStrings) {
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
