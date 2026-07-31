import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;

public class ghidra_find_offsets extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Ghidra Offset Finder ===");
        println("Program: " + currentProgram.getName());
        println("Image Base: " + currentProgram.getImageBase());
        
        // List all functions matching our target names
        String[] targets = {
            "kmem_cache_alloc", "kmalloc_slab", "__kmalloc", "krealloc",
            "create_kmalloc_caches", "security_file_open", "ashmem_mmap",
            "generic_pipe_buf_confirm", "generic_pipe_buf_release",
            "noop_llseek", "copy_splice_read", "configfs_read_iter",
            "selinux_task_alloc", "selinux_cred_alloc"
        };
        
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            String name = func.getName();
            for (String target : targets) {
                if (name.equals(target)) {
                    Address addr = func.getEntryPoint();
                    println("FOUND: " + name + " @ " + addr);
                    
                    // Scan first 200 instructions for ADRP+ADD
                    AddressIterator body = func.getBody().getAddresses(true);
                    int count = 0;
                    while (body.hasNext() && count < 200) {
                        Address a = body.next();
                        count++;
                        try {
                            int instr = currentProgram.getMemory().getInt(a);
                            if ((instr & 0x9F00001F) == 0x90000000) {
                                // ADRP
                                int rd = instr & 0x1f;
                                int immlo = (instr >> 29) & 0x3;
                                int immhi = (instr >> 5) & 0x7ffff;
                                long imm = ((long)(immhi << 2) | immlo) << 12;
                                if (imm >= 0x100000000L) imm -= 0x200000000L;
                                long pc = a.getOffset();
                                long page = (pc & ~0xfffL) + imm;
                                
                                // Check next instruction
                                Address nextA = a.add(4);
                                int next = currentProgram.getMemory().getInt(nextA);
                                if ((next & 0xFFC00000) == 0x91000000) {
                                    int rd2 = next & 0x1f;
                                    if (rd == rd2) {
                                        int imm12 = (next >> 10) & 0xfff;
                                        int sh = (next >> 22) & 3;
                                        if (sh == 1) imm12 <<= 12;
                                        long target_addr = page + imm12;
                                        println("  ADRP+ADD -> 0x" + Long.toHexString(target_addr));
                                    }
                                } else if ((next & 0xFFC00000) == 0xF9400000) {
                                    int rn = (next >> 5) & 0x1f;
                                    if (rd == rn) {
                                        int imm12 = (next >> 10) & 0xfff;
                                        long target_addr = page + imm12 * 8;
                                        println("  ADRP+LDR -> 0x" + Long.toHexString(target_addr));
                                    }
                                }
                            }
                        } catch (Exception e) {
                            // skip
                        }
                    }
                    break;
                }
            }
        }
        println("=== Done ===");
    }
}
