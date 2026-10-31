// Probe a Ghidra program's identity: name, image base, block sizes.
// @category Cyanide

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

public class CndProbeProgram extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("PROGRAM_NAME=" + currentProgram.getName());
        println("IMAGE_BASE=" + currentProgram.getImageBase().toString());
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        long total = 0;
        for (MemoryBlock block : blocks) {
            println("BLOCK " + block.getName() + " "
                    + block.getStart().toString() + "-"
                    + block.getEnd().toString()
                    + " " + Long.toString(block.getSize()));
            total += block.getSize();
        }
        println("TOTAL_BYTES=" + Long.toString(total));
    }
}