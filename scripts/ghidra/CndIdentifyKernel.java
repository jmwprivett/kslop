// Identify a kernel program: function count plus version/cstring anchors.
// @category Cyanide

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public class CndIdentifyKernel extends GhidraScript {
    private static String clean(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte b : bytes) {
            int c = b & 0xff;
            if (c >= 0x20 && c < 0x7f) {
                text.append((char) c);
            } else {
                break;
            }
        }
        return text.toString();
    }

    @Override
    public void run() throws Exception {
        println("PROGRAM=" + currentProgram.getName());
        println("BASE=" + currentProgram.getImageBase().toString());
        println("FUNCTIONS=" + Integer.toString(
                currentProgram.getFunctionManager().getFunctionCount()));
        Memory memory = currentProgram.getMemory();
        Address start = currentProgram.getMinAddress();
        Address end = currentProgram.getMaxAddress();
        byte[] needle = "xnu-1".getBytes("UTF-8");
        Address cursor = start;
        int found = 0;
        while (found < 8) {
            Address hit = memory.findBytes(cursor, end, needle, null,
                    true, monitor);
            if (hit == null) {
                break;
            }
            byte[] context = new byte[96];
            memory.getBytes(hit, context);
            println("XNU@" + hit.toString() + " " + clean(context));
            cursor = hit.add(1);
            found++;
        }
    }
}