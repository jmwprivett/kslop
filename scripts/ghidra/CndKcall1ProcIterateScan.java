// Program-wide structural scan for the proc_iterate shape, independent
// of symbol names: a function that loads a 64-bit list head guarded by
// `tbz/tbnz wN,#0` (PROC_ALLPROCLIST == 1) and another 64-bit list head
// guarded by `tbz/tbnz wN,#1` (PROC_ZOMBPROCLIST == 2), where the two
// statics are adjacent 8-byte globals (zombproc == allproc + 8, the
// kern_proc.c declaration order). Every function in the program is
// scanned with the same raw adrp/add/ldr decoding as
// CndKcall1AllProcFind; MATCH lines list each function that fits and
// MATCH-COUNT how many did. With EXPECT_HEX the script also reports
// whether the unique match's allproc equals the pin (SELF-CHECK).
// usage: CndKcall1ProcIterateScan.java OUTPUT [EXPECT_HEX]
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Symbol;

public class CndKcall1ProcIterateScan extends GhidraScript {
    private static int word(byte[] bytes) {
        return (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8)
                | ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24);
    }

    /** The bit index tested by a tbz/tbnz instruction, or -1. */
    private static int testedBit(Instruction instruction, int encoding) {
        String mnemonic = instruction.getMnemonicString();
        if (!mnemonic.equals("tbz") && !mnemonic.equals("tbnz")) {
            return -1;
        }
        // TBZ/TBNZ: b5 at bit 31, b40 at bits 23:19.
        int b5 = (encoding >>> 31) & 1;
        int b40 = (encoding >> 19) & 0x1f;
        return (b5 << 5) | b40;
    }

    private String symbolAt(Address address) {
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(
                address);
        return symbol == null ? "-" : symbol.getName();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: OUTPUT [EXPECT_HEX]");
            return;
        }
        long expect = args.length > 1 && !args[1].equals("-")
                ? Long.parseUnsignedLong(args[1].replace("0x", ""), 16) : 0;
        Listing listing = currentProgram.getListing();
        int matchCount = 0;
        long uniqueAllProc = 0;
        int scanned = 0;
        try (PrintWriter out = new PrintWriter(new File(args[0]), "UTF-8")) {
            out.printf("PROGRAM %s base %s%n", currentProgram.getName(),
                    currentProgram.getImageBase());
            FunctionIterator functions = listing.getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                scanned++;
                Map<String, Long> page = new HashMap<>();
                Map<String, Long> fixed = new HashMap<>();
                int lastBit = -1;
                Set<Long> bit0 = new LinkedHashSet<>();
                Set<Long> bit1 = new LinkedHashSet<>();
                int instructions = 0;
                InstructionIterator iterator = listing.getInstructions(
                        function.getBody(), true);
                while (iterator.hasNext()) {
                    Instruction instruction = iterator.next();
                    instructions++;
                    int encoding;
                    try {
                        encoding = word(instruction.getBytes());
                    } catch (Exception e) {
                        continue;
                    }
                    long pc = instruction.getAddress().getOffset();
                    int bit = testedBit(instruction, encoding);
                    if (bit >= 0) {
                        lastBit = bit;
                    }
                    int rd = encoding & 0x1f;
                    int rn = (encoding >> 5) & 0x1f;
                    String xd = "x" + rd;
                    String xn = "x" + rn;
                    if ((encoding & 0x9f000000) == 0x90000000) {
                        int immlo = (encoding >> 29) & 0x3;
                        int immhi = (encoding >> 5) & 0x7ffff;
                        long imm = ((long) ((immhi << 2) | immlo) << 12);
                        imm = (imm << 31) >> 31;
                        page.put(xd, (pc & ~0xfffL) + imm);
                        fixed.remove(xd);
                        continue;
                    }
                    if ((encoding & 0xff800000) == 0x91000000
                            && page.containsKey(xn)) {
                        long imm = (encoding >> 10) & 0xfff;
                        fixed.put(xd, page.get(xn) + imm);
                        page.remove(xd);
                        continue;
                    }
                    if ((encoding & 0xffc00000) == 0xf9400000) {
                        long imm = ((encoding >> 10) & 0xfff) * 8L;
                        long target = -1;
                        if (page.containsKey(xn)) {
                            target = page.get(xn) + imm;
                        } else if (fixed.containsKey(xn) && imm == 0) {
                            target = fixed.get(xn);
                        }
                        if (target != -1) {
                            if (lastBit == 0) {
                                bit0.add(target);
                            } else if (lastBit == 1) {
                                bit1.add(target);
                            }
                        }
                    }
                    for (Object object : instruction.getResultObjects()) {
                        String written = object.toString();
                        if (written.startsWith("w")) {
                            written = "x" + written.substring(1);
                        }
                        page.remove(written);
                        fixed.remove(written);
                    }
                }
                if (bit0.size() != 1 || bit1.size() != 1) {
                    continue;
                }
                long allproc = bit0.iterator().next();
                long zombproc = bit1.iterator().next();
                if (zombproc - allproc != 8) {
                    continue;
                }
                matchCount++;
                uniqueAllProc = allproc;
                out.printf("MATCH %s name %s symbol %s size %d "
                        + "instructions %d allproc %016x zombproc %016x%n",
                        function.getEntryPoint(), function.getName(),
                        symbolAt(function.getEntryPoint()),
                        function.getBody().getNumAddresses(), instructions,
                        allproc, zombproc);
            }
            out.printf("FUNCTIONS-SCANNED %d%n", scanned);
            out.printf("MATCH-COUNT %d%n", matchCount);
            if (expect != 0) {
                out.printf("SELF-CHECK expect %016x match %s%n", expect,
                        Boolean.toString(matchCount == 1
                                && uniqueAllProc == expect));
            }
        }
    }
}
