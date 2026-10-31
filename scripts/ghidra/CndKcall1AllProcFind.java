// Derive the allproc list head from a proc-list walker (proc_iterate).
//
// The walker loads the head of `allproc` through an adrp page plus an
// add/ldr page offset; this script decodes those chains from the raw
// AArch64 encodings (no reliance on analysis-created references), lists
// every static the function loads through (HEAD-LOAD lines, in function
// order, each with the nearest preceding flag test on the walker's
// `flags` argument), and then enumerates every program-wide reference
// to each 64-bit head-load static so a candidate carries independent
// witnesses (other readers/writers of the same list head).
//
// Self-check discipline: run first on the research (VM) program with
// the pinned vPhone allproc as EXPECT_HEX; the method is trusted only if
// the HEAD-LOAD selection rule reproduces that pin (SELF-CHECK true).
// Then run on the phone program with the same selection rule.
//
// usage: CndKcall1AllProcFind.java OUTPUT FUNCTION_NAME [FUNCTION_HEX]
//        [EXPECT_HEX]
// FUNCTION_NAME is tried as a symbol (with and without a leading `_`);
// FUNCTION_HEX (or `-`) is the fallback entry address when the program
// has no such symbol. EXPECT_HEX (or `-`) is the pin to self-check.
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class CndKcall1AllProcFind extends GhidraScript {
    private static final class HeadLoad {
        final long offset;
        final long target;
        final int width;
        final String form;
        final String flagTest;
        final String text;

        HeadLoad(long offset, long target, int width, String form,
                String flagTest, String text) {
            this.offset = offset;
            this.target = target;
            this.width = width;
            this.form = form;
            this.flagTest = flagTest;
            this.text = text;
        }
    }

    private static String normalized(Instruction instruction) {
        StringBuilder text = new StringBuilder();
        for (int operand = 0; operand < instruction.getNumOperands();
                operand++) {
            if (text.length() > 0) {
                text.append(";");
            }
            StringBuilder part = new StringBuilder();
            for (Object object : instruction.getOpObjects(operand)) {
                if (part.length() > 0) {
                    part.append(",");
                }
                if (object instanceof Address) {
                    part.append("ADDR");
                } else {
                    String value = object.toString();
                    if (value.startsWith("0x") || value.startsWith("-0x")) {
                        part.append("IMM").append(value);
                    } else {
                        part.append(value);
                    }
                }
            }
            text.append(part);
        }
        return (instruction.getMnemonicString() + " " + text).trim();
    }

    private static int word(byte[] bytes) {
        return (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8)
                | ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24);
    }

    private Function resolve(String name, String fallbackHex)
            throws Exception {
        for (String candidate : new String[] {name, "_" + name,
                name.startsWith("_") ? name.substring(1) : name}) {
            SymbolIterator symbols = currentProgram.getSymbolTable()
                    .getSymbols(candidate);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                Function function = getFunctionAt(symbol.getAddress());
                if (function != null) {
                    println("RESOLVED-BY symbol " + symbol.getName()
                            + " at " + symbol.getAddress());
                    return function;
                }
            }
        }
        if (fallbackHex == null || fallbackHex.equals("-")) {
            return null;
        }
        Address address = toAddr(Long.parseUnsignedLong(
                fallbackHex.replace("0x", ""), 16));
        Function function = getFunctionAt(address);
        if (function == null) {
            function = getFunctionContaining(address);
        }
        if (function != null) {
            println("RESOLVED-BY address " + address + " function "
                    + function.getName() + " entry "
                    + function.getEntryPoint());
        }
        return function;
    }

    private String blockName(long address) {
        MemoryBlock block = currentProgram.getMemory().getBlock(
                toAddr(address));
        return block == null ? "none" : block.getName();
    }

    private String symbolAt(long address) {
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(
                toAddr(address));
        return symbol == null ? "-" : symbol.getName();
    }

    private List<HeadLoad> scan(Function function, PrintWriter out) {
        Listing listing = currentProgram.getListing();
        long entry = function.getEntryPoint().getOffset();
        long end = function.getBody().getMaxAddress().getOffset();
        Map<String, Long> page = new HashMap<>();   // reg -> adrp page
        Map<String, Long> fixed = new HashMap<>();  // reg -> adrp+add
        String lastFlagTest = "-";
        List<HeadLoad> loads = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(
                function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            long pc = instruction.getAddress().getOffset();
            if (pc < entry || pc > end) {
                continue;
            }
            int encoding;
            try {
                encoding = word(instruction.getBytes());
            } catch (Exception e) {
                continue;
            }
            String text = normalized(instruction);
            String mnemonic = instruction.getMnemonicString();
            if (mnemonic.equals("tbz") || mnemonic.equals("tbnz")
                    || mnemonic.equals("tst") || mnemonic.equals("ands")) {
                lastFlagTest = String.format("+0x%x %s", pc - entry, text);
            }
            out.printf("  DIS +0x%x %s%n", pc - entry, text);
            int rd = encoding & 0x1f;
            int rn = (encoding >> 5) & 0x1f;
            String xd = "x" + rd;
            String xn = "x" + rn;
            if ((encoding & 0x9f000000) == 0x90000000) {
                // ADRP: immlo bits 30:29, immhi bits 23:5, imm <<= 12.
                int immlo = (encoding >> 29) & 0x3;
                int immhi = (encoding >> 5) & 0x7ffff;
                long imm = ((long) ((immhi << 2) | immlo) << 12);
                imm = (imm << 31) >> 31;  // sign-extend 33-bit value
                long target = (pc & ~0xfffL) + imm;
                page.put(xd, target);
                fixed.remove(xd);
                out.printf("  ADRP +0x%x %s page %016x%n", pc - entry,
                        xd, target);
                continue;
            }
            if ((encoding & 0xff800000) == 0x91000000
                    && page.containsKey(xn)) {
                // ADD (immediate, 64-bit, no shift) on an adrp page.
                long imm = (encoding >> 10) & 0xfff;
                long target = page.get(xn) + imm;
                fixed.put(xd, target);
                page.remove(xd);
                out.printf("  ADRP-ADD +0x%x %s static %016x%n",
                        pc - entry, xd, target);
                continue;
            }
            boolean ldr64 = (encoding & 0xffc00000) == 0xf9400000;
            boolean ldr32 = (encoding & 0xffc00000) == 0xb9400000;
            if (ldr64 || ldr32) {
                long imm12 = (encoding >> 10) & 0xfff;
                long imm = imm12 * (ldr64 ? 8 : 4);
                int width = ldr64 ? 64 : 32;
                if (page.containsKey(xn)) {
                    long target = page.get(xn) + imm;
                    HeadLoad load = new HeadLoad(pc - entry, target, width,
                            "adrp+ldr", lastFlagTest, text);
                    loads.add(load);
                    out.printf("  HEAD-LOAD +0x%x width %d %s static %016x "
                            + "block %s symbol %s flag-test \"%s\"%n",
                            pc - entry, width, load.form, target,
                            blockName(target), symbolAt(target),
                            lastFlagTest);
                } else if (fixed.containsKey(xn) && imm == 0) {
                    long target = fixed.get(xn);
                    HeadLoad load = new HeadLoad(pc - entry, target, width,
                            "adrp+add+ldr", lastFlagTest, text);
                    loads.add(load);
                    out.printf("  HEAD-LOAD +0x%x width %d %s static %016x "
                            + "block %s symbol %s flag-test \"%s\"%n",
                            pc - entry, width, load.form, target,
                            blockName(target), symbolAt(target),
                            lastFlagTest);
                } else if (fixed.containsKey(xn)) {
                    out.printf("  FIELD-LOAD +0x%x width %d static %016x "
                            + "+ 0x%x%n", pc - entry, width, fixed.get(xn),
                            imm);
                }
            }
            // Any instruction writing a tracked register clobbers it
            // (the adrp/add cases above returned before reaching here).
            for (Object object : instruction.getResultObjects()) {
                String written = object.toString();
                if (written.startsWith("w")) {
                    written = "x" + written.substring(1);
                }
                page.remove(written);
                fixed.remove(written);
            }
        }
        return loads;
    }

    private void references(long target, PrintWriter out) {
        ReferenceIterator iterator = currentProgram.getReferenceManager()
                .getReferencesTo(toAddr(target));
        int count = 0;
        Map<String, Integer> byFunction = new LinkedHashMap<>();
        while (iterator.hasNext()) {
            Reference reference = iterator.next();
            Function from = getFunctionContaining(reference.getFromAddress());
            String name = from == null ? "-" : from.getName();
            out.printf("  REF-TO %016x from %s in %s %s%n", target,
                    reference.getFromAddress(), name,
                    reference.getReferenceType());
            byFunction.merge(name, 1, Integer::sum);
            count++;
        }
        out.printf("  REF-TO-COUNT %016x %d functions %d%n", target, count,
                byFunction.size());
        for (Map.Entry<String, Integer> entry : byFunction.entrySet()) {
            out.printf("  REF-TO-FUNCTION %016x %s %d%n", target,
                    entry.getKey(), entry.getValue());
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("usage: OUTPUT FUNCTION_NAME [FUNCTION_HEX] "
                    + "[EXPECT_HEX]");
            return;
        }
        String fallback = args.length > 2 ? args[2] : "-";
        String expectHex = args.length > 3 ? args[3] : "-";
        long expect = expectHex.equals("-") ? 0 : Long.parseUnsignedLong(
                expectHex.replace("0x", ""), 16);
        try (PrintWriter out = new PrintWriter(new File(args[0]), "UTF-8")) {
            out.printf("PROGRAM %s base %s%n", currentProgram.getName(),
                    currentProgram.getImageBase());
            Function function = resolve(args[1], fallback);
            if (function == null) {
                out.printf("FUNCTION %s unresolved (no symbol; fallback %s)%n",
                        args[1], fallback);
                return;
            }
            long size = function.getBody().getNumAddresses();
            out.printf("FUNCTION %s entry %s size %d name %s%n", args[1],
                    function.getEntryPoint(), size, function.getName());
            List<HeadLoad> loads = scan(function, out);
            int sixtyFour = 0;
            long firstSixtyFour = 0;
            List<Long> distinct = new ArrayList<>();
            for (HeadLoad load : loads) {
                if (load.width != 64) {
                    continue;
                }
                sixtyFour++;
                if (firstSixtyFour == 0) {
                    firstSixtyFour = load.target;
                }
                if (!distinct.contains(load.target)) {
                    distinct.add(load.target);
                }
            }
            out.printf("HEAD-LOAD-COUNT %d width64 %d distinct64 %d%n",
                    loads.size(), sixtyFour, distinct.size());
            for (int index = 0; index < distinct.size(); index++) {
                out.printf("HEAD-STATIC %d %016x block %s symbol %s%n", index,
                        distinct.get(index), blockName(distinct.get(index)),
                        symbolAt(distinct.get(index)));
            }
            // Selection rule: the 64-bit head load guarded by the bit-0
            // flag test (PROC_ALLPROCLIST == 1); the bit-1 guarded load
            // (PROC_ZOMBPROCLIST == 2) is zombproc.
            long bit0 = 0;
            int bit0Count = 0;
            long bit1 = 0;
            int bit1Count = 0;
            for (HeadLoad load : loads) {
                if (load.width != 64) {
                    continue;
                }
                if (load.flagTest.contains("IMM0x0") && bit0 != load.target) {
                    bit0 = load.target;
                    bit0Count++;
                } else if (load.flagTest.contains("IMM0x1")
                        && bit1 != load.target) {
                    bit1 = load.target;
                    bit1Count++;
                }
            }
            out.printf("ALLPROC-CANDIDATE-COUNT %d%n", bit0Count);
            if (bit0Count == 1) {
                out.printf("ALLPROC-CANDIDATE %016x (bit-0 guarded head "
                        + "load)%n", bit0);
            }
            out.printf("ZOMBPROC-CANDIDATE-COUNT %d%n", bit1Count);
            if (bit1Count == 1) {
                out.printf("ZOMBPROC-CANDIDATE %016x (bit-1 guarded head "
                        + "load)%n", bit1);
                if (bit0Count == 1) {
                    out.printf("ZOMBPROC-MINUS-ALLPROC 0x%x%n", bit1 - bit0);
                }
            }
            if (expect != 0) {
                out.printf("SELF-CHECK expect %016x candidate %s match %s%n",
                        expect, bit0Count == 1
                                ? String.format("%016x", bit0) : "none",
                        Boolean.toString(bit0Count == 1 && bit0 == expect));
            }
            for (long target : distinct) {
                references(target, out);
            }
        }
    }
}
