// Find kcall1 kernel-proper roles by matching the VM (xnu-12377.42.6~55)
// fingerprints: the ether_check_multi stock callback by body fingerprint
// (exact then mnemonic-only fallback), and the two outline stub arrays
// (ENOEXEC mov w0,imm array; load/ldr w0,[x0] array) by walking every
// maximal run of consecutive 12-byte (bti; X; ret) outline elements and
// matching each run's mnemonic:scalar value sequence against the VM
// array structure. Self-check on the research program must rediscover
// the pinned VM statics before any phone output is trusted.
// usage: CndKcall1PhoneKernelFind.java OUTPUT STOCK_FINGERPRINT_FILE
//        [GOT_CANDIDATE_HEX]
// The optional third argument is the stock-callback candidate implied
// by the kext __got donor slot (container base + chained-fixup target
// offset, as computed by the caller); the script dumps the function at
// that address and reports its exact/mnemonic agreement with the
// fingerprint, so the GOT-derived route can be checked without any
// address scanning.
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class CndKcall1PhoneKernelFind extends GhidraScript {
    // VM array structure (vm-signatures.txt ROLE enoexec_return_stub /
    // ROLE load_w0_from_x0_stub): the contiguous element value sequences
    // whose FIRST element is the pinned stub.
    private static final String[] ENOEXEC_SEQUENCE = {
        "mov:0x8", "mov:0x1", "mov:0x2", "mov:0x4", "mov:0x8", "mov:0x4",
        "mov:0x8",
    };
    private static final String[] LOAD_SEQUENCE = {
        "ldr:", "ldr:0x4", "ldr:0x8", "str:0x8",
    };
    private static final String ENOEXEC_MIDDLE = "mov w0;IMM0x8";
    private static final String LOAD_MIDDLE = "ldr w0;x0";

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
                    if (value.startsWith("0x")) {
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

    private static String mnemonicOf(String line) {
        return line.trim().split(" ", 2)[0];
    }

    // The element's "mnemonic:scalar" token: the scalar objects of the
    // last operand (register objects are dropped), so that
    //   mov w0,#0x8      -> mov:0x8
    //   ldr w0,[x0]      -> ldr:
    //   ldr w0,[x0,#0x4] -> ldr:0x4
    //   str x1,[x0,#0x8] -> str:0x8
    private static String valueToken(Instruction middle) {
        StringBuilder scalar = new StringBuilder();
        int operands = middle.getNumOperands();
        if (operands > 0) {
            for (Object object : middle.getOpObjects(operands - 1)) {
                if (object instanceof ghidra.program.model.scalar.Scalar) {
                    scalar.append(object.toString());
                }
            }
        }
        return middle.getMnemonicString() + ":" + scalar;
    }

    private List<Instruction> instructionsAt(Address address, int count) {
        Listing listing = currentProgram.getListing();
        List<Instruction> result = new ArrayList<>();
        Instruction current = listing.getInstructionAt(address);
        while (current != null && result.size() < count) {
            result.add(current);
            current = listing.getInstructionAfter(current.getAddress());
        }
        return result;
    }

    // One maximal run of consecutive (bti; X; ret) 12-byte elements.
    private static final class OutlineRun {
        final List<Address> starts = new ArrayList<>();
        final List<String> tokens = new ArrayList<>();
        final List<String> middles = new ArrayList<>();
    }

    // Returns the 3-instruction window if `address` begins a 12-byte
    // (bti; X; ret) element with X neither bti nor ret, else null.
    private List<Instruction> elementAt(Address address) {
        List<Instruction> window = instructionsAt(address, 3);
        if (window.size() < 3) {
            return null;
        }
        Instruction bti = window.get(0);
        Instruction middle = window.get(1);
        Instruction ret = window.get(2);
        if (!bti.getMnemonicString().equals("bti")
                || !ret.getMnemonicString().equals("ret")
                || middle.getMnemonicString().equals("bti")
                || middle.getMnemonicString().equals("ret")
                || bti.getLength() != 4 || middle.getLength() != 4
                || ret.getLength() != 4
                || !middle.getAddress().equals(address.add(4))
                || !ret.getAddress().equals(address.add(8))) {
            return null;
        }
        return window;
    }

    private List<OutlineRun> outlineRuns() {
        Listing listing = currentProgram.getListing();
        InstructionIterator all = listing.getInstructions(true);
        List<OutlineRun> runs = new ArrayList<>();
        OutlineRun current = null;
        Address expectedNext = null;
        while (all.hasNext()) {
            Instruction instruction = all.next();
            Address address = instruction.getAddress();
            if (expectedNext != null && address.compareTo(expectedNext) < 0) {
                continue;  // inside the element just accepted
            }
            List<Instruction> window = null;
            if (instruction.getMnemonicString().equals("bti")) {
                window = elementAt(address);
            }
            if (window == null) {
                if (current != null) {
                    runs.add(current);
                    current = null;
                }
                expectedNext = null;
                continue;
            }
            if (current == null || expectedNext == null
                    || !address.equals(expectedNext)) {
                if (current != null) {
                    runs.add(current);
                }
                current = new OutlineRun();
            }
            current.starts.add(address);
            current.tokens.add(valueToken(window.get(1)));
            current.middles.add(normalized(window.get(1)));
            expectedNext = address.add(12);
        }
        if (current != null) {
            runs.add(current);
        }
        return runs;
    }

    private static int indexOfSequence(List<String> tokens,
            String[] sequence) {
        for (int start = 0; start + sequence.length <= tokens.size();
                start++) {
            boolean match = true;
            for (int i = 0; i < sequence.length; i++) {
                if (!tokens.get(start + i).equals(sequence[i])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return start;
            }
        }
        return -1;
    }

    private void printRun(PrintWriter out, String label, OutlineRun run) {
        out.println(label + " " + run.starts.get(0) + " elements "
                + run.starts.size() + " values "
                + String.join(",", run.tokens));
    }

    private void printElement(PrintWriter out, String label, OutlineRun run,
            int index) {
        out.println("  " + label + " element " + index + " at "
                + run.starts.get(index) + " middle \""
                + run.middles.get(index) + "\"");
        for (Instruction instruction : instructionsAt(
                run.starts.get(index), 3)) {
            out.println("    DIS " + Long.toString(instruction.getAddress()
                    .subtract(run.starts.get(index))) + " "
                    + normalized(instruction));
        }
        ReferenceIterator refs = currentProgram.getReferenceManager()
                .getReferencesTo(run.starts.get(index));
        int counted = 0;
        while (refs.hasNext() && counted < 40) {
            Reference reference = refs.next();
            out.println("    REF " + reference.getFromAddress() + " "
                    + reference.getReferenceType());
            counted++;
        }
        if (counted == 0) {
            out.println("    REF none");
        }
    }

    private void reportCandidate(PrintWriter out, String hex,
            List<String> fingerprintLines) {
        Address candidate = currentProgram.getAddressFactory()
                .getAddress(hex);
        out.println("GOT-CANDIDATE " + candidate);
        if (currentProgram.getMemory().getBlock(candidate) == null) {
            out.println("GOT-CANDIDATE-BLOCK none-in-this-program");
            return;
        }
        out.println("GOT-CANDIDATE-BLOCK " + currentProgram.getMemory()
                .getBlock(candidate).getName());
        Function function = currentProgram.getFunctionManager()
                .getFunctionContaining(candidate);
        if (function == null) {
            out.println("GOT-CANDIDATE-FUNCTION none");
        } else {
            out.println("GOT-CANDIDATE-FUNCTION " + function.getName()
                    + " entry " + function.getEntryPoint() + " size "
                    + function.getBody().getNumAddresses()
                    + " offset-in-function "
                    + candidate.subtract(function.getEntryPoint()));
        }
        List<Instruction> body = instructionsAt(candidate, 40);
        for (Instruction instruction : body) {
            out.println("  DIS " + Long.toString(instruction.getAddress()
                    .subtract(candidate)) + " " + normalized(instruction));
        }
        int length = fingerprintLines.size();
        // Compare from the entry, and (if the entry is a `bti` landing
        // pad) from entry+4 as well; each comparison is reported.
        for (int skip = 0; skip < 2; skip++) {
            if (skip == 1 && (body.isEmpty()
                    || !body.get(0).getMnemonicString().equals("bti"))) {
                break;
            }
            List<Instruction> window = body.subList(skip, body.size());
            boolean exact = window.size() >= length;
            int sameMnemonic = 0;
            for (int i = 0; i < length && i < window.size(); i++) {
                String line = normalized(window.get(i));
                if (!line.equals(fingerprintLines.get(i))) {
                    exact = false;
                    out.println("  DIFF" + (skip == 1 ? "-AFTER-BTI " : " ")
                            + i + " vm=" + fingerprintLines.get(i)
                            + " this=" + line);
                }
                if (mnemonicOf(line).equals(
                        mnemonicOf(fingerprintLines.get(i)))) {
                    sameMnemonic++;
                }
            }
            String label = skip == 1 ? "GOT-CANDIDATE-AFTER-BTI-"
                    : "GOT-CANDIDATE-";
            out.println(label + "EXACT " + exact);
            out.println(label + "SAME-MNEMONIC " + sameMnemonic + "/"
                    + length);
        }
        ReferenceIterator refs = currentProgram.getReferenceManager()
                .getReferencesTo(candidate);
        int counted = 0;
        while (refs.hasNext() && counted < 40) {
            Reference reference = refs.next();
            out.println("  REF " + reference.getFromAddress() + " "
                    + reference.getReferenceType());
            counted++;
        }
        out.println("GOT-CANDIDATE-REF-COUNT " + counted);
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 2 && arguments.length != 3) {
            throw new IllegalArgumentException(
                "usage: CndKcall1PhoneKernelFind.java OUTPUT "
                + "STOCK_FINGERPRINT_FILE [GOT_CANDIDATE_HEX]");
        }
        // Fingerprint lines are "DIS <decimal-offset> <normalized>"; keep
        // only the normalized text (part 2 of a 3-way split).
        List<String> fingerprintLines = new ArrayList<>();
        for (String line : Files.readAllLines(
                new File(arguments[1]).toPath(), StandardCharsets.UTF_8)) {
            if (!line.startsWith("DIS ")) {
                continue;
            }
            String[] parts = line.split(" ", 3);
            fingerprintLines.add(parts.length < 3 ? "" : parts[2].trim());
        }
        try (PrintWriter out = new PrintWriter(new File(arguments[0]),
                StandardCharsets.UTF_8)) {
            out.println("PROGRAM " + currentProgram.getName()
                    + " base " + currentProgram.getImageBase());
            out.println("FINGERPRINT-LENGTH " + fingerprintLines.size());
            for (int i = 0; i < fingerprintLines.size(); i++) {
                out.println("FINGERPRINT " + i + " "
                        + fingerprintLines.get(i));
            }
            int length = fingerprintLines.size();

            // 1. Stock callback: exact body, then mnemonic-only fallback.
            FunctionIterator functions = currentProgram
                    .getFunctionManager().getFunctions(true);
            int exact = 0;
            int exactBti = 0;
            int loose = 0;
            while (functions.hasNext()) {
                Function function = functions.next();
                long size = function.getBody().getNumAddresses();
                if (size < length * 4 - 4 || size > length * 4 + 24) {
                    continue;
                }
                List<Instruction> body = instructionsAt(
                        function.getEntryPoint(), length + 1);
                if (body.size() < length) {
                    continue;
                }
                // A RELEASE kernel may prefix the identical body with a
                // single `bti c` landing pad; that is reported as its own
                // tier (STOCK-EXACT-BTI), never folded into STOCK-EXACT.
                boolean btiPrefixed = body.size() == length + 1
                        && body.get(0).getMnemonicString().equals("bti");
                if (btiPrefixed) {
                    body = body.subList(1, length + 1);
                } else {
                    body = body.subList(0, length);
                }
                boolean exactMatch = true;
                int sameMnemonic = 0;
                for (int i = 0; i < length; i++) {
                    String line = normalized(body.get(i));
                    if (!line.equals(fingerprintLines.get(i))) {
                        exactMatch = false;
                    }
                    if (mnemonicOf(line).equals(
                            mnemonicOf(fingerprintLines.get(i)))) {
                        sameMnemonic++;
                    }
                }
                if (exactMatch) {
                    if (btiPrefixed) {
                        exactBti++;
                    } else {
                        exact++;
                    }
                    out.println((btiPrefixed ? "STOCK-EXACT-BTI "
                            : "STOCK-EXACT ") + function.getEntryPoint()
                            + " size " + size + " name "
                            + function.getName()
                            + (btiPrefixed ? " (entry is `bti`; body "
                                    + "offsets below are from the entry)"
                                    : ""));
                    if (btiPrefixed) {
                        out.println("  DIS 0 bti");
                    }
                    for (Instruction instruction : body) {
                        out.println("  DIS " + Long.toString(instruction
                                .getAddress().subtract(
                                        function.getEntryPoint()))
                                + " " + normalized(instruction));
                    }
                    ReferenceIterator refs = currentProgram
                            .getReferenceManager().getReferencesTo(
                                    function.getEntryPoint());
                    int counted = 0;
                    while (refs.hasNext() && counted < 40) {
                        Reference reference = refs.next();
                        out.println("  REF " + reference.getFromAddress()
                                + " " + reference.getReferenceType());
                        counted++;
                    }
                    out.println("  REF-COUNT " + counted);
                } else if (sameMnemonic == length) {
                    loose++;
                    out.println("STOCK-MNEMONIC " + function.getEntryPoint()
                            + " size " + size + " name "
                            + function.getName() + " bti-prefixed "
                            + btiPrefixed);
                    for (int i = 0; i < length; i++) {
                        String line = normalized(body.get(i));
                        if (!line.equals(fingerprintLines.get(i))) {
                            out.println("  DIFF " + i + " vm="
                                    + fingerprintLines.get(i)
                                    + " this=" + line);
                        }
                    }
                }
            }
            out.println("STOCK-EXACT-COUNT " + exact);
            out.println("STOCK-EXACT-BTI-COUNT " + exactBti);
            out.println("STOCK-MNEMONIC-COUNT " + loose);

            // 2. Outline element runs, selected by value sequence.
            List<OutlineRun> runs = outlineRuns();
            out.println("OUTLINE-RUN-COUNT " + runs.size());
            int enoexecMatches = 0;
            int loadMatches = 0;
            for (OutlineRun run : runs) {
                int enoexecAt = indexOfSequence(run.tokens,
                        ENOEXEC_SEQUENCE);
                int loadAt = indexOfSequence(run.tokens, LOAD_SEQUENCE);
                if (enoexecAt < 0 && loadAt < 0) {
                    continue;
                }
                printRun(out, "OUTLINE-RUN", run);
                if (enoexecAt >= 0) {
                    boolean middleOk = run.middles.get(enoexecAt)
                            .equals(ENOEXEC_MIDDLE);
                    enoexecMatches++;
                    out.println("  ENOEXEC-SEQUENCE at element "
                            + enoexecAt + " middle-ok " + middleOk);
                    printElement(out, "ENOEXEC-CANDIDATE", run, enoexecAt);
                }
                if (loadAt >= 0) {
                    boolean middleOk = run.middles.get(loadAt)
                            .equals(LOAD_MIDDLE);
                    loadMatches++;
                    out.println("  LOAD-SEQUENCE at element " + loadAt
                            + " middle-ok " + middleOk);
                    printElement(out, "LOAD-CANDIDATE", run, loadAt);
                }
            }
            out.println("ENOEXEC-SEQUENCE-COUNT " + enoexecMatches);
            out.println("LOAD-SEQUENCE-COUNT " + loadMatches);

            // 3. Optional GOT-derived stock candidate: dump and compare.
            if (arguments.length == 3) {
                reportCandidate(out, arguments[2], fingerprintLines);
            }
        }
    }
}
