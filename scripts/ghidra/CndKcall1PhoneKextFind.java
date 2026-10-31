// Find the kcall1 IONetworkingFamily roles by matching the VM
// (vPhone 23A341) kext fingerprints dumped by CndKcall1VMSignatures:
//   init_ifnet_params  - the 123-instruction body (exact match first,
//                        mnemonic-only fallback second; which one is
//                        reported);
//   stock_signer       - inside the matched function: the
//                        `mov x17,#0xe4fe; pacia x16,x17;
//                        str x16,[x19,#0x48]` step, located by pattern
//                        and checked against the VM offset (+0x1B8);
//   checkmulti_got_donor - the __got slot READ-referenced by the
//                        `ldr x16,[x16,#page-off]` immediately before
//                        that step (VM: +0x1B0), with its block, raw
//                        8-byte value and referencing instruction;
//   ifnet_x0_dispatcher - the 28-byte `bti c; ldr x16,[x0,#0xb0]; cbz;
//                        ldr x0,[x0,#0x90]; mov x17,#0xe4fe; braa; ret`
//                        body, exact match of all seven instructions.
// Self-check on ionetworking-23A341 must rediscover the pinned VM
// statics before the ionetworking-physical-23A341 output is trusted.
// usage: CndKcall1PhoneKextFind.java OUTPUT VM_KEXT_SIGNATURES_FILE
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

public class CndKcall1PhoneKextFind extends GhidraScript {
    private static final String INIT_ROLE = "init_ifnet_params";
    private static final String DISPATCHER_ROLE = "ifnet_x0_dispatcher";
    private static final int INIT_INSTRUCTIONS = 123;   // size 492 / 4
    private static final int DISPATCHER_INSTRUCTIONS = 7; // size 28 / 4
    private static final long VM_SIGNER_OFFSET = 0x1B8;
    private static final long VM_GOT_READ_OFFSET = 0x1B0;

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

    private static long readLong(Memory memory, Address address,
            int size) throws Exception {
        byte[] bytes = new byte[size];
        memory.getBytes(address, bytes);
        long value = 0;
        for (int i = size - 1; i >= 0; i--) {
            value = (value << 8) | (bytes[i] & 0xffL);
        }
        return value;
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

    // Parse "ROLE <name> <addr>" sections and their "DIS <off> <text>"
    // lines (normalized text only; the offset token is dropped).
    private static Map<String, List<String>> parseSignatures(File file)
            throws Exception {
        Map<String, List<String>> roles = new LinkedHashMap<>();
        String current = null;
        for (String line : Files.readAllLines(file.toPath(),
                StandardCharsets.UTF_8)) {
            if (line.startsWith("ROLE ")) {
                current = line.split(" ", 3)[1];
                roles.put(current, new ArrayList<>());
            } else if (current != null && line.startsWith("DIS ")) {
                String[] parts = line.split(" ", 3);
                roles.get(current).add(parts.length < 3 ? ""
                        : parts[2].trim());
            }
        }
        return roles;
    }

    private void printReferencesTo(PrintWriter out, Address address,
            String indent) {
        ReferenceIterator refs = currentProgram.getReferenceManager()
                .getReferencesTo(address);
        int counted = 0;
        while (refs.hasNext() && counted < 40) {
            Reference reference = refs.next();
            Function from = currentProgram.getFunctionManager()
                    .getFunctionContaining(reference.getFromAddress());
            out.println(indent + "REF " + reference.getFromAddress() + " "
                    + reference.getReferenceType() + " in "
                    + (from == null ? "?" : from.getName() + "@"
                            + from.getEntryPoint()));
            counted++;
        }
        out.println(indent + "REF-COUNT " + counted);
    }

    // Inside a matched init_ifnet_params body: locate the
    // `ldr x16,[x16,#off]; mov x17,#0xe4fe; pacia x16,x17;
    // str x16,[x19,#0x48]` step and report the signer and the GOT slot.
    private void reportSignerAndDonor(PrintWriter out, Function function,
            List<Instruction> body) throws Exception {
        int found = 0;
        for (int i = 1; i + 2 < body.size(); i++) {
            String mov = normalized(body.get(i));
            String pacia = normalized(body.get(i + 1));
            String str = normalized(body.get(i + 2));
            String ldr = normalized(body.get(i - 1));
            if (!mov.equals("mov x17;IMM0xe4fe")
                    || !pacia.equals("pacia x16;x17")
                    || !str.equals("str x16;x19,IMM0x48")
                    || !ldr.startsWith("ldr x16;x16,")) {
                continue;
            }
            found++;
            Address signer = body.get(i + 1).getAddress();
            Address gotRead = body.get(i - 1).getAddress();
            long signerOffset = signer.subtract(function.getEntryPoint());
            long gotReadOffset = gotRead.subtract(function.getEntryPoint());
            out.println("SIGNER " + signer + " offset 0x"
                    + Long.toHexString(signerOffset) + " vm-offset-match "
                    + (signerOffset == VM_SIGNER_OFFSET) + " \"" + pacia
                    + "\" preceded by \"" + mov + "\" followed by \""
                    + str + "\"");
            out.println("GOT-READ " + gotRead + " offset 0x"
                    + Long.toHexString(gotReadOffset)
                    + " vm-offset-match "
                    + (gotReadOffset == VM_GOT_READ_OFFSET) + " \"" + ldr
                    + "\"");
            Reference[] from = currentProgram.getReferenceManager()
                    .getReferencesFrom(gotRead);
            int slots = 0;
            for (Reference reference : from) {
                Address slot = reference.getToAddress();
                MemoryBlock block = currentProgram.getMemory()
                        .getBlock(slot);
                if (block == null || !reference.getReferenceType().isData()) {
                    continue;
                }
                slots++;
                Symbol symbol = currentProgram.getSymbolTable()
                        .getPrimarySymbol(slot);
                out.println("GOT-SLOT " + slot + " block " + block.getName()
                        + " reftype " + reference.getReferenceType()
                        + " raw8 0x" + Long.toHexString(readLong(
                                currentProgram.getMemory(), slot, 8))
                        + " symbol " + (symbol == null ? "none"
                                : symbol.getName()));
                out.println("  REFERENCES-TO-GOT-SLOT");
                printReferencesTo(out, slot, "    ");
            }
            out.println("GOT-SLOT-COUNT " + slots);
        }
        out.println("SIGNER-PATTERN-COUNT " + found);
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 2) {
            throw new IllegalArgumentException(
                "usage: CndKcall1PhoneKextFind.java OUTPUT "
                + "VM_KEXT_SIGNATURES_FILE");
        }
        Map<String, List<String>> roles = parseSignatures(
                new File(arguments[1]));
        List<String> initLines = roles.getOrDefault(INIT_ROLE,
                new ArrayList<>());
        List<String> dispatcherLines = roles.getOrDefault(DISPATCHER_ROLE,
                new ArrayList<>());
        if (initLines.size() < INIT_INSTRUCTIONS
                || dispatcherLines.size() < DISPATCHER_INSTRUCTIONS) {
            throw new IllegalArgumentException(
                "signature file lacks the " + INIT_ROLE + " ("
                + initLines.size() + ") or " + DISPATCHER_ROLE + " ("
                + dispatcherLines.size() + ") DIS dumps");
        }
        initLines = initLines.subList(0, INIT_INSTRUCTIONS);
        dispatcherLines = dispatcherLines.subList(0, DISPATCHER_INSTRUCTIONS);

        try (PrintWriter out = new PrintWriter(new File(arguments[0]),
                StandardCharsets.UTF_8)) {
            out.println("PROGRAM " + currentProgram.getName()
                    + " base " + currentProgram.getImageBase());
            out.println("INIT-FINGERPRINT-LENGTH " + initLines.size());
            out.println("DISPATCHER-FINGERPRINT-LENGTH "
                    + dispatcherLines.size());

            // 1. init_ifnet_params: exact, then mnemonic-only.
            int initExact = 0;
            int initMnemonic = 0;
            FunctionIterator functions = currentProgram
                    .getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                long size = function.getBody().getNumAddresses();
                if (size < INIT_INSTRUCTIONS * 4 - 4
                        || size > INIT_INSTRUCTIONS * 4 + 64) {
                    continue;
                }
                List<Instruction> body = instructionsAt(
                        function.getEntryPoint(), INIT_INSTRUCTIONS);
                if (body.size() < INIT_INSTRUCTIONS) {
                    continue;
                }
                boolean exact = true;
                int sameMnemonic = 0;
                for (int i = 0; i < INIT_INSTRUCTIONS; i++) {
                    String line = normalized(body.get(i));
                    if (!line.equals(initLines.get(i))) {
                        exact = false;
                    }
                    if (mnemonicOf(line).equals(
                            mnemonicOf(initLines.get(i)))) {
                        sameMnemonic++;
                    }
                }
                if (!exact && sameMnemonic != INIT_INSTRUCTIONS) {
                    continue;
                }
                String tier = exact ? "INIT-EXACT" : "INIT-MNEMONIC";
                if (exact) {
                    initExact++;
                } else {
                    initMnemonic++;
                }
                out.println(tier + " " + function.getEntryPoint() + " size "
                        + size + " name " + function.getName());
                int diffs = 0;
                for (int i = 0; i < INIT_INSTRUCTIONS; i++) {
                    String line = normalized(body.get(i));
                    if (!line.equals(initLines.get(i))) {
                        diffs++;
                        out.println("  DIFF " + (i * 4) + " vm="
                                + initLines.get(i) + " this=" + line);
                    }
                }
                out.println("  DIFF-COUNT " + diffs);
                for (Instruction instruction : body) {
                    out.println("  DIS " + Long.toString(instruction
                            .getAddress().subtract(function.getEntryPoint()))
                            + " " + normalized(instruction));
                }
                out.println("  REFERENCES-TO-FUNCTION");
                printReferencesTo(out, function.getEntryPoint(), "    ");
                reportSignerAndDonor(out, function, body);
            }
            out.println("INIT-EXACT-COUNT " + initExact);
            out.println("INIT-MNEMONIC-COUNT " + initMnemonic);

            // 2. ifnet_x0_dispatcher: the 28-byte body, exact.
            int dispatcherExact = 0;
            functions = currentProgram.getFunctionManager()
                    .getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                long size = function.getBody().getNumAddresses();
                if (size != DISPATCHER_INSTRUCTIONS * 4) {
                    continue;
                }
                List<Instruction> body = instructionsAt(
                        function.getEntryPoint(), DISPATCHER_INSTRUCTIONS);
                if (body.size() < DISPATCHER_INSTRUCTIONS) {
                    continue;
                }
                boolean exact = true;
                for (int i = 0; i < DISPATCHER_INSTRUCTIONS; i++) {
                    if (!normalized(body.get(i)).equals(
                            dispatcherLines.get(i))) {
                        exact = false;
                        break;
                    }
                }
                if (!exact) {
                    continue;
                }
                dispatcherExact++;
                out.println("DISPATCHER-EXACT " + function.getEntryPoint()
                        + " size " + size + " name " + function.getName());
                for (Instruction instruction : body) {
                    out.println("  DIS " + Long.toString(instruction
                            .getAddress().subtract(function.getEntryPoint()))
                            + " " + normalized(instruction));
                }
                // Neighbor witness: the VM has a +28 variant using 0xb8.
                List<Instruction> neighbor = instructionsAt(
                        function.getEntryPoint().add(28), 2);
                if (neighbor.size() == 2) {
                    out.println("  NEIGHBOR+28 " + normalized(neighbor.get(0))
                            + " / " + normalized(neighbor.get(1)));
                }
                out.println("  REFERENCES-TO-FUNCTION");
                printReferencesTo(out, function.getEntryPoint(), "    ");
            }
            out.println("DISPATCHER-EXACT-COUNT " + dispatcherExact);
        }
    }
}
