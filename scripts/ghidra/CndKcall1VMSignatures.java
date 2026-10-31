// Dump the kcall1 route signatures from the vPhone research kernel:
// for each pinned static, print its block, containing function, size,
// disassembly (normalized), references, and for the GOT donor its raw
// pointer value and referencing code.
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;

public class CndKcall1VMSignatures extends GhidraScript {
    private static final long[] STATICS = {
        0xfffffe000799f588L,  // checkmulti got donor
        0xfffffe0007d293fcL, // ether_check_multi (stock callback)
        0xfffffe0008f87a38L, // init_ifnet_params
        0xfffffe0008f87bf0L, // stock signer
        0xfffffe00082f6a38L, // enoexec return stub
        0xfffffe00082f6590L, // load w0 from x0 stub
        0xfffffe0008f94a8cL, // ifnet x0 dispatcher
    };
    private static final String[] ROLES = {
        "checkmulti_got_donor", "stock_callback", "init_ifnet_params",
        "stock_signer", "enoexec_return_stub", "load_w0_from_x0_stub",
        "ifnet_x0_dispatcher",
    };

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
        return instruction.getMnemonicString() + " " + text;
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

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException(
                "usage: CndKcall1VMSignatures.java OUTPUT");
        }
        try (PrintWriter out = new PrintWriter(new File(arguments[0]),
                StandardCharsets.UTF_8)) {
            for (int index = 0; index < STATICS.length; index++) {
                Address address = currentProgram.getAddressFactory()
                        .getAddress(Long.toHexString(STATICS[index]));
                out.println("ROLE " + ROLES[index] + " "
                        + address.toString());
                Memory memory = currentProgram.getMemory();
                if (memory.getBlock(address) == null) {
                    out.println("BLOCK none-in-this-program");
                } else {
                    out.println("BLOCK "
                            + memory.getBlock(address).getName());
                }
                Function function = currentProgram.getFunctionManager()
                        .getFunctionContaining(address);
                if (function == null) {
                    out.println("FUNCTION none");
                } else {
                    Address entry = function.getEntryPoint();
                    out.println("FUNCTION " + function.getName() + " entry "
                            + entry.toString() + " size "
                            + Long.toString(function.getBody().getNumAddresses()));
                    out.println("OFFSET_IN_FUNCTION "
                            + Long.toString(address.subtract(entry)));
                    Listing listing = currentProgram.getListing();
                    InstructionIterator instructions = listing
                            .getInstructions(entry, true);
                    int printed = 0;
                    while (instructions.hasNext() && printed < 140) {
                        Instruction instruction = instructions.next();
                        out.println("DIS " + Long.toString(
                                instruction.getAddress().subtract(entry))
                                + " " + normalized(instruction));
                        printed++;
                    }
                    out.println("REFERENCES-TO-FUNCTION");
                    ReferenceIterator iterator = currentProgram
                            .getReferenceManager()
                            .getReferencesTo(entry);
                    int counted = 0;
                    while (iterator.hasNext() && counted < 40) {
                        Reference reference = iterator.next();
                        out.println("  " + reference.getFromAddress()
                                .toString() + " " + reference.getReferenceType());
                        counted++;
                    }
                }
                if (STATICS[index] == 0xfffffe000799f588L) {
                    if (memory.getBlock(address) != null) {
                        out.println("GOT-RAW8 0x" + Long.toHexString(
                                readLong(memory, address, 8)));
                    } else {
                        out.println("GOT-RAW8 none-in-this-program");
                    }
                    out.println("REFERENCES-TO-GOT");
                    ReferenceIterator iterator = currentProgram
                            .getReferenceManager()
                            .getReferencesTo(address);
                    int counted = 0;
                    while (iterator.hasNext() && counted < 40) {
                        Reference reference = iterator.next();
                        Function from = currentProgram.getFunctionManager()
                                .getFunctionContaining(
                                        reference.getFromAddress());
                        out.println("  " + reference.getFromAddress()
                                + " " + reference.getReferenceType()
                                + " in " + (from == null ? "?" : from.getName()
                                        + "@" + from.getEntryPoint()));
                        counted++;
                    }
                    Symbol symbol = currentProgram.getSymbolTable()
                            .getPrimarySymbol(address);
                    out.println("GOT-SYMBOL " + (symbol == null ? "none"
                            : symbol.getName()));
                }
                out.println();
            }
        }
    }
}