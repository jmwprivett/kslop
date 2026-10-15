// Decompile explicit addresses from an analyzeHeadless session into one JSON file.
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class CndDecompileAddresses extends GhidraScript {
    private static String quote(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\': result.append("\\\\"); break;
                case '"': result.append("\\\""); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        result.append(String.format("\\u%04x", (int) character));
                    }
                    else {
                        result.append(character);
                    }
            }
        }
        return result.append('"').toString();
    }

    private String addressText(Address address) {
        return "0x" + address.toString(false, false).toLowerCase();
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 2) {
            throw new IllegalArgumentException(
                "usage: CndDecompileAddresses.java OUTPUT ADDRESS [ADDRESS ...]"
            );
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("cannot open program in decompiler");
        }

        List<String> entries = new ArrayList<>();
        try {
            for (int index = 1; index < arguments.length; index++) {
                monitor.checkCancelled();
                Address requested = toAddr(arguments[index]);
                Function function = getFunctionAt(requested);
                if (function == null) {
                    function = getFunctionContaining(requested);
                }
                if (function == null) {
                    entries.add("{" +
                        "\"requested\":" + quote(addressText(requested)) + "," +
                        "\"error\":\"no containing function\"}");
                    continue;
                }

                List<String> assembly = new ArrayList<>();
                InstructionIterator instructions = currentProgram.getListing()
                    .getInstructions(function.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    assembly.add(addressText(instruction.getAddress()) + ": " +
                                 instruction.toString());
                }

                DecompileResults decompiled = decompiler.decompileFunction(
                    function, 120, monitor
                );
                String pseudocode = "";
                String decompileError = "";
                if (decompiled.decompileCompleted() &&
                        decompiled.getDecompiledFunction() != null) {
                    pseudocode = decompiled.getDecompiledFunction().getC();
                }
                else {
                    decompileError = decompiled.getErrorMessage();
                }

                StringBuilder encodedAssembly = new StringBuilder("[");
                for (int instructionIndex = 0;
                        instructionIndex < assembly.size(); instructionIndex++) {
                    if (instructionIndex != 0) {
                        encodedAssembly.append(',');
                    }
                    encodedAssembly.append(quote(assembly.get(instructionIndex)));
                }
                encodedAssembly.append(']');

                entries.add("{" +
                    "\"requested\":" + quote(addressText(requested)) + "," +
                    "\"entry\":" + quote(addressText(function.getEntryPoint())) + "," +
                    "\"name\":" + quote(function.getName()) + "," +
                    "\"assembly\":" + encodedAssembly + "," +
                    "\"pseudocode\":" + quote(pseudocode) + "," +
                    "\"decompileError\":" + quote(decompileError) + "}");
            }
        }
        finally {
            decompiler.dispose();
        }

        File destination = new File(arguments[0]).getAbsoluteFile();
        File parent = destination.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory " + parent);
        }
        try (PrintWriter writer = new PrintWriter(destination, StandardCharsets.UTF_8)) {
            writer.println("{");
            writer.println("  \"schema\": \"cyanide.ghidra-explicit-decompile.v1\",");
            writer.println("  \"program\": " + quote(currentProgram.getName()) + ",");
            writer.println("  \"language\": " + quote(
                currentProgram.getLanguageID().toString()) + ",");
            writer.println("  \"functions\": [");
            for (int index = 0; index < entries.size(); index++) {
                writer.print("    " + entries.get(index));
                writer.println(index + 1 == entries.size() ? "" : ",");
            }
            writer.println("  ]");
            writer.println("}");
        }
        println("CND_GHIDRA_OUTPUT=" + destination.getAbsolutePath());
    }
}
