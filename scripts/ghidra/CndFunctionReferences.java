// Export incoming and outgoing references for explicit functions as JSON.
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

public class CndFunctionReferences extends GhidraScript {
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

    private String functionNameAt(Address address) {
        Function function = getFunctionContaining(address);
        if (function == null) {
            return "";
        }
        return function.getName();
    }

    private String symbolNameAt(Address address) {
        Symbol symbol = getSymbolAt(address);
        if (symbol == null) {
            return "";
        }
        return symbol.getName(true);
    }

    private String encodeReference(Reference reference, boolean incoming) {
        Address peer = incoming ? reference.getFromAddress() : reference.getToAddress();
        return "{" +
            "\"address\":" + quote(addressText(peer)) + "," +
            "\"type\":" + quote(reference.getReferenceType().getName()) + "," +
            "\"source\":" + quote(reference.getSource().toString()) + "," +
            "\"operandIndex\":" + reference.getOperandIndex() + "," +
            "\"primary\":" + reference.isPrimary() + "," +
            "\"function\":" + quote(functionNameAt(peer)) + "," +
            "\"symbol\":" + quote(symbolNameAt(peer)) +
            "}";
    }

    private String encodeList(List<String> values) {
        StringBuilder encoded = new StringBuilder("[");
        for (int index = 0; index < values.size(); index++) {
            if (index != 0) {
                encoded.append(',');
            }
            encoded.append(values.get(index));
        }
        return encoded.append(']').toString();
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 2) {
            throw new IllegalArgumentException(
                "usage: CndFunctionReferences.java OUTPUT ADDRESS [ADDRESS ...]"
            );
        }

        List<String> entries = new ArrayList<>();
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

            List<String> incoming = new ArrayList<>();
            ReferenceIterator incomingIterator = currentProgram.getReferenceManager()
                .getReferencesTo(function.getEntryPoint());
            while (incomingIterator.hasNext()) {
                incoming.add(encodeReference(incomingIterator.next(), true));
            }

            List<String> outgoing = new ArrayList<>();
            InstructionIterator instructions = currentProgram.getListing()
                .getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                Reference[] references = instruction.getReferencesFrom();
                for (Reference reference : references) {
                    outgoing.add("{" +
                        "\"site\":" + quote(addressText(instruction.getAddress())) + "," +
                        "\"instruction\":" + quote(instruction.toString()) + "," +
                        "\"reference\":" + encodeReference(reference, false) +
                        "}");
                }
            }

            entries.add("{" +
                "\"requested\":" + quote(addressText(requested)) + "," +
                "\"entry\":" + quote(addressText(function.getEntryPoint())) + "," +
                "\"name\":" + quote(function.getName()) + "," +
                "\"signature\":" + quote(function.getSignature().getPrototypeString()) + "," +
                "\"incoming\":" + encodeList(incoming) + "," +
                "\"outgoing\":" + encodeList(outgoing) +
                "}");
        }

        File destination = new File(arguments[0]).getAbsoluteFile();
        File parent = destination.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory " + parent);
        }
        try (PrintWriter writer = new PrintWriter(destination, StandardCharsets.UTF_8)) {
            writer.println("{");
            writer.println("  \"schema\": \"cyanide.ghidra-function-references.v1\",");
            writer.println("  \"program\": " + quote(currentProgram.getName()) + ",");
            writer.println("  \"functions\": " + encodeList(entries));
            writer.println("}");
        }
        println("CND_GHIDRA_OUTPUT=" + destination.getAbsolutePath());
    }
}
