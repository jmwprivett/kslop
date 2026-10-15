// Export every reference to explicit addresses as JSON.
// Unlike CndFunctionReferences, this also accepts data addresses such as
// global block literals and reports the containing function for each use.
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
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

public class CndAddressReferences extends GhidraScript {
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

    private String symbolNameAt(Address address) {
        Symbol symbol = getSymbolAt(address);
        return symbol == null ? "" : symbol.getName(true);
    }

    private String encodeReferences(Address requested) {
        List<String> references = new ArrayList<>();
        ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(requested);
        while (iterator.hasNext()) {
            Reference reference = iterator.next();
            Address from = reference.getFromAddress();
            Function function = getFunctionContaining(from);
            Instruction instruction = getInstructionAt(from);
            references.add("{" +
                "\"from\":" + quote(addressText(from)) + "," +
                "\"type\":" + quote(reference.getReferenceType().getName()) + "," +
                "\"source\":" + quote(reference.getSource().toString()) + "," +
                "\"operandIndex\":" + reference.getOperandIndex() + "," +
                "\"primary\":" + reference.isPrimary() + "," +
                "\"functionEntry\":" + quote(function == null ? "" : addressText(function.getEntryPoint())) + "," +
                "\"function\":" + quote(function == null ? "" : function.getName()) + "," +
                "\"instruction\":" + quote(instruction == null ? "" : instruction.toString()) +
                "}");
        }
        return encodeList(references);
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
                "usage: CndAddressReferences.java OUTPUT ADDRESS [ADDRESS ...]"
            );
        }

        List<String> entries = new ArrayList<>();
        for (int index = 1; index < arguments.length; index++) {
            monitor.checkCancelled();
            Address requested = toAddr(arguments[index]);
            entries.add("{" +
                "\"address\":" + quote(addressText(requested)) + "," +
                "\"symbol\":" + quote(symbolNameAt(requested)) + "," +
                "\"references\":" + encodeReferences(requested) +
                "}");
        }

        File destination = new File(arguments[0]).getAbsoluteFile();
        File parent = destination.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory " + parent);
        }
        try (PrintWriter writer = new PrintWriter(destination, StandardCharsets.UTF_8)) {
            writer.println("{");
            writer.println("  \"schema\": \"cyanide.ghidra-address-references.v1\",");
            writer.println("  \"program\": " + quote(currentProgram.getName()) + ",");
            writer.println("  \"addresses\": " + encodeList(entries));
            writer.println("}");
        }
        println("CND_GHIDRA_OUTPUT=" + destination.getAbsolutePath());
    }
}
