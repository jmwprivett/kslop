// Find callable AArch64 function entries that immediately return a constant.
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;

public class CndReturnConstantFunctions extends GhidraScript {
    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\")
            .replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }

    private static String address(Instruction instruction) {
        return "0x" + instruction.getAddress().toString(false, false)
            .toLowerCase();
    }

    private static String assembly(Instruction instruction) {
        return address(instruction) + ": " + instruction.toString();
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 2) {
            throw new IllegalArgumentException(
                "usage: CndReturnConstantFunctions.java OUTPUT HEX_CONSTANT"
            );
        }
        boolean anyConstant = arguments[1].equalsIgnoreCase("any");
        long constant = anyConstant ? 0 : Long.decode(arguments[1]);
        String expected = String.format("mov w0,#0x%x", constant);
        Pattern immediateReturn = Pattern.compile(
            "mov\\s+w0,#(0x[0-9a-f]+|[0-9]+)",
            Pattern.CASE_INSENSITIVE
        );
        List<String> matches = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager()
            .getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            Instruction first = currentProgram.getListing().getInstructionAt(
                function.getEntryPoint());
            if (first == null) continue;
            List<Instruction> prefix = new ArrayList<>();
            prefix.add(first);
            Instruction cursor = first;
            if (cursor.toString().equalsIgnoreCase("bti c")) {
                cursor = cursor.getNext();
                if (cursor == null || !function.getBody().contains(
                        cursor.getAddress())) continue;
                prefix.add(cursor);
            }
            Matcher constantMatch = immediateReturn.matcher(cursor.toString());
            if (!constantMatch.matches()) continue;
            long observedConstant = Long.decode(constantMatch.group(1));
            if (!anyConstant &&
                    !cursor.toString().equalsIgnoreCase(expected)) continue;
            cursor = cursor.getNext();
            if (cursor == null || !function.getBody().contains(
                    cursor.getAddress()) ||
                    !cursor.getMnemonicString().equalsIgnoreCase("ret")) {
                continue;
            }
            prefix.add(cursor);
            StringBuilder encoded = new StringBuilder("[");
            for (int index = 0; index < prefix.size(); index++) {
                if (index != 0) encoded.append(',');
                encoded.append(quote(assembly(prefix.get(index))));
            }
            encoded.append(']');
            matches.add("{" +
                "\"entry\":" + quote("0x" + function.getEntryPoint()
                    .toString(false, false).toLowerCase()) + "," +
                "\"name\":" + quote(function.getName()) + "," +
                "\"constant\":" + quote(String.format(
                    "0x%x", observedConstant)) + "," +
                "\"assembly\":" + encoded + "}");
        }

        File destination = new File(arguments[0]).getAbsoluteFile();
        File parent = destination.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory " + parent);
        }
        try (PrintWriter writer = new PrintWriter(
                destination, StandardCharsets.UTF_8)) {
            writer.println("{");
            writer.println("  \"schema\": \"cyanide.ghidra-return-constant.v1\",");
            writer.println("  \"program\": " + quote(currentProgram.getName()) + ",");
            writer.println("  \"constant\": " + quote(anyConstant
                ? "any" : String.format("0x%x", constant)) + ",");
            writer.println("  \"matches\": [");
            for (int index = 0; index < matches.size(); index++) {
                writer.print("    " + matches.get(index));
                writer.println(index + 1 == matches.size() ? "" : ",");
            }
            writer.println("  ]");
            writer.println("}");
        }
        println("CND_GHIDRA_OUTPUT=" + destination.getAbsolutePath());
    }
}
