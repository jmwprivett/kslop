// Find callable entries that load a scalar through x0 and immediately return.
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;

public class CndLoadX0ReturnFunctions extends GhidraScript {
    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\")
            .replace("\"", "\\\"") + "\"";
    }

    private static String line(Instruction instruction) {
        return "0x" + instruction.getAddress().toString(false, false)
            .toLowerCase() + ": " + instruction.toString();
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException(
                "usage: CndLoadX0ReturnFunctions.java OUTPUT"
            );
        }
        List<String> matches = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager()
            .getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            Instruction cursor = currentProgram.getListing().getInstructionAt(
                function.getEntryPoint());
            if (cursor == null) continue;
            List<Instruction> prefix = new ArrayList<>();
            prefix.add(cursor);
            boolean hasBTI = cursor.toString().equalsIgnoreCase("bti c");
            if (hasBTI) {
                cursor = cursor.getNext();
                if (cursor == null || !function.getBody().contains(
                        cursor.getAddress())) continue;
                prefix.add(cursor);
            }
            String load = cursor.toString().toLowerCase();
            if (!(load.equals("ldr w0,[x0]") ||
                  load.equals("ldr x0,[x0]") ||
                  load.equals("ldrh w0,[x0]") ||
                  load.equals("ldrb w0,[x0]"))) {
                continue;
            }
            cursor = cursor.getNext();
            if (cursor == null || !function.getBody().contains(
                    cursor.getAddress()) ||
                    !cursor.getMnemonicString().equalsIgnoreCase("ret")) {
                continue;
            }
            prefix.add(cursor);
            StringBuilder assembly = new StringBuilder("[");
            for (int index = 0; index < prefix.size(); index++) {
                if (index != 0) assembly.append(',');
                assembly.append(quote(line(prefix.get(index))));
            }
            assembly.append(']');
            matches.add("{" +
                "\"entry\":" + quote("0x" + function.getEntryPoint()
                    .toString(false, false).toLowerCase()) + "," +
                "\"name\":" + quote(function.getName()) + "," +
                "\"hasBTI\":" + hasBTI + "," +
                "\"load\":" + quote(load) + "," +
                "\"assembly\":" + assembly + "}");
        }
        File destination = new File(arguments[0]).getAbsoluteFile();
        File parent = destination.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory " + parent);
        }
        try (PrintWriter writer = new PrintWriter(
                destination, StandardCharsets.UTF_8)) {
            writer.println("{");
            writer.println("  \"schema\": \"cyanide.ghidra-load-x0-return.v1\",");
            writer.println("  \"program\": " + quote(currentProgram.getName()) + ",");
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
