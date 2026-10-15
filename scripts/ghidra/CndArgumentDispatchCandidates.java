// Rank short callable functions that derive an indirect call from x1.
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class CndArgumentDispatchCandidates extends GhidraScript {
    private static class Candidate {
        Function function;
        int score;
        boolean rawBranch;
        boolean authenticatedBranch;
        boolean directSourceLoad;
        List<String> assembly;
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\")
            .replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }

    private static String address(Instruction instruction) {
        return "0x" + instruction.getAddress().toString(false, false)
            .toLowerCase();
    }

    private static boolean indirectBranch(String mnemonic) {
        String value = mnemonic.toLowerCase();
        return value.equals("br") || value.equals("blr") ||
            value.equals("braa") || value.equals("brab") ||
            value.equals("braaz") || value.equals("brabz") ||
            value.equals("blraa") || value.equals("blrab") ||
            value.equals("blraaz") || value.equals("blrabz");
    }

    private static boolean rawBranch(String mnemonic) {
        String value = mnemonic.toLowerCase();
        return value.equals("br") || value.equals("blr");
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 1 || arguments.length > 2) {
            throw new IllegalArgumentException(
                "usage: CndArgumentDispatchCandidates.java OUTPUT [x0..x7]"
            );
        }
        String sourceRegister = arguments.length == 2
            ? arguments[1].toLowerCase() : "x1";
        if (!sourceRegister.matches("x[0-7]")) {
            throw new IllegalArgumentException("invalid source register");
        }
        List<Candidate> candidates = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager()
            .getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            InstructionIterator iterator = currentProgram.getListing()
                .getInstructions(function.getBody(), true);
            Candidate candidate = new Candidate();
            candidate.function = function;
            candidate.assembly = new ArrayList<>();
            int count = 0;
            boolean mentionsX1 = false;
            boolean writesArgumentRegister = false;
            while (iterator.hasNext() && count < 48) {
                Instruction instruction = iterator.next();
                count++;
                String text = instruction.toString().toLowerCase();
                String mnemonic = instruction.getMnemonicString();
                candidate.assembly.add(address(instruction) + ": " +
                    instruction.toString());
                if (text.contains("[" + sourceRegister) ||
                        text.contains(" " + sourceRegister + ",") ||
                        text.endsWith("," + sourceRegister)) {
                    mentionsX1 = true;
                }
                if (text.contains("[" + sourceRegister)) {
                    candidate.directSourceLoad = true;
                }
                if (text.matches("^(ldr|ldp|mov)\\s+x[0-7],.*")) {
                    writesArgumentRegister = true;
                }
                if (indirectBranch(mnemonic)) {
                    candidate.rawBranch |= rawBranch(mnemonic);
                    candidate.authenticatedBranch |= !rawBranch(mnemonic);
                }
            }
            if (!mentionsX1 ||
                    (!candidate.rawBranch && !candidate.authenticatedBranch)) {
                continue;
            }
            candidate.score = candidate.rawBranch ? 100 : 40;
            if (candidate.directSourceLoad) candidate.score += 30;
            if (writesArgumentRegister) candidate.score += 15;
            if (count <= 12) candidate.score += 25;
            else if (count <= 24) candidate.score += 10;
            candidates.add(candidate);
        }
        candidates.sort(Comparator
            .comparingInt((Candidate item) -> item.score).reversed()
            .thenComparing(item -> item.function.getEntryPoint()));

        File destination = new File(arguments[0]).getAbsoluteFile();
        File parent = destination.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory " + parent);
        }
        try (PrintWriter writer = new PrintWriter(
                destination, StandardCharsets.UTF_8)) {
            writer.println("{");
            writer.println("  \"schema\": \"cyanide.ghidra-argument-dispatch.v1\",");
            writer.println("  \"program\": " + quote(currentProgram.getName()) + ",");
            writer.println("  \"sourceRegister\": " +
                quote(sourceRegister) + ",");
            writer.println("  \"candidates\": [");
            for (int index = 0; index < candidates.size(); index++) {
                Candidate item = candidates.get(index);
                StringBuilder encoded = new StringBuilder("[");
                for (int line = 0; line < item.assembly.size(); line++) {
                    if (line != 0) encoded.append(',');
                    encoded.append(quote(item.assembly.get(line)));
                }
                encoded.append(']');
                writer.print("    {" +
                    "\"entry\":" + quote("0x" + item.function
                        .getEntryPoint().toString(false, false).toLowerCase()) + "," +
                    "\"name\":" + quote(item.function.getName()) + "," +
                    "\"score\":" + item.score + "," +
                    "\"rawBranch\":" + item.rawBranch + "," +
                    "\"authenticatedBranch\":" +
                        item.authenticatedBranch + "," +
                    "\"directSourceLoad\":" +
                        item.directSourceLoad + "," +
                    "\"assembly\":" + encoded + "}");
                writer.println(index + 1 == candidates.size() ? "" : ",");
            }
            writer.println("  ]");
            writer.println("}");
        }
        println("CND_GHIDRA_OUTPUT=" + destination.getAbsolutePath());
    }
}
