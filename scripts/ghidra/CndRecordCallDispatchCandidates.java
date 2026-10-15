// Find callable record-driven indirect dispatchers for KRW-to-kcall chaining.
// @category Cyanide

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class CndRecordCallDispatchCandidates extends GhidraScript {
    private static final Pattern LOAD = Pattern.compile(
        "^ldr\\s+([xw][0-7]),\\[(x(?:[0-9]|1[0-5]))" +
        "(?:,\\s*#?[^]]+)?\\].*$");
    private static final Pattern PAIR = Pattern.compile(
        "^ldp\\s+([xw][0-7]),([xw][0-7]),\\[(x(?:[0-9]|1[0-5]))" +
        "(?:,\\s*#?[^]]+)?\\].*$");
    private static final Pattern MOVE = Pattern.compile(
        "^mov\\s+(x(?:[0-9]|1[0-5])),(x(?:[0-9]|1[0-5]))$");
    private static final Pattern ADD = Pattern.compile(
        "^add\\s+(x(?:[0-9]|1[0-5])),(x(?:[0-9]|1[0-5])),#.*$");

    private static class Candidate {
        Function function;
        int score;
        boolean hasBTI;
        boolean hasCallLanding;
        String landingInstruction = "";
        boolean rawBranch;
        boolean authenticatedBranch;
        Set<Integer> loadedArguments = new HashSet<>();
        List<String> assembly = new ArrayList<>();
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\")
            .replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }

    private static String address(Instruction instruction) {
        return "0x" + instruction.getAddress().toString(false, false)
            .toLowerCase();
    }

    private static boolean isRawBranch(String mnemonic) {
        return mnemonic.equals("br") || mnemonic.equals("blr");
    }

    private static boolean isAuthenticatedBranch(String mnemonic) {
        return mnemonic.equals("braa") || mnemonic.equals("brab") ||
            mnemonic.equals("braaz") || mnemonic.equals("brabz") ||
            mnemonic.equals("blraa") || mnemonic.equals("blrab") ||
            mnemonic.equals("blraaz") || mnemonic.equals("blrabz");
    }

    private static boolean isCallLanding(String text) {
        return text.equals("bti c") || text.equals("bti jc") ||
            text.equals("paciasp") || text.equals("pacibsp");
    }

    private static int registerNumber(String register) {
        return Integer.parseInt(register.substring(1));
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException(
                "usage: CndRecordCallDispatchCandidates.java OUTPUT"
            );
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
            Set<String> recordAliases = new HashSet<>();
            recordAliases.add("x0");
            int count = 0;
            while (iterator.hasNext() && count < 64) {
                Instruction instruction = iterator.next();
                String text = instruction.toString().toLowerCase();
                String mnemonic = instruction.getMnemonicString()
                    .toLowerCase();
                if (count == 0) {
                    candidate.hasBTI = text.equals("bti c") ||
                        text.equals("bti jc");
                    candidate.hasCallLanding = isCallLanding(text);
                    candidate.landingInstruction = text;
                }
                count++;
                candidate.assembly.add(address(instruction) + ": " +
                    instruction.toString());
                Matcher move = MOVE.matcher(text);
                if (move.matches() && recordAliases.contains(move.group(2))) {
                    recordAliases.add(move.group(1));
                }
                Matcher add = ADD.matcher(text);
                if (add.matches() && recordAliases.contains(add.group(2))) {
                    recordAliases.add(add.group(1));
                }
                Matcher load = LOAD.matcher(text);
                if (load.matches() && recordAliases.contains(load.group(2))) {
                    candidate.loadedArguments.add(
                        registerNumber(load.group(1)));
                }
                Matcher pair = PAIR.matcher(text);
                if (pair.matches() && recordAliases.contains(pair.group(3))) {
                    candidate.loadedArguments.add(
                        registerNumber(pair.group(1)));
                    candidate.loadedArguments.add(
                        registerNumber(pair.group(2)));
                }
                candidate.rawBranch |= isRawBranch(mnemonic);
                candidate.authenticatedBranch |=
                    isAuthenticatedBranch(mnemonic);
            }
            if ((!candidate.rawBranch && !candidate.authenticatedBranch) ||
                candidate.loadedArguments.size() < 2) continue;
            candidate.score = candidate.loadedArguments.size() * 25;
            if (candidate.hasCallLanding) candidate.score += 30;
            if (candidate.rawBranch) candidate.score += 30;
            if (candidate.authenticatedBranch) candidate.score += 15;
            if (count <= 16) candidate.score += 25;
            else if (count <= 32) candidate.score += 10;
            candidates.add(candidate);
        }
        candidates.sort(Comparator
            .comparingInt((Candidate item) -> item.score).reversed()
            .thenComparing(item -> item.function.getEntryPoint()));

        File destination = new File(arguments[0]).getAbsoluteFile();
        File parent = destination.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException(
                "cannot create output directory " + parent
            );
        }
        try (PrintWriter writer = new PrintWriter(
                destination, StandardCharsets.UTF_8)) {
            writer.println("{");
            writer.println("  \"schema\": " +
                "\"cyanide.ghidra-record-call-dispatch.v1\",");
            writer.println("  \"program\": " +
                quote(currentProgram.getName()) + ",");
            writer.println("  \"candidates\": [");
            for (int index = 0; index < candidates.size(); index++) {
                Candidate item = candidates.get(index);
                List<Integer> registers = new ArrayList<>(
                    item.loadedArguments);
                registers.sort(Integer::compareTo);
                StringBuilder encodedRegisters = new StringBuilder("[");
                for (int register = 0; register < registers.size(); register++) {
                    if (register != 0) encodedRegisters.append(',');
                    encodedRegisters.append(registers.get(register));
                }
                encodedRegisters.append(']');
                StringBuilder encodedAssembly = new StringBuilder("[");
                for (int line = 0; line < item.assembly.size(); line++) {
                    if (line != 0) encodedAssembly.append(',');
                    encodedAssembly.append(quote(item.assembly.get(line)));
                }
                encodedAssembly.append(']');
                writer.print("    {" +
                    "\"entry\":" + quote("0x" + item.function
                        .getEntryPoint().toString(false, false)
                        .toLowerCase()) + "," +
                    "\"name\":" + quote(item.function.getName()) + "," +
                    "\"score\":" + item.score + "," +
                    "\"hasBTI\":" + item.hasBTI + "," +
                    "\"hasCallLanding\":" + item.hasCallLanding + "," +
                    "\"landingInstruction\":" +
                        quote(item.landingInstruction) + "," +
                    "\"rawBranch\":" + item.rawBranch + "," +
                    "\"authenticatedBranch\":" +
                        item.authenticatedBranch + "," +
                    "\"loadedArguments\":" + encodedRegisters + "," +
                    "\"assembly\":" + encodedAssembly + "}");
                writer.println(index + 1 == candidates.size() ? "" : ",");
            }
            writer.println("  ]");
            writer.println("}");
        }
        println("CND_GHIDRA_OUTPUT=" + destination.getAbsolutePath());
    }
}
