import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class wh_decompile_function extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args[0];
        String addressText = args[1];
        Address address = currentProgram.getAddressFactory().getAddress(addressText);
        if (address == null) {
            throw new IllegalArgumentException("invalid address: " + addressText);
        }

        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            function = currentProgram.getFunctionManager().getFunctionContaining(address);
        }
        if (function == null) {
            throw new IllegalArgumentException("no function found at or containing address: " + addressText);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
        String pseudocode = "";
        if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
            pseudocode = result.getDecompiledFunction().getC();
        }
        decompiler.dispose();

        String payload = "{"
            + "\"address\":" + quote(function.getEntryPoint().toString()) + ","
            + "\"name\":" + quote(function.getName()) + ","
            + "\"pseudocode\":" + quote(pseudocode) + ","
            + "\"callers\":" + stringArray(callers(function)) + ","
            + "\"callees\":" + stringArray(callees(function)) + ","
            + "\"referenced_strings\":" + stringArray(referencedStrings(function))
            + "}";
        Files.write(Paths.get(outputPath), payload.getBytes(StandardCharsets.UTF_8));
    }

    private Set<String> callers(Function function) {
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        Set<String> callers = new TreeSet<>();
        ReferenceIterator references = referenceManager.getReferencesTo(function.getEntryPoint());
        for (Reference reference : references) {
            Function caller = currentProgram.getFunctionManager()
                .getFunctionContaining(reference.getFromAddress());
            callers.add(caller != null ? caller.getEntryPoint().toString() : reference.getFromAddress().toString());
        }
        return callers;
    }

    private Set<String> callees(Function function) {
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        Set<String> callees = new TreeSet<>();
        InstructionIterator instructions = currentProgram.getListing()
            .getInstructions(function.getBody(), true);
        for (Instruction instruction : instructions) {
            for (Reference reference : referenceManager.getReferencesFrom(instruction.getAddress())) {
                Function target = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
                if (target == null) {
                    target = currentProgram.getFunctionManager().getFunctionContaining(reference.getToAddress());
                }
                if (target != null && !target.getEntryPoint().equals(function.getEntryPoint())) {
                    callees.add(target.getEntryPoint().toString());
                }
            }
        }
        return callees;
    }

    private Set<String> referencedStrings(Function function) {
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        Set<String> strings = new TreeSet<>();
        InstructionIterator instructions = currentProgram.getListing()
            .getInstructions(function.getBody(), true);
        for (Instruction instruction : instructions) {
            for (Reference reference : referenceManager.getReferencesFrom(instruction.getAddress())) {
                Data data = currentProgram.getListing().getDataContaining(reference.getToAddress());
                if (data == null) {
                    continue;
                }
                Object value = data.getValue();
                if (value == null) {
                    continue;
                }
                String text = value.toString();
                if (looksLikeString(text)) {
                    strings.add(text);
                }
            }
        }
        return strings;
    }

    private boolean looksLikeString(String text) {
        if (text.length() < 4) {
            return false;
        }
        int printable = 0;
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (character >= 32 && character <= 126) {
                printable++;
            }
        }
        return printable >= Math.max(4, (int) (text.length() * 0.8));
    }

    private String stringArray(Set<String> values) {
        StringBuilder builder = new StringBuilder("[");
        boolean first = true;
        int count = 0;
        for (String value : values) {
            if (count >= 200) {
                break;
            }
            if (!first) {
                builder.append(",");
            }
            first = false;
            builder.append(quote(value));
            count++;
        }
        builder.append("]");
        return builder.toString();
    }

    private String quote(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder builder = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\':
                    builder.append("\\\\");
                    break;
                case '"':
                    builder.append("\\\"");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        builder.append(String.format("\\u%04x", (int) character));
                    }
                    else {
                        builder.append(character);
                    }
                    break;
            }
        }
        builder.append('"');
        return builder.toString();
    }
}
