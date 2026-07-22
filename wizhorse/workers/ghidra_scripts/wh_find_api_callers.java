import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class wh_find_api_callers extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args[0];
        String requestedName = args[1];
        Set<Address> targetAddresses = new HashSet<>();
        Map<String, Function> callers = new TreeMap<>();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        for (Function function : functions) {
            if (matchesApi(function.getName(), requestedName)) {
                targetAddresses.add(function.getEntryPoint());
            }
        }

        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        for (Symbol symbol : symbols) {
            if (matchesApi(symbol.getName(), requestedName)) {
                targetAddresses.add(symbol.getAddress());
            }
        }

        for (Address targetAddress : targetAddresses) {
            ReferenceIterator references = referenceManager.getReferencesTo(targetAddress);
            for (Reference reference : references) {
                Function caller = currentProgram.getFunctionManager()
                    .getFunctionContaining(reference.getFromAddress());
                if (
                    caller != null
                    && !caller.isExternal()
                    && !caller.getEntryPoint().equals(targetAddress)
                ) {
                    callers.put(caller.getEntryPoint().toString(), caller);
                }
            }
        }

        StringBuilder payload = new StringBuilder("[");
        boolean first = true;
        for (Map.Entry<String, Function> entry : callers.entrySet()) {
            Function caller = entry.getValue();
            if (!first) {
                payload.append(",");
            }
            first = false;
            payload.append("{")
                .append("\"caller_address\":").append(quote(caller.getEntryPoint().toString())).append(",")
                .append("\"caller_name\":").append(quote(caller.getName()))
                .append("}");
        }
        payload.append("]");
        Files.write(Paths.get(outputPath), payload.toString().getBytes(StandardCharsets.UTF_8));
    }

    private boolean matchesApi(String candidateName, String requestedName) {
        String candidate = normalizeName(candidateName);
        String requested = normalizeName(requestedName);
        if (candidate.equals(requested)) {
            return true;
        }
        if (hasExplicitAnsiWideSuffix(requestedName)) {
            return false;
        }
        return candidate.equals(requested + "a") || candidate.equals(requested + "w");
    }

    private String normalizeName(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase();
        int namespaceSeparator = normalized.lastIndexOf("::");
        if (namespaceSeparator >= 0) {
            normalized = normalized.substring(namespaceSeparator + 2);
        }
        while (normalized.startsWith("_")) {
            normalized = normalized.substring(1);
        }
        int atIndex = normalized.indexOf('@');
        if (atIndex > 0) {
            normalized = normalized.substring(0, atIndex);
        }
        return normalized;
    }

    private boolean hasExplicitAnsiWideSuffix(String value) {
        String normalized = value == null ? "" : value.trim();
        int namespaceSeparator = normalized.lastIndexOf("::");
        if (namespaceSeparator >= 0) {
            normalized = normalized.substring(namespaceSeparator + 2);
        }
        while (normalized.startsWith("_")) {
            normalized = normalized.substring(1);
        }
        int atIndex = normalized.indexOf('@');
        if (atIndex > 0) {
            normalized = normalized.substring(0, atIndex);
        }
        return normalized.length() > 1
            && (normalized.endsWith("A") || normalized.endsWith("W"));
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
