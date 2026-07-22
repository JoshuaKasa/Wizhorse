import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class wh_list_strings extends GhidraScript {
    private static final int MAX_VALUE_LENGTH = 200;

    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs()[0];
        DataIterator dataItems = currentProgram.getListing().getDefinedData(true);
        StringBuilder payload = new StringBuilder("[");
        boolean first = true;

        while (dataItems.hasNext()) {
            Data data = dataItems.next();
            String value = stringValue(data);
            if (value == null) {
                continue;
            }

            if (!first) {
                payload.append(",");
            }
            first = false;
            payload.append("{")
                .append("\"address\":").append(quote(data.getAddress().toString())).append(",")
                .append("\"value\":").append(quote(truncate(value))).append(",")
                .append("\"referenced_by\":").append(stringArray(referencedBy(data.getAddress())))
                .append("}");
        }

        payload.append("]");
        Files.write(Paths.get(outputPath), payload.toString().getBytes(StandardCharsets.UTF_8));
    }

    private String stringValue(Data data) {
        Object value = data.getValue();
        if (value == null) {
            return null;
        }
        String dataTypeName = data.getDataType().getName().toLowerCase();
        if (!dataTypeName.contains("string") && !(value instanceof String)) {
            return null;
        }

        String text = value.toString();
        if (text.length() < 4 || !looksPrintable(text)) {
            return null;
        }
        return text;
    }

    private boolean looksPrintable(String text) {
        int printable = 0;
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (character >= 32 && character != 127) {
                printable++;
            }
        }
        return printable >= Math.max(4, (int) (text.length() * 0.8));
    }

    private String truncate(String value) {
        if (value.length() <= MAX_VALUE_LENGTH) {
            return value;
        }
        return value.substring(0, MAX_VALUE_LENGTH);
    }

    private Set<String> referencedBy(Address address) {
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        Set<String> callers = new TreeSet<>();
        ReferenceIterator references = referenceManager.getReferencesTo(address);
        for (Reference reference : references) {
            Function caller = currentProgram.getFunctionManager()
                .getFunctionContaining(reference.getFromAddress());
            if (caller != null) {
                callers.add(caller.getEntryPoint().toString());
            }
        }
        return callers;
    }

    private String stringArray(Set<String> values) {
        StringBuilder builder = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) {
                builder.append(",");
            }
            first = false;
            builder.append(quote(value));
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
