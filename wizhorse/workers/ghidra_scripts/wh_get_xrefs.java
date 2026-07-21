import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class wh_get_xrefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args[0];
        String addressText = args[1];
        Address address = currentProgram.getAddressFactory().getAddress(addressText);
        if (address == null) {
            throw new IllegalArgumentException("invalid address: " + addressText);
        }

        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        StringBuilder payload = new StringBuilder("[");
        boolean first = true;
        ReferenceIterator toReferences = referenceManager.getReferencesTo(address);
        for (Reference reference : toReferences) {
            first = appendReference(payload, first, "to", reference);
        }
        for (Reference reference : referenceManager.getReferencesFrom(address)) {
            first = appendReference(payload, first, "from", reference);
        }
        payload.append("]");
        Files.write(Paths.get(outputPath), payload.toString().getBytes(StandardCharsets.UTF_8));
    }

    private boolean appendReference(
        StringBuilder payload,
        boolean first,
        String direction,
        Reference reference
    ) {
        if (!first) {
            payload.append(",");
        }
        payload.append("{")
            .append("\"direction\":").append(quote(direction)).append(",")
            .append("\"source_address\":").append(quote(reference.getFromAddress().toString())).append(",")
            .append("\"target_address\":").append(quote(reference.getToAddress().toString())).append(",")
            .append("\"reference_type\":").append(quote(reference.getReferenceType().toString()))
            .append("}");
        return false;
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
