import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;

public class wh_list_functions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs()[0];
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        StringBuilder payload = new StringBuilder("[");
        boolean first = true;

        for (Function function : functions) {
            if (!first) {
                payload.append(",");
            }
            first = false;
            payload.append("{")
                .append("\"address\":").append(quote(function.getEntryPoint().toString())).append(",")
                .append("\"name\":").append(quote(function.getName())).append(",")
                .append("\"size\":").append(function.getBody().getNumAddresses()).append(",")
                .append("\"instruction_count\":").append(instructionCount(function))
                .append("}");
        }

        payload.append("]");
        Files.write(Paths.get(outputPath), payload.toString().getBytes(StandardCharsets.UTF_8));
    }

    private int instructionCount(Function function) {
        int count = 0;
        InstructionIterator instructions = currentProgram.getListing()
            .getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            instructions.next();
            count++;
        }
        return count;
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
