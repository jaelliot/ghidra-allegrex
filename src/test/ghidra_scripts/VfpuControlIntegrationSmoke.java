// End-to-end static differential: all three control fixes vs pinned PPSSPP readbacks.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VfpuControlIntegrationSmoke extends GhidraScript {
    private static final String[] EXPECTED = {
        "0xfffff", "0xfff", "0x3f", "0x3f8fffff",
        null, null, "0xfffff", "0xfffff"
    };

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Unexpected ISA");
        }
        Address start = currentProgram.getMinAddress();
        if (currentProgram.getMemory().getInt(start) != 0x3c08ffff
                || currentProgram.getMemory().getInt(start.add(27 * 4L)) != 0) {
            throw new IllegalStateException("Unexpected 28-word source-owned control fixture");
        }
        if (!disassemble(start)) throw new IllegalStateException("Cannot disassemble control fixture");

        Function function = currentProgram.getFunctionManager().createFunction(
                "vfpu_control_probe", start, new AddressSet(start, start.add(111)),
                SourceType.USER_DEFINED);
        if (function == null) throw new IllegalStateException("Could not create probe function");

        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Decompiler unavailable");
            DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
            if (results == null || !results.decompileCompleted()
                    || results.getDecompiledFunction() == null) {
                throw new IllegalStateException("Decompilation did not complete");
            }
            String c = results.getDecompiledFunction().getC();
            println("VFPU_CTRL_INTEGRATION_C_START");
            println(c);
            println("VFPU_CTRL_INTEGRATION_C_END");
            Matcher statements = Pattern.compile("(\\*param_1|param_1\\[([0-9]+)\\])\\s*=\\s*([^;]+);")
                    .matcher(c);
            Map<Integer, String> outputs = new HashMap<>();
            while (statements.find()) {
                int offset = statements.group(2) == null ? 0 : Integer.parseInt(statements.group(2));
                outputs.put(offset, statements.group(3).trim());
            }
            if (outputs.size() != 8) throw new IllegalStateException("Expected eight stored values: " + outputs);
            for (int i = 0; i < EXPECTED.length; i++) {
                if (EXPECTED[i] != null && !EXPECTED[i].equals(outputs.get(i))) {
                    throw new IllegalStateException("Wrong value at word " + i + ": " + outputs.get(i));
                }
            }
            if (outputs.get(4) == null || !outputs.get(4).equals(outputs.get(5))) {
                throw new IllegalStateException("Read-only control changed: " + outputs);
            }
            println("VFPU_CTRL_INTEGRATION_PASS eight_outputs=matched readonly=preserved");
        } finally {
            decompiler.dispose();
        }
    }
}
