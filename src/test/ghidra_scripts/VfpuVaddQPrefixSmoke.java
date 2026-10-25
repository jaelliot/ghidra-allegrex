// Source-owned headless regression for vadd.q VFPU prefix dataflow and consumption.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VfpuVaddQPrefixSmoke extends GhidraScript {
    private static final int[] WORDS = {
        0xd8800000, 0xd8a40000, 0xdc0000e4, 0xdd0000e4,
        0xde000000, 0x60048090, 0xf8d00000, 0xdc0000c6,
        0x60048090, 0xf8d00010, 0x60048090, 0xf8d00020,
        0x03e00008, 0x00000000
    };
    private static final int[] ADD_SITES = {5, 8, 10};
    private static final long[] PREFIX_REGISTERS = {0x5300, 0x5304, 0x5308};
    private static final long[] CONSUMED_STATE = {0xe4, 0xe4, 0};

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Expected the Allegrex language");
        }
        Address start = currentProgram.getMinAddress();
        for (int i = 0; i < WORDS.length; i++) {
            if (currentProgram.getMemory().getInt(start.add(i * 4L)) != WORDS[i]) {
                throw new IllegalStateException("Unexpected fixture word at " + i);
            }
        }
        if (!disassemble(start)) throw new IllegalStateException("Disassembly failed");

        for (int site : ADD_SITES) {
            Instruction ins = currentProgram.getListing().getInstructionAt(start.add(site * 4L));
            if (ins == null || !"vadd.q".equals(ins.getMnemonicString())) {
                throw new IllegalStateException("Expected vadd.q at word " + site);
            }
            int opaqueOps = 0;
            int floatAdds = 0;
            int[] prefixReads = new int[3];
            int[] prefixResets = new int[3];
            for (PcodeOp op : ins.getPcode()) {
                if (op.getOpcode() == PcodeOp.CALLOTHER) opaqueOps++;
                if (op.getOpcode() == PcodeOp.FLOAT_ADD) floatAdds++;
                for (Varnode input : op.getInputs()) {
                    if (!input.isRegister()) continue;
                    for (int i = 0; i < 3; i++) {
                        if (input.getOffset() == PREFIX_REGISTERS[i]) prefixReads[i]++;
                    }
                }
                if (op.getOpcode() != PcodeOp.COPY || !op.getInput(0).isConstant()) continue;
                Varnode output = op.getOutput();
                if (output == null || !output.isRegister()) continue;
                for (int i = 0; i < 3; i++) {
                    if (output.getOffset() == PREFIX_REGISTERS[i]
                            && op.getInput(0).getOffset() == CONSUMED_STATE[i]) {
                        prefixResets[i]++;
                    }
                }
            }
            for (int i = 0; i < 3; i++) {
                if (prefixReads[i] != 1 || prefixResets[i] != 1) {
                    throw new IllegalStateException("Incorrect prefix dataflow/reset at word "
                            + site + ", register " + i + ": reads=" + prefixReads[i]
                            + ", resets=" + prefixResets[i]);
                }
            }
            // Read source, target and old destination; opaque arithmetic; write destination.
            if (opaqueOps != 5 || floatAdds != 0) {
                throw new IllegalStateException("Unexpected vadd.q p-code at " + site
                        + ": CALLOTHER=" + opaqueOps + " FLOAT_ADD=" + floatAdds);
            }
            println("VFPU_VADDQ_PASS word=" + site + " prefix_inputs=3 prefix_resets=3 callother=5");
        }

        Function function = currentProgram.getFunctionManager().getFunctionAt(start);
        if (function == null) {
            function = currentProgram.getFunctionManager().createFunction(
                "vfpu_prefix_probe", start, new AddressSet(start, start.add(55)), SourceType.USER_DEFINED);
        }
        if (function == null) throw new IllegalStateException("Could not create fixture function");

        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Could not open Ghidra decompiler");
            }
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IllegalStateException("Decompiler failed on source-owned fixture");
            }
            String pseudocode = result.getDecompiledFunction().getC();
            println("VFPU_VADDQ_C_START");
            println(pseudocode);
            println("VFPU_VADDQ_C_END");
            Matcher matcher = Pattern.compile("vadd_q\\([^;]*\\)").matcher(pseudocode);
            List<String> calls = new ArrayList<>();
            while (matcher.find()) calls.add(matcher.group().replaceAll("\\s+", "").toLowerCase());
            if (calls.size() != 3) {
                throw new IllegalStateException("Expected three vadd_q calls, got " + calls.size());
            }
            String[] suffixes = {",0xe4,0xe4,0)", ",0xc6,0xe4,0)", ",0xe4,0xe4,0)"};
            for (int i = 0; i < calls.size(); i++) {
                if (!calls.get(i).endsWith(suffixes[i])) {
                    throw new IllegalStateException("Unexpected prefix flow at call " + i + ": " + calls.get(i));
                }
            }
            println("VFPU_VADDQ_DECOMP_PASS calls=3 swizzle_and_consumption=visible");
        } finally {
            decompiler.dispose();
        }
        println("VFPU_VADDQ_SMOKE_COMPLETE");
    }
}
