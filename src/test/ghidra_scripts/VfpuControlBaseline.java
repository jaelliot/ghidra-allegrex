// Baseline only: record Ghidra's raw decoding, p-code and pseudocode without changing semantics.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

public class VfpuControlBaseline extends GhidraScript {
    private static final int[] WORDS = {
        0x3c08ffff, 0x3508ffff, 0x48e80080, 0x48690080,
        0xac890000, 0x48e80082, 0x48690082, 0xac890004,
        0x48e80083, 0x48690083, 0xac890008, 0x48e80088,
        0x48690088, 0xac89000c, 0x48690085, 0xac890010,
        0x48e80085, 0x48690085, 0xac890014, 0x48e80000,
        0xd0510001, 0x48690081, 0xac890018, 0xd0500100,
        0x48690000, 0xac89001c, 0x03e00008, 0x00000000
    };
    private static final String[] CONTROL = {"mtvc", "mfvc", "vmtvc", "vmfvc", "mtv", "mfv"};

    private boolean relevant(String mnemonic) {
        for (String name : CONTROL) {
            if (name.equals(mnemonic)) return true;
        }
        return false;
    }

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Unexpected language " + currentProgram.getLanguageID());
        }
        Address start = currentProgram.getMinAddress();
        for (int i = 0; i < WORDS.length; i++) {
            if (currentProgram.getMemory().getInt(start.add(i * 4L)) != WORDS[i]) {
                throw new IllegalStateException("Fixture byte mismatch at " + i);
            }
        }
        if (!disassemble(start)) throw new IllegalStateException("Disassembly failed");

        int transfers = 0;
        for (int i = 0; i < WORDS.length; i++) {
            Instruction instruction = currentProgram.getListing().getInstructionAt(start.add(i * 4L));
            if (instruction == null) {
                throw new IllegalStateException("No instruction at index " + i);
            }
            println("VFPU_CTRL_INST index=" + i + " mnemonic=" + instruction.getMnemonicString()
                    + " assembly=" + instruction);
            if (!relevant(instruction.getMnemonicString())) continue;
            transfers++;
            for (PcodeOp op : instruction.getPcode()) {
                println("VFPU_CTRL_PCODE index=" + i + " opcode=" + op.getMnemonic()
                        + " output=" + op.getOutput() + " operation=" + op);
            }
        }
        if (transfers < 15) {
            throw new IllegalStateException("Too few control transfers decoded: " + transfers);
        }

        Function function = currentProgram.getFunctionManager().getFunctionAt(start);
        if (function == null) {
            function = currentProgram.getFunctionManager().createFunction(
                    "vfpu_control_probe", start, new AddressSet(start, start.add(WORDS.length * 4L - 1)),
                    SourceType.USER_DEFINED);
        }
        if (function == null) throw new IllegalStateException("Could not create probe function");

        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Cannot open Ghidra decompiler");
            }
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IllegalStateException("Decompiler did not complete");
            }
            println("VFPU_CONTROL_C_START");
            println(result.getDecompiledFunction().getC());
            println("VFPU_CONTROL_C_END");
        } finally {
            decompiler.dispose();
        }
        println("VFPU_CONTROL_BASELINE_COMPLETE transfers=" + transfers);
    }
}
