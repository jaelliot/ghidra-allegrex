// Validate valid/invalid vmfvc control selectors without altering legacy display.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class VfpuControlSelectorSmoke extends GhidraScript {
    private static final int[] WORDS = {0xd0500f00, 0xd0501000, 0xd0507f00};
    private static final String[] DISPLAY = {"RCX7", "S400", "(interlock)"};

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Unexpected processor");
        }
        Address start = currentProgram.getMinAddress();
        for (int i = 0; i < WORDS.length; i++) {
            if (currentProgram.getMemory().getInt(start.add(i * 4L)) != WORDS[i]) {
                throw new IllegalStateException("Selector fixture bytes changed at " + i);
            }
        }
        if (!disassemble(start)) throw new IllegalStateException("Cannot disassemble selector fixture");

        for (int i = 0; i < WORDS.length; i++) {
            Instruction ins = currentProgram.getListing().getInstructionAt(start.add(i * 4L));
            if (ins == null || !"vmfvc".equals(ins.getMnemonicString())
                    || !ins.toString().contains(DISPLAY[i])) {
                throw new IllegalStateException("Legacy selector spelling changed: " + ins);
            }
            int matches = 0;
            for (PcodeOp op : ins.getPcode()) {
                if (op.getOpcode() != PcodeOp.COPY || op.getOutput() == null) continue;
                Varnode output = op.getOutput();
                Varnode input = op.getInput(0);
                if (!output.isRegister() || output.getOffset() != 0x5000) continue;
                if (i == 0 && input.isRegister() && input.getOffset() == 0x533c) matches++;
                if (i != 0 && input.isConstant() && input.getOffset() == 0) matches++;
            }
            if (matches != 1) {
                throw new IllegalStateException("Invalid selector operand behavior at " + i);
            }
            println("VFPU_CTRL_SELECTOR_PASS index=" + i + " display=" + DISPLAY[i]);
        }
        println("VFPU_CTRL_SELECTOR_COMPLETE");
    }
}
