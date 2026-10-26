// Verify vmtvc masks and no-ops at control-register selector boundaries.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class VfpuVmtvcMaskEdges extends GhidraScript {
    private static final int[] WORDS = {
        0xd0510000, 0xd0510004, 0xd0510006, 0xd0510007,
        0xd051000f, 0xd0510010, 0xd051007f
    };
    private static final String[] DISPLAY = {
        "SPFX", "INF4", "RSV6", "REV", "RCX7", "S400", "(interlock)"
    };
    private static final int[] MASKED = {1, 0, 0, 0, 1, 0, 0};
    private static final int[] WRITES = {1, 1, 0, 0, 1, 0, 0};

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Not Allegrex");
        }
        Address start = currentProgram.getMinAddress();
        for (int i = 0; i < WORDS.length; i++) {
            if (currentProgram.getMemory().getInt(start.add(i * 4L)) != WORDS[i]) {
                throw new IllegalStateException("vmtvc boundary fixture changed at " + i);
            }
        }
        if (!disassemble(start)) throw new IllegalStateException("Cannot disassemble fixture");
        for (int i = 0; i < WORDS.length; i++) {
            Instruction ins = currentProgram.getListing().getInstructionAt(start.add(i * 4L));
            if (ins == null || !"vmtvc".equals(ins.getMnemonicString())
                    || !ins.toString().contains("S000," + DISPLAY[i])) {
                throw new IllegalStateException("Unexpected vmtvc display: " + ins);
            }
            int ands = 0, ors = 0, writes = 0;
            for (PcodeOp op : ins.getPcode()) {
                if (op.getOpcode() == PcodeOp.INT_AND) ands++;
                if (op.getOpcode() == PcodeOp.INT_OR) ors++;
                if (op.getOutput() != null && op.getOutput().isRegister()) writes++;
            }
            if (ands != MASKED[i] || ors != (i == 4 ? 1 : 0) || writes != WRITES[i]) {
                throw new IllegalStateException("Unexpected vmtvc write at " + i
                        + ": ands=" + ands + " ors=" + ors + " writes=" + writes);
            }
            println("VFPU_VMTVC_EDGE_PASS index=" + i + " register=" + DISPLAY[i]);
        }
        println("VFPU_VMTVC_EDGES_COMPLETE");
    }
}
