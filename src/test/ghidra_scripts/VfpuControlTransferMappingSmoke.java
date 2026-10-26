// Verifies scalar/control operand mapping only; control-write masks are separate.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class VfpuControlTransferMappingSmoke extends GhidraScript {
    private static final long SCALAR_S000 = 0x5000;
    private static final long TPFX = 0x5304;

    private void assertTransfer(Address start, int index, String mnemonic,
                                long expectedDest, long expectedSource) throws Exception {
        Instruction ins = currentProgram.getListing().getInstructionAt(start.add(index * 4L));
        if (ins == null || !mnemonic.equals(ins.getMnemonicString())
                || !ins.toString().contains("S000,TPFX")) {
            throw new IllegalStateException("Wrong control-transfer decoding at " + index + ": " + ins);
        }
        int copies = 0;
        for (PcodeOp op : ins.getPcode()) {
            if (op.getOpcode() != PcodeOp.COPY || op.getOutput() == null
                    || !op.getOutput().isRegister()) continue;
            Varnode input = op.getInput(0);
            if (input.isRegister() && op.getOutput().getOffset() == expectedDest
                    && input.getOffset() == expectedSource) {
                copies++;
            }
        }
        if (copies != 1) {
            throw new IllegalStateException(mnemonic + " should copy VFPU registers "
                    + Long.toHexString(expectedSource) + " -> " + Long.toHexString(expectedDest)
                    + ", got " + copies + " valid copies");
        }
        println("VFPU_CTRL_MAPPING_PASS index=" + index + " mnemonic=" + mnemonic);
    }

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Unexpected language " + currentProgram.getLanguageID());
        }
        Address start = currentProgram.getMinAddress();
        if (currentProgram.getMemory().getInt(start.add(20 * 4L)) != 0xd0510001
                || currentProgram.getMemory().getInt(start.add(23 * 4L)) != 0xd0500100) {
            throw new IllegalStateException("Control-transfer instruction words changed");
        }
        if (!disassemble(start)) throw new IllegalStateException("Cannot disassemble fixture");
        assertTransfer(start, 20, "vmtvc", TPFX, SCALAR_S000);
        assertTransfer(start, 23, "vmfvc", SCALAR_S000, TPFX);
        println("VFPU_CTRL_MAPPING_COMPLETE");
    }
}
