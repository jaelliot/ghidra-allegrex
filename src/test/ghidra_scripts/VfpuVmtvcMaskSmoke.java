// Source-owned vmtvc mask regression: scalar mapping is a separate prerequisite.
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

public class VfpuVmtvcMaskSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Not Allegrex");
        }
        Address start = currentProgram.getMinAddress();
        if (currentProgram.getMemory().getInt(start.add(80)) != 0xd0510001) {
            throw new IllegalStateException("vmtvc fixture changed");
        }
        if (!disassemble(start)) throw new IllegalStateException("Cannot disassemble fixture");
        Instruction ins = currentProgram.getListing().getInstructionAt(start.add(80));
        if (ins == null || !"vmtvc".equals(ins.getMnemonicString())
                || !ins.toString().contains("S000,TPFX")) {
            throw new IllegalStateException("Unexpected vmtvc " + ins);
        }
        int masks = 0, writes = 0, sourceReads = 0;
        for (PcodeOp op : ins.getPcode()) {
            if (op.getOpcode() == PcodeOp.INT_AND) {
                masks++;
                for (Varnode input : op.getInputs()) {
                    if (input.isRegister() && input.getOffset() == 0x5000) sourceReads++;
                }
            }
            if (op.getOutput() != null && op.getOutput().isRegister()
                    && op.getOutput().getOffset() == 0x5304) writes++;
        }
        if (masks != 1 || writes != 1 || sourceReads != 1) {
            throw new IllegalStateException("Wrong vmtvc p-code: masks=" + masks
                    + " writes=" + writes + " sources=" + sourceReads);
        }

        Function function = currentProgram.getFunctionManager().getFunctionAt(start);
        if (function == null) {
            function = currentProgram.getFunctionManager().createFunction(
                    "vfpu_control_probe", start, new AddressSet(start, start.add(111)),
                    SourceType.USER_DEFINED);
        }
        if (function == null) throw new IllegalStateException("Missing probe function");
        DecompInterface d = new DecompInterface();
        try {
            if (!d.openProgram(currentProgram)) throw new IllegalStateException("Decompiler unavailable");
            DecompileResults results = d.decompileFunction(function, 30, monitor);
            if (results == null || !results.decompileCompleted()
                    || results.getDecompiledFunction() == null) {
                throw new IllegalStateException("Decompiler did not complete");
            }
            String c = results.getDecompiledFunction().getC();
            println("VFPU_VMTVC_C_START");
            println(c);
            println("VFPU_VMTVC_C_END");
            if (!c.contains("param_1[6] = 0xfffff;") || !c.contains("param_1[7] = 0xfffff;")) {
                throw new IllegalStateException("vmtvc mask not visible in decompiled C");
            }
        } finally {
            d.dispose();
        }
        println("VFPU_VMTVC_MASK_COMPLETE");
    }
}
