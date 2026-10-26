# VFPU control-transfer characterization (#40)

This source-only fixture captures **unmodified Allegrex v21.5 / Ghidra 12.2**
instruction lifting and decompilation. It is an investigative baseline,
not a processor fix or a claim of PSP equivalence.

The 28-word fixture sets `t0 = 0xffffffff`, transfers that value into
control registers with `mtvc` or `vmtvc`, reads them using `mfvc` or
`vmfvc`, and stores eight observations at offsets 0–28 from `a0`.

The pinned PPSSPP interpreter revision
`0c6aa15f9be365bb88265636881814914ee8ac58` predicts:

| Offset | Observation | PPSSPP-derived prediction |
| --- | --- | --- |
| 0 | SPFX after mtvc | 0x000fffff |
| 4 | DPFX after mtvc | 0x00000fff |
| 8 | CC after mtvc | 0x0000003f |
| 12 | RCX0 after mtvc | 0x3f8fffff |
| 16 | RSV5 before write | initial value not fixed here |
| 20 | RSV5 after attempted write | unchanged from offset 16 |
| 24 | TPFX after vmtvc | 0x000fffff |
| 28 | VFPU scalar copied from TPFX by vmfvc | 0x000fffff |

Those are **source-derived predictions, not runtime observations**.
Reference: `Core/MIPS/MIPSVFPUUtils.cpp` (`GetVFPUCtrlMask`,
`GetVFPUCtrlSetBits`) and `Core/MIPS/InterpreterVFPU.cpp`
(`Int_Mftv`, `Int_Vmfvc`, `Int_Vmtvc`).

The final `vmfvc` intentionally selects control register 1 using bits
8–14, independently from its scalar destination at bits 0–6.
Record how current Ghidra decodes this instead of altering the fixture
to fit expectations.

The CI workflow assembles the raw source-owned instruction words,
imports the 112-byte binary into fresh Ghidra 12.2, and archives the
raw disassembly, p-code and decompiled C. A green baseline means
**complete evidence capture**, not correct ISA semantics.

Do not submit this baseline as an upstream fix. Confirm any discrepancy
with an independent execution oracle, and propose a separate surgical
change only after that confirmation.
