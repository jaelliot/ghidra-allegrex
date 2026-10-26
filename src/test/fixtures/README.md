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


## Captured Ghidra baseline

The complete Ghidra 12.2 run [#40247312778](https://github.com/jaelliot/ghidra-allegrex/actions/runs/40247312778)
passed its **capture** gate at source revision
`6a5a09c87c98e9a47d7b2927b3b374bd97db4dff`.
Raw probe SHA-256: `89bba60eebfd6e398d2211c0ab03c9c7241ae1c0cd04e823ebad2906f67c66f4`.

Ghidra's decompiled C stores `0xffffffff` at offsets 0, 4, 8, 12
and 20 (instead of masking the writes or respecting read-only RSV5);
it also stores zero at 24 and `0xffffffff` at 28.
The disassembly shows `vmtvc S000,TPFX` at word 20 but its p-code is
`COPY (const,0)` to `TPFX`. Word 23 **should be**
`vmfvc S000,TPFX` from encoding bits 8–14, but is shown as
`vmfvc S000,SPFX` and outputs `COPY (...)` to `(const,0)`.

These are actual Ghidra outputs; the PPSSPP expectations above are
source-derived, **not** yet direct emulator or hardware observations.
The mask and operand-mapping discrepancies must be treated as distinct
fixes, and changes must retain useful decoded pseudocode.


## Scalar-transfer mapping experiment

An isolated patch on `codex/vfpu-control-mapping-040e` was tested on
[Ghidra 12.2 run #40247803622](https://github.com/jaelliot/ghidra-allegrex/actions/runs/40247803622)
at commit `bc980024095badbca077bb77e2759dedc41fe3ed`.
The instruction decoder and resulting p-code now agree for the two
**defined-control-register** examples:

- `vmtvc S000,TPFX`: `COPY` from scalar register `0x5000` to TPFX `0x5304`.
- `vmfvc S000,TPFX`: `COPY` from TPFX `0x5304` to scalar register `0x5000`.

The extension build, Sleigh compilation, baseline evidence capture, and
focused mapping regression all passed. This fixes operand selection only.
The write-mask and read-only discrepancies remain (the decompiled C still
shows all ones where a masked value is expected).

**Selector boundary verified:** `VfpuCtlSource` now preserves the
existing scalar-register names for selectors 16–126 and `(interlock)`
for selector 127. These invalid control selectors lift to zero, rather
than an unrelated control register, while selector 15 still reads RCX7.
All three were checked by Ghidra 12.2 in
[run #40250785203](https://github.com/jaelliot/ghidra-allegrex/actions/runs/40250785203).
The fixture and p-code tests passed. This validates static instruction
semantics, **not** observed behavior on original PSP hardware.
