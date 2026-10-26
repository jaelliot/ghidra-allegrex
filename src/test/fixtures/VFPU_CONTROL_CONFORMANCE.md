# Allegrex VFPU control-register conformance (source-owned)

This is a public, minimal evidence summary for the control-transfer fixes
related to [upstream issue #40](https://github.com/kotcrab/ghidra-allegrex/issues/40).
No commercial game data, PSP dumps, or copied GPLv3 PSPDEV test implementation
was used.

## Input and independent runtime observation

The [28-word source fixture](vfpu-control-transfers.S) was reused *unchanged*
in an isolated PSPDEV homebrew ELF.

- Instruction bytes: 112 bytes, SHA-256
  `89bba60eebfd6e398d2211c0ab03c9c7241ae1c0cd04e823ebad2906f67c66f4`
- Resulting PSP ELF: SHA-256
  `3b0031f3824c2420bd306210b18fa74da9181fa465b37d99a316d23a5560af01`
- PSPDEV: pinned `v20260901`
- PPSSPP: source revision `0c6aa15f9be365bb88265636881814914ee8ac58`,
  headless IR interpreter, network-disabled container
- Three fresh PPSSPP processes: PID 8, 21, 34
- 24/24 exact 32-bit readbacks matched the declared oracle;
  all three failure masks and process exit codes were zero.

| Word | Readback | Observed value |
| --- | --- | --- |
| 0 | SPFX, after `mtvc` | `0x000fffff` |
| 1 | DPFX, after `mtvc` | `0x00000fff` |
| 2 | CC, after `mtvc` | `0x0000003f` |
| 3 | RCX0, after `mtvc` | `0x3f8fffff` |
| 4 | RSV5 before attempted write | `0x00000000` |
| 5 | RSV5 after attempted write | `0x00000000` |
| 6 | TPFX after `vmtvc S000,TPFX` | `0x000fffff` |
| 7 | S000 after `vmfvc S000,TPFX` | `0x000fffff` |

The underlying timestamped debugger transcripts, ELF identities, process logs
and aggregate JSON evidence are preserved in the original private lab's
successful GitHub Actions run. This public summary contains only source-owned
test observations. The runtime result is **emulator-specific, not PSP hardware
verification**.

## Ghidra 12.2 static verification

The original Allegrex extension mis-lifted unrestricted control writes and
two scalar/control transfer operands. The three independently tested changes
are organized for review:

- [Operand mapping](https://github.com/jaelliot/ghidra-allegrex/tree/codex/vfpu-control-mapping-review-040e):
  correct `vmfvc` source selector and `vmtvc` attached scalar, including
  out-of-range selector representation.
- [`mtvc` write masks](https://github.com/jaelliot/ghidra-allegrex/tree/codex/vfpu-mtvc-write-masks-review-040f):
  handle writable, read-only and invalid control selectors.
- [`vmtvc` write masks](https://github.com/jaelliot/ghidra-allegrex/tree/codex/vfpu-vmtvc-write-masks-review-040g):
  dependent on operand mapping; same masks for VFPU scalar sources.

The combined Ghidra 12.2 Sleigh build and decompilation check
[passed in run #40255488690](https://github.com/jaelliot/ghidra-allegrex/actions/runs/40255488690)
at source commit `7c05640fefc7c5304f8a1570350422b379b62720`.
Ghidra's decompiled readbacks are:

```c
*param_1 = 0xfffff;
param_1[1] = 0xfff;
param_1[2] = 0x3f;
param_1[3] = 0x3f8fffff;
param_1[4] = in_RSV5;
param_1[5] = in_RSV5;
param_1[6] = 0xfffff;
param_1[7] = 0xfffff;
```

Ghidra does not invent RSV5's starting value; the PSP runtime observation
happened to start at zero. All three changes are **bounded** and leave the
original `vpfxs`, `vpfxt` and `vpfxd` decompiler-visible calls intact.
Full VFPU arithmetic, destination masks on vector calculations,
`setjmp`/`longjmp`, hardware accuracy and Monster Hunter reconstruction
are outside this result.

This document is a post-test evidence summary. Its own documentation commit
was not the revision exercised in the combined Ghidra run.
