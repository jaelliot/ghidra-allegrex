/* Source-owned vmtvc selector boundaries; source scalar register S000. */
    .text
    .set noreorder
    .word 0xd0510000  /* vmtvc S000,SPFX: 20-bit mask */
    .word 0xd0510004  /* vmtvc S000,INF4: full write */
    .word 0xd0510006  /* vmtvc S000,RSV6: ignored */
    .word 0xd0510007  /* vmtvc S000,REV: ignored */
    .word 0xd051000f  /* vmtvc S000,RCX7: mask + forced high bits */
    .word 0xd0510010  /* vmtvc S000,S400: invalid control selector */
    .word 0xd051007f  /* vmtvc S000,(interlock): invalid control selector */
