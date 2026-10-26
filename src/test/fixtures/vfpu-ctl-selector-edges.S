/* Out-of-range vmfvc control selectors: source-owned three-word probe.
 * RCX7 is last valid control register, index 16 is first invalid,
 * and index 127 is the historical interlock spelling.
 */
    .text
    .set noreorder
    .word 0xd0500f00  /* vmfvc S000,RCX7 */
    .word 0xd0501000  /* vmfvc S000,S400 (invalid control selector) */
    .word 0xd0507f00  /* vmfvc S000,(interlock) (invalid control selector) */
