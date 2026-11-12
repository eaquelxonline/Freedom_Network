// THE DPI — AArch64 (ARM64) Assembly (NEON). Android primary architecture.
//
// the_dpi_ascii_lowercase(dst=x0, src=x1, len=x2)
//   NEON-vectorized counterpart of Core.s (x86_64). ARM64 has native unsigned byte
//   compares (cmhs), so the range test needs no sign-bias trick. Separate from Core.s
//   because the integrated assembler builds one architecture per object; both files are
//   the measurable, architecture-specific low-level path the project reserves for Assembly.

.text
.globl the_dpi_ascii_lowercase
.p2align 4
the_dpi_ascii_lowercase:
    cbz     x2, 2f
    movi    v1.16b, #0x41              // 'A'
    movi    v2.16b, #0x5a              // 'Z'
    movi    v3.16b, #0x20
    mov     x3, #0                     // index
1:
    cmp     x2, #16
    blo     3f
    ldr     q0, [x1, x3]               // b
    cmhs    v4.16b, v0.16b, v1.16b     // b >= 'A'
    cmhs    v5.16b, v2.16b, v0.16b     // 'Z' >= b
    and     v4.16b, v4.16b, v5.16b     // mask
    and     v4.16b, v4.16b, v3.16b     // & 0x20
    add     v0.16b, v0.16b, v4.16b     // b += delta
    str     q0, [x0, x3]
    add     x3, x3, #16
    sub     x2, x2, #16
    b       1b
3:
    cbz     x2, 2f
4:
    ldrb    w4, [x1, x3]
    sub     w5, w4, #0x41              // b - 'A'
    cmp     w5, #25
    bhi     5f                         // unsigned > 25 -> not a letter
    add     w4, w4, #0x20
5:
    strb    w4, [x0, x3]
    add     x3, x3, #1
    sub     x2, x2, #1
    cbnz    x2, 4b
2:
    ret
