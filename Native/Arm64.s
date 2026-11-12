// Freedom Network — AArch64 (ARM64) Assembly (NEON). Android primary architecture.
//
// NEON-vectorized counterparts of x86_64.s (x86_64):
// 1. freedom_ascii_lowercase(dst=x0, src=x1, len=x2)
//      ARM64 has native unsigned byte compares (cmhs), so the range test needs no sign-bias trick.
// 2. freedom_csum_fold(buf=x0, len=x1, initial=x2) -> w0 (u16)
//      NEON RFC 1071 16-bit one's-complement big-endian accumulator (`rev16` + `uadalp` + `uaddlv`).
// 3. freedom_csum_delta(old_check=w0, old_word=w1, new_word=w2) -> w0 (u16)
//      RFC 1624 incremental checksum update in branchless scalar instructions.
// 4. freedom_scan_pattern(hay=x0, hay_len=x1, needle=x2, needle_len=x3) -> x0 (usize)
//      NEON 16-byte broadcast (`dup v1.16b` + `cmeq` + `umaxv`) pattern scanner for TLS SNI/ECH
//      and HTTP Host header inspection.

.text
.globl freedom_ascii_lowercase
.p2align 4
freedom_ascii_lowercase:
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

.globl freedom_csum_fold
.p2align 4
freedom_csum_fold:
    mov     x3, x2                     // 64-bit accumulator = initial
    cbz     x1, 14f
    movi    v4.4s, #0                  // 32-bit lane accumulator
    mov     x4, #0                     // offset
11:
    cmp     x1, #16
    blo     12f
    ldr     q0, [x0, x4]
    rev16   v0.16b, v0.16b             // swap big-endian bytes into host u16 lanes
    uadalp  v4.4s, v0.8h               // accumulate pairs of u16 into u32 lanes
    add     x4, x4, #16
    sub     x1, x1, #16
    b       11b
12:
    uaddlv  d5, v4.4s                  // sum 4 x u32 lanes into 64-bit d5
    fmov    x5, d5
    add     x3, x3, x5
    add     x5, x0, x4                 // pointer to remaining tail bytes
13:
    cmp     x1, #2
    blo     15f
    ldrb    w6, [x5], #1
    ldrb    w7, [x5], #1
    orr     w6, w7, w6, lsl #8
    add     x3, x3, x6
    sub     x1, x1, #2
    b       13b
15:
    cbz     x1, 14f
    ldrb    w6, [x5]
    lsl     w6, w6, #8
    add     x3, x3, x6
14:
    lsr     x6, x3, #32
    and     x3, x3, #0xffffffff
    add     x3, x3, x6
    lsr     x6, x3, #16
    and     x3, x3, #0xffff
    add     x3, x3, x6
    lsr     x6, x3, #16
    and     w0, w3, #0xffff
    add     w0, w0, w6
    and     w0, w0, #0xffff
    ret

.globl freedom_csum_delta
.p2align 4
freedom_csum_delta:
    mvn     w0, w0
    and     w0, w0, #0xffff
    mvn     w1, w1
    and     w1, w1, #0xffff
    and     w2, w2, #0xffff
    add     w0, w0, w1
    add     w0, w0, w2
    lsr     w3, w0, #16
    and     w0, w0, #0xffff
    add     w0, w0, w3
    lsr     w3, w0, #16
    add     w0, w0, w3
    mvn     w0, w0
    and     w0, w0, #0xffff
    ret

.globl freedom_scan_pattern
.p2align 4
freedom_scan_pattern:
    cbz     x3, 28f
    cmp     x3, x1
    bhi     29f
    sub     x4, x1, x3                 // max_pos = hay_len - needle_len
    ldrb    w5, [x2]                   // needle[0]
    dup     v1.16b, w5                 // broadcast needle[0] across 16 bytes
    mov     x6, #0                     // pos = 0
21:
    cmp     x6, x4
    bhi     29f
    sub     x7, x4, x6
    cmp     x7, #15
    blo     25f
    ldr     q0, [x0, x6]
    cmeq    v0.16b, v0.16b, v1.16b
    umaxv   b2, v0.16b
    fmov    w7, s2
    cbnz    w7, 22f
    add     x6, x6, #16
    b       21b
22:
    mov     x11, #16
23:
    cbz     x11, 21b
    cmp     x6, x4
    bhi     29f
    mov     x7, #0
24:
    cmp     x7, x3
    bhs     27f
    add     x8, x0, x6
    ldrb    w9, [x8, x7]
    ldrb    w10, [x2, x7]
    cmp     w9, w10
    bne     26f
    add     x7, x7, #1
    b       24b
26:
    add     x6, x6, #1
    sub     x11, x11, #1
    b       23b
25:
    cmp     x6, x4
    bhi     29f
    mov     x7, #0
30:
    cmp     x7, x3
    bhs     27f
    add     x8, x0, x6
    ldrb    w9, [x8, x7]
    ldrb    w10, [x2, x7]
    cmp     w9, w10
    bne     31f
    add     x7, x7, #1
    b       30b
31:
    add     x6, x6, #1
    b       25b
27:
    mov     x0, x6
    ret
28:
    mov     x0, #0
    ret
29:
    mov     x0, x1
    ret
