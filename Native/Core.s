// THE DPI — x86_64 Assembly (SSE2), AT&T syntax, System V AMD64 calling convention.
//
// Low-level SIMD hot-path primitives for line-rate packet inspection and desynchronization:
// 1. the_dpi_ascii_lowercase(dst=%rdi, src=%rsi, len=%rdx)
//      Lowercases ASCII 'A'..'Z' in `src[0..len]`, writing to `dst[0..len]`. Bytes >= 0x80
//      and non-letters are copied unchanged, so a UTF-8 buffer stays valid.
// 2. the_dpi_csum_fold(buf=%rdi, len=%rsi, initial=%rdx) -> %eax (u16)
//      RFC 1071 16-bit one's-complement big-endian accumulator and folder (SSE2 vectorized).
//      Used to compute and verify IPv4, IPv6 pseudo-header, TCP and UDP checksums across
//      split/disordered segments and synthetic fake packets.
// 3. the_dpi_csum_delta(old_check=%edi, old_word=%esi, new_word=%edx) -> %eax (u16)
//      RFC 1624 incremental checksum update: HC' = ~(~HC + ~m + m'). Updates TCP/IP checksums
//      in O(1) registers when mutating TTL, Sequence Number or BadSum fields.
// 4. the_dpi_scan_pattern(hay=%rdi, hay_len=%rsi, needle=%rdx, needle_len=%rcx) -> %rax (usize)
//      SSE2 16-byte broadcast + bitmask pattern scanner (`pcmpeqb` + `pmovmskb` + `bsf`).
//      Locates TLS ClientHello SNI/ECH extensions and HTTP `Host:` headers in packet payloads.
//
// The forced System V convention (extern "sysv64" in Core.rs) makes this one file correct
// on Linux, Android x86_64 and Windows x64 alike. Read-only constants live in .text so no
// OS-specific data-section name is needed. Assembled by LLVM via core::arch::global_asm!.

.text
.globl the_dpi_ascii_lowercase
.p2align 4
the_dpi_ascii_lowercase:
    test    %rdx, %rdx
    je      .Ldpi_done
    movdqa  .Ldpi_c80(%rip), %xmm5      // 0x80 bias (unsigned->signed order)
    movdqa  .Ldpi_clo(%rip), %xmm6      // ('A' ^ 0x80) - 1 = 0xC0
    movdqa  .Ldpi_chi(%rip), %xmm7      // ('Z' ^ 0x80) + 1 = 0xDB
    movdqa  .Ldpi_c20(%rip), %xmm8      // 0x20
    xor     %rax, %rax                  // index
    mov     %rdx, %rcx                  // remaining
.Ldpi_chunk:
    cmp     $16, %rcx
    jb      .Ldpi_tail
    movdqu  (%rsi,%rax), %xmm0          // b
    movdqa  %xmm0, %xmm1
    pxor    %xmm5, %xmm1                // s = b ^ 0x80
    movdqa  %xmm1, %xmm2
    pcmpgtb %xmm6, %xmm2                // ge = s > 0xC0  (unsigned b >= 'A')
    movdqa  %xmm7, %xmm3
    pcmpgtb %xmm1, %xmm3                // le = 0xDB > s  (unsigned b <= 'Z')
    pand    %xmm3, %xmm2                // mask = ge & le
    pand    %xmm8, %xmm2                // delta = mask & 0x20
    paddb   %xmm2, %xmm0               // b += delta  (== b | 0x20 for A..Z)
    movdqu  %xmm0, (%rdi,%rax)
    add     $16, %rax
    sub     $16, %rcx
    jmp     .Ldpi_chunk
.Ldpi_tail:
    test    %rcx, %rcx
    je      .Ldpi_done
.Ldpi_byte:
    movzbl  (%rsi,%rax), %r8d
    mov     %r8d, %r9d
    sub     $0x41, %r9d                 // b - 'A'
    cmp     $25, %r9d
    ja      .Ldpi_store                 // unsigned > 25 -> not a letter
    add     $0x20, %r8d
.Ldpi_store:
    mov     %r8b, (%rdi,%rax)
    inc     %rax
    dec     %rcx
    jnz     .Ldpi_byte
.Ldpi_done:
    ret

.globl the_dpi_csum_fold
.p2align 4
the_dpi_csum_fold:
    mov     %rdx, %rax                  // 64-bit accumulator = initial
    test    %rsi, %rsi
    je      .Lcsum_fold64
    pxor    %xmm4, %xmm4                // zero register
    pxor    %xmm5, %xmm5                // 32-bit lane accumulator
    xor     %rcx, %rcx                  // byte offset
.Lcsum_vec16:
    cmp     $16, %rsi
    jb      .Lcsum_vec_done
    movdqu  (%rdi,%rcx), %xmm0          // load 16 bytes
    movdqa  %xmm0, %xmm1
    psrlw   $8, %xmm0                   // low byte of BE word = byte[2k]
    psllw   $8, %xmm1                   // high byte of BE word = byte[2k+1] << 8
    por     %xmm1, %xmm0                // 8 x u16 big-endian words in host order
    movdqa  %xmm0, %xmm2
    punpcklwd %xmm4, %xmm0              // first 4 x u16 -> 4 x u32
    punpckhwd %xmm4, %xmm2              // next 4 x u16 -> 4 x u32
    paddd   %xmm0, %xmm5
    paddd   %xmm2, %xmm5
    add     $16, %rcx
    sub     $16, %rsi
    jmp     .Lcsum_vec16
.Lcsum_vec_done:
    movdqa  %xmm5, %xmm0
    psrldq  $8, %xmm0
    paddd   %xmm0, %xmm5
    movdqa  %xmm5, %xmm0
    psrldq  $4, %xmm0
    paddd   %xmm0, %xmm5
    movd    %xmm5, %r8d
    add     %r8, %rax
.Lcsum_words:
    cmp     $2, %rsi
    jb      .Lcsum_odd
    movzbl  (%rdi,%rcx), %r8d
    movzbl  1(%rdi,%rcx), %r9d
    shl     $8, %r8d
    or      %r9d, %r8d
    add     %r8, %rax
    add     $2, %rcx
    sub     $2, %rsi
    jmp     .Lcsum_words
.Lcsum_odd:
    test    %rsi, %rsi
    je      .Lcsum_fold64
    movzbl  (%rdi,%rcx), %r8d
    shl     $8, %r8d
    add     %r8, %rax
.Lcsum_fold64:
    mov     %rax, %r8
    shr     $32, %r8
    mov     %eax, %eax
    add     %r8, %rax
    mov     %rax, %r8
    shr     $16, %r8
    and     $0xffff, %eax
    add     %r8d, %eax
    mov     %eax, %r8d
    shr     $16, %r8d
    add     %r8w, %ax
    movzwl  %ax, %eax
    ret

.globl the_dpi_csum_delta
.p2align 4
the_dpi_csum_delta:
    movzwl  %di, %eax
    not     %eax
    and     $0xffff, %eax
    movzwl  %si, %ecx
    not     %ecx
    and     $0xffff, %ecx
    movzwl  %dx, %r8d
    add     %ecx, %eax
    add     %r8d, %eax
    mov     %eax, %ecx
    shr     $16, %ecx
    and     $0xffff, %eax
    add     %ecx, %eax
    mov     %eax, %ecx
    shr     $16, %ecx
    add     %cx, %ax
    not     %ax
    movzwl  %ax, %eax
    ret

.globl the_dpi_scan_pattern
.p2align 4
the_dpi_scan_pattern:
    test    %rcx, %rcx
    je      .Lscan_zero
    cmp     %rsi, %rcx
    ja      .Lscan_not_found
    mov     %rsi, %r8
    sub     %rcx, %r8                   // max_pos = hay_len - needle_len
    movzbl  (%rdx), %eax                // first byte of needle
    movd    %eax, %xmm4
    punpcklbw %xmm4, %xmm4
    punpcklwd %xmm4, %xmm4
    pshufd  $0, %xmm4, %xmm4            // broadcast needle[0] across 16 bytes
    xor     %r9, %r9                    // pos = 0
.Lscan_vec_loop:
    mov     %r8, %r10
    sub     %r9, %r10
    cmp     $15, %r10
    jb      .Lscan_scalar_loop
    movdqu  (%rdi,%r9), %xmm0
    pcmpeqb %xmm4, %xmm0
    pmovmskb %xmm0, %r10d
    test    %r10d, %r10d
    je      .Lscan_vec_next
.Lscan_mask_bits:
    bsf     %r10d, %eax                 // lowest set bit index in 0..15
    lea     (%r9,%rax), %r11            // candidate offset = pos + bit_idx
    cmp     %r8, %r11
    ja      .Lscan_not_found
    lea     -1(%r10d), %eax
    and     %eax, %r10d                 // clear lowest set bit in mask
    movq    %r10, %xmm1                 // save remaining mask in xmm1
    lea     (%rdi,%r11), %r11           // &hay[cand]
    mov     $1, %rax                    // k = 1
.Lscan_cmp_vec:
    cmp     %rcx, %rax
    jae     .Lscan_vec_hit
    movzbl  (%r11,%rax), %r10d
    cmpb    (%rdx,%rax), %r10b
    jne     .Lscan_cmp_miss
    inc     %rax
    jmp     .Lscan_cmp_vec
.Lscan_cmp_miss:
    movq    %xmm1, %r10                 // restore mask
    test    %r10d, %r10d
    jne     .Lscan_mask_bits
.Lscan_vec_next:
    add     $16, %r9
    jmp     .Lscan_vec_loop
.Lscan_vec_hit:
    sub     %rdi, %r11
    mov     %r11, %rax
    ret
.Lscan_scalar_loop:
    cmp     %r8, %r9
    ja      .Lscan_not_found
    xor     %r11, %r11
.Lscan_scalar_inner:
    cmp     %rcx, %r11
    jae     .Lscan_found_r9
    lea     (%r9,%r11), %r10
    movzbl  (%rdi,%r10), %eax
    cmpb    (%rdx,%r11), %al
    jne     .Lscan_scalar_next
    inc     %r11
    jmp     .Lscan_scalar_inner
.Lscan_scalar_next:
    inc     %r9
    jmp     .Lscan_scalar_loop
.Lscan_found_r9:
    mov     %r9, %rax
    ret
.Lscan_zero:
    xor     %rax, %rax
    ret
.Lscan_not_found:
    mov     %rsi, %rax
    ret

.p2align 4
.Ldpi_c80: .byte 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80
.Ldpi_clo: .byte 0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0
.Ldpi_chi: .byte 0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB
.Ldpi_c20: .byte 0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20
