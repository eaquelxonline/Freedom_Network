// THE DPI — x86_64 Assembly (SSE2), AT&T syntax, System V AMD64 calling convention.
//
// the_dpi_ascii_lowercase(dst=%rdi, src=%rsi, len=%rdx)
//   Lowercases ASCII 'A'..'Z' in `src[0..len]`, writing to `dst[0..len]`. Bytes >= 0x80
//   and non-letters are copied unchanged, so a UTF-8 buffer stays valid. Used in-place on
//   the DNS/target name-normalization path (see `mod ascii` in Core.rs).
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

.p2align 4
.Ldpi_c80: .byte 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80
.Ldpi_clo: .byte 0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0
.Ldpi_chi: .byte 0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB,0xDB
.Ldpi_c20: .byte 0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20
