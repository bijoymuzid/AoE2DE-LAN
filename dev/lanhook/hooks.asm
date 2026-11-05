; hooks.asm — generic detour thunk. Entered from the near-page stub with r10 = hook id
; and the stack exactly as at the original function's entry (return address on top,
; shadow space + stack args in place). Saves all volatile GPRs + XMM0-5, calls the C
; logger, restores everything, then tail-jumps to the per-hook trampoline so the
; original prologue executes with a pristine entry state. Any calling convention
; (any arg count, stack args, FP args) survives intact.
PUBLIC lanhook_thunk
PUBLIC g_TailTable
EXTERN lanhook_log_hit:PROC

.data?
ALIGN 8
g_TailTable QWORD 16 DUP(?)

.code
lanhook_thunk PROC
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10                    ; = hook id (set by the near-page stub; volatile)
    push r11
    sub  rsp, 80h               ; [rsp+00..1F] shadow for the call, [rsp+20..7F] xmm saves
    movdqu xmmword ptr [rsp+20h], xmm0
    movdqu xmmword ptr [rsp+30h], xmm1
    movdqu xmmword ptr [rsp+40h], xmm2
    movdqu xmmword ptr [rsp+50h], xmm3
    movdqu xmmword ptr [rsp+60h], xmm4
    movdqu xmmword ptr [rsp+70h], xmm5
    mov  rcx, r10               ; id
    lea  rdx, [rsp+20h]         ; ctx: [0x00..5F]=xmm0-5, [0x60]=r11 [0x68]=r10
    call lanhook_log_hit        ; [0x70]=r9 [0x78]=r8 [0x80]=rdx [0x88]=rcx
    movdqu xmm0, xmmword ptr [rsp+20h]   ; [0x90]=rax [0x98]=original return address
    movdqu xmm1, xmmword ptr [rsp+30h]
    movdqu xmm2, xmmword ptr [rsp+40h]
    movdqu xmm3, xmmword ptr [rsp+50h]
    movdqu xmm4, xmmword ptr [rsp+60h]
    movdqu xmm5, xmmword ptr [rsp+70h]
    add  rsp, 80h
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rax
    lea  r11, g_TailTable       ; r11 is volatile — safe to repurpose after restore
    jmp  QWORD PTR [r11 + r10*8]
lanhook_thunk ENDP
END
