; hooks.asm — generic detour thunk. Entered from the near-page stub with r10 = hook id
; and the stack exactly as at the original function's entry (return address on top,
; shadow space + stack args in place). Saves all volatile GPRs + XMM0-5, calls the C
; logger, restores everything, then tail-jumps to the per-hook trampoline so the
; original prologue executes with a pristine entry state. Any calling convention
; (any arg count, stack args, FP args) survives intact. Also snapshots the four
; callee-saved GPRs at ctx[-8..-5] (rbx, rsi, rdi, rbp) so a handler can see the
; CALLER's object pointers; they are recorded, never modified.
PUBLIC lanhook_thunk
PUBLIC g_TailTable
EXTERN lanhook_log_hit:PROC

.data?
ALIGN 8
g_TailTable QWORD 20 DUP(?)

.code
lanhook_thunk PROC
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10                    ; = hook id (set by the near-page stub; volatile)
    push r11
    sub  rsp, 0C0h              ; [rsp+00..1F] shadow for the call,
    mov  qword ptr [rsp+20h], rbx   ; [rsp+20..3F] callee-saved snapshot
    mov  qword ptr [rsp+28h], rsi   ;   (= ctx[-8..-5], the CALLER's values)
    mov  qword ptr [rsp+30h], rdi
    mov  qword ptr [rsp+38h], rbp
    movdqu xmmword ptr [rsp+60h], xmm0   ; [rsp+60..BF] xmm saves
    movdqu xmmword ptr [rsp+70h], xmm1
    movdqu xmmword ptr [rsp+80h], xmm2
    movdqu xmmword ptr [rsp+90h], xmm3
    movdqu xmmword ptr [rsp+0A0h], xmm4
    movdqu xmmword ptr [rsp+0B0h], xmm5
    mov  rcx, r10               ; id
    lea  rdx, [rsp+60h]         ; ctx: [0x00..5F]=xmm0-5, [0x60]=r11 [0x68]=r10
    call lanhook_log_hit        ; [0x70]=r9 [0x78]=r8 [0x80]=rdx [0x88]=rcx
    movdqu xmm0, xmmword ptr [rsp+60h]   ; [0x90]=rax [0x98]=original return address
    movdqu xmm1, xmmword ptr [rsp+70h]   ; ctx+0x98 == S and ctx[20..] == the
    movdqu xmm2, xmmword ptr [rsp+80h]   ; CALLER's stack, exactly as before the
    movdqu xmm3, xmmword ptr [rsp+90h]   ; snapshot was added (HK_WSET depends
    movdqu xmm4, xmmword ptr [rsp+0A0h]  ; on ctx[20..31] and ctx[25]).
    movdqu xmm5, xmmword ptr [rsp+0B0h]
    add  rsp, 0C0h
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
