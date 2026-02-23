; ==============================================================================
; Secure Morse Chat - x86-64 Assembly (NASM)
; Dependencies: libc, libcrypto (OpenSSL)
; Compile: nasm -f elf64 secure_morse.asm -o secure_morse.o
; Link: gcc secure_morse.o -lcrypto -no-pie -o secure_morse
; ==============================================================================

extern printf, fgets, stdin, stdout, fflush, strlen, strcmp, strtok, malloc, free, memcpy, memset
extern EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free, EVP_EncryptInit_ex, EVP_EncryptUpdate
extern EVP_EncryptFinal_ex, EVP_CIPHER_CTX_ctrl, EVP_DecryptInit_ex, EVP_DecryptUpdate
extern EVP_DecryptFinal_ex, EVP_aes_256_gcm

section .data
    ; --- 1. Morse Dictionary (Static Table) ---
    ; Struct: char (1 byte), padding (7 bytes), pointer to string (8 bytes)
    morse_table:
        db 'a', 0,0,0,0,0,0,0 : dq s_a
        db 'b', 0,0,0,0,0,0,0 : dq s_b
        db 'c', 0,0,0,0,0,0,0 : dq s_c
        db 'd', 0,0,0,0,0,0,0 : dq s_d
        db 'e', 0,0,0,0,0,0,0 : dq s_e
        db 'f', 0,0,0,0,0,0,0 : dq s_f
        db 'g', 0,0,0,0,0,0,0 : dq s_g
        db 'h', 0,0,0,0,0,0,0 : dq s_h
        db 'i', 0,0,0,0,0,0,0 : dq s_i
        db 'j', 0,0,0,0,0,0,0 : dq s_j
        db 'k', 0,0,0,0,0,0,0 : dq s_k
        db 'l', 0,0,0,0,0,0,0 : dq s_l
        db 'm', 0,0,0,0,0,0,0 : dq s_m
        db 'n', 0,0,0,0,0,0,0 : dq s_n
        db 'o', 0,0,0,0,0,0,0 : dq s_o
        db 'p', 0,0,0,0,0,0,0 : dq s_p
        db 'q', 0,0,0,0,0,0,0 : dq s_q
        db 'r', 0,0,0,0,0,0,0 : dq s_r
        db 's', 0,0,0,0,0,0,0 : dq s_s
        db 't', 0,0,0,0,0,0,0 : dq s_t
        db 'u', 0,0,0,0,0,0,0 : dq s_u
        db 'v', 0,0,0,0,0,0,0 : dq s_v
        db 'w', 0,0,0,0,0,0,0 : dq s_w
        db 'x', 0,0,0,0,0,0,0 : dq s_x
        db 'y', 0,0,0,0,0,0,0 : dq s_y
        db 'z', 0,0,0,0,0,0,0 : dq s_z
        db '0', 0,0,0,0,0,0,0 : dq s_0
        db '1', 0,0,0,0,0,0,0 : dq s_1
        db '2', 0,0,0,0,0,0,0 : dq s_2
        db '3', 0,0,0,0,0,0,0 : dq s_3
        db '4', 0,0,0,0,0,0,0 : dq s_4
        db '5', 0,0,0,0,0,0,0 : dq s_5
        db '6', 0,0,0,0,0,0,0 : dq s_6
        db '7', 0,0,0,0,0,0,0 : dq s_7
        db '8', 0,0,0,0,0,0,0 : dq s_8
        db '9', 0,0,0,0,0,0,0 : dq s_9
    morse_table_end:

    s_a db ".-", 0 : s_b db "-...", 0 : s_c db "-.-.", 0 : s_d db "-..", 0
    s_e db ".", 0  : s_f db "..-.", 0 : s_g db "--.", 0  : s_h db "....", 0
    s_i db "..", 0  : s_j db ".---", 0 : s_k db "-.-", 0  : s_l db ".-..", 0
    s_m db "--", 0  : s_n db "-.", 0   : s_o db "---", 0  : s_p db ".--.", 0
    s_q db "--.-", 0: s_r db ".-.", 0  : s_s db "...", 0  : s_t db "-", 0
    s_u db "..-", 0 : s_v db "...-", 0 : s_w db ".--", 0  : s_x db "-..-", 0
    s_y db "-.--", 0: s_z db "--..", 0 : s_0 db "-----", 0: s_1 db ".----", 0
    s_2 db "..---", 0: s_3 db "...--", 0: s_4 db "....-", 0: s_5 db ".....", 0
    s_6 db "-....", 0: s_7 db "--...", 0: s_8 db "---..", 0: s_9 db "----.", 0

    ; UI Strings
    msg_title      db "Secure Morse Chat", 10, 0
    msg_key_gen    db " Session key generated (hidden)", 10, 0
    msg_sep        db "----------------------------------------", 10, 0
    msg_menu       db 10, "1️⃣ Encrypt text → Morse", 10, "2️⃣ Decrypt Morse → text", 10, "3️⃣ Exit", 10, "Choose: ", 0
    msg_enter_txt  db "Enter text: ", 0
    msg_enter_mor  db "Enter Morse: ", 0
    msg_out_morse  db 10, "Encrypted Morse:", 10, "%s", 10, 0
    msg_out_text   db 10, "Decrypted text:", 10, "%s", 10, 0
    msg_err_morse  db "Invalid Morse or wrong session!", 10, 0
    msg_exit       db "Session ended. Key destroyed.", 10, 0
    msg_invalid    db "Invalid choice", 10, 0
    fmt_s          db "%s", 0
    hex_chars      db "0123456789abcdef", 0
    space_delim    db " ", 10, 13, 0

section .bss
    session_key    resb 32
    input_buffer   resb 1024
    crypto_buffer  resb 2048
    hex_buffer     resb 4096
    morse_buffer   resb 8192

section .text
global main

; ========================
; 2️⃣ AES encryption
; ========================

; generate_key() -> fills session_key with 32 random bytes
generate_key:
    mov rax, 318    ; sys_getrandom
    mov rdi, session_key
    mov rsi, 32
    mov rdx, 0
    syscall
    ret

; encrypt_text(text: rdi, key: rsi, out: rdx)
; Internal logic: [Nonce(12)][Ciphertext(N)][Tag(16)]
encrypt_text:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    
    mov r12, rdi ; text
    mov r13, rdx ; out_buffer
    
    ; 1. Generate Nonce (12 bytes)
    mov rax, 318
    mov rdi, r13
    mov rsi, 12
    mov rdx, 0
    syscall

    ; 2. Initialize OpenSSL EVP
    call EVP_CIPHER_CTX_new
    mov rbx, rax ; ctx

    call EVP_aes_256_gcm
    mov rdi, rbx
    mov rsi, rax
    xor rdx, rdx
    xor rcx, rcx
    xor r8, r8
    call EVP_EncryptInit_ex

    ; Set nonce length (12)
    mov rdi, rbx
    mov rsi, 2 ; EVP_CTRL_GCM_SET_IVLEN
    mov rdx, 12
    xor rcx, rcx
    call EVP_CIPHER_CTX_ctrl

    ; Set Key and Nonce
    call EVP_aes_256_gcm
    mov rdi, rbx
    mov rsi, 0
    mov rdx, session_key
    mov rcx, r13 ; nonce is at start of out_buffer
    call EVP_EncryptInit_ex

    ; Encrypt Update
    mov rdi, r12
    call strlen
    mov rdx, rax ; input len
    
    mov rdi, rbx
    lea rsi, [r13 + 12] ; output after nonce
    lea rcx, [rbp - 24] ; outlen ptr
    mov r8, r12 ; input
    call EVP_EncryptUpdate
    
    mov r14d, [rbp - 24] ; save ciphertext len

    ; Final
    mov rdi, rbx
    lea rsi, [r13 + 12 + r14]
    lea rdx, [rbp - 24]
    call EVP_EncryptFinal_ex

    ; Get Tag (16 bytes)
    mov rdi, rbx
    mov rsi, 16 ; EVP_CTRL_GCM_GET_TAG
    mov rdx, 16
    lea rcx, [r13 + 12 + r14]
    call EVP_CIPHER_CTX_ctrl

    ; Total length = 12 + r14 + 16
    add r14, 28
    mov rax, r14 ; return total size

    mov rdi, rbx
    call EVP_CIPHER_CTX_free
    
    pop r13
    pop r12
    pop rbx
    leave
    ret

; decrypt_text(data: rdi, len: rsi, key: rdx, out: rcx)
decrypt_text:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov [rbp-8], rdi  ; data
    mov [rbp-16], rsi ; len
    mov [rbp-24], rcx ; out_buffer

    cmp rsi, 28 ; Minimum 12(nonce) + 16(tag)
    jl .decrypt_fail

    call EVP_CIPHER_CTX_new
    mov rbx, rax

    call EVP_aes_256_gcm
    mov rdi, rbx
    mov rsi, rax
    xor rdx, rdx
    xor rcx, rcx
    call EVP_DecryptInit_ex

    ; Set IV length
    mov rdi, rbx
    mov rsi, 2
    mov rdx, 12
    xor rcx, rcx
    call EVP_CIPHER_CTX_ctrl

    ; Set Key and Nonce (Nonce is first 12 bytes of data)
    call EVP_aes_256_gcm
    mov rdi, rbx
    mov rsi, 0
    mov rdx, session_key
    mov rcx, [rbp-8]
    call EVP_DecryptInit_ex

    ; Decrypt Update
    ; Ciphertext length = Total - 12 (nonce) - 16 (tag)
    mov r14, [rbp-16]
    sub r14, 28
    
    mov rdi, rbx
    mov rsi, [rbp-24] ; out
    lea rdx, [rbp-32] ; outlen ptr
    mov r8, [rbp-8]
    add r8, 12       ; ciphertext start
    mov rcx, r14     ; ciphertext len
    call EVP_DecryptUpdate

    ; Set expected Tag (Tag is last 16 bytes)
    mov rdi, rbx
    mov rsi, 17      ; EVP_CTRL_GCM_SET_TAG
    mov rdx, 16
    mov rcx, [rbp-8]
    add rcx, [rbp-16]
    sub rcx, 16      ; Tag start
    call EVP_CIPHER_CTX_ctrl

    ; Final (Verifies Tag)
    mov rdi, rbx
    mov rsi, [rbp-24]
    mov r15, [rbp-32]
    add rsi, r15
    lea rdx, [rbp-32]
    call EVP_DecryptFinal_ex
    
    test rax, rax
    jz .decrypt_fail

    ; Null terminate
    mov rdi, [rbp-24]
    add rdi, r15
    mov byte [rdi], 0
    
    mov rax, r15
    jmp .dec_end

.decrypt_fail:
    xor rax, rax
.dec_end:
    mov rdi, rbx
    call EVP_CIPHER_CTX_free
    leave
    ret

; ========================
; 3️⃣ Helper functions
; ========================

; bytes_to_hex(in: rdi, len: rsi, out: rdx)
bytes_to_hex:
    xor rcx, rcx
.loop:
    cmp rcx, rsi
    je .done
    movzx rax, byte [rdi + rcx]
    mov rbx, rax
    shr rax, 4
    and rbx, 0x0F
    mov al, [hex_chars + rax]
    mov bl, [hex_chars + rbx]
    mov [rdx], al
    mov [rdx + 1], bl
    add rdx, 2
    inc rcx
    jmp .loop
.done:
    mov byte [rdx], 0
    ret

; hex_to_bytes(in: rdi, out: rsi) -> rax = len
hex_to_bytes:
    xor rdx, rdx
.loop:
    movzx rax, byte [rdi]
    test al, al
    jz .done
    
    ; First nibble
    sub al, '0'
    cmp al, 9
    jbe .n1
    sub al, 39 ; 'a' - '0' = 49, 49-39=10
.n1:
    shl al, 4
    mov bl, al
    
    inc rdi
    movzx rax, byte [rdi]
    sub al, '0'
    cmp al, 9
    jbe .n2
    sub al, 39
.n2:
    or bl, al
    mov [rsi + rdx], bl
    
    inc rdi
    inc rdx
    jmp .loop
.done:
    mov rax, rdx
    ret

; bytes_to_morse(hex: rdi, out: rsi)
bytes_to_morse:
    push rbx
    mov rbx, rsi
.char_loop:
    movzx rax, byte [rdi]
    test al, al
    jz .done
    
    ; Find in table
    mov r8, morse_table
.table_search:
    cmp byte [r8], al
    je .found
    add r8, 16
    jmp .table_search
.found:
    mov rsi, [r8 + 8] ; string ptr
.copy_morse:
    movzx rax, byte [rsi]
    test al, al
    jz .space
    mov [rbx], al
    inc rsi
    inc rbx
    jmp .copy_morse
.space:
    mov byte [rbx], ' '
    inc rbx
    inc rdi
    jmp .char_loop
.done:
    dec rbx
    mov byte [rbx], 0
    pop rbx
    ret

; morse_to_bytes(morse: rdi, out: rsi) -> rax (1=ok, 0=err)
morse_to_bytes_helper:
    push rbx
    push r12
    push r13
    mov r12, rdi ; input morse
    mov r13, rsi ; hex output buffer
    
    mov rdi, r12
    mov rsi, space_delim
    call strtok
    mov rbx, rax
.token_loop:
    test rbx, rbx
    jz .finish
    
    ; Lookup char by morse string
    mov r8, morse_table
.search_table:
    mov rdi, rbx
    mov rsi, [r8 + 8]
    call strcmp
    test rax, rax
    jz .found_char
    add r8, 16
    cmp r8, morse_table_end
    jae .error
    jmp .search_table
.found_char:
    mov al, [r8]
    mov [r13], al
    inc r13
    
    mov rdi, 0
    mov rsi, space_delim
    call strtok
    mov rbx, rax
    jmp .token_loop
.finish:
    mov byte [r13], 0
    mov rax, 1
    jmp .end
.error:
    xor rax, rax
.end:
    pop r13
    pop r12
    pop rbx
    ret

; ========================
; 4️⃣ Main loop
; ========================
main:
    push rbp
    mov rbp, rsp

    call generate_key

    ; Welcome message
    mov rdi, msg_title
    xor rax, rax
    call printf
    mov rdi, msg_key_gen
    call printf
    mov rdi, msg_sep
    call printf

.menu_loop:
    mov rdi, msg_menu
    xor rax, rax
    call printf
    
    mov rdi, [stdout]
    call fflush

    ; Read choice
    mov rdi, input_buffer
    mov rsi, 1024
    mov rdx, [stdin]
    call fgets
    
    mov al, [input_buffer]
    cmp al, '1'
    je .do_encrypt
    cmp al, '2'
    je .do_decrypt
    cmp al, '3'
    je .do_exit
    
    mov rdi, msg_invalid
    call printf
    jmp .menu_loop

.do_encrypt:
    mov rdi, msg_enter_txt
    xor rax, rax
    call printf
    mov rdi, [stdout]
    call fflush

    mov rdi, input_buffer
    mov rsi, 1024
    mov rdx, [stdin]
    call fgets
    
    ; Trim newline
    mov rdi, input_buffer
    call strlen
    mov byte [input_buffer + rax - 1], 0

    ; Encrypt
    mov rdi, input_buffer
    mov rsi, session_key
    mov rdx, crypto_buffer
    call encrypt_text
    
    ; Bytes -> Hex
    mov rdi, crypto_buffer
    mov rsi, rax
    mov rdx, hex_buffer
    call bytes_to_hex
    
    ; Hex -> Morse
    mov rdi, hex_buffer
    mov rsi, morse_buffer
    call bytes_to_morse
    
    mov rdi, msg_out_morse
    mov rsi, morse_buffer
    xor rax, rax
    call printf
    jmp .menu_loop

.do_decrypt:
    mov rdi, msg_enter_morse
    xor rax, rax
    call printf
    mov rdi, [stdout]
    call fflush

    mov rdi, input_buffer
    mov rsi, 1024
    mov rdx, [stdin]
    call fgets

    ; Morse -> Hex (stored in hex_buffer)
    mov rdi, input_buffer
    mov rsi, hex_buffer
    call morse_to_bytes_helper
    test rax, rax
    jz .dec_err
    
    ; Hex -> Bytes
    mov rdi, hex_buffer
    mov rsi, crypto_buffer
    call hex_to_bytes
    
    ; Decrypt
    mov rdi, crypto_buffer
    mov rsi, rax
    mov rdx, session_key
    mov rcx, input_buffer ; reuse for decrypted text
    call decrypt_text
    test rax, rax
    jz .dec_err
    
    mov rdi, msg_out_text
    mov rsi, input_buffer
    xor rax, rax
    call printf
    jmp .menu_loop

.dec_err:
    mov rdi, msg_err_morse
    call printf
    jmp .menu_loop

.do_exit:
    ; Rust's "Key destroyed" (Clear memory)
    mov rdi, session_key
    xor rsi, rsi
    mov rdx, 32
    call memset
    
    mov rdi, msg_exit
    xor rax, rax
    call printf
    
    xor rax, rax
    leave
    ret

section .rodata
    msg_enter_morse db "Enter Morse: ", 0
