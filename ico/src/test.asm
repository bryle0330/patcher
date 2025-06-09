%define MB_OK                  0
%define GENERIC_WRITE          40000000h
%define CREATE_ALWAYS          2
%define FILE_ATTRIBUTE_NORMAL  80h

BITS 32

extern __imp__MessageBoxA@16
extern __imp__CreateFileA@28
extern __imp__GetTickCount@0

section .text
global main
main:
    push    MB_OK
    push    msgTitle
    push    msgText
    push    0
    call    [__imp__MessageBoxA@16]     

    push    0
    push    FILE_ATTRIBUTE_NORMAL
    push    CREATE_ALWAYS
    push    0
    push    0
    push    GENERIC_WRITE
    push    txtName
    call    [__imp__CreateFileA@28]  

    push    eax
    call    [__imp__GetTickCount@0]     

    xor     eax, eax
    ret

section .rdata
msgText    db "Hello from ASM",0
msgTitle   db "ASM Test",0
txtName    db "test.txt",0
