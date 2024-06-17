# Problem

Ở [Chapter 1](https://hackmd.io/@0r3o/BJrxqpvc6), ta đã tìm hiểu về cấu trúc của một file PE (Portable Execution) và tiếp tục cho Chapter 2 tôi sẽ thực hiện lại kỹ thuật Code Injection. Cụ thể vấn đề của chúng ta như sau:

> Viết chương trình (C/C++) chèn vào một file exe bất kỳ một MessageBox "You've got infected". Sau khi hiện lên MessageBox đó thì chương trình tiếp tục chạy bình thường.
VD: Có file notepad.exe. Bạn viết chương trình để chèn vào file đó một đoạn code để khi chạy file notepad.exe thì nó sẽ bật MessageBox lên, sau khi ấn nút Ok trên MessageBox đó thì file notepad tiếp tục chạy như ban đầu.

Và kết quả mong muốn của vấn đề sẽ như dưới đây:

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/GIF/Result.gif)

# Explaination

Chương trình `calc.exe` gốc sẽ có các thông số đáng chú ý như sau: 

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/OEP.png)

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/Old%20SectionHeaders.png)

Chương trình `injected_calc.exe` của tôi đã được thực thi như sau: 

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/New%20EP.png)

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/New%20SectionHeaders.png)

> Tôi đã thêm một Section mới vào trong file và thay đổi `AddressOfEntryPoint` để có khi khởi động, chương trình sẽ thực thi code ở trong section này trước khi trở về code ở vị trí ban đầu. Từ đây ta có thể biết được các bước cần phải thực hiện để giải quyết vấn đề:
> 
> * Thêm một section mới vào cuối file
> * Thêm code vào trong section 
> * Thay đổi địa chỉ của EntryPoint trỏ đến section này

# Demo

Trước khi code bằng C/C++, tôi đã thực hiện điều này một cách thủ công:

## Bước 1

Tại CFF Explore, thêm vào một section mới với size 1000h rồi đặt tên là `.newsec`, thay đổi các quyển cần thiết và đổi `AddressOfEntryPoint` thành `VirtualAdress` của Section này

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/AddSection.png)

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/New%20SectionHeaders.png)

## Bước 2

Tại OLLYDBG, mở file và dùng tổ hợp phím `Alt + M` để mở cửa số Memory Map của chương trình, tìm địa chỉ của section `.newsec` mà ta vừa thêm vào. Select section này là dùng phím `F7` để truy cập vào trong. Tại đây, ta chọn 2 vùng trống và thay đổi nội dung của nó bằng tổ hợp `Ctrl + E` để ta thêm 2 đoạn strings cần hiển thị trên MessageBox (ghi nhớ địa chỉ của 2 đoạn string này) rồi quay về dòng đầu tiên và bằng đầu viết một đoạn code sau:
```ASM
PUSH 0
PUSH 101F030 ; Title String Address
PUSH 101F050 ; Caption String Address
PUSH 0
CALL MessageBoxA
JMP 1012475 ; Jump back to OEP
```

Kết quả sẽ giống như hình dưới (nhấn vào ảnh để xem thêm)

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/ASM.png)

Để rõ hơn những thay đổi của file mới so với file gốc thì ta sẽ dùng PE-bear để so sánh sự khác biệt giữa chúng

* File Header

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/FileHeaderDiff.png)

`NumberOfSections`: `0x00000003` -> `0x00000004`

* Optional Header

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/OptionalHeaderDiff.png)

`AddressOfEntryPoint`: `0x00012475` -> `0x0001F000`

`ImageSize`: `0x0001F000` -> `0x00020000`

* Section Content

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/SectionContent.png)

_Code của ta cần làm được những điều sau:_

_* Tạo một section mới trong file PE_

_* Thêm shellcode vào trong section đó (đoạn code này sau khi thực thi xong sẽ thực hiện lại đoạn code gốc)_

_* Thay đổi giá trị `AddressOfEntryPoint` trỏ đến Section vừa tạo_

# Code (C/C++)

## Add New Section

Trước khi thực hiện việc thêm một section mới, ta cần thực hiện căn chỉnh cho Section mới để sau khi thêm Section này mà không làm lỗi file. Khi ta thêm section mới trên CFF Explorer, việc căn chỉnh này đã được làm tự động nhưng khi code ta cần tự làm điều này.

> `VirtualAddress` là bội số của `SectionAlignment`
> 
> `RawSize` là bội số của `FileAlignment`

Vì thế ta cần một hàm có thể thực hiện căn chỉnh file theo đúng những gì mà ta mong muốn

```Cpp
// Utility function to align a value up to the nearest multiple of 'alignment'.
DWORD AlignUp(DWORD size, DWORD alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}
```

Sau khi có được hàm `AlignUp` để căn chỉnh, ta có thể thực hiện việc thêm một section mới và thay đổi các giá trị cho các trường của `IMAGE_SECTION_HEADER` một cách hợp lý.

```Cpp
#define NEW_SECTION_NAME ".newsec"
#define NEW_SECTION_SIZE 0x1000

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
    // 0xE0000E0: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA

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
```

## Add Code Into New Section

Theo nội dung của Section mới, ta thấy được đoạn shellcode như sau:

```shellcode
0x6A 0x00                        (PUSH 0)
0x68 0x30 0xF0 0x01 0x00         (PUSH 0x101F030)
0x68 0x50 0xF0 0x01 0x00         (PUSH 0x101F030)
0x6A 0x00                        (PUSH 0)
0xE8 0x2D 0xBE 0x88 0x75         (CALL 0x7588BE2D)
0xE9 0x5D 0x34 0xFF 0xFF         (JMP 0x1012475)
```

Tuy nhiên khi code ta cần phải tính toán lại địa chỉ để code có thể hoạt động trên các file khác nhau vì thế đoạn shellcode chung sẽ như sau:

```Cpp
char shellCode[] = 
    "\x6A\x00"                  // PUSH 0
    "\x68\x00\x00\x00\x00"      // PUSH "Injected Calculator"
    "\x68\x00\x00\x00\x00"      // PUSH "You've got infected"
    "\x6A\x00"                  // PUSH 0
    "\xE8\x00\x00\x00\x00"      // CALL USER32.MessageBoxA
    "\xE9\x00\x00\x00\x00";     // JMP 1012475
```

Đầu tiên ta cần đưa 2 đoạn string mà ta cần vào trong section tại một địa chỉ nhất định rồi sau đó thay đổi shellcode để lấy được 2 strings dựa vào địa chỉ của chúng

```Cpp
HANDLE hFile;
HANDLE hFileMapping;
LPVOID lpFileBase;
PIMAGE_DOS_HEADER dosHeader;
PIMAGE_NT_HEADERS ntHeaders;
PIMAGE_SECTION_HEADER sectionHeader;

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

char shellCode[] = 
    "\x6A\x00"                  // PUSH 0
    "\x68\x00\x00\x00\x00"      // PUSH "Injected Calculator"
    "\x68\x00\x00\x00\x00"      // PUSH "You've got infected"
    "\x6A\x00"                  // PUSH 0
    "\xE8\x00\x00\x00\x00"      // CALL USER32.MessageBoxA
    "\xE9\x00\x00\x00\x00";     // JMP 1012475

// Calculate the offset and size for the new data with added the section
const char* titleStr = "Code Injector";
DWORD titleOffset = 0x30;
const char* captionStr = "You've got infected";
DWORD captionOffset = 0x50;

// Append the strings into section (+1 at strlen() since both strings are null-terminated strings)
memcpy((PBYTE)lpFileBase + sectionHeader->PointerToRawData + titleOffset, titleStr, strlen(titleStr) + 1);
memcpy((PBYTE)lpFileBase + sectionHeader->PointerToRawData + captionOffset, captionStr, strlen(captionStr) + 1);

// Edit shellcode with 2 added strings
*(DWORD*)(shellCode + 3) = sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.ImageBase + titleOffset;
*(DWORD*)(shellCode + 8) = sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.ImageBase + captionOffset;
```

Vì lệnh CALL sẽ gọi đến địa chỉ tương đối (Relative Address) của một hàm nên trong khi debug ta sẽ thấy địa chỉ trên shellcode là 0x761FBE2D. Địa chỉ này được tính như sau:

> Địa chỉ tương đối = Địa chỉ của hàm - Địa chỉ của lệnh tiếp theo

Vì thế, ta cần một hàm có thể lấy được địa chỉ của hàm ta cần gọi (trong trường hợp này là hàm `MessageBoxA()`)

```Cpp
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
```

Còn địa chỉ lệnh tiếp theo là địa chỉ của lệnh sau lệnh CALL. Như vậy là ta có thể tính được địa chỉ của lệnh tiếp theo như sau:

```Cpp
DWORD messageBoxARVA = GetMessageBoxAAddress() - (sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.ImageBase + 19);
*(DWORD*)(shellCode + 15) = messageBoxARVA;
```

Tương tự như lệnh CALL, địa chỉ trong lệnh JMP cũng là một địa chỉ tương đối với cách tính như sau

> Địa chỉ đích = Địa chỉ của lệnh tiếp theo + Địa chỉ tương đối

Rồi ta cũng cần một hàm để tính được địa chỉ tương đối này như sau:

```Cpp
DWORD calculateJMPAdress(DWORD instructionAddress, DWORD targetAddress) {
    if (targetAddress >= instructionAddress) {
        return targetAddress - instructionAddress;
    }
    else {
        return (0xFFFFFFFF - instructionAddress) + targetAddress + 1;
    }
}
```

Cuối cùng, ta đã có thể tạo ra một shellcode hoàn chỉnh và thêm shellcode vào section cùng với việc đổi `OEP` theo địa chỉ của section là vấn đề của chúng ta đã hoàn thành.

```Cpp
DWORD nextJMPAddress = sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.ImageBase + sizeof(shellCode) - 1;
DWORD oldOEP = ntHeaders->OptionalHeader.ImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
DWORD jmpRVA = calculateJMPAdress(nextJMPAddress, oldOEP);
*(DWORD*)(shellCode + 20) = jmpRVA;
memcpy((PBYTE)lpFileBase + sectionHeader->PointerToRawData, shellCode, sizeof(shellCode));
ntHeaders->OptionalHeader.AddressOfEntryPoint = sectionHeader->VirtualAddress;
```

Source code đầy đủ [tại đây](https://github.com/0r3o-r3vEr5e/Episode-2-PE-Code-Injector/blob/main/Code/Chapter_1.cpp)
