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

Kết quả sẽ giống như hình dưới

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Images/ASM.png)

