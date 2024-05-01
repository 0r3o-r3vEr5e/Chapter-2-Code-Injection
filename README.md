# Problem

Ở [Chapter 1](https://hackmd.io/@0r3o/BJrxqpvc6), ta đã tìm hiểu về cấu trúc của một file PE (Portable Execution) và tiếp tục cho Chapter 2 tôi sẽ thực hiện lại kỹ thuật Code Injection. Cụ thể vấn đề của chúng ta như sau:

> Viết chương trình (C/C++) chèn vào một file exe bất kỳ một MessageBox "You've got infected". Sau khi hiện lên MessageBox đó thì chương trình tiếp tục chạy bình thường.
VD: Có file notepad.exe. Bạn viết chương trình để chèn vào file đó một đoạn code để khi chạy file notepad.exe thì nó sẽ bật MessageBox lên, sau khi ấn nút Ok trên MessageBox đó thì file notepad tiếp tục chạy như ban đầu.

Và kết quả mong muốn của vấn đề sẽ như dưới đây:

![](https://github.com/0r3o-r3vEr5e/Chapter-2-Code-Injection/blob/main/Result.gif)

# Explaination

Chương trình 

Chương trình `injected_calc.exe` của tôi đã được thực thi như sau: 
