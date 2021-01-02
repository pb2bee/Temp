import sys, os
import struct
from qiling import *
from idaapi import *
from idc import *
from idautils import *

func_size = 0
func_size_list = []

def show_func_size(ql:Qiling):
    func_size_bytes = bytes(ql.mem.read(ql.reg.read('RAX')+0x8, 0x4))
    func_size_str = hex(struct.unpack('<I', func_size_bytes)[0])
    print('Function size is -> '+func_size_str)
    global func_size
    func_size = int(func_size_str, 16)

def patch_to_ida(ql:Qiling):
    global func_size
    base_addr = ql.reg.read('RCX')
    print('Encode function from -> '+hex(base_addr)+' to -> '+hex(base_addr+func_size))
    enc_func_bytes_list = list(bytes(ql.mem.read(ql.reg.read('RCX'), func_size)))
    
    for i in range(func_size):
        patch_byte(base_addr+i, enc_func_bytes_list[i])    
    print('patch success')

def show_enc_func(ql:Qiling):
    global func_size, func_size_list
    base_addr = ql.reg.read('RCX')
    create_data(base_addr, byte_flag(), func_size, BADNODE)
    is_create_func = add_func(base_addr, base_addr+func_size)

    if not is_create_func:
        for i in range(func_size):
            del_items(base_addr+i)
        create_insn(base_addr)
        add_func(base_addr, base_addr+func_size)

    if 'Verify_' not in get_func_name(base_addr) and func_size not in set(func_size_list):
        set_name(base_addr, 'Verify_'+hex(base_addr), SN_CHECK)
        func_size_list.append(func_size)
    # jumpto(base_addr)

def force_jmp(ql:Qiling):
    ql.reg.write('RAX', 0x1)

def rewrite_mem(ql:Qiling):
    ql.mem.write(ql.reg.read('RAX'), b'a'*128)


class QILING_IDA():
    def __init__(self):
        pass

    def custom_prepare(self, ql:Qiling):
        ql.patch(0x403B2B, b'\xEB')                    # 1  force jump
        ql.patch(0x402F06, b'\x90\x90')                # 5  nop rcx
        ql.patch(0x403033, b'\x90'*5)                  # 5  nop _memcpy

        ql.hook_address(show_func_size, 0x402EA6)      # 4  get magic_table address == 0x605100
        ql.hook_address(patch_to_ida, 0x402F03)        # 5  patch decrypted opcode
        ql.hook_address(force_jmp, 0x402F08)           # 3  force jump to 0x402F70
        ql.hook_address(rewrite_mem, 0x403B3E)         # 2  fill input


    def custom_continue(self, ql:Qiling):
        hook = []
        hook.append(ql.hook_address(show_enc_func, 0x402F06)) # 6 create IDA function
        return hook

    def custom_step(self, ql:Qiling):
        hook = []
        return hook


# 400c55 -- Fibonacci
# 400e20 -- RC4
# 40111e -- cmp
# 40166e -- CRC32
# 40179d -- XOR
# 401a34 -- ROT13
# 4027a7 -- Base64