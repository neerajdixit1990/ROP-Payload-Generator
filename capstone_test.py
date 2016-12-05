from capstone import *
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
import argparse
import struct
import subprocess
import os
import io

gadget_map = {}
unique_gadget_map = {}
disassembled_map = {}
register_list = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"]


def find_gadgets(sectionData, startAddr):
    retCount = sectionData.count("\xc3")
    if retCount == 0:
        return
    splitList = sectionData.split("\xc3")
    idx = 0

    while idx < len(splitList) - 1: 
        splitList[idx] += "\xc3"
        idx += 1

    valOffset = 0
    for val in splitList:
        i = 0
        val_length = len(val)
        if val_length > 10:
            i = val_length - 10
        while i < val_length:
            gadget_map[startAddr + valOffset + i] = val[i:val_length]
            i += 1
        valOffset += val_length

    for gadget_addr in gadget_map:
        if gadget_map[gadget_addr] not in unique_gadget_map.values():
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.detail = False
            endWithRet = False
            discardGadget = False
            gadget = gadget_map[gadget_addr]
            instr_list = md.disasm(gadget, gadget_addr)
            n_bytes = len(gadget)
            byte_count = 0
            i = 0
            if instr_list is None:
                continue
            for instr in instr_list:
                i += 1
                byte_count += instr.size
                if (instr.mnemonic == "ret") and (instr.op_str == "") and (byte_count == n_bytes):
                    endWithRet = True
                if (instr.mnemonic == "call") or (instr.mnemonic == "leave") or (instr.mnemonic[0] == 'j'):
                    discardGadget = True
                    break
                if (instr.mnemonic == "ret") and (instr.op_str != ""):
                    discardGadget = True
                    break
            if (discardGadget is False) and (n_bytes == byte_count) and (n_bytes > 1) and (endWithRet is True):
                unique_gadget_map[gadget_addr] = gadget_map[gadget_addr]


def build_disassembled_gadgets_map(gadgetMap):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False 

    for gadget_addr in gadgetMap:
        gadget = gadgetMap[gadget_addr]
        instr_list = md.disasm(gadget, gadget_addr)
        disassembled_map[gadget_addr] = instr_list

def print_gadgets(gadgetMap):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False 

    for gadget_addr in gadgetMap:
        gadget = gadgetMap[gadget_addr]
        instr_list = md.disasm(gadget, gadget_addr)
        out_str = format(gadget_addr, '#010x') + " : "
        for instr in instr_list:
            out_str += instr.mnemonic
            if instr.op_str != "":
                out_str += " " + instr.op_str
            out_str += " ; "
        print out_str


def is_forbidden_register(op_str, restricted_reg_list):
    for reg in restricted_reg_list:
        if op_str.count(reg) > 0:
            return True
    return False

def find_pop_ret(gadgetMap, count, restricted_reg_list):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        pop_count = 0
        for instr in instr_list:
            if (instr.mnemonic != "pop") and (instr.mnemonic != "ret"):
                break
            if is_forbidden_register(instr.op_str, restricted_reg_list) is True:
                break
            if instr.mnemonic == "pop":
                pop_count += 1
            if instr.mnemonic == "ret":
                if pop_count == count:
                    return gadget_addr
                break

    return 0

def find_xor_zero(gadgetMap, restricted_reg_list):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        xorFound = False
        for instr in instr_list:
            if (instr.mnemonic != "xor") and (instr.mnemonic != "ret"):
                break
            if is_forbidden_register(instr.op_str, restricted_reg_list) is True:
                break
            if (instr.mnemonic == "xor"):
                for reg in register_list:
                    if instr.op_str.count(reg) == 2:
                        xorFound = True
            if instr.mnemonic == "ret" and xorFound is True:
                    return gadget_addr

    return 0

def get_binary_instr(filename):
    with open(filename, 'rb') as f:
        # read fbinary file 
        elffile = ELFFile(f)

        if filename.count(".so") == 1:
            textSec = elffile.get_section_by_name(b'.text')
            textStartAddr = textSec.header['sh_addr']
            textSection = textSec.data()
            find_gadgets(textSection, textStartAddr)

        else:
            initSec = elffile.get_section_by_name(b'.init')
            initStartAddr = initSec.header['sh_addr']
            initSection = initSec.data()
            find_gadgets(initSection, initStartAddr)

            pltSec = elffile.get_section_by_name(b'.plt')
            pltStartAddr = pltSec.header['sh_addr']
            pltSection = pltSec.data()
            find_gadgets(pltSection, pltStartAddr)

            textSec = elffile.get_section_by_name(b'.text')
            textStartAddr = textSec.header['sh_addr']
            textSection = textSec.data()
            find_gadgets(textSection, textStartAddr)

            finiSec = elffile.get_section_by_name(b'.fini')
            finiStartAddr = finiSec.header['sh_addr']
            finiSection = finiSec.data()
            find_gadgets(finiSection, finiStartAddr)

    build_disassembled_gadgets_map(unique_gadget_map)
    print_gadgets(unique_gadget_map)
    print str(len(unique_gadget_map)) + " unique gadgets found." 

    print hex(find_pop_ret(disassembled_map, 3, []))
    print hex(find_xor_zero(disassembled_map, []))
#/lib/ld-linux.so.2
#mprotect-shellcode/vuln2
#/lib/i386-linux-gnu/libc.so.6
get_binary_instr("/lib/i386-linux-gnu/libc.so.6")