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

def find_gadgets(sectionData, startAddr):
    tmpList = sectionData.split("\xc3")
    idx = 0
    splitList = []
    for item in tmpList:
        if item != "":
            splitList.append(item)

    while idx < len(splitList): 
        splitList[idx] += "\xc3"
        idx += 1

    valOffset = 0
    for val in splitList:
        i = 0
        val_length = len(val)
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


def print_gadgets():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False 

    for gadget_addr in gadget_map:
        gadget = gadget_map[gadget_addr]
        instr_list = md.disasm(gadget, gadget_addr)
        out_str = format(gadget_addr, '#010x') + " : "
        for instr in instr_list:
            out_str += instr.mnemonic
            if instr.op_str != "":
                out_str += " " + instr.op_str
            out_str += " ; "
        print out_str

def print_unique_gadgets():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False

    for gadget_addr in unique_gadget_map:
        gadget = unique_gadget_map[gadget_addr]
        instr_list = md.disasm(gadget, gadget_addr)
        out_str = format(gadget_addr, '#010x') + " : "
        for instr in instr_list:
            out_str += instr.mnemonic
            if instr.op_str != "":
                out_str += " " + instr.op_str
            out_str += " ; "
        print out_str

def get_binary_instr(filename):
    with open(filename, 'rb') as f:
        # read fbinary file 
        elffile = ELFFile(f)
        '''
        textSec = elffile.get_section_by_name(b'.text')
        textStartAddr = textSec.header['sh_addr']
        textSection = textSec.data()
        find_gadgets(textSection, textStartAddr)
        '''

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

    #print_gadgets()
    #print str(len(gadget_map)) + " gadgets found." 
    print_unique_gadgets()
    print str(len(unique_gadget_map)) + " unique gadgets found." 

get_binary_instr("./vuln1")