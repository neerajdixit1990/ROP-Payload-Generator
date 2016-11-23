from capstone import *
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
import argparse
import struct 
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
        print 'Found 3 pop ret at address 0x%x' %(instr_list[temp_index].address)
        return instr_list[temp_index].address
    else:
        print '3 pop gadget not found !'
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
        print 'Found 2 pop ret at address 0x%x: %s' %(instr_list[temp_index].address, instr_list[temp_index].mnemonic)
        return instr_list[temp_index].address
    else:
        print '2 pop gadget not found !'
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
	#process_file('/lib/i386-linux-gnu/libc.so.6')
	#process_file('../Offensive-Security/hw3/vuln3')

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
            lib_list.append((instr, ret))

    instr, ret = get_binary_instr(args.vuln_bin)
    if instr == None or ret == None:
        print '%s binary not present !' %(args.vuln_bin)
        exit(2)
    lib_list.append((instr, ret))
   
    for entry in lib_list:
        print 'Found %d instructions with %d rets' %(len(entry[0]), len(entry[1]))
 
    pop_pop_ret_addr = None
    for entry in lib_list:
        instr = entry[0]
        ret = entry[1]
        
        if instr == None or ret == None:
            print 'Inconsistent data for libraries !'
            exit(3)

        result = find_2pop_ret(instr, ret)
        if result != None:
            pop_pop_ret_addr = result
            break

    if pop_pop_ret_addr == None:
        print 'Unable to find gadget with 2 pops !'
        exit(3)

    pop_pop_pop_ret_addr = None
    for entry in lib_list:
        instr = entry[0]
        ret = entry[1]

        if instr == None or ret == None:
            print 'Inconsistent data for libraries !'
            exit(4)

        result = find_3pop_ret(instr, ret)
        if result != None:
            pop_pop_pop_ret_addr = result
            break

    if pop_pop_pop_ret_addr == None:
        print 'Unable to find gadget with 3 pops !'
        exit(4)

