from capstone import *
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile

# 128k flash for the ATXmega128a4u
flashsize = 128 * 1024


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

def process_file(filename):
    with open(filename, 'rb') as f:
        # read fbinary file 
        elffile = ELFFile(f)
        for s in elffile.iter_sections():
            __printSectionInfo(s)
        
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

	print 'Found %d instructions with %d rets in binary %s' %(count, len(ret_index), filename)
	'''
	for instr in ret_index:
		print("0x%x:\t%s\t%s" %(instr_list[instr].address, instr_list[instr].mnemonic, instr_list[instr].op_str))
	'''

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
	else:
		print '3 pop gadget not found !'
	
	
if __name__ == '__main__':
	#process_file('/lib/i386-linux-gnu/libc.so.6')
	process_file('../Offensive-Security/hw3/vuln3')