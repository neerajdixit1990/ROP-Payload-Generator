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
    print('In file: ' + filename)
    with open(filename, 'rb') as f:
        # get the data
        elffile = ELFFile(f)
        print ('sections:')
        for s in elffile.iter_sections():
            __printSectionInfo(s)
        
	print ('get the code from the .text section')
        textSec = elffile.get_section_by_name(b'.text')
        
	# the text section
        startAddr = textSec.header['sh_addr']
        val = textSec.data()

	md = Cs(CS_ARCH_X86, CS_MODE_32)
	md.detail = True
	for i in md.disasm(val, startAddr):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
	
if __name__ == '__main__':
	#process_file('/lib/i386-linux-gnu/libc.so.6')
	process_file('../Offensive-Security/hw3/vuln3')
