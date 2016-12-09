                  # ROP-Payload-Generator

										ROP Chain Compiler
									Krishnan V - 110284307
									Neeraj Dixit - 109951838

Introduction
-------------
- The submission consists of a python code file 'rop-generator.py' and a README
- The program builds a ROP chain which would make the stack executable in a
  binary
- The program options can be seen by the command 'python rop-generator.py -h'

usage: python rop-generator.py [-h] [-lib LIB] [-t]

-lib is used to specify one or more libraries to extract gadgets from.
-t option is used to specify whether to run the payload in a test vulnerable program.
If -t is not specified, all the found gadgets will be printed. 
Otherwise, the rop payload will be run in a test program which will first make the stack 
executable and then execute a secondary shellcode to invoke /bin/sh.

Tools/softwares
----------------
1) Pyelf
	- It is a python library for parsing and analyzing ELF files
	- We used this library to read the code sections of binary files and
	  libraries
	- We used read the '.text' section and '.rodata' in binary files
	- The code of the binary lies in '.text', '.init', '.plt' & '.fini' section
	 and those of libraries lie in the '.text' section.
2) Capstone
	- It is a multi-architecture disassembly framework
	- We used this framework to disassemble the bytes in the text section

Approach
---------
- The aim of the ROP chain is to execute the 'mprotect' system call
- mprotect takes three arguments - the page aligned address, length of the memory whose
  permission needs to be changed and, the permissions (7 for read + write + execute)
  The page aligned address has null (0x00) as its first byte (in little endian notation).
  Also, the length and permissions have null bytes in them as well.
  The gadgets we find overcomes the nul byte restrictions and manages to execute mprotect.
- We have two approaches to do this :
  a) Put the arguments on the stack replacing the null bytes with some other byte (say 0xff).
     Chain a series of strcpy functions and their arguments to replace these dummy bytes with
     null at runtime. The source null byte for strcpy is obtained from the '.rodata' section.
     Once all the null bytes are inserted at the appropriate locations, invoke mprotect libc
     function. This method assumes the presence of libc.
  b) This second approach does not make use of any libc functions. It involves finding the
     necessary gadgets to invoke the mprotect system call. The syscall number (0x7d) must
     be put in the register eax, the page aligned address in ebx, length in ecx and the
     permissions in edx.
- The payload in the buffer is also given a sample shell code which spawns a
  shell process (/bin/bash, /bin/sh)

Finding ROP Gadgets
--------------------
- Gadgets are any sequence of instructions which end with a 'ret'
  (or opcode 'c3')
- Capstone disassembler does NOT account for unaligned gadgets if we pass the
  address of '.text' section directly
- To solve this issue we partition the raw bytes of .text section with 'c3'
  delimiter
- This way we divide the binary instructions into sections between 2 rets
- We consider only 10 bytes before the ending ret to find out gadgets as
  higher depth consume more time for finding gadgets in large binaries
  (like libc)
- These gadgets are later picked up by ROP chain algorithm to assemble on the
  stack

ROP Payload
------------

References
----------
http://www.capstone-engine.org/lang_python.html
http://stackoverflow.com/questions/24997541/getting-the-memory-layout-out-of-an-avrelf-file-by-useing-python-pyelftools
