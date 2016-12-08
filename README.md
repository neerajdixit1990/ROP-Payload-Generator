                  # ROP-Payload-Generator

										ROP Chain Compiler
									Krishnan V - 110284307
									Neeraj Dixit - 109951838

Introduction
-------------
- The program consists of python code file 'rop-generator.py' and a README
- The program builds a ROP chain which would make the stack executable in a
  binary
- This would help us achieve traditional exploits like buffer overflow and
  ret2libc
- The program options can be seen by the command 'python rop-generator.py -h'

Tools/softwares
----------------
1) Pyelf
	- It is a python library for parsing and analyzing ELF files
	- We used this library to read the code sections of binary files and
	  libraries
	- We used read the '.text' section and '.rodata' in binary files
	- The code of the binary lies in '.text', '.init', '.plt' & '.fini' section
2) Capstone
	- It is a multi-architecture disassembly framework
	- We used this framework to get the binary instructions in the text section

Approach
---------
- The aim of the ROP chain is to execute the 'mprotect' system call
- The address range on the stack is given as input address and read, write
  & execute permissions (i.e stack is made executable)
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
