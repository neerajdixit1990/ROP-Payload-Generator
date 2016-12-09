
						ROP Chain Compiler
						Krishnan V - 110284307
						Neeraj Dixit - 109951838

Introduction
-------------
- The submission consists of a python code file 'rop-generator.py' and a README
- The program builds a ROP chain which would make the stack executable in a
  binary and then execute a secondary shellcode to invoke /bin/sh
- The program options can be seen by the command 'python rop-generator.py -h'

  usage: python rop-generator.py [-h] [-lib LIB] [-t]

- lib is used to specify one or more libraries to extract gadgets from.
- t option is used to specify whether to run the payload in a test vulnerable program.
- If -t is not specified, all the found gadgets will be printed. 

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
- Stack frame layout is as follows:
  | &mprotect | <addr_of_pop_pop_pop_ret_gadget> | <page_aligned_addr> | <length> | <permissions_rwx> | <addr_of_shellcode>
- The page aligned address has null (0x00) as its first byte (in little endian notation).
  Also, the length and permissions have null bytes in them as well.
  The gadgets we find overcomes the NULL byte restrictions and execute mprotect.
- We have two approaches to do this :
  a) Put the arguments on the stack replacing the null bytes with some other byte (say 0xff).
     Chain a series of strcpy functions and their arguments to replace these dummy bytes with
     null at runtime. The source null byte for strcpy is obtained from the '.rodata' section.
  b) Insert syscall number (0x7d) must be put in the register eax, the page aligned address in
     ebx, length in ecx and the permissions in edx. We invoke the system call using int 0x80 or
     call dword ptr gs:[0x10]
- We use the above mentioned approaches using 4 stack frame layouts (mentioned in 'ROP Payload')
- The payload in the buffer is also given a sample shell code which spawns a
  shell process (/bin/bash, /bin/sh)

Finding ROP Gadgets
--------------------
- Gadgets are any sequence of instructions which end with a 'ret'
  (or the byte 'c3')
- Capstone disassembler does not account for unaligned gadgets if we disassemble 
  the entire '.text' section directly.
- To solve this issue, we partition the raw bytes of .text section with 'c3'
  as delimiter
- This way we divide the binary instructions into sections between 2 rets
- We consider only 10 bytes before the ending ret to find out gadgets as
  higher depth consume more time for finding gadgets in large libraries
  (like libc)
- These gadgets are later picked up by ROP chain algorithm to assemble on the
  stack

ROP Payload
------------
We came up with 4 stack frame layouts to invoke mprotect :
1) strcpy and the mprotect in libc
- We use _strcpy_g instead of the regular strcpy as otherwise, it will be replaced 
  with the processor specific _strcpy_sse2()
- We first scan the sybol table (.dynsym) in libc to get the addresses of mprotect and _strcpy_g().
- We replace all the NULL bytes in payload by using _strcpy_
- This ROP payload is easy to build as it just requires 2 gadgets but it assumes the presence of libc

2) mprotect syscall (without strcpy, no dependency on libc)
- All the remaining 3 stack frame layouts do not rely on libc to find gadgets
- They use different combinations of registers to execute the mprotect syscall
- Stack frame layout for each of them is printed as the code executes

References
----------
http://www.capstone-engine.org/lang_python.html

http://stackoverflow.com/questions/24997541/getting-the-memory-layout-out-of-an-avrelf-file-by-useing-python-pyelftools
