# HatAsm

<p>
    <a href="https://entysec.com">
        <img src="https://img.shields.io/badge/developer-EntySec-blue.svg">
    </a>
    <a href="https://github.com/EntySec/HatAsm">
        <img src="https://img.shields.io/badge/language-Python-blue.svg">
    </a>
    <a href="https://github.com/EntySec/HatAsm/forks">
        <img src="https://img.shields.io/github/forks/EntySec/HatAsm?color=green">
    </a>
    <a href="https://github.com/EntySec/HatAsm/stargazers">
        <img src="https://img.shields.io/github/stars/EntySec/HatAsm?color=yellow">
    </a>
    <a href="https://www.codefactor.io/repository/github/EntySec/HatAsm">
        <img src="https://www.codefactor.io/repository/github/EntySec/Pex/HatAsm" />
    </a>
</p>

HatAsm is a powerful assembler and disassembler that provides support for all common architectures.

## Features

* Assembler and disassembler both available in one tool.
* Support for most common architectures like `x64`, `x86`, `aarch64`, `armle`, `mipsle`, `mipsbe`.
* Ability to assemble code right into the byte code.

## Installation

```shell
pip3 install git+https://github.com/EntySec/HatAsm
```

## Basic functions

There are all HatAsm basic functions that can be used to generate payload, covert data, assemble code or inject shellcode.

### Assembler functions

* `assemble(arch, code, mode=None, syntax='intel')` - Generate byte code for specified target from specified assembly code.
* `assemble_to(arch, code, mode=None, syntax='intel', filename='a.bin')` - Generate byte code for specified target from specified assembly code and save it in to the specified file.
* `assembler_cli(arch, mode=None, syntax='intel')` - Assembler CLI.

### Disassembler functions

* `disassemble(arch, code, mode=None, syntax='intel')` - Generate assembly code for specified target from specified byte
  code.
* `disassemble_to(arch, code, mode=None, syntax='intel', filename='a.asm')` - Generate assembly code for specified
  target from specified byte code and save it in to the specified file.
* `disassembler_cli(arch, mode=None, syntax='intel')` - Disassembler CLI.

### Misc functions

* `hexdump(code, length=16, sep='.')` - Hexdump for byte code.

## Assembling code

It's very easy to assemble code for various targets in HatAsm. Let's assemble a simple code that calls shutdown for Linux.

### Examples

```python
from hatasm import HatAsm

code = """
start:
    push 0x3e
    pop rax
    push -1
    pop rdi
    push 0x9
    pop rsi
    syscall
"""

hatasm = HatAsm()
shellcode = hatasm.assemble('x64', code)
```

## HatAsm CLI

HatAsm also has its own command line interface that can be invoked by executing `hatasm` command:

```
usage: hatasm [-h] [--arch ARCH] [--mode MODE] [--syntax SYNTAX] [-i INPUT]
              [-o OUTPUT] [-a] [-d]

HatAsm is a powerful assembler and disassembler that provides
support for all common architectures.

optional arguments:
  -h, --help            show this help message and exit
  --arch ARCH           Architecture to assemble or disassemble for.
  --mode MODE           Architecture mode (for example - arm/thumb).
  --syntax SYNTAX       Assembler/Disassembler syntax (for example -
                        intel/att).
  -i INPUT, --input INPUT
                        Input file for assembler or disassembler.
  -o OUTPUT, --output OUTPUT
                        Output file to write output.
  -a, --assembler       Launch HatAsm assembler.
  -d, --disassembler    Launch HatAsm disassembler.
```

### Examples

```
hatasm -a --arch x64
```

Run interactive assembler shell for `x64` architecture.

```
hatasm > nop
00000000  90                                               |.               |
hatasm > start:
........     xor rax, rax
........     cdq
........     nop
........     
00000000  48 31 c0 99 90                                   |H1...           |
hatasm >
```

Write macos execve /bin/sh shellcode from command-line.

```
hatasm > start:
........     xor rax, rax
........     cdq
........     push rax
........     mov rdi, 0x68732f6e69622f2f
........     push rdi
........     push rsp
........     pop rdi
........     xor rsi, rsi
........     mov al, 0x2
........     ror rax, 0x28
........     mov al, 0x3b
........     syscall
........
00000000  48 31 c0 99 50 48 bf 2f  2f 62 69 6e 2f 73 68 57 |H1..PH.//bin/shW|
00000010  54 5f 48 31 f6 b0 02 48  c1 c8 28 b0 3b 0f 05    |T_H1...H..(.;.. |
hatasm > 
```
