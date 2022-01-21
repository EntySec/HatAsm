# HatAsm

<p>
    <a href="https://entysec.netlify.app">
        <img src="https://img.shields.io/badge/developer-EntySec-3572a5.svg">
    </a>
    <a href="https://github.com/EntySec/HatAsm">
        <img src="https://img.shields.io/badge/language-Python-3572a5.svg">
    </a>
    <a href="https://github.com/EntySec/HatAsm/stargazers">
        <img src="https://img.shields.io/github/stars/EntySec/HatAsm?color=yellow">
    </a>
</p>

HatAsm is a HatSploit native powerful assembler and disassembler that provides support for all common architectures.

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

* `assemble(arch, code, mode=None)` - Generate byte code for specified target from specified code (`mode` argument is used for `armle` and `armbe` to switch between `thumb` command set mode or `arm`).
* `disassemble(arch, code, mode=None)` - 

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
