#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2022 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import capstone


class Disassembler:
    disassembler_architectures = {
        'x86': [capstone.CS_ARCH_X86, capstone.CS_MODE_32],
        'x64': [capstone.CS_ARCH_X86, capstone.CS_MODE_64],

        'ppc': [capstone.CS_ARCH_PPC, capstone.CS_MODE_32],
        'ppc64': [capstone.CS_ARCH_PPC, capstone.CS_MODE_64],

        'aarch64': [capstone.CS_ARCH_ARM64, 0],
        'armle': [capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_LITTLE_ENDIAN],
        'armbe': [capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_BIG_ENDIAN],

        'mips64le': [capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 + capstone.CS_MODE_LITTLE_ENDIAN],
        'mips64be': [capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 + capstone.CS_MODE_BIG_ENDIAN],
        'mipsle': [capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN],
        'mipsbe': [capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_BIG_ENDIAN]
    }

    def disassemble_code(self, arch, code, mode=None):
        if arch in self.disassembler_architectures:
            target = self.disassembler_architectures[arch]

            if arch == 'armle' and mode == 'thumb':
                target[1] = capstone.CS_MODE_THUMB + capstone.CS_MODE_LITTLE_ENDIAN
            elif arch == 'armbe' and mode == 'thumb':
                target[1] = capstone.CS_MODE_THUMB + capstone.CS_MODE_BIG_ENDIAN

            cs = capstone.Cs(*target)
            assembly = []

            for i in cs.disasm(code, 0x10000000):
                assembly.append({
                    'address': i.address,
                    'mnemonic': i.mnemonic,
                    'operand': i.op_str
                })

            return assembly
        return []
