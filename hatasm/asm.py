"""
MIT License

Copyright (c) 2020-2024 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import keystone
import capstone

from typing import Union
from badges import Badges


class ASM(Badges):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended for providing
    an implementation of HatAsm assembler.
    """

    keystone_arch = {
        'x86': [keystone.KS_ARCH_X86, keystone.KS_MODE_32],
        'x64': [keystone.KS_ARCH_X86, keystone.KS_MODE_64],

        'ppc': [keystone.KS_ARCH_PPC, keystone.KS_MODE_32 + keystone.KS_MODE_BIG_ENDIAN],
        'ppc64': [keystone.KS_ARCH_PPC, keystone.KS_MODE_64],

        'aarch64': [keystone.KS_ARCH_ARM64, 0],
        'armle': [keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM + keystone.KS_MODE_LITTLE_ENDIAN],
        'armbe': [keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM + keystone.KS_MODE_BIG_ENDIAN],

        'sparc': [keystone.KS_ARCH_SPARC, keystone.KS_MODE_SPARC32 + keystone.KS_MODE_BIG_ENDIAN],
        'sparc64': [keystone.KS_ARCH_SPARC, keystone.KS_MODE_SPARC64 + keystone.KS_MODE_BIG_ENDIAN],

        'mips64le': [keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64 + keystone.KS_MODE_LITTLE_ENDIAN],
        'mips64be': [keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64 + keystone.KS_MODE_BIG_ENDIAN],
        'mipsle': [keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32 + keystone.KS_MODE_LITTLE_ENDIAN],
        'mipsbe': [keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32 + keystone.KS_MODE_BIG_ENDIAN]
    }

    keystone_syntax = {
        'intel': keystone.KS_OPT_SYNTAX_INTEL,
        'att': keystone.KS_OPT_SYNTAX_ATT
    }

    capstone_arch = {
        'x86': [capstone.CS_ARCH_X86, capstone.CS_MODE_32],
        'x64': [capstone.CS_ARCH_X86, capstone.CS_MODE_64],

        'ppc': [capstone.CS_ARCH_PPC, capstone.CS_MODE_32 + capstone.CS_MODE_BIG_ENDIAN],
        'ppc64': [capstone.CS_ARCH_PPC, capstone.CS_MODE_64],

        'aarch64': [capstone.CS_ARCH_ARM64, 0],
        'armle': [capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_LITTLE_ENDIAN],
        'armbe': [capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_BIG_ENDIAN],

        'sparc': [capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN],
        'sparc64': [capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN],

        'mips64le': [capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 + capstone.CS_MODE_LITTLE_ENDIAN],
        'mips64be': [capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 + capstone.CS_MODE_BIG_ENDIAN],
        'mipsle': [capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN],
        'mipsbe': [capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_BIG_ENDIAN]
    }

    capstone_syntax = {
        'intel': capstone.CS_OPT_SYNTAX_INTEL,
        'att': capstone.CS_OPT_SYNTAX_ATT
    }

    def assemble(self, arch: str, code: str, mode: str = '', syntax: str = 'intel') -> bytes:
        """ Assemble code for the specified architecture.

        :param str arch: architecture to assemble for
        :param str code: code to assemble
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :return bytes: assembled code for the specified architecture
        """

        if arch in self.keystone_arch:
            target = self.keystone_arch[arch]

            if arch == 'armle' and mode == 'thumb':
                target[1] = keystone.KS_MODE_THUMB + keystone.KS_MODE_LITTLE_ENDIAN
            elif arch == 'armbe' and mode == 'thumb':
                target[1] = keystone.KS_MODE_THUMB + keystone.KS_MODE_BIG_ENDIAN

            ks = keystone.Ks(*target)
            if syntax in self.keystone_syntax:
                try:
                    ks.syntax = self.keystone_syntax[syntax]
                except BaseException:
                    pass

            machine = ks.asm(code.encode())

            if machine:
                return bytes(machine[0])
        return b''

    def recursive_assemble(self, arch: str, lines: list, mode: str = "",
                           syntax: str = 'intel') -> Union[bytes, dict]:
        """ Assemble each entry of a list for the specified architecture.

        :param str arch: architecture to assemble for
        :param list lines: list of code entries to assemble
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :return Union[bytes, dict]: assembled code in case of success,
        dictionary of errors in case of fail
        """

        count = 1
        errors = {}
        result = b''

        for line in lines:
            try:
                if line:
                    result += self.assemble(arch, line, mode, syntax)
            except Exception as e:
                errors.update({count: str(e).split(' (')[0]})

            count += 1
        return errors if errors else result

    def assemble_from(self, arch: str, filename: str, mode: str = '', syntax: str = 'intel') -> bytes:
        """ Assemble each line of a source file for the specified architecture
        and print result to stdout.

        :param str arch: architecture to assembler for
        :param str filename: name of a file to assemble from
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :return bytes: assembled code
        """

        if os.path.exists(filename):
            with open(filename, 'r') as f:
                code = f.read()

                try:
                    return self.assemble(arch, code, mode, syntax)

                except (KeyboardInterrupt, EOFError):
                    self.print_empty()

                except Exception as e:
                    print(str(e))
                    errors = self.recursive_assemble(arch, code.split('\n'), mode)

                    if isinstance(errors, dict):
                        for line in errors:
                            self.print_error(f"HatAsm: line {str(line)}: {errors[line]}")

                    else:
                        return errors
        else:
            self.print_error(f"Local file: {filename}: does not exist!")

        return b''

    def disassemble(self, arch: str, code: bytes, mode: str = '', syntax: str = 'intel') -> list:
        """ Disassemble code for the specified architecture.

        :param str arch: architecture to disassemble for
        :param bytes code: code to disassemble
        :param str mode: special disassembler mode
        :param str syntax: special disassembler syntax
        :return list: disassembled code for the specified architecture
        """

        if arch in self.capstone_arch:
            target = self.capstone_arch[arch]

            if arch == 'armle' and mode == 'thumb':
                target[1] = capstone.CS_MODE_THUMB + capstone.CS_MODE_LITTLE_ENDIAN
            elif arch == 'armbe' and mode == 'thumb':
                target[1] = capstone.CS_MODE_THUMB + capstone.CS_MODE_BIG_ENDIAN

            cs = capstone.Cs(*target)
            if syntax in self.capstone_syntax:
                try:
                    cs.syntax = self.capstone_syntax[syntax]
                except BaseException:
                    pass

            assembly = []

            for i in cs.disasm(code, 0x10000000):
                assembly.append(i)

            return assembly
        return []

    def disassemble_from(self, arch: str, filename: str, mode: str = '', syntax: str = 'intel') -> list:
        """ Disassemble each line of a source file for the specified architecture
        and print result to stdout.

        :param str arch: architecture to disassembler for
        :param str filename: name of a file to disassemble from
        :param str mode: special disassembler mode
        :param str syntax: special disassembler syntax
        :return list: disassembled code
        """

        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                code = codecs.escape_decode(f.read())[0]
                return self.disassemble(arch, code, mode, syntax)
        else:
            self.print_error(f"Local file: {filename}: does not exist!")

        return []

    @staticmethod
    def hexdump(code: bytes, length: int = 16, sep: str = '.') -> list:
        """ Dump assembled code as hex.

        :param bytes code: assembled code to dump as hex
        :param int length: length of each string
        :param str sep: non-printable chars replacement
        :return list: list of hexdump strings
        """

        src = code
        filt = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
        lines = []

        for c in range(0, len(src), length):
            chars = src[c: c + length]
            hex_ = ' '.join(['{:02x}'.format(x) for x in chars])

            if len(hex_) > 24:
                hex_ = '{} {}'.format(hex_[:24], hex_[24:])

            printable = ''.join(['{}'.format((x <= 127 and filt[x]) or sep) for x in chars])
            lines.append('{0:08x}  {1:{2}s} |{3:{4}s}|'.format(c, hex_, length * 3, printable, length))

        return lines

    def hexdump_asm(self, arch: str, code: bytes, mode: str = '', syntax: str = 'intel',
                    length: int = 16, sep: str = '.') -> list:
        """ Dump assembled code as hex.

        :param str arch: architecture to disassemble for
        :param bytes code: code to disassemble
        :param str mode: special disassembler mode
        :param str syntax: special disassembler syntax
        :param int length: length of each string
        :param str sep: non-printable chars replacement
        :return list: list of hexdump strings
        """

        assembly = self.disassemble(arch, code, mode, syntax)
        data = []

        for line in assembly:
            for result in self.hexdump(line.bytes, length, sep):
                data.append('{}  {}\t{}'.format(result, line.mnemonic, line.op_str))

        return data
