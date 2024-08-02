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

from keystone import *
from capstone import *

from typing import Union
from badges import Badges


class ASM(Badges):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended for providing
    an implementation of HatAsm assembler.
    """

    ks_arch = {
        'x86': (KS_ARCH_X86, KS_MODE_32),
        'x64': (KS_ARCH_X86, KS_MODE_64),

        'ppc': (KS_ARCH_PPC, KS_MODE_32 + KS_MODE_BIG_ENDIAN),
        'ppc64': (KS_ARCH_PPC, KS_MODE_64),

        'aarch64': (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),
        'armle': (KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_LITTLE_ENDIAN),
        'armbe': (KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN),

        'sparc': (KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_BIG_ENDIAN),
        'sparc64': (KS_ARCH_SPARC, KS_MODE_SPARC64 + KS_MODE_BIG_ENDIAN),

        'mips64le': (KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_LITTLE_ENDIAN),
        'mips64be': (KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN),
        'mipsle': (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN),
        'mipsbe': (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)
    }

    cs_arch = {
        'x86': (CS_ARCH_X86, CS_MODE_32),
        'x64': (CS_ARCH_X86, CS_MODE_64),

        'ppc': (CS_ARCH_PPC, CS_MODE_32 + CS_MODE_BIG_ENDIAN),
        'ppc64': (CS_ARCH_PPC, CS_MODE_64),

        'aarch64': (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
        'armle': (CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN),
        'armbe': (CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_BIG_ENDIAN),

        'sparc': (CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN),
        'sparc64': (CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN),

        'mips64le': (CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN),
        'mips64be': (CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN),
        'mipsle': (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN),
        'mipsbe': (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
    }

    ks_syntax = {
        'intel': KS_OPT_SYNTAX_INTEL,
        'att': KS_OPT_SYNTAX_ATT
    }

    cs_syntax = {
        'intel': CS_OPT_SYNTAX_INTEL,
        'att': CS_OPT_SYNTAX_ATT
    }

    def assemble(self, arch: str, code: str, mode: str = '', syntax: str = 'intel') -> bytes:
        """ Assemble code for the specified architecture.

        :param str arch: architecture to assemble for
        :param str code: code to assemble
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :return bytes: assembled code for the specified architecture
        """

        if arch in self.ks_arch:
            target = list(self.ks_arch[arch])

            if arch == 'armle' and mode == 'thumb':
                target[1] = KS_MODE_THUMB + KS_MODE_LITTLE_ENDIAN
            elif arch == 'armbe' and mode == 'thumb':
                target[1] = KS_MODE_THUMB + KS_MODE_BIG_ENDIAN

            ks = Ks(*target)

            if syntax in self.ks_syntax:
                try:
                    ks.syntax = self.ks_syntax[syntax]
                except BaseException:
                    ks = Ks(*target)

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

        if arch in self.cs_arch:
            target = list(self.cs_arch[arch])

            if arch == 'armle' and mode == 'thumb':
                target[1] = CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN
            elif arch == 'armbe' and mode == 'thumb':
                target[1] = CS_MODE_THUMB + CS_MODE_BIG_ENDIAN

            cs = Cs(*target)

            if syntax in self.cs_syntax:
                try:
                    cs.syntax = self.cs_syntax[syntax]
                except BaseException:
                    cs = Cs(*target)

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
