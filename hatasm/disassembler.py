"""
MIT License

Copyright (c) 2020-2023 EntySec

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

import capstone
import codecs
import os
import readline

from badges import Badges


class Disassembler(Badges):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended for providing
    an implementation of HatAsm disassembler.
    """

    def __init__(self) -> None:
        super().__init__()

        self.disassembler_architectures = {
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

        self.disassembler_syntaxes = {
            'intel': capstone.CS_OPT_SYNTAX_INTEL,
            'att': capstone.CS_OPT_SYNTAX_ATT
        }

    def disassemble_code(self, arch: str, code: bytes, mode: str = '', syntax: str = 'intel') -> list:
        """ Disassemble code for the specified architecture.

        :param str arch: architecture to disassemble for
        :param bytes code: code to disassemble
        :param str mode: special disassembler mode
        :param str syntax: special disassembler syntax
        :return list: disassembled code for the specified architecture
        """

        if arch in self.disassembler_architectures:
            target = self.disassembler_architectures[arch]

            if arch == 'armle' and mode == 'thumb':
                target[1] = capstone.CS_MODE_THUMB + capstone.CS_MODE_LITTLE_ENDIAN
            elif arch == 'armbe' and mode == 'thumb':
                target[1] = capstone.CS_MODE_THUMB + capstone.CS_MODE_BIG_ENDIAN

            cs = capstone.Cs(*target)
            if syntax in self.disassembler_syntaxes:
                try:
                    cs.syntax = self.disassembler_syntaxes[syntax]
                except BaseException:
                    pass

            assembly = []

            for i in cs.disasm(code, 0x10000000):
                assembly.append(i)

            return assembly
        return []

    def disassemble_from(self, arch: str, filename: str, mode: str = '', syntax: str = 'intel') -> None:
        """ Disassemble each line of a source file for the specified architecture
        and print result to stdout.

        :param str arch: architecture to disassembler for
        :param str filename: name of a file to disassemble from
        :param str mode: special disassembler mode
        :param str syntax: special disassembler syntax
        :return None: None
        """

        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                code = codecs.escape_decode(f.read())[0]
                result = self.disassemble_code(arch, code, mode, syntax)

                for line in result:
                    self.print_empty("0x%x:\t%s\t%s" % (line.address, line.mnemonic, line.op_str))
        else:
            self.print_error(f"Local file: {filename}: does not exist!")

    def disassemble_cli(self, arch: str, mode: str = '', syntax: str = 'intel') -> None:
        """ Start the disassembler command-line interface.

        :param str arch: architecture to disassemble for
        :param str mode: special disassembler mode
        :param str syntax: special disassembler syntax
        :return None: None
        """

        readline.parse_and_bind('tab: complete')

        while True:
            try:
                code = input('hatasm > ')

                if not code:
                    continue

                if code in ['exit', 'quit']:
                    break

                code = codecs.escape_decode(code)[0]
                result = self.disassemble_code(arch, code, mode, syntax)

                for line in result:
                    self.print_empty("0x%x:\t%s\t%s" % (line.address, line.mnemonic, line.op_str))

            except Exception:
                self.print_empty()

    @staticmethod
    def hexdump_code(code: bytes, length: int = 16, sep: str = '.') -> list:
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

    def hexdump_asm_code(self, arch: str, code: bytes, mode: str = '', syntax: str = 'intel',
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

        assembly = self.disassemble_code(arch, code, mode, syntax)
        data = []

        for line in assembly:
            for result in self.hexdump_code(line.bytes, length, sep):
                data.append('{}  {}\t{}'.format(result, line.mnemonic, line.op_str))

        return data
