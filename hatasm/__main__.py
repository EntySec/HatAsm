"""
MIT License

Copyright (c) 2020-2022 EntySec

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

from .assembler import Assembler
from .disassembler import Disassembler


class HatAsm(Assembler, Disassembler):
    """ Main class of hatasm module.

    This main class of hatasm module is intended for providing
    some main HatAsm methods.
    """

    def assemble(self, arch: str, code: str, mode: str = '', syntax: str = 'intel') -> bytes:
        """ Assemble code for the specified architecture.

        :param str arch: architecture to assemble for
        :param str code: code to assemble
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :return bytes: assembled code for the specified architecture
        """

        return self.assemble_code(arch, code, mode, syntax)

    def assemble_to(self, arch: str, code: str, mode: str = '',
                    syntax: str = 'intel', filename: str = 'a.bin') -> None:
        """ Assemble code for the specified architecture and save it
        to the specified file.

        :param str arch: architecture to assemble for
        :param str code: code to assemble
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :param str filename: name of the file to save assembled code to
        :return None: None
        """

        with open(filename, 'wb') as f:
            f.write(self.assemble_code(arch, code, mode, syntax))

    def assembler_cli(self, arch: str, mode: str = '', syntax: str = 'intel') -> None:
        """ Start the assembler command-line interface.

        :param str arch: architecture to assemble for
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :return None: None
        """

        self.assemble_cli(arch, mode, syntax)

    def disassemble(self, arch: str, code: bytes, mode: str = '', syntax: str = 'intel') -> list:
        """ Disassemble code for the specified architecture.

        :param str arch: architecture to disassemble for
        :param bytes code: code to disassemble
        :param str mode: special disassembler mode
        :param str syntax: special disassembler syntax
        :return list: disassembled code for the specified architecture
        """

        return self.disassemble_code(arch, code, mode, syntax)

    def disassemble_to(self, arch: str, code: bytes, mode: str = '',
                       syntax: str = 'intel', filename: str = 'a.asm') -> None:
        """ Disassemble code for the specified architecture and save it
        to the specified file.

        :param str arch: architecture to disassemble for
        :param bytes code: code to disassemble
        :param str mode: special disassembler mode
        :param str syntax: special disassembler syntax
        :param str filename: name of the file to save disassembled code to
        :return None: None
        """

        code = self.disassemble_code(arch, code, mode, syntax)

        with open(filename, 'w') as f:
            f.write("start:\n")
            f.write(f"    {code['mnemonic']} {code['operand']}\n")

    def disassembler_cli(self, arch: str, mode: str = '', syntax: str = 'intel') -> None:
        """ Start the disassembler command-line interface.

        :param str arch: architecture to disassemble for
        :param str mode: special disassembler mode
        :param str syntax: special disassembler syntax
        :return None: None
        """

        self.disassemble_cli(arch, mode, syntax)

    def hexdump(self, code: bytes, length: int = 16, sep: str = '.') -> list:
        """ Dump assembled code as hex.

        :param bytes code: assembled code to dump as hex
        :param int length: length of each string
        :param str sep: non-printable chars replacement
        :return list: list of hexdump strings
        """

        return self.hexdump_code(code, length, sep)
