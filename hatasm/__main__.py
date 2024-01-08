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

from .assembler import Assembler
from .disassembler import Disassembler


class HatAsm(Assembler, Disassembler):
    """ Main class of hatasm module.

    This main class of hatasm module is intended for providing
    some main HatAsm methods.
    """

    def __init__(self) -> None:
        super().__init__()

    def assemble(self, *args, **kwargs) -> bytes:
        """ Assemble code for the specified architecture.

        :return bytes: assembled code for the specified architecture
        """

        return self.assemble_code(*args, **kwargs)

    def assemble_to(self, *args, filename: str = 'a.bin', **kwargs) -> None:
        """ Assemble code for the specified architecture and save it
        to the specified file.

        :param str filename: name of the file to save assembled code to
        :return None: None
        """

        with open(filename, 'wb') as f:
            f.write(self.assemble_code(*args, **kwargs))

    def assembler_cli(self, *args, **kwargs) -> None:
        """ Start the assembler command-line interface.

        :return None: None
        """

        self.assemble_cli(*args, **kwargs)

    def disassemble(self, *args, **kwargs) -> list:
        """ Disassemble code for the specified architecture.

        :return list: disassembled code for the specified architecture
        """

        return self.disassemble_code(*args, **kwargs)

    def disassemble_to(self, *args, filename: str = 'a.asm', **kwargs) -> None:
        """ Disassemble code for the specified architecture and save it
        to the specified file.

        :param str filename: name of the file to save disassembled code to
        :return None: None
        """

        code = self.disassemble_code(*args, **kwargs)

        with open(filename, 'w') as f:
            f.write(f"{code.mnemonic}\t{code.op_str}\n")

    def disassembler_cli(self, *args, **kwargs) -> None:
        """ Start the disassembler command-line interface.

        :return None: None
        """

        self.disassemble_cli(*args, **kwargs)

    def hexdump(self, *args, **kwargs) -> list:
        """ Dump assembled code as hex.

        :return list: list of hexdump strings
        """

        return self.hexdump_code(*args, **kwargs)

    def hexdump_asm(self, *args, **kwargs) -> list:
        """ Dump assembled code as hex.

        :return list: list of hexdump strings
        """

        return self.hexdump_asm_code(*args, **kwargs)
