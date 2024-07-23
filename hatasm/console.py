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

import codecs

from .asm import ASM

from badges.cmd import Cmd


class Console(Cmd, ASM):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended to provide
    and interface for interactive assembler/disassembler.
    """

    def __init__(self, arch: str, mode: str = '',
                 prompt: str = '%linehatasm%end % ',
                 asm: bool = True) -> None:
        """ Initialize assembler/disassembler console.

        :param str arch: architecture
        :param str mode: assemble mode (e.g. thumb)
        :param str prompt: prompt message to display
        :param bool asm: mode (assemble/disassemble)
        :return None: None
        """

        super().__init__(
            prompt=prompt)

        self.scheme = prompt

        self.arch = arch
        self.mode = mode
        self.asm = asm
        self.cached = ""

    def emptyline(self) -> None:
        """ Complete cached code.

        :return None: None
        """

        if not self.cached or not self.asm:
            return

        self.set_prompt(self.scheme)

        try:
            result = self.assemble(
                self.arch, self.cached, self.mode, 'intel')

            for line in self.hexdump(result):
                self.print_empty(line)

        except (KeyboardInterrupt, EOFError):
            self.print_empty()

        except Exception:
            errors = self.recursive_assemble(
                self.arch, self.cached.split('\n'), self.mode, 'intel')

            if isinstance(errors, dict):
                for line in errors:
                    self.print_error(f"HatAsm: line {str(line)}: {errors[line]}")

            else:
                for line in self.hexdump(errors):
                    self.print_empty(line)

        self.cached = ""

    def default(self, args: list) -> None:
        """ Main handler for commands.

        :param list args: arguments
        :return None: None
        """

        code = ' '.join(args)

        if not self.asm:
            code = codecs.escape_decode(code)[0]
            result = self.disassemble(
                self.arch, code, self.mode, 'intel')

            for line in result:
                self.print_empty("0x%x:\t%s\t%s" % (line.address, line.mnemonic, line.op_str))

            return

        if self.cached:
            self.cached += code + '\n'
            return

        if code.endswith(':'):
            self.set_prompt('........     ')
            self.cached += code + '\n'

            return

        result = self.assemble(
            self.arch, code, self.mode, 'intel')

        for line in self.hexdump(result):
            self.print_empty(line)

    def shell(self) -> None:
        """ Run console shell.

        :return None: None
        """

        self.loop()
