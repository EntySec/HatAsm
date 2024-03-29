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

import argparse
import sys

from .assembler import Assembler
from badges import Badges
from .disassembler import Disassembler


class HatAsmCLI(Assembler, Disassembler, Badges):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended for providing
    command-line interface for HatAsm.
    """

    def __init__(self) -> None:
        super().__init__()

        self.description = (
            "HatAsm is a powerful assembler and disassembler"
            " that provides support for all common architectures."
        )

        self.parser = argparse.ArgumentParser(description=self.description)
        self.parser.add_argument('--arch', dest='arch', help='Architecture to assemble or disassemble for.')
        self.parser.add_argument('--mode', dest='mode', help='Architecture mode (for example - arm/thumb).')
        self.parser.add_argument('--syntax', dest='syntax', help='Assembler/Disassembler syntax (for example - intel/att).')
        self.parser.add_argument('-i', '--input', dest='input', help='Input file for assembler or disassembler.')
        self.parser.add_argument('-o', '--output', dest='output', help='Output file to write output.')
        self.parser.add_argument('-a', '--assembler', action='store_true', dest='assembler', help='Launch HatAsm assembler.')
        self.parser.add_argument('-d', '--disassembler', action='store_true', dest='disassembler',
                                 help='Launch HatAsm disassembler.')
        self.args = self.parser.parse_args()

    def start(self) -> None:
        """ Main command-line arguments handler.

        :return None: None
        """

        if not self.args.syntax:
            self.args.syntax = 'intel'

        if (self.args.assembler or self.args.disassembler) and self.args.arch:
            if self.args.assembler:
                if self.args.arch not in self.assembler_architectures:
                    self.print_error(f"HatAsm: assembler failed: unsupported architecture")
                    return
            else:
                if self.args.arch not in self.disassembler_architectures:
                    self.print_error(f"HatAsm: disassembler failed: unsupported architecture")
                    return

            if self.args.input:
                if self.args.assembler:
                    self.assemble_from(self.args.arch, self.args.input, self.args.mode, self.args.syntax)
                else:
                    self.disassemble_from(self.args.arch, self.args.input, self.args.mode, self.args.syntax)

            else:
                if self.args.assembler:
                    self.assemble_cli(self.args.arch, self.args.mode, self.args.syntax)
                else:
                    self.disassemble_cli(self.args.arch, self.args.mode, self.args.syntax)
        else:
            self.parser.print_help()


def main() -> None:
    """ HatAsm command-line interface.

    :return None: None
    """

    try:
        cli = HatAsmCLI()
        cli.start()
    except BaseException:
        pass
