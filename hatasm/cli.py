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

import codecs
import readline

import sys
import argparse

from .assembler import Assembler
from .disassembler import Disassembler


class HatAsmCLI(Assembler, Disassembler):
    description = (
        "HatAsm is a HatSploit native powerful assembler and disassembler"
        " that provides support for all common architectures."
    )
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--arch', dest='arch', help='Architecture to assemble or disassemble for.')
    parser.add_argument('--mode', dest='mode', help='Architecture mode (used for armle or armbe - arm/thumb).')
    parser.add_argument('-a', '--assembler', action='store_true', dest='assembler', help='Launch HatAsm assembler.')
    parser.add_argument('-d', '--disassembler', action='store_true', dest='disassembler', help='Launch HatAsm disassembler.')
    args = parser.parse_args()

    def start(self):
        if (self.args.assembler or self.args.disassembler) and self.args.arch:
            readline.parse_and_bind('tab: complete')

            while True:
                code = input('hatasm > ')

                if self.args.assembler:
                    if code.endswith(':'):
                        code = code

                        while True:
                            if not code:
                                break
                            code += input('......... ')
                else:
                    code = codecs.escape_decode(code)[0]

                try:
                    if self.args.assemble:
                        result = self.assemble(self.args.arch, code, self.args.mode)
                    else:
                        result = self.disassemble(self.args.arch, code, self.args.mode)
                except (KeyboardInterrupt, EOFError):
                    continue
                except Exception as e:
                    print(f"{'assembler' if self.args.assembler else 'disassembler'} failed: {str(e)}")
                    return

                if self.args.assembler
                    for line in self.hexdump(result):
                        print(line)
                else:
                    for line in result:
                        print(line)
        else:
            self.parser.print_help()

def main():
    try:
        cli = HatAsmCLI()
        cli.start()
    except Exception:
        pass
