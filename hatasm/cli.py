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

import os

import codecs
import readline

import sys
import argparse

from .badges import Badges
from .assembler import Assembler
from .disassembler import Disassembler


class HatAsmCLI(Assembler, Disassembler, Badges):
    description = (
        "HatAsm is a HatSploit native powerful assembler and disassembler"
        " that provides support for all common architectures."
    )
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--arch', dest='arch', help='Architecture to assemble or disassemble for.')
    parser.add_argument('--mode', dest='mode', help='Architecture mode (used for armle or armbe - arm/thumb).')
    parser.add_argument('-i', '--input', dest='input', help='Input file for assembler or disassembler.')
    parser.add_argument('-o', '--output', dest='output', help='Output file to write output.')
    parser.add_argument('-a', '--assembler', action='store_true', dest='assembler', help='Launch HatAsm assembler.')
    parser.add_argument('-d', '--disassembler', action='store_true', dest='disassembler', help='Launch HatAsm disassembler.')
    args = parser.parse_args()

    def start(self):
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
                if not os.path.exists(self.args.input):
                    self.print_error(f"Input file: {self.args.input}: does not exist!")
                    return

                errors, result, lines = {}, b'', 1

                if self.args.assembler:
                    with open(self.args.input, 'r') as f:
                        f_lines = f.read().strip().split('\n')

                        for line in f_lines:
                            try:
                                result += self.assemble_code(self.args.arch, line, self.args.mode)
                            except Exception as e:
                                errors.update({lines: str(e).split(' (')[0]})

                            lines += 1

                    if not errors:
                        if self.args.output:
                            with open(self.args.output, 'wb') as f:
                                f.write(result)
                        else:
                            for line in self.hexdump(result):
                                print(line)
                    else:
                        for line in errors:
                            self.print_error(f"HatAsm: line {str(line)}: {errors[line]}")
                else:
                    with open(self.args.input, 'rb') as f:
                        line = codecs.escape_decode(f.read())[0]
                        result = self.disassemble_code(self.args.arch, line, self.args.mode)

                    if self.args.output:
                        with open(self.args.output, 'w') as f:
                            f.write('start:\n')

                            for line in result:
                                f.write(f'    {line.mnemonic} {line.op_str}')
                    else:
                        for line in result:
                            print("0x%x: %s %s" % (line.address, line.mnemonic, line.op_str))
            else:
                readline.parse_and_bind('tab: complete')

                while True:
                    try:
                        errors, result, lines = {}, b'', 1
                        code = input('hatasm > ')

                        if not code:
                            continue

                        if code in ['exit', 'quit']:
                            break

                        if self.args.assembler:
                            if code.endswith(':'):
                                while True:
                                    lines += 1
                                    line = input('........     ')

                                    if not line:
                                        break

                                    try:
                                        result += self.assemble_code(self.args.arch, line, self.args.mode)
                                    except (KeyboardInterrupt, EOFError):
                                        print()

                                    except Exception as e:
                                        errors.update({lines: str(e).split(' (')[0]})
                            else:
                                result = self.assemble_code(self.args.arch, code, self.args.mode)
                        else:
                            line = codecs.escape_decode(code)[0]
                            result = self.disassemble_code(self.args.arch, line, self.args.mode)

                        if self.args.assembler:
                            if not errors:
                                for line in self.hexdump(result):
                                    print(line)
                            else:
                                for line in errors:
                                    self.print_error(f"HatAsm: line {str(line)}: {errors[line]}")

                        else:
                            for line in result:
                                print("0x%x: %s %s" % (line.address, line.mnemonic, line.op_str))

                    except (KeyboardInterrupt, EOFError):
                        print()

                    except Exception as e:
                        self.print_error(f"HatAsm: line 1: {str(e).split(' (')[0]}")
                        continue
        else:
            self.parser.print_help()

def main():
    try:
        cli = HatAsmCLI()
        cli.start()
    except Exception:
        pass
