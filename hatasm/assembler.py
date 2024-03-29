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

import keystone
import os
import readline
from typing import Union

from badges import Badges


class Assembler(Badges):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended for providing
    an implementation of HatAsm assembler.
    """

    def __init__(self) -> None:
        super().__init__()

        self.assembler_architectures = {
            'x86': [keystone.KS_ARCH_X86, keystone.KS_MODE_32],
            'x64': [keystone.KS_ARCH_X86, keystone.KS_MODE_64],

            'ppc': [keystone.KS_ARCH_PPC, keystone.KS_MODE_32],
            'ppc64': [keystone.KS_ARCH_PPC, keystone.KS_MODE_64],

            'aarch64': [keystone.KS_ARCH_ARM64, 0],
            'armle': [keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM + keystone.KS_MODE_LITTLE_ENDIAN],
            'armbe': [keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM + keystone.KS_MODE_BIG_ENDIAN],

            'mips64le': [keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64 + keystone.KS_MODE_LITTLE_ENDIAN],
            'mips64be': [keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64 + keystone.KS_MODE_BIG_ENDIAN],
            'mipsle': [keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32 + keystone.KS_MODE_LITTLE_ENDIAN],
            'mipsbe': [keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32 + keystone.KS_MODE_BIG_ENDIAN]
        }

        self.assembler_syntaxes = {
            'intel': keystone.KS_OPT_SYNTAX_INTEL,
            'att': keystone.KS_OPT_SYNTAX_ATT
        }

    def assemble_code(self, arch: str, code: str, mode: str = '', syntax: str = 'intel') -> bytes:
        """ Assemble code for the specified architecture.

        :param str arch: architecture to assemble for
        :param str code: code to assemble
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :return bytes: assembled code for the specified architecture
        """

        if arch in self.assembler_architectures:
            target = self.assembler_architectures[arch]

            if arch == 'armle' and mode == 'thumb':
                target[1] = keystone.KS_MODE_THUMB + keystone.KS_MODE_LITTLE_ENDIAN
            elif arch == 'armbe' and mode == 'thumb':
                target[1] = keystone.KS_MODE_THUMB + keystone.KS_MODE_BIG_ENDIAN

            ks = keystone.Ks(*target)
            if syntax in self.assembler_syntaxes:
                try:
                    ks.syntax = self.assembler_syntaxes[syntax]
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
                    result += self.assemble_code(arch, line, mode, syntax)
            except Exception as e:
                errors.update({count: str(e).split(' (')[0]})

            count += 1
        return errors if errors else result

    def assemble_from(self, arch: str, filename: str, mode: str = '', syntax: str = 'intel') -> None:
        """ Assemble each line of a source file for the specified architecture
        and print result to stdout.

        :param str arch: architecture to assembler for
        :param str filename: name of a file to assemble from
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :return None: None
        """

        if os.path.exists(filename):
            with open(filename, 'r') as f:
                code = f.read()

                try:
                    result = self.assemble_code(arch, code, mode, syntax)

                    for line in self.hexdump_code(result):
                        self.print_empty(line)

                except (KeyboardInterrupt, EOFError):
                    self.print_empty()

                except Exception:
                    errors = self.recursive_assemble(arch, code.split('\n'), mode)

                    if isinstance(errors, dict):
                        for line in errors:
                            self.print_error(f"HatAsm: line {str(line)}: {errors[line]}")

                    else:
                        for line in self.hexdump_code(errors):
                            self.print_empty(line)
        else:
            self.print_error(f"Local file: {filename}: does not exist!")

    def assemble_cli(self, arch: str, mode: str = '', syntax: str = 'intel') -> None:
        """ Start the assembler command-line interface.

        :param str arch: architecture to assemble for
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
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

                if code.endswith(':'):
                    while True:
                        line = input('........ ')

                        if not line:
                            break

                        code += line + '\n'

                try:
                    result = self.assemble_code(arch, code, mode, syntax)

                    for line in self.hexdump_code(result):
                        self.print_empty(line)

                except (KeyboardInterrupt, EOFError):
                    self.print_empty()

                except Exception:
                    errors = self.recursive_assemble(arch, code.split('\n'), mode, syntax)

                    if isinstance(errors, dict):
                        for line in errors:
                            self.print_error(f"HatAsm: line {str(line)}: {errors[line]}")

                    else:
                        for line in self.hexdump_code(errors):
                            self.print_empty(line)

            except (KeyboardInterrupt, EOFError):
                self.print_empty()

            except Exception as e:
                self.print_error(f"HatAsm: line 1: {str(e).split(' (')[0]}")
