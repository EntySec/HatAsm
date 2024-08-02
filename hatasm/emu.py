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

from unicorn import *

from badges import Badges

ADDRESS = 0x1000000


class Emu(Badges):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended to provide
    an emulation interface.
    """

    uc_arch = {
        'x86': (UC_ARCH_X86, UC_MODE_32),
        'x64': (UC_ARCH_X86, UC_MODE_64),

        'ppc': (UC_ARCH_PPC, UC_MODE_32 + UC_MODE_BIG_ENDIAN),
        'ppc64': (UC_ARCH_PPC, UC_MODE_64),

        'aarch64': (UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN),
        'armle': (UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN),
        'armbe': (UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_BIG_ENDIAN),

        'sparc': (UC_ARCH_SPARC, UC_MODE_BIG_ENDIAN),
        'sparc64': (UC_ARCH_SPARC, UC_MODE_BIG_ENDIAN),

        'mips64le': (UC_ARCH_MIPS, UC_MODE_MIPS64 + UC_MODE_LITTLE_ENDIAN),
        'mips64be': (UC_ARCH_MIPS, UC_MODE_MIPS64 + UC_MODE_BIG_ENDIAN),
        'mipsle': (UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN),
        'mipsbe': (UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
    }

    def __init__(self, arch: str) -> None:
        """ Initialize emulator.

        :param str arch: architecture
        :return None: None
        """

        if arch not in self.uc_arch:
            raise RuntimeError(f"Wrong architecture: {arch}!")

        self.vm = Uc(*self.uc_arch[arch])
        self.vm.mem_map(ADDRESS, 2 * 1024 * 1024)

    def emulate(self, code: bytes) -> None:
        """ Emulate code.

        :param bytes code: code
        :return None: None
        """

        self.vm.mem_write(ADDRESS, code)
        self.vm.emu_start(ADDRESS, ADDRESS + len(code))

    def print_stack(self) -> None:
        """ Print stack trace.

        :return None: None
        """

        pass
