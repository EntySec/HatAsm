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
import importlib.util

from typing import Optional

from hatasm.lib.format import Format


class Formats(object):
    """ Subclass of hatasm.lib module.

    This subclass of hatasm.lib module is intended for providing
    tools for working with HatAsm formats.
    """

    formats = f'{os.path.dirname(os.path.dirname(__file__))}/exe/formats/'

    @staticmethod
    def import_format(format_path: str) -> Format:
        """ Import format from path.

        :param str format_path: path to format
        :return Format: format object
        :raises RuntimeError: with trailing error message
        """

        try:
            if not format_path.endswith('.py'):
                format_path = format_path + '.py'

            spec = importlib.util.spec_from_file_location(format_path, format_path)
            format_object = importlib.util.module_from_spec(spec)

            spec.loader.exec_module(format_object)
            format_object = format_object.HatAsmFormat()

        except Exception as e:
            raise RuntimeError(f"Failed to import format: {str(e)}!")

        return format_object

    def get_format(self, name: str, arch: Optional[str] = None,
                   platform: Optional[str] = None) -> Format:
        """ Get format by name, arch and platform.

        :param str name: format name
        :param Optional[str] arch: architecture
        :param Optional[str] platform: platform
        :return Format: format object
        :raises RuntimeError: with trailing error message
        """

        path = self.formats + name + '.py'

        if not os.path.exists(path):
            raise RuntimeError(f"Invalid format: {name}!")

        format_object = self.import_format(path)

        if arch and arch not in format_object.info['Arch']:
            raise RuntimeError(f"Incompatible format: {name}!")

        if platform and platform != format_object.info['Platform']:
            raise RuntimeError(f"Incompatible format: {name}!")

        return format_object
