"""
Author: Dominik Reichel - Palo Alto Networks (2022)

Disassemble .NET assembly IL code with the help of dncil (https://github.com/mandiant/dncil).
"""

# pylint: disable=E1101,E0401

import argparse

from dncil.cil.body import reader
from dncil.cil.error import MethodBodyFormatError

from dotnetfile import DotNetPE
from dotnetfile.dotnetfile import Struct

from typing import List


class Disassembler:
    def __init__(self, file_path: str):
        self.dotnet_file = DotNetPE(file_path)
        self.metadata_tables = self.dotnet_file.existent_metadata_tables()
        self.typedef_names_with_methods = self._get_typedef_names_with_methods()

    def _get_typedef_names_with_methods(self) -> List[Struct.TypesMethods]:
        result = []

        if 'TypeDef' in self.metadata_tables:
            result = self.dotnet_file.TypeDef.get_type_names_with_methods()

        return result

    def disassemble_file(self) -> None:
        if self.typedef_names_with_methods:
            for typedef_name_with_methods in self.typedef_names_with_methods:
                print(f'Namespace: {typedef_name_with_methods.Namespace}')
                print(f'\tType: {typedef_name_with_methods.Type}')

                for method in typedef_name_with_methods.Methods:
                    try:
                        print(f'\t\tMethod: {method.Name}')
                        if method.RawBytes:
                            method_body = reader.read_method_body_from_bytes(method.RawBytes)

                            print('\t\tDisassembled code:')
                            for instruction in method_body.instructions:
                                if instruction.operand:
                                    print(f'\t\t\t{instruction.mnemonic}\t{instruction.operand}')
                                else:
                                    print(f'\t\t\t{instruction.mnemonic}')
                    except MethodBodyFormatError as e:
                        print(f'Disassembling of method failed - {e}')


def main():
    parser = argparse.ArgumentParser(prog='dotnetfile_disassemble.py', description='Disassemble .NET assembly IL code.')
    parser.add_argument('file', type=str, help='Absolute file path of .NET assembly.')
    args = parser.parse_args()

    disasm = Disassembler(args.file)
    disasm.disassemble_file()


if __name__ == '__main__':
    main()
