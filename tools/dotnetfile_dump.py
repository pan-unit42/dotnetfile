"""
Author: Dominik Reichel - Palo Alto Networks (2022-2025)

Display CLR header information of .NET assemblies.
"""

# pylint: disable=E1101

import os
import sys
import argparse
import traceback

from dotnetfile import DotNetPE
from typing import List


def process_file(file_path: str) -> None:
    if not os.path.isabs(file_path):
        print('[-] Please provide absolute file path of .NET assembly.')
        return

    print('---')
    print(f"Processing: {file_path}")
    print('---\n')

    dotnet_file = DotNetPE(file_path)

    print('General information')
    print(f'\t.NET runtime target version: {dotnet_file.get_runtime_target_version()}')
    print(f'\tNumber of streams: {dotnet_file.get_number_of_streams()}')
    print(f'\tHas .NET resources: {dotnet_file.has_resources()}')
    print(f'\tIs a mixed .NET assembly (managed + native code): {dotnet_file.is_mixed_assembly()}')
    print(f'\tHas a native entry point: {dotnet_file.has_native_entry_point()}')
    print(f'\tIs a native image (precompiled) created by Ngen: {dotnet_file.is_native_image()}')
    print(f'\tIs a Windows Forms app: {dotnet_file.is_windows_forms_app()}')
    print(f'\tIs a reference assembly: {dotnet_file.is_reference_assembly()}\n')

    print('General assembly information')
    print('\tAssembly attributes:')
    assembly_attributes = dotnet_file.get_assembly_attributes()
    for assembly_attribute in assembly_attributes:
        print(f'\t\t{assembly_attribute}')
    print('\tCommon assembly attributes with values:')
    assembly_attributes_with_values = dotnet_file.get_assembly_attributes_with_values()
    for assembly_attribute, assembly_attribute_value in assembly_attributes_with_values.items():
        if assembly_attribute_value:
            print(f'\t\t{assembly_attribute}: {assembly_attribute_value}')

    print('Anti analysis tricks')
    print(f'\t.NET data directory hidden in PE header: {dotnet_file.AntiMetadataAnalysis.is_dotnet_data_directory_hidden}')
    print(f'\tHas extra data at the end of the metadata header: {dotnet_file.AntiMetadataAnalysis.has_metadata_table_extra_data}')
    print(f'\tHas fake types that reference each other: {dotnet_file.AntiMetadataAnalysis.has_self_referenced_typeref_entries}')
    print(f'\tHas invalid entries in TypeRef table: {dotnet_file.AntiMetadataAnalysis.has_invalid_typeref_entries}')
    print(f'\tHas fake data streams: {dotnet_file.AntiMetadataAnalysis.has_fake_data_streams}')
    print(f'\tHas more than one row in Module table: {dotnet_file.AntiMetadataAnalysis.module_table_has_multiple_rows}')
    print(f'\tHas more than one row in Assembly table: {dotnet_file.AntiMetadataAnalysis.assembly_table_has_multiple_rows}')
    print(f'\tHas invalid entries in #Strings stream: {dotnet_file.AntiMetadataAnalysis.has_invalid_strings_stream_entries}')
    print(f'\tHas invalid entries in MethodDef table: {dotnet_file.AntiMetadataAnalysis.has_invalid_methoddef_entries}')
    print(f'\tHas maximum length exceeding string(s): {dotnet_file.AntiMetadataAnalysis.has_max_len_exceeding_strings}')
    print(f'\tHas mixed case stream name(s): {dotnet_file.AntiMetadataAnalysis.has_mixed_case_stream_names}')
    print(f'\tStream name(s) padding bytes patched: {dotnet_file.AntiMetadataAnalysis.stream_name_padding_bytes_patched}\n')

    defined_entry_point = dotnet_file.Cor20Header.get_header_entry_point()
    if defined_entry_point:
        print('Cor20Header')
        if defined_entry_point.EntryPointType == 'Managed':
            print('\tManaged entry point:')
            print(f'\t\tMethod: {defined_entry_point.Method}')
            print(f'\t\tType: {defined_entry_point.Type}')
            print(f'\t\tNamespace: {defined_entry_point.Namespace}')
            if defined_entry_point.Signature:
                print('\t\tSignature:')
                print(f'\t\t\tParameter: {defined_entry_point.Signature["parameter"]}')
                print(f'\t\t\tReturn value: {defined_entry_point.Signature["return"]}')
                print(f'\t\t\tHas this pointer: {defined_entry_point.Signature["hasthis"]}')
        elif defined_entry_point.EntryPointType == 'Native':
            print('\tNative entry point:')
            print(f'\t\tAddress: {defined_entry_point.Address}')
        print()

    print('Stream names:')
    stream_names = dotnet_file.get_stream_names()
    for stream_name in stream_names:
        print(f'\t{stream_name}')
    print()

    print('All references:')
    all_references = dotnet_file.get_all_references()
    for reference in all_references:
        print(f'\t{reference}')
    print()

    print('#Strings stream strings:')
    strings_stream_strings = dotnet_file.get_strings_stream_strings()
    for string in strings_stream_strings:
        print(f'\t{string}')
    print()

    print('#US stream strings:')
    us_stream_strings = dotnet_file.get_user_stream_strings()
    for string in us_stream_strings:
        print(f'\t{string}')
    print()

    print('Existent metadata tables')
    available_tables = dotnet_file.existent_metadata_tables()
    for table in available_tables:
        print(f'\t{table}')
    print()

    if 'Module' in available_tables:
        print('Module')
        print(f'\tName: {dotnet_file.Module.get_module_name()}\n')

    if 'Assembly' in available_tables:
        print('Assembly')
        print(f'\tName: {dotnet_file.Assembly.get_assembly_name()}')
        print(f'\tCulture: {dotnet_file.Assembly.get_assembly_culture()}')
        assembly_version_info = dotnet_file.Assembly.get_assembly_version_information()
        if assembly_version_info:
            print(f'\tVersion information: {assembly_version_info.BuildNumber}.{assembly_version_info.MajorVersion}.'
                  f'{assembly_version_info.MinorVersion}.{assembly_version_info.RevisionNumber}')
        print()

    if 'AssemblyRef' in available_tables:
        print('AssemblyRef')
        print('\tNames with versions:')
        assembly_names_with_versions = dotnet_file.AssemblyRef.get_assemblyref_names_with_versions(deduplicate=True)
        for assembly_name, assembly_version in assembly_names_with_versions.items():
            if isinstance(assembly_version, List):
                assembly_versions = ', '.join(assembly_version)
                print(f'\t\t{assembly_name}: {assembly_versions}')
            else:
                print(f'\t\t{assembly_name}: {assembly_version}')
        print('\tCultures:')
        culture_names = dotnet_file.AssemblyRef.get_assemblyref_cultures()
        for culture_name in culture_names:
            print(f'\t\t{culture_name}')
        print()

    if 'ModuleRef' in available_tables:
        print('ModuleRef')
        print('\tUnmanaged module names (normalized):')
        unmanaged_modules = dotnet_file.ModuleRef.get_unmanaged_module_names(dotnet_file.Type.UnmanagedModules.NORMALIZED)
        for unmanaged_module in unmanaged_modules:
            print(f'\t\t{unmanaged_module}')
        print()

    if 'ImplMap' in available_tables:
        print('ImplMap')
        print('\tUnmanaged functions:')
        unmanaged_functions = dotnet_file.ImplMap.get_unmanaged_functions()
        for unmanaged_function in unmanaged_functions:
            print(f'\t\t{unmanaged_function}')

    if 'TypeRef' in available_tables:
        print('TypeRef')
        print('\tReferenced type names:')
        ref_type_names = dotnet_file.TypeRef.get_typeref_names()
        for ref_type_name in ref_type_names:
            print(f'\t\t{ref_type_name}')

        print('\tTypeRef hash (unsorted):')
        print(f'\t\tSHA256: {dotnet_file.TypeRef.get_typeref_hash()}')

        print('\tTypeRef hash (sorted, include self-referenced entries):')
        print(f'\t\tSHA256: {dotnet_file.TypeRef.get_typeref_hash(skip_self_referenced_entries=False, strings_sorted=True)}\n')

    if 'TypeDef' in available_tables:
        print('TypeDef')
        print('\tType names:')
        type_names = dotnet_file.TypeDef.get_type_names()
        for type_name in type_names:
            print(f'\t\t{type_name}')
        print()

    if 'MethodDef' in available_tables:
        print('MethodDef')
        print('\tMethod names:')
        method_names = dotnet_file.MethodDef.get_method_names()
        for method_name in method_names:
            print(f'\t\t{method_name}')

        print('\tPossible method entry points:')
        entry_points = dotnet_file.MethodDef.get_entry_points()
        for entry_point in entry_points:
            print(f'\t\tMethod: {entry_point.Method}')
            print(f'\t\tType: {entry_point.Type}')
            print(f'\t\tNamespace: {entry_point.Namespace}')
            if entry_point.Signature:
                print('\t\tSignature:')
                print(f'\t\t\t\tParameter: {entry_point.Signature["parameter"]}')
                print(f'\t\t\t\tReturn value: {entry_point.Signature["return"]}')
                print(f'\t\t\t\tHas this pointer: {entry_point.Signature["hasthis"]}')
            print('\t\t---')
        print()

    if 'MemberRef' in available_tables:
        print('MemberRef')
        print('\tNames:')
        memberref_names = dotnet_file.MemberRef.get_fully_qualified_memberref_names(deduplicate=True, strings_sorted=True)
        for memberref_name in memberref_names:
            print(f'\t\t{memberref_name}')

        print('\tMemberRef hash (unsorted):')
        print(f'\t\tSHA256: {dotnet_file.MemberRef.get_memberref_hash()}')

        print('\tMemberRef hash (sorted):')
        print(f'\t\tSHA256: {dotnet_file.MemberRef.get_memberref_hash(strings_sorted=True)}\n')

    if 'Event' in available_tables:
        print('Event')
        print('\tNames:')
        event_names = dotnet_file.Event.get_event_names()
        for event_name in event_names:
            print(f'\t\t{event_name}')
        print()

    if 'ManifestResource' in available_tables:
        print('ManifestResource')
        print('\tNames:')
        resource_names = dotnet_file.ManifestResource.get_resource_names()
        for resource_name in resource_names:
            print(f'\t\t{resource_name}')
        print()

    print('Resources:')
    resource_data = dotnet_file.get_resources()
    for data in resource_data:
        for resource_item in data.items():
            if resource_item[0] == 'SubResources':
                if resource_item[1]:
                    print('\tSubResources:')
                    for sub_resource in resource_item[1]:
                        for sub_resource_item in sub_resource.items():
                            print(f'\t\t{sub_resource_item[0]}: {sub_resource_item[1]}')
                        print('\t\t---')
            else:
                print(f'\t{resource_item[0]}: {resource_item[1]}')
        print('\t---')


def main():
    parser = argparse.ArgumentParser(prog='dotnetfile_dump.py', description='Show .NET header information of assembly.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', dest='input_file', type=str, help='Absolute file path of .NET assembly.')
    group.add_argument('-d', '--directory', dest='input_dir', type=str,
                       help='Absolute directory path containing .NET assemblies.')
    args = parser.parse_args()

    if args.input_file:
        process_file(args.input_file)
    elif args.input_dir:
        if not os.path.isabs(args.input_dir):
            print('[-] Please provide absolute directory path.')
            return

        if not os.path.isdir(args.input_dir):
            print(f'[-] Directory does not exist: {args.input_dir}')
            return

        file_count = 0
        for file_name in os.listdir(args.input_dir):
            file_path = os.path.join(args.input_dir, file_name)
            if os.path.isfile(file_path):
                try:
                    process_file(file_path)
                    file_count += 1
                except Exception as e:
                    print(f'[-] Error processing {file_path} - {e}')
                    print('\tException details:', file=sys.stderr)
                    traceback.print_exc(file=sys.stderr)

        print(f'\nProcessed {file_count} files from directory: {args.input_dir}')


if __name__ == '__main__':
    main()
