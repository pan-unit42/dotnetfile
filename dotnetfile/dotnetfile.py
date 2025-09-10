"""
Author: Dominik Reichel - Palo Alto Networks (2021-2025)

dotnetfile - Interface library for the CLR header parser library for Windows .NET assemblies.

The following references were used:
    CLI specification (ECMA-335 standard)
        https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-335.pdf
    Microsoft .NET metadata documentation
        https://docs.microsoft.com/en-us/dotnet/api/system.reflection.metadata.ecma335?view=net-5.0
    .NET runtime code
        https://github.com/dotnet/runtime

Thanks to the authors of the following tools and libraries:
    - dnSpy + dnlib
    - dotPeek
    - ILSpy
"""

from struct import unpack
from dataclasses import dataclass, field
from hashlib import md5, sha1, sha256
from enum import Enum, IntEnum, IntFlag, auto
from typing import List, Dict, Optional, Union, Tuple, Set

from pefile import PEFormatError

from .parser import DotNetPEParser
from .constants import METADATA_TABLE_INDEXES, FAST_LOAD_TABLES_DEFAULT, METADATA_TOKEN_TABLES


METADATA_TABLES = {}
FAST_LOAD_OPTIONS = {
    'header_only',
    'normal',
    'normal_resources'
}
FULL_LOAD_OPTIONS = {
    'normal',
    'normal_resources',
    'full'
}


def metatable(cls):
    METADATA_TABLES[cls.__name__] = cls
    return cls


class Type:
    class MethodDefMask(IntEnum):
        """
        Sources:
        https://www.ecma-international.org/publications-and-standards/standards/ecma-335/
        https://docs.microsoft.com/en-us/dotnet/api/system.reflection.methodattributes?view=net-5.0
        """
        MEMBERACCESS = 7
        UNMANAGEDEXPORT = 8
        STATIC = 16
        FINAL = 32
        VIRTUAL = 64
        HIDEBYSIG = 128
        VTABLELAYOUTMASK = 256
        STRICT = 512
        ABSTRACT = 1024
        SPECIALNAME = 2048
        RTSPECIALNAME = 4096
        PINVOKEIMPL = 8192
        HASSECURITY = 16384
        REQUIRESECOBJECT = 32768

    class MethodDefMemberAccess(IntFlag):
        """
        Sources:
        https://www.ecma-international.org/publications-and-standards/standards/ecma-335/
        https://docs.microsoft.com/en-us/dotnet/api/system.reflection.methodattributes?view=net-5.0
        """
        COMPILERCONTROLLED = auto()
        PRIVATE = auto()
        FAMANDASSEM = auto()
        ASSEM = auto()
        FAMILY = auto()
        FAMORASSEM = auto()
        PUBLIC = auto()
        ANY = auto()

    class TypeDefMask(IntEnum):
        """
        Sources:
        https://www.ecma-international.org/publications-and-standards/standards/ecma-335/
        https://docs.microsoft.com/en-us/dotnet/api/system.reflection.typeattributes?view=net-5.0
        """
        VISIBILITY = 7
        LAYOUT = 24
        CLASSSEMANTIC = 32

    class TypeDefVisibility(IntFlag):
        """
        Sources:
        https://www.ecma-international.org/publications-and-standards/standards/ecma-335/
        https://docs.microsoft.com/en-us/dotnet/api/system.reflection.typeattributes?view=net-5.0
        """
        NOTPUBLIC = auto()
        PUBLIC = auto()
        NESTEDPUBLIC = auto()
        NESTEDPRIVATE = auto()
        NESTEDFAMILY = auto()
        NESTEDASSEMBLY = auto()
        NESTEDFAMANDASSEM = auto()
        NESTEDFAMORASSEM = auto()
        ANY = auto()

    class TypeDefClassSemantics(IntEnum):
        """
        Sources:
        https://www.ecma-international.org/publications-and-standards/standards/ecma-335/
        https://docs.microsoft.com/en-us/dotnet/api/system.reflection.typeattributes?view=net-5.0
        """
        CLASS = 0
        INTERFACE = 32

    class UnmanagedFunctions(IntEnum):
        RAW = 0
        CHARSET = 1
        NOSET = 2

    class UnmanagedModules(IntEnum):
        RAW = 0
        NORMALIZED = 1

    class Hash(IntEnum):
        MD5 = 0
        SHA1 = 1
        SHA256 = 2

    class EntryPoint(Enum):
        NATIVE = 'Native'
        MANAGED = 'Managed'


class Struct:
    @dataclass
    class NativeEntryPoint:
        EntryPointType: str
        Address: str

    @dataclass
    class ManagedEntryPoint:
        EntryPointType: str
        Method: str
        Type: Optional[str] = ''
        Namespace: Optional[str] = ''
        Signature: Optional[Dict] = ''

    @dataclass
    class TypesMethods:
        Type: str
        Namespace: str
        Methods: List['Methods']
        Flags: int

    @dataclass
    class Methods:
        Name: str
        Signature: Dict
        Flags: int
        RVA: int
        HeaderSize: int
        CodeSize: int
        RawBytes: bytes

    @dataclass
    class EntryPoint:
        Method: str
        Signature: Dict
        Type: str
        Namespace: str

    @dataclass
    class AssemblyInfo:
        MajorVersion: int
        MinorVersion: int
        BuildNumber: int
        RevisionNumber: int

    @dataclass
    class StringToken:
        stream: str
        string_address: int
        string: str = ''

    @dataclass
    class TableToken:
        table: str
        row: int
        strings: Dict = field(default_factory=dict)


class DotNetPE(DotNetPEParser):
    def __init__(self, path: str, fast_load: str = '', fast_load_tables: List = FAST_LOAD_TABLES_DEFAULT):
        # Fast load options:
        # header_only      - Load only header data and skip metadata tables
        # normal           - Load header data and only metadata tables necessary for the interface library.
        #                    Optionally, you can choose your own list of metadata tables to be loaded in
        #                    fast_load_tables. However, it's advised not to change the default list unless
        #                    you know what you are doing.
        # normal_resources - Load header data, only metadata tables necessary for interface library and resources.
        #                    Optionally, you can also choose your own list of metadata tables.
        #
        # By default, when no fast load option is used, all data is loaded (can be slow for big files).
        if fast_load:
            if not self._is_fast_load_valid(fast_load):
                raise Exception(f'Fast load option "{fast_load}" does not exist.')
        super().__init__(path, fast_load, fast_load_tables)
        self.AntiMetadataAnalysis = AntiMetadataAnalysis(self)
        self.Cor20Header = Cor20Header(self)
        self.Type = Type()
        self._initialize_metadata_table_objects()

    @staticmethod
    def _is_fast_load_valid(option: str) -> bool:
        result = False

        if option in FAST_LOAD_OPTIONS:
            result = True

        return result

    def _initialize_metadata_table_objects(self) -> None:
        for table_name, table_obj in METADATA_TABLES.items():
            if self.metadata_table_exists(table_name):
                table_instance = table_obj(self)
                setattr(self, table_name, table_instance)

    def full_load_data(self, option: str = '') -> bool:
        # Full load options:
        # normal           - Load header data and only metadata tables necessary for the interface library.
        #                    Possible preceding fast load option: header_only
        # normal_resources - Depending on the previous fast load option(s), load metadata tables necessary for
        #                    the interface library and resources or only the resources.
        #                    Possible preceding fast load options: header_only, normal
        # full             - Depending on the previous fast load option(s), load all or the remaining metadata
        #                    tables necessary for the interface library and the resources.
        #                    Possible preceding fast load options: header_only, normal, normal_resource
        result = False

        if option not in FULL_LOAD_OPTIONS:
            self.logger.info(f'Full load option "{option}" does not exist.')
            return result

        if option == 'normal' and self.fast_load == 'header_only':
            self.parse_dotnet_streams()
            self._initialize_metadata_table_objects()
            self.fast_load = 'normal'
            result = True
        elif option == 'normal_resources' and self.fast_load == 'header_only':
            self.parse_dotnet_streams()
            self.parse_dotnet_resources()
            self._initialize_metadata_table_objects()
            self.fast_load = 'normal_resources'
            result = True
        elif option == 'full' and self.fast_load == 'header_only':
            self.fast_load = None
            self.parse_dotnet_streams()
            self.parse_dotnet_resources()
            self._initialize_metadata_table_objects()
            result = True
        elif option == 'normal_resources' and self.fast_load == 'normal':
            self.parse_dotnet_resources()
            self.fast_load = 'normal_resources'
            result = True
        elif option == 'full' and self.fast_load == 'normal':
            self.parse_metadata_tables(self.full_load_tables)
            self.parse_non_standard_strings()
            self.parse_dotnet_resources()
            self._initialize_metadata_table_objects()
            self.fast_load = None
            result = True
        elif option == 'full' and self.fast_load == 'normal_resources':
            self.parse_metadata_tables(self.full_load_tables)
            self.parse_non_standard_strings()
            self._initialize_metadata_table_objects()
            self.fast_load = None
            result = True
        else:
            self.logger.info(f'Full load option "{option}" does not work with fast load option "{self.fast_load}".')

        return result

    def metadata_table_exists(self, name: str) -> bool:
        """
        Check if table exists in metadata tables.
        """
        result = False

        if name in self.metadata_tables_lookup.keys():
            result = True

        return result

    def existent_metadata_tables(self) -> List[str]:
        """
        Get all metadata tables that exist in the file.
        """
        return [*self.metadata_tables_lookup]

    def is_mixed_assembly(self) -> bool:
        """
        Check if the file is a mixed assembly that contains managed + native code.
        """
        result = False

        mixed_assembly_namespaces = [
            '<CppImplementationDetails>',
            '<CrtImplementationDetails>'
        ]

        # Check if the common mixed assembly namespaces '<CppImplementationDetails>' and '<CrtImplementationDetails>'
        # are referenced in the TypeDef table. We could also check for presence of these strings in the MethodDef table
        # or the #Strings stream.
        if self.metadata_table_exists('TypeDef'):
            namespaces = []
            for table_row in self.metadata_tables_lookup['TypeDef'].table_rows:
                namespace_string_address = table_row.string_stream_references['TypeNamespace']
                namespaces.append(self.get_string(namespace_string_address))

            if all(x in namespaces for x in mixed_assembly_namespaces):
                result = True

        return result

    def has_native_entry_point(self) -> bool:
        """
        Check if the file has a native entry point (and thus is also a mixed assembly).
        """
        result = False

        # Check if the file has the native entry point value set in the Cor20 header's flags. If the value 0x10 is set
        # (COMIMAGE_FLAGS_NATIVE_ENTRYPOINT), the file is also automatically a mixed assembly. However, not all mixed
        # assemblies have a native entry point. Additionally, we check if the EntryPointToken field that contains the
        # entry point address is not zero.
        if (self.clr_header.Flags.value & 0x10) == 0x10 and self.clr_header.EntryPointToken.value:
            result = True

        return result

    def is_native_image(self) -> bool:
        """
        Check if the file is a native image generated by the Ngen tool ngen.exe.
        """
        result = False

        # Check if the file has the IL Library value set in the Cor20 header's flags. If the value 0x4 is set
        # (COMIMAGE_FLAGS_IL_LIBRARY), the file is a native image created by Ngen. Additionally, we check if the
        # ManagedNativeHeader address field contains a value that points to the native image header.
        if (self.clr_header.Flags.value & 0x4) == 0x4 and self.clr_header.ManagedNativeHeaderAddress.value:
            result = True

        return result

    def is_windows_forms_app(self) -> bool:
        """
        Check if the file is a Windows Forms app.
        """
        result = False

        if 'System.Windows.Forms' in self.get_all_references():
            if self.metadata_table_exists('TypeRef'):
                for table_row in self.metadata_tables_lookup['TypeRef'].table_rows:
                    type_name_address = table_row.string_stream_references['TypeName']
                    if self.get_string(type_name_address) == 'STAThreadAttribute':
                        result = True

        return result

    def is_reference_assembly(self) -> bool:
        """
        Check if the file is a reference assembly:
        https://learn.microsoft.com/en-us/dotnet/standard/assembly/reference-assemblies
        """
        result = False

        if 'ReferenceAssembly' in self.get_assembly_attributes():
            result = True

        return result

    def has_resources(self) -> bool:
        """
        Check if .NET resources exist.
        """
        result = False

        # Check if the Resources RVA value in the Cor20 header isn't empty. If positive, the file has at least one
        # resource. Additionally, check if the assembly has a ManifestResource table that contains resource information.
        if self.clr_header.ResourcesDirectoryAddress.value and self.metadata_table_exists('ManifestResource'):
            result = True

        return result

    def get_string(self, string_address: int) -> str:
        """
        Get string from the #Strings stream lookup dictionary or the overlap strings list
        """
        string = self.dotnet_string_lookup.get(string_address, None)

        # If string index not present in normal string lookup dictionary, try to get it from overlap
        # string lookup dictionary
        if string is None:
            string = self.dotnet_overlap_string_lookup.get(string_address, None)

            # If that fails too, string index is bogus or points to non-existing string as done
            # by some obfuscators.
            if string is None:
                self.logger.debug(f'Failed to get string with address "{string_address}".')
                return ''

        return string.string_representation

    def get_user_string(self, string_address: int) -> str:
        """
        Get string from the #US (user-string) stream lookup dictionary
        """
        result = ''

        try:
            result = self.dotnet_user_string_lookup[string_address].string_representation
        except KeyError:
            self.logger.debug(f'There is no user string that starts at 0x{string_address:x}.')
        except Exception:
            self.logger.debug(f'Failed to get user string with address "{string_address}".')

        return result

    @staticmethod
    def get_hash(hash_type: Type.Hash, string_list: List) -> str:
        """
        Convert list of strings to single string and calculate hash.
        """
        result = ''

        if hash_type == Type.Hash.MD5:
            result = md5(','.join(string_list).encode())
        elif hash_type == Type.Hash.SHA1:
            result = sha1(','.join(string_list).encode())
        elif hash_type == Type.Hash.SHA256:
            result = sha256(','.join(string_list).encode())

        return result.hexdigest()

    def get_all_references(self) -> List[str]:
        """
        Get a list of all referenced libraries.
        """
        result = []

        if self.metadata_table_exists('AssemblyRef'):
            result = self.AssemblyRef.get_assemblyref_names(deduplicate=True)

        if self.metadata_table_exists('ModuleRef'):
            result += self.ModuleRef.get_unmanaged_module_names(Type.UnmanagedModules.NORMALIZED)

        return result

    def get_strings_stream_strings(self) -> List[str]:
        """
        Get all strings of the #Strings stream.
        """
        result = []

        for string in self.dotnet_string_lookup.values():
            result.append(string.string_representation)

        return result

    def get_user_stream_strings(self) -> List[str]:
        """
        Get all strings of the #US stream.
        """
        result = []

        for string in self.dotnet_user_string_lookup.values():
            result.append(string.string_representation)

        return result

    def get_stream_names(self) -> List[str]:
        """
        Get a list of stream names.
        """
        result = []

        for stream in self.dotnet_streams:
            result.append(stream.string_representation)

        return result

    def get_resources(self) -> List[Dict]:
        """
        Get .NET resources with additional information.
        """
        if not self.has_resources():
            self.logger.debug('File does not have .NET resources.')
            return []

        return self.dotnet_resources

    def get_runtime_target_version(self) -> str:
        """
        Get file's .NET runtime target version.
        """
        return self.dotnet_metadata_header.VersionString.field_text

    def get_number_of_streams(self) -> int:
        """
        Get number of total streams (includes fake streams).
        """
        return self.dotnet_metadata_header.NumberOfStreams.value

    def _resolve_token(self, token: int) -> Optional[Union[Struct.StringToken, Struct.TableToken]]:
        """
        Resolve a token to its TID (table index/#US stream) and RID (row index/string offset).
        """
        result = None

        try:
            tid = token >> 24
            rid = token & 0xffffff
            # Check if TID is 0x70 and thus referring to the #US heap (string token)
            if tid == 0x70:
                result = Struct.StringToken(stream='#US', string_address=rid)
            # Check if TID is referring to a metadata token table
            elif tid in (x >> 24 for x in METADATA_TOKEN_TABLES.keys()):
                table = METADATA_TOKEN_TABLES[tid << 24]
                if self.metadata_table_exists(table):
                    result = Struct.TableToken(table=table, row=rid)
        except Exception as e:
            self.logger.info(f'Could not resolve token "{token}" - {e}.')

        return result

    def get_token_strings(self, token_string: str) -> Optional[Union[Struct.StringToken, Struct.TableToken]]:
        """
        Get all strings from a token 0x... (hex string). String(s) can be from a table row -> TableToken
        or from #US stream offset -> StringToken.
        """
        token = int(token_string, 16)

        result = self._resolve_token(token)
        if isinstance(result, Struct.StringToken):
            result.string = self.get_user_string(result.string_address)  # pylint: disable=W0201
        elif isinstance(result, Struct.TableToken):
            try:
                row_data = self.metadata_tables_lookup[result.table].table_rows[result.row - 1]
                if row_data.string_stream_references:
                    for string_type, string_address in row_data.string_stream_references.items():
                        result.strings[string_type] = self.get_string(string_address)
            except Exception as e:
                self.logger.info(f'Token "{token_string}" seems to be invalid - {e}.')
                return None

        return result

    def get_assembly_attributes(self) -> Set[str]:
        """
        Get all assembly attributes from the CustomAttribute table.
        """
        result = set()

        if self.metadata_table_exists('CustomAttribute'):
            assembly_references = []
            for table_row in self.metadata_tables_lookup['CustomAttribute'].table_rows:
                if table_row.table_references['Parent'][0] == 'Assembly':
                    assembly_ref = table_row.table_references['Type']
                    assembly_references.append((assembly_ref[0], assembly_ref[1] - 1))

            memberref_references = []
            for assembly_reference in assembly_references:
                if self.metadata_table_exists(assembly_reference[0]):
                    if assembly_reference[0] == 'MemberRef':
                        member_ref = self.metadata_tables_lookup[assembly_reference[0]].table_rows[
                            assembly_reference[1]].table_references['Class']
                        memberref_references.append((member_ref[0], member_ref[1] - 1))

            string_references = []
            for memberref_reference in memberref_references:
                if self.metadata_table_exists(memberref_reference[0]):
                    if memberref_reference[0] == 'TypeRef':
                        string_references.append(self.metadata_tables_lookup[memberref_reference[0]].table_rows[
                            memberref_reference[1]].string_stream_references['TypeName'])

            for string_reference in string_references:
                attribute_name = self.get_string(string_reference)
                if attribute_name.endswith('Attribute'):
                    attribute_name = attribute_name[:-9]
                result.add(attribute_name)

        return result

    def get_assembly_attribute_value(self, attribute_name: str) -> str:
        """
        Get a specific attribute with details from the assembly.
        """
        result = ''

        if not self.metadata_table_exists('CustomAttribute') or not self.metadata_table_exists('Assembly'):
            return result

        try:
            assembly_name = self.Assembly.get_assembly_name()  # pylint: disable=E1101

            for table_row in self.metadata_tables_lookup['CustomAttribute'].table_rows:
                parent_ref = table_row.table_references['Parent']
                if parent_ref[0] != 'Assembly':
                    continue

                type_ref = table_row.table_references['Type']
                if type_ref[0] != 'MemberRef':
                    continue

                member_ref = self.metadata_tables_lookup[type_ref[0]].table_rows[type_ref[1] - 1]
                if self.get_string(member_ref.string_stream_references['Name']) != '.ctor':
                    continue

                parent_row = self.metadata_tables_lookup[parent_ref[0]].table_rows[parent_ref[1] - 1]
                if 'Name' not in parent_row.string_stream_references:
                    continue

                if self.get_string(parent_row.string_stream_references['Name']) != assembly_name:
                    continue

                class_ref = member_ref.table_references['Class']
                type_name_address = self.metadata_tables_lookup[
                    class_ref[0]].table_rows[class_ref[1] - 1].string_stream_references['TypeName']
                type_name = self.get_string(type_name_address)

                if type_name == attribute_name:
                    result = self.dotnet_blob_lookup[table_row.Value.value].structure_fields['FixedArguments'][0]
        except Exception as e:
            self.logger.debug(f"Error getting custom attribute '{attribute_name}' - {e}")

        return result

    def get_assembly_attributes_with_values(self) -> Dict[Optional[str], str]:
        """
        Get assembly attributes with values.
        References (assembly specific attributes):
        https://learn.microsoft.com/en-us/dotnet/standard/assembly/set-attributes
        https://learn.microsoft.com/en-us/dotnet/api/system.runtime.versioning.targetframeworkattribute
        Not assembly specific attributes:
        https://learn.microsoft.com/de-de/dotnet/api/system.runtime.interopservices.guidattribute
        """
        result = {}
        attributes = [
            'AssemblyCompanyAttribute',
            'AssemblyConfigurationAttribute',
            'AssemblyCopyrightAttribute',
            'AssemblyCultureAttribute',
            'AssemblyDefaultAliasAttribute',
            'AssemblyDelaySignAttribute',
            'AssemblyDescriptionAttribute',
            'AssemblyFileVersionAttribute',
            'AssemblyFlagsAttribute',
            'AssemblyInformationalVersionAttribute',
            'AssemblyKeyFileAttribute',
            'AssemblyKeyNameAttribute',
            'AssemblyProductAttribute',
            'AssemblyTitleAttribute',
            'AssemblyTrademarkAttribute',
            'AssemblyVersionAttribute',
            'TargetFrameworkAttribute',
            'GuidAttribute'  # not assembly specific
        ]

        for attr in attributes:
            key = attr.replace('Attribute', '')
            result[key] = self.get_assembly_attribute_value(attr)

        return result


class AntiMetadataAnalysis:
    """
    Contains detected metadata anti-parsing tricks.
    """
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    @property
    def is_dotnet_data_directory_hidden(self) -> bool:
        """
        .NET data directory in the PE header is hidden.
        """
        return self.dotnetpe.dotnet_anti_metadata['data_directory_hidden']

    @property
    def has_metadata_table_extra_data(self) -> bool:
        """
        Tables header contains 4 bytes of extra data.
        """
        return self.dotnetpe.dotnet_anti_metadata['metadata_table_has_extra_data']

    @property
    def has_self_referenced_typeref_entries(self) -> bool:
        """
        TypeRef table contains entries that reference each other.
        """
        result = False

        if not self.dotnetpe.metadata_table_exists('TypeRef'):
            self.dotnetpe.logger.debug('File does not have a TypeRef table.')
            return result

        for current_row_index, table_row in enumerate(self.dotnetpe.metadata_tables_lookup['TypeRef'].table_rows):
            type_name = table_row.table_references['ResolutionScope'][0]

            if type_name == 'TypeRef':
                table_row_reference = table_row.table_references['ResolutionScope'][1] - 1

                # Skip invalid entries
                if table_row_reference >= len(self.dotnetpe.metadata_tables_lookup['TypeRef'].table_rows):
                    continue

                if self.dotnetpe.metadata_tables_lookup['TypeRef'].table_rows[
                        table_row_reference].table_references['ResolutionScope'][1] - 1 == current_row_index:
                    result = True
                    break

        return result

    @property
    def has_invalid_typeref_entries(self) -> bool:
        """
        TypeRef table contains invalid entries.
        """
        result = False

        if not self.dotnetpe.metadata_table_exists('TypeRef'):
            self.dotnetpe.logger.debug('File does not have a TypeRef table.')
            return result

        for table_row in self.dotnetpe.metadata_tables_lookup['TypeRef'].table_rows:
            type_name = table_row.table_references['ResolutionScope'][0]

            if type_name == 'TypeRef':
                table_row_reference = table_row.table_references['ResolutionScope'][1] - 1
                type_name_address = table_row.string_stream_references['TypeName']

                if table_row_reference > len(self.dotnetpe.metadata_tables_lookup[
                        'TypeRef'].table_rows) or not type_name_address:
                    result = True
                    break

        return result

    @property
    def has_fake_data_streams(self) -> bool:
        """
        CLR header contains fake data streams.
        """
        return self.dotnetpe.dotnet_anti_metadata['has_fake_data_streams']

    @property
    def module_table_has_multiple_rows(self) -> bool:
        """
        Module table has more than one row.
        """
        result = False

        if self.dotnetpe.metadata_table_exists('Module'):
            if len(self.dotnetpe.metadata_tables_lookup['Module'].table_rows) > 1:
                result = True

        return result

    @property
    def assembly_table_has_multiple_rows(self) -> bool:
        """
        Assembly table has more than one row.
        """
        result = False

        if self.dotnetpe.metadata_table_exists('Assembly'):
            if len(self.dotnetpe.metadata_tables_lookup['Assembly'].table_rows) > 1:
                result = True

        return result

    @property
    def has_invalid_strings_stream_entries(self) -> bool:
        """
        #Strings stream contains invalid entries.
        """
        return self.dotnetpe.dotnet_anti_metadata['has_invalid_strings_stream_entries']

    @property
    def has_invalid_methoddef_entries(self) -> bool:
        """
        MethodDef table contains invalid entries.
        """
        result = False

        if not self.dotnetpe.metadata_table_exists('MethodDef'):
            self.dotnetpe.logger.debug('File does not have a MethodDef table.')
            return result

        for table_row in self.dotnetpe.metadata_tables_lookup['MethodDef'].table_rows:
            if table_row.RVA.value == table_row.Flags.value == table_row.Name.value == table_row.Signature.value == 0:
                result = True
                break

        return result

    @property
    def has_max_len_exceeding_strings(self) -> bool:
        """
        #Strings stream contains string(s) that exceed(s) maximum length defined in Roslyn compiler.
        """
        return self.dotnetpe.dotnet_anti_metadata['has_max_len_exceeding_strings']

    @property
    def has_mixed_case_stream_names(self) -> bool:
        """
        Stream names are made of mixed case characters (e.g. #strinGs, #BloB, ...) instead of the
        officially used names (#Strings, #Blob, ...)
        """
        return self.dotnetpe.dotnet_anti_metadata['has_mixed_case_stream_names']

    @property
    def stream_name_padding_bytes_patched(self) -> bool:
        """
        Stream name padding/boundary bytes in the metadata header were overwritten with random values
        instead of being 0x0.
        """
        return self.dotnetpe.dotnet_anti_metadata['stream_name_padding_bytes_patched']


class Cor20Header:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def entry_point_exists(self) -> bool:
        """
        Check if defined entry point exists.
        """
        return True if self.dotnetpe.clr_header.EntryPointToken.value else False

    def get_header_entry_point(self) -> Optional[Union[Struct.NativeEntryPoint, Struct.ManagedEntryPoint]]:
        """
        Get defined entry point along with type, namespace and possible parameter(s).

        TODO: Add more blob signatures or create proper blob signature decoding
        """
        flag_native_entry_point = 0x10
        result = None

        if not self.entry_point_exists() or not self.dotnetpe.metadata_table_exists(
                'TypeDef') or not self.dotnetpe.metadata_table_exists(
                'MethodDef') or not self.dotnetpe.dotnet_string_lookup:
            self.dotnetpe.logger.debug('Cross-reference error: File does not have a TypeDef or MethodDef table.')
            return result

        # Check if the file has a native entry point
        if (self.dotnetpe.clr_header.Flags.value & flag_native_entry_point) == flag_native_entry_point:
            return Struct.NativeEntryPoint(Type.EntryPoint.NATIVE.value,
                                           hex(self.dotnetpe.clr_header.EntryPointToken.value))

        entry_point_token = self.dotnetpe.clr_header.EntryPointToken.value
        table_index = entry_point_token >> 24
        table_row = entry_point_token & 0xffffff

        metadata_table_row = self.dotnetpe.metadata_tables_lookup[METADATA_TABLE_INDEXES[table_index]].table_rows[
            table_row - 1]

        method_string_address = metadata_table_row.string_stream_references['Name']
        method_name = self.dotnetpe.get_string(method_string_address)
        result = Struct.ManagedEntryPoint(Type.EntryPoint.MANAGED.value, method_name)

        method_signature_index = metadata_table_row.blob_stream_references['Signature']
        method_signature = self.dotnetpe.dotnet_blob_lookup[method_signature_index]

        types_with_methods = self.dotnetpe.TypeDef.get_type_names_with_methods()

        for type_with_method in types_with_methods:
            for method in type_with_method.Methods:
                if method.Name == method_name and method.Signature == method_signature.structure_fields:
                    result.Type = type_with_method.Type
                    result.Namespace = type_with_method.Namespace
                    result.Signature = method_signature.structure_fields

        return result


# Table 0
@metatable
class Module:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_module_name(self) -> str:
        """
        Get module name.
        """
        # To counteract .NET protectors like ConfuserEx that add additional entries, we skip the remaining row(s) as
        # they are officially not supported and contain invalid entries
        string_address = self.dotnetpe.metadata_tables_lookup['Module'].table_rows[0].string_stream_references['Name']
        return self.dotnetpe.get_string(string_address)


# Table 1
@metatable
class TypeRef:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_typeref_names(self) -> List[str]:
        """
        Get a list of referenced type names.
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['TypeRef'].table_rows:
            type_string_address = table_row.string_stream_references['TypeName']
            type_name = self.dotnetpe.get_string(type_string_address)
            result.append(type_name)

        return result

    def get_typeref_hash(self, hash_type: Type.Hash = Type.Hash.SHA256, skip_self_referenced_entries: bool = True,
                         strings_sorted: bool = False) -> str:
        """
        Get hash of type and their corresponding resolution scope names.

        In contrast to the TypeRefHash implementation from GData, we use the resolution scope names instead of
        the namespace names as they're always present. Additionally, you can skip types that reference each other as
        added by some .NET protectors. Furthermore, the list of scope and type names can be sorted alphabetically after
        the type names before being hashed. Strings are also used case-sensitive and the resolution scope <-> type ref
        name pairs are also concatenated with a dash.

        Options:
            - Type.Hash.MD5, Type.Hash.SHA1, Type.Hash.SHA256
            - Skip types that reference each other (added by some .NET protectors)
            - Strings unsorted or sorted (after the type names)

        GData TypeRef hash:
            https://www.gdatasoftware.com/blog/2020/06/36164-introducing-the-typerefhash-trh
        """
        scopes_types = []
        for current_row_index, table_row in enumerate(self.dotnetpe.metadata_tables_lookup['TypeRef'].table_rows):
            type_string_address = table_row.string_stream_references['TypeName']
            type_name = self.dotnetpe.get_string(type_string_address)

            resolution_scope_table = table_row.table_references['ResolutionScope'][0]
            resolution_scope_index = table_row.table_references['ResolutionScope'][1] - 1
            current_type_name_address = table_row.string_stream_references['TypeName']

            # Skip invalid type rows
            if resolution_scope_index > len(
                    self.dotnetpe.metadata_tables_lookup['TypeRef'].table_rows) or not current_type_name_address:
                continue

            if skip_self_referenced_entries and \
                resolution_scope_table == 'TypeRef' and \
                self.dotnetpe.AntiMetadataAnalysis.has_self_referenced_typeref_entries and \
                self.dotnetpe.metadata_tables_lookup['TypeRef'].table_rows[
                    resolution_scope_index].table_references['ResolutionScope'][1] - 1 == current_row_index:
                continue

            name = ''
            if resolution_scope_table in ['Module', 'ModuleRef', 'AssemblyRef']:
                name = 'Name'
            elif resolution_scope_table == 'TypeRef':
                name = 'TypeName'

            resolution_scope_string_address = self.dotnetpe.metadata_tables_lookup[resolution_scope_table].table_rows[
                resolution_scope_index].string_stream_references[name]
            resolution_scope_name = self.dotnetpe.get_string(resolution_scope_string_address)

            scopes_types.append((resolution_scope_name, type_name))

        if strings_sorted:
            def key(x):
                return x[0].lower(), x[1].lower()

            scopes_types = sorted(scopes_types, key=key)

        scopes_types = [x[0] + '-' + x[1] for x in scopes_types]

        return self.dotnetpe.get_hash(hash_type, scopes_types)


# Table 2
@metatable
class TypeDef:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_type_names(self, visibility: int = Type.TypeDefVisibility.ANY) -> List[str]:
        """
        Get a list of defined type names.

        Visibility options:
            Type.TypeDefVisibility.NOTPUBLIC, Type.TypeDefVisibility.PUBLIC,
            Type.TypeDefVisibility.NESTEDPUBLIC, Type.TypeDefVisibility.NESTEDPRIVATE,
            Type.TypeDefVisibility.NESTEDFAMILY, Type.TypeDefVisibility.NESTEDASSEMBLY,
            Type.TypeDefVisibility.NESTEDFAMANDASSEM, Type.TypeDefVisibility.NESTEDFAMORASSEM,
            Type.TypeDefVisibility.ANY
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['TypeDef'].table_rows:
            type_string_address = table_row.string_stream_references['TypeName']
            type_name = self.dotnetpe.get_string(type_string_address)

            if (visibility & Type.TypeDefVisibility.ANY) == Type.TypeDefVisibility.ANY:
                result.append(type_name)
                continue

            flag = table_row.Flags.value & Type.TypeDefMask.VISIBILITY

            if (visibility & Type.TypeDefVisibility.NOTPUBLIC) == Type.TypeDefVisibility.NOTPUBLIC \
                    and flag == 0:
                result.append(type_name)
            elif (visibility & Type.TypeDefVisibility.PUBLIC) == Type.TypeDefVisibility.PUBLIC \
                    and flag == 1:
                result.append(type_name)
            elif (visibility & Type.TypeDefVisibility.NESTEDPUBLIC) == Type.TypeDefVisibility.NESTEDPUBLIC \
                    and flag == 2:
                result.append(type_name)
            elif (visibility & Type.TypeDefVisibility.NESTEDPRIVATE) == Type.TypeDefVisibility.NESTEDPRIVATE \
                    and flag == 3:
                result.append(type_name)
            elif (visibility & Type.TypeDefVisibility.NESTEDFAMILY) == Type.TypeDefVisibility.NESTEDFAMILY \
                    and flag == 4:
                result.append(type_name)
            elif (visibility & Type.TypeDefVisibility.NESTEDASSEMBLY) == Type.TypeDefVisibility.NESTEDASSEMBLY \
                    and flag == 5:
                result.append(type_name)
            elif (visibility & Type.TypeDefVisibility.NESTEDFAMANDASSEM) == Type.TypeDefVisibility.NESTEDFAMANDASSEM \
                    and flag == 6:
                result.append(type_name)
            elif (visibility & Type.TypeDefVisibility.NESTEDFAMORASSEM) == Type.TypeDefVisibility.NESTEDFAMORASSEM \
                    and flag == 7:
                result.append(type_name)

        return result

    def _get_method_header_information(self, reader_pos: int) -> Tuple[int, int, int, int]:
        header_size, code_size, flags = 0, 0, 0

        if self._is_reader_position_valid(reader_pos):
            header_data = self.dotnetpe.get_data(reader_pos, 1)
            if header_data:
                header_byte = unpack('B', header_data)[0]
                reader_pos += 1
                header_flag = header_byte & 7

                if header_flag == 2 or header_flag == 6:
                    header_size = 1
                    code_size = header_byte >> 2
                elif header_flag == 3:
                    flags = (unpack('B', self.dotnetpe.get_data(reader_pos, 1))[0] << 8) | header_byte
                    reader_pos += 3
                    header_size = flags >> 12
                    code_size = unpack('I', self.dotnetpe.get_data(reader_pos, 4))[0]
                    reader_pos += 8

                    reader_pos = reader_pos - 12 + header_size * 4

                if header_size < 3:
                    flags &= 0xFFF7

                header_size *= 4

        return header_size, code_size, flags, reader_pos

    def _is_reader_position_valid(self, position: int) -> bool:
        result = True

        try:
            if self.dotnetpe.get_offset_from_rva(position) >= self.dotnetpe.file_size:
                result = False
        except PEFormatError:
            result = False

        if not result:
            self.dotnetpe.logger.debug(f'Method reader at position "{position}" (RVA) exceeds file size.')

        return result

    def get_method_data(self, rva: int) -> Tuple[int, int, bytes]:
        reader_position = rva
        method_header_size, method_code_size, method_flags, reader_position = \
            self._get_method_header_information(reader_position)

        if method_header_size == method_code_size == method_flags == 0:
            return 0, 0, bytes()

        reader_position += method_code_size
        if not self._is_reader_position_valid(reader_position):
            return 0, 0, bytes()

        if method_flags & 8 != 0:
            reader_position = (reader_position + 3) & ~3
            b = unpack('B', self.dotnetpe.get_data(reader_position, 1))[0]
            reader_position += 1

            if (b & 0x3F) != 1:
                reader_position -= 1
            elif (b & 0x40) != 0:
                reader_position -= 1
                num = ((unpack('I', self.dotnetpe.get_data(reader_position, 4))[0] >> 8) // 24)
                reader_position = reader_position + 4 + num * 24
            else:
                num = unpack('B', self.dotnetpe.get_data(reader_position, 1))[0] // 12
                reader_position = reader_position + 1 + 2 + num * 12

        method_body_length = reader_position - rva

        method_data = self.dotnetpe.get_data(rva, method_body_length)

        return method_header_size, method_code_size, method_data

    def get_type_names_with_methods(self) -> List[Struct.TypesMethods]:
        """
        Get type names with all corresponding methods.
        """
        result = []

        if not self.dotnetpe.metadata_table_exists('MethodDef'):
            self.dotnetpe.logger.debug('Cross-reference error: File does not have a TypeDef or MethodDef table.')
            return result

        typedef_table_rows = self.dotnetpe.metadata_tables_lookup['TypeDef'].table_rows
        methoddef_table_rows = self.dotnetpe.metadata_tables_lookup['MethodDef'].table_rows

        current_method_index = 0
        for i, typedef_table_row in enumerate(typedef_table_rows, start=1):
            current_methodlist_count = typedef_table_row.MethodList.value
            try:
                next_methodlist_count = typedef_table_rows[i].MethodList.value
                method_count = next_methodlist_count - current_methodlist_count
            except IndexError:
                method_count = len(methoddef_table_rows) + 1 - current_methodlist_count

            type_string_address = typedef_table_row.string_stream_references['TypeName']
            type_name = self.dotnetpe.get_string(type_string_address)
            namespace_string_address = typedef_table_row.string_stream_references['TypeNamespace']
            namespace_name = self.dotnetpe.get_string(namespace_string_address)
            type_flags = typedef_table_row.Flags.value

            if not method_count:
                result.append(Struct.TypesMethods(type_name, namespace_name, [], type_flags))
                continue

            methods = []
            for j in range(current_method_index, current_method_index + method_count):
                method_string_address = methoddef_table_rows[j].string_stream_references['Name']
                method_name = self.dotnetpe.get_string(method_string_address)

                method_signature_index = methoddef_table_rows[j].Signature.value
                try:
                    method_signature = self.dotnetpe.dotnet_blob_lookup[method_signature_index].structure_fields
                except KeyError:
                    self.dotnetpe.logger.debug(f'Method signature index "{method_signature_index}" not available in '
                                               f'#Blob stream lookup table.')
                    method_signature = {}

                method_flags = methoddef_table_rows[j].Flags.value
                method_rva = methoddef_table_rows[j].RVA.value

                if method_rva == 0:
                    self.dotnetpe.logger.debug(f'Method RVA value is 0, skip getting method data. '
                                               f'Flags: {methoddef_table_rows[j].Flags.value}, '
                                               f'ImplFlags: {methoddef_table_rows[j].ImplFlags.value}')
                    method_header_size, method_code_size, method_data = 0, 0, bytes()
                else:
                    method_header_size, method_code_size, method_data = self.get_method_data(method_rva)

                methods.append(Struct.Methods(method_name, method_signature, method_flags, method_rva,
                                              method_header_size, method_code_size, method_data))

            result.append(Struct.TypesMethods(type_name, namespace_name, methods, type_flags))
            current_method_index += method_count

        return result


# Table 6
@metatable
class MethodDef:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_method_names(self, method_access: int = Type.MethodDefMemberAccess.ANY) -> List[str]:
        """
        Get a list of method names.

        Method access options:
            Type.MethodDefMemberAccess.COMPILERCONTROLLED, Type.MethodDefMemberAccess.PRIVATE,
            Type.MethodDefMemberAccess.FAMANDASSEM, Type.MethodDefMemberAccess.ASSEM,
            Type.MethodDefMemberAccess.FAMILY, Type.MethodDefMemberAccess.FAMORASSEM,
            Type.MethodDefMemberAccess.PUBLIC, Type.MethodDefMemberAccess.ANY
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['MethodDef'].table_rows:
            method_string_address = table_row.string_stream_references['Name']
            method_name = self.dotnetpe.get_string(method_string_address)

            if (method_access & Type.MethodDefMemberAccess.ANY) == Type.MethodDefMemberAccess.ANY:
                result.append(method_name)
                continue

            flag = table_row.Flags.value & Type.MethodDefMask.MEMBERACCESS

            if (method_access & Type.MethodDefMemberAccess.COMPILERCONTROLLED) == Type.MethodDefMemberAccess.COMPILERCONTROLLED \
                    and flag == 0:
                result.append(method_name)
            elif (method_access & Type.MethodDefMemberAccess.PRIVATE) == Type.MethodDefMemberAccess.PRIVATE \
                    and flag == 1:
                result.append(method_name)
            elif (method_access & Type.MethodDefMemberAccess.FAMANDASSEM) == Type.MethodDefMemberAccess.FAMANDASSEM \
                    and flag == 2:
                result.append(method_name)
            elif (method_access & Type.MethodDefMemberAccess.ASSEM) == Type.MethodDefMemberAccess.ASSEM \
                    and flag == 3:
                result.append(method_name)
            elif (method_access & Type.MethodDefMemberAccess.FAMILY) == Type.MethodDefMemberAccess.FAMILY \
                    and flag == 4:
                result.append(method_name)
            elif (method_access & Type.MethodDefMemberAccess.FAMORASSEM) == Type.MethodDefMemberAccess.FAMORASSEM \
                    and flag == 5:
                result.append(method_name)
            elif (method_access & Type.MethodDefMemberAccess.PUBLIC) == Type.MethodDefMemberAccess.PUBLIC \
                    and flag == 6:
                result.append(method_name)

        return result

    def get_windows_forms_app_entry_point(self) -> List[Optional[Struct.EntryPoint]]:
        """
        Get entry point of Windows Forms app which is the method with STAThreadAttribute
        """
        result = []

        if not self.dotnetpe.metadata_table_exists('CustomAttribute') and not \
                self.dotnetpe.metadata_table_exists('MemberRef') and not \
                self.dotnetpe.metadata_table_exists('MethodDef') and not \
                self.dotnetpe.metadata_table_exists('TypeRef') and not \
                self.dotnetpe.metadata_table_exists('TypeDef'):
            self.dotnetpe.logger.debug('Cross-reference error: File does not have CustomAttribute, MemberRef,'
                                       ' MethodDef, TypeRef and TypeDef tables.')
            return result

        for table_row in self.dotnetpe.metadata_tables_lookup['CustomAttribute'].table_rows:
            if table_row.table_references['Type'][0] == 'MemberRef':
                member_ref_index = table_row.table_references['Type'][1] - 1
                member_ref_parent_table = \
                    self.dotnetpe.metadata_tables_lookup['MemberRef'].table_rows[member_ref_index].table_references[
                        'Class'][0]

                if member_ref_parent_table == 'TypeRef':
                    typeref_table_index = \
                        self.dotnetpe.metadata_tables_lookup['MemberRef'].table_rows[member_ref_index].table_references[
                            'Class'][1] - 1
                    type_name_address = self.dotnetpe.metadata_tables_lookup['TypeRef'].table_rows[
                        typeref_table_index].string_stream_references['TypeName']

                    if self.dotnetpe.get_string(type_name_address) == 'STAThreadAttribute':
                        parent_table = table_row.table_references['Parent'][0]

                        if parent_table == 'MethodDef':
                            methoddef_table_index = table_row.table_references['Parent'][1] - 1
                            method_string_address = self.dotnetpe.metadata_tables_lookup['MethodDef'].table_rows[
                                methoddef_table_index].string_stream_references['Name']
                            method_name = self.dotnetpe.get_string(method_string_address)

                            method_signature_index = self.dotnetpe.metadata_tables_lookup['MethodDef'].table_rows[
                                methoddef_table_index].blob_stream_references['Signature']
                            method_signature = self.dotnetpe.dotnet_blob_lookup[method_signature_index]

                            types_with_methods = self.dotnetpe.TypeDef.get_type_names_with_methods()

                            for type_with_method in types_with_methods:
                                for method in type_with_method.Methods:
                                    if method.Name == method_name and \
                                            method.Signature == method_signature.structure_fields:
                                        result.append(
                                            Struct.EntryPoint(method_name, method_signature.structure_fields,
                                                              type_with_method.Type, type_with_method.Namespace))

        return result

    @staticmethod
    def _is_valid_entry_point_type(general_type: Struct.TypesMethods) -> bool:
        """
        Determine if a type can contain valid entry point methods.
        """
        # Check if type is a class and not an interface
        type_class_semantics = general_type.Flags & Type.TypeDefMask.CLASSSEMANTIC
        if not type_class_semantics == Type.TypeDefClassSemantics.CLASS:
            return False

        # Check if type is public (1) or nested public (2) and contains methods
        type_visibility = general_type.Flags & Type.TypeDefMask.VISIBILITY
        if not ((type_visibility == 1 or type_visibility == 2) and general_type.Methods):
            return False

        return True

    @staticmethod
    def _is_valid_entry_point_method(method: Struct.Methods) -> bool:
        """
        Determine if a method can be an entry point.
        """
        # Method must be public
        if method.Flags & Type.MethodDefMask.MEMBERACCESS != 6:
            return False

        # Skip constructors
        if method.Name in ['.ctor', '.cctor']:
            return False

        # Skip special property and event accessors
        auto_generated_prefixes = ("set_", "get_", "add_", "remove_")
        if method.Name.startswith(auto_generated_prefixes):
            return False

        # Skip special names and delegate methods
        is_special_name = method.Flags & Type.MethodDefMask.SPECIALNAME == Type.MethodDefMask.SPECIALNAME
        is_virtual = method.Flags & Type.MethodDefMask.VIRTUAL == Type.MethodDefMask.VIRTUAL
        is_delegate_method = method.Name in ['Invoke', 'BeginInvoke', 'EndInvoke']

        if (is_special_name and method.Name.startswith(auto_generated_prefixes)) or \
                (is_virtual and (is_delegate_method or method.Name.startswith(auto_generated_prefixes))):
            return False

        return True

    def get_entry_points(self) -> List[Optional[Struct.EntryPoint]]:
        """
        Get possible entry point methods along with their types, namespaces and parameters.

        TODO: Add more blob signatures or create proper blob signature decoding
        """
        result = []

        if self.dotnetpe.is_windows_forms_app():
            return self.get_windows_forms_app_entry_point()

        all_types = self.dotnetpe.TypeDef.get_type_names_with_methods()

        for general_type in all_types:
            if not self._is_valid_entry_point_type(general_type):
                continue

            for method in general_type.Methods:
                if self._is_valid_entry_point_method(method):
                    result.append(Struct.EntryPoint(
                        method.Name,
                        method.Signature,
                        general_type.Type,
                        general_type.Namespace
                    ))

        return result


# Table 10
@metatable
class MemberRef:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_memberref_names(self, deduplicate: bool = False) -> List[str]:
        """
        Get a list of referenced methods and fields of a class.
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['MemberRef'].table_rows:
            memberref_string_address = table_row.string_stream_references['Name']
            memberref_name = self.dotnetpe.get_string(memberref_string_address)

            result.append(memberref_name)

        if deduplicate:
            result = list(set(result))

        return result

    def get_fully_qualified_memberref_names(self, deduplicate: bool = False, strings_sorted: bool = False) -> List[str]:
        """
        Get a list of referenced methods/fields with their fully qualified names (namespace.typename::method).
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['MemberRef'].table_rows:
            try:
                name_string_address = table_row.string_stream_references['Name']
                name_string = self.dotnetpe.get_string(name_string_address)
                if not name_string:
                    continue

                if name_string.startswith("."):
                    name_string = name_string[1:]

                class_table = table_row.table_references['Class'][0]
                class_index = table_row.table_references['Class'][1] - 1

                if class_index < 0 or class_index >= len(
                        self.dotnetpe.metadata_tables_lookup.get(class_table, {}).table_rows):
                    continue

                if class_table not in ["TypeRef", "TypeDef"]:
                    continue

                type_name_address = self.dotnetpe.metadata_tables_lookup[
                    class_table].table_rows[class_index].string_stream_references['TypeName']
                type_namespace_address = self.dotnetpe.metadata_tables_lookup[
                    class_table].table_rows[class_index].string_stream_references['TypeNamespace']

                type_name = self.dotnetpe.get_string(type_name_address)
                type_namespace = self.dotnetpe.get_string(type_namespace_address)

                if type_name.startswith("."):
                    type_name = type_name[1:]

                full_type_name = type_namespace
                if type_namespace and type_name:
                    full_type_name += "."
                full_type_name += type_name

                if full_type_name:
                    result.append(f"{full_type_name}::{name_string}")
            except (KeyError, IndexError, AttributeError) as e:
                self.dotnetpe.logger.debug(f"Error processing MemberRef: {e}")
                continue

        if deduplicate:
            result = list(set(result))

        if strings_sorted:
            result.sort(key=lambda x: (x.split('::')[1] if '::' in x else x).lower())

        return result

    def get_memberref_hash(self, hash_type: Type.Hash = Type.Hash.SHA256, strings_sorted: bool = False) -> str:
        """
        MemberRefHash: Get hash of reference (to methods and fields of a class) and table names of their
        corresponding classes.

        We take the table name of the belonging class and the reference name to create a string pair separated by a "-"
        character. This table<->name string pair is added to a list and the hash value is calculated at the end. The
        class always belongs to one of the five tables 'TypeDef', 'TypeRef', 'ModuleRef', 'MethodDef' or 'TypeSpec'.

        The list of table and reference names can be sorted alphabetically after the reference names before being
        hashed. Strings are used case-sensitive.

        Options:
            - Type.Hash.MD5, Type.Hash.SHA1, Type.Hash.SHA256
            - Strings unsorted or sorted (after the reference names)
        """
        tables_names = []
        for _, table_row in enumerate(self.dotnetpe.metadata_tables_lookup['MemberRef'].table_rows):
            name_string_address = table_row.string_stream_references['Name']
            name_string = self.dotnetpe.get_string(name_string_address)

            class_table = table_row.table_references['Class'][0]

            tables_names.append(f'{class_table}-{name_string}')

        if strings_sorted:
            tables_names.sort(key=lambda x: x.split('-')[1])

        return self.dotnetpe.get_hash(hash_type, tables_names)


# Table 20
@metatable
class Event:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_event_names(self) -> List[str]:
        """
        Get a list of event names.
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['Event'].table_rows:
            event_string_address = table_row.string_stream_references['Name']
            event_name = self.dotnetpe.get_string(event_string_address)
            result.append(event_name)

        return result


# Table 26
@metatable
class ModuleRef:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_unmanaged_module_names(self, modules_type: Type.UnmanagedModules = Type.UnmanagedModules.RAW) -> List[str]:
        """
        Get a list of unmanaged module names.

        Type options:
            Type.UnmanagedModules.RAW, Type.UnmanagedModules.NORMALIZED
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['ModuleRef'].table_rows:
            string_address = table_row.string_stream_references['Name']
            module_name = self.dotnetpe.get_string(string_address)

            # Condition for mixed assemblies
            if module_name:
                if modules_type == Type.UnmanagedModules.RAW:
                    result.append(module_name)
                elif modules_type == Type.UnmanagedModules.NORMALIZED:
                    module_name = module_name.lower()
                    if not module_name.endswith('.dll'):
                        module_name = f'{module_name}.dll'
                    if module_name not in result:
                        result.append(module_name)

        return result


# Table 28
@metatable
class ImplMap:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def _get_function_name_from_methoddef_table(self, table_index: int) -> str:
        result = ''

        if not self.dotnetpe.metadata_table_exists('MethodDef'):
            self.dotnetpe.logger.debug('Cross-reference error: File does not have an MethodDef table.')
            return result

        string_address = self.dotnetpe.metadata_tables_lookup['MethodDef'].table_rows[
            table_index].string_stream_references['Name']
        result = self.dotnetpe.get_string(string_address)

        return result

    def get_unmanaged_functions(self) -> List[str]:
        """
        Get a list of unmanaged function names.
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['ImplMap'].table_rows:
            string_address = table_row.string_stream_references['ImportName']
            function_name = self.dotnetpe.get_string(string_address)

            # Handle mixed assemblies by getting the function name from the MethodDef table
            if not function_name:
                function_name = self._get_function_name_from_methoddef_table(
                    table_row.table_references['MemberForwarded'][1] - 1)

            result.append(function_name)

        return result


# Table 32
@metatable
class Assembly:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_assembly_name(self) -> str:
        """
        Get assembly name.
        """
        # To counteract .NET protectors like ConfuserEx that add additional entries, we skip the remaining row(s) as
        # they are officially not supported and contain invalid entries
        string_address = self.dotnetpe.metadata_tables_lookup['Assembly'].table_rows[0].string_stream_references['Name']

        return self.dotnetpe.get_string(string_address)

    def get_assembly_culture(self) -> str:
        """
        Get assembly culture.
        """
        # To counteract .NET protectors like ConfuserEx that add additional entries, we skip the remaining row(s) as
        # they are officially not supported and contain invalid entries
        string_address = self.dotnetpe.metadata_tables_lookup['Assembly'].table_rows[0].string_stream_references[
            'Culture']

        return self.dotnetpe.get_string(string_address)

    def get_assembly_version_information(self) -> Optional[Struct.AssemblyInfo]:
        """
        Get assembly version information (MajorVersion, MinorVersion, BuildNumber, RevisionNumber).
        """
        result = None

        try:
            assembly = self.dotnetpe.metadata_tables_lookup['Assembly'].table_rows[0]
            result = Struct.AssemblyInfo(assembly.MajorVersion.value, assembly.MinorVersion.value,
                                         assembly.BuildNumber.value, assembly.RevisionNumber.value)
        except (IndexError, AttributeError, KeyError):
            pass

        return result


# Table 35
@metatable
class AssemblyRef:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_assemblyref_names(self, deduplicate: bool = False) -> List[str]:
        """
        Get a list of referenced assembly names.
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['AssemblyRef'].table_rows:
            string_address = table_row.string_stream_references['Name']
            if string_address:
                assembly_name = self.dotnetpe.get_string(string_address)
                result.append(assembly_name)

        if deduplicate:
            result = list(dict.fromkeys(result))

        return result

    def get_assemblyref_names_with_versions(self, deduplicate: bool = False) -> Dict[str, Union[str, List[str]]]:
        """
        Get a dictionary of referenced assembly names and their versions.
        """
        result = {}
        seen_pairs = set()

        for table_row in self.dotnetpe.metadata_tables_lookup['AssemblyRef'].table_rows:
            string_address = table_row.string_stream_references['Name']
            if string_address:
                assembly_name = self.dotnetpe.get_string(string_address)
                version = (f'{table_row.MajorVersion.value}.{table_row.MinorVersion.value}.'
                           f'{table_row.BuildNumber.value}.{table_row.RevisionNumber.value}')

                if deduplicate:
                    pair = (assembly_name, version)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)

                if assembly_name in result:
                    current = result[assembly_name]
                    if isinstance(current, list):
                        if version not in current:
                            current.append(version)
                    elif current != version:
                        result[assembly_name] = [current, version]
                else:
                    result[assembly_name] = version

        return result

    def get_assemblyref_cultures(self) -> List[str]:
        """
        Get a list of referenced assembly cultures.
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['AssemblyRef'].table_rows:
            string_address = table_row.string_stream_references['Culture']
            if string_address:
                result.append(self.dotnetpe.get_string(string_address))

        return result


# Table 40
@metatable
class ManifestResource:
    def __init__(self, dotnet_obj):
        self.dotnetpe = dotnet_obj

    def get_resource_names(self) -> List[str]:
        """
        Get a list of .NET resource names.
        """
        result = []

        for table_row in self.dotnetpe.metadata_tables_lookup['ManifestResource'].table_rows:
            string_address = table_row.string_stream_references['Name']
            if string_address:
                result.append(self.dotnetpe.get_string(string_address))

        return result
