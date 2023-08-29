"""
Original author:        Bob Jung - Palo Alto Networks (2016)
Modified/Expanded by:   Yaron Samuel - Palo Alto Networks (2021-2022),
                        Dominik Reichel - Palo Alto Networks (2021-2023)

dotnetfile - CLR header parsing library for Windows .NET PE files.

The following references were used:
    Jeff Valore's tutorial on how to build a .NET Disassembler
        https://codingwithspike.wordpress.com/2012/08/12/building-a-net-disassembler-part-3-parsing-the-text-section/
    Erik Pistelli's .NET file format documentation
        https://www.ntcore.com/files/dotnetformat.htm
    CLI specification (ECMA-335 standard)
        https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-335.pdf
    Microsoft .NET documentation
        https://docs.microsoft.com/en-us/dotnet/api/system.reflection.metadata.ecma335?view=net-5.0
    .NET runtime code
        https://github.com/dotnet/runtime
    dnlib
        https://github.com/0xd4d/dnlib
"""

from __future__ import annotations

import os
import binascii
import struct
import logging
from struct import unpack
from math import log, floor
from pefile import PE, DIRECTORY_ENTRY, PEFormatError
from typing import List, Dict, Tuple, Any, Set, Union, Optional, Type
from pathlib import PurePath

from .util import read_null_terminated_byte_string, get_reasonable_display_string_for_bytes, FileLocation, \
    read_7bit_encoded_uint32, read_7bit_encoded_int32
from .logger import get_logger
from .structures import DOTNET_CLR_HEADER, DOTNET_METADATA_HEADER, DOTNET_STREAM_HEADER, DOTNET_METADATA_STREAM_HEADER
from .metadata_rows import get_metadata_row_class_for_table, MODULE_TABLE_ROW
from .constants import TABLE_ROW_VARIABLE_LENGTH_FIELDS, MAX_DOTNET_STRING_LENGTH, BLOB_SIGNATURES, RESOURCE_TYPE_CODES


PathLike = Union[str, bytes, os.PathLike, PurePath]


class CLRFormatError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class MetadataTable(object):
    def __init__(self, table_rows: list, addr: int = None, string_representation: str = None, size: int = None):
        self.address = addr
        self.string_representation = string_representation
        self.size = size
        self.table_rows = table_rows


class DotNetPEParser(PE):
    def __init__(self, file_ref: PathLike, fast_load: str, fast_load_tables: list, parse: bool = True,
                 log_level: int = logging.INFO, *args, **kwargs):
        if isinstance(file_ref, bytes):
            super().__init__(data=file_ref, *args, **kwargs)
        else:
            super().__init__(name=file_ref, *args, **kwargs)

        # Detected anti metadata parsing tricks
        self.dotnet_anti_metadata = {
            'data_directory_hidden': False,
            'metadata_table_has_extra_data': False,
            'has_fake_data_streams': False,
            'has_invalid_strings_stream_entries': False,
            'has_max_len_exceeding_strings': False,
            'has_mixed_case_stream_names': False
        }

        if not self.is_dotnet_file():
            raise CLRFormatError('File is not a .NET assembly.')

        self.file_size = 0

        if not self.is_metadata_header_complete_and_valid(file_ref):
            raise CLRFormatError('CLR header of file is most likely corrupt.')

        self.logger = get_logger('extended_pe_logger', level=log_level)

        # Mapping for mixed case stream names (e.g. "#StRinG") as created by some obfuscators
        self.stream_names_map = {
            '#Strings': '#Strings',
            '#GUID': '#GUID',
            '#Blob': '#Blob',
            '#US': '#US'
        }

        self.fast_load = fast_load
        if self.fast_load:
            self.fast_load_tables = fast_load_tables
            self.full_load_tables = []

        self.metadata_table_rva = None
        self.metadata_tables_rva = {}

        self.clr_header = None
        self.dotnet_metadata_header = None

        self.dotnet_streams = []
        self.dotnet_stream_headers = []
        self.dotnet_stream_lookup = {}
        self.dotnet_stream_header_lookup = {}
        # "#~/#-" stream
        self.dotnet_metadata_stream_header = None
        self.dotnet_field_size_info = None
        # tables under "#~/#-" stream
        self.metadata_tables = []
        self.metadata_tables_lookup = {}
        self.non_overlap_string_references = set()
        self.dotnet_resources = []

        # mapping of offsets inside "#Strings" to string at that offset
        self.dotnet_string_lookup: Dict[int, FileLocation] = {}
        # mapping of offsets inside "#US" to string at that offset
        self.dotnet_user_string_lookup: Dict[int, FileLocation] = {}
        # mapping of offsets inside "#Blob" to string at that offset
        self.dotnet_blob_lookup: Dict[int, FileLocation] = {}
        # list of GUIDs inside "#GUID"
        self.guid_stream_guids: List[FileLocation] = []
        # list of overlap strings inside "#Strings"
        self.dotnet_overlap_string_lookup: Dict[int, FileLocation] = {}
        # list of unused strings inside "#Strings"
        self.dotnet_unused_string_lookup: Dict[int, FileLocation] = {}

        if parse:
            self.parse_all()

    def is_dotnet_data_directory_hidden(self) -> bool:
        """
        Check if the .NET data directory is hidden in the PE data directories by lowering the NumberOfRvaAndSizes value
        """
        result = False

        dotnet_dir_number = DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']
        number_of_rva_and_sizes = self.OPTIONAL_HEADER.NumberOfRvaAndSizes

        try:
            if number_of_rva_and_sizes <= dotnet_dir_number:
                # Calculate the necessary offsets for verification
                optional_header_offset = self.NT_HEADERS.get_file_offset() + 4 + self.FILE_HEADER.sizeof()
                section_offset = optional_header_offset + self.FILE_HEADER.SizeOfOptionalHeader
                data_dir_offset = self.OPTIONAL_HEADER.DATA_DIRECTORY[number_of_rva_and_sizes - 1].get_file_offset() + 8

                if data_dir_offset != section_offset and section_offset > data_dir_offset:
                    # NumberOfRvaAndSize has been tampered to hide the .NET data directory entry. Pefile fails to parse
                    # this, so we must do it manually
                    remaining_entries = (section_offset - data_dir_offset) // (2 * 4)

                    if remaining_entries > 0:
                        self.dotnet_anti_metadata['data_directory_hidden'] = True
                        result = True

        except (ValueError, IndexError, PEFormatError):
            pass

        return result

    def is_dotnet_file(self) -> bool:
        """
        Check if the file is a .NET assembly
        """
        result = False
        dotnet_data_dir = DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']

        if self.is_dotnet_data_directory_hidden():
            result = True
        else:
            try:
                if dotnet_data_dir <= self.OPTIONAL_HEADER.NumberOfRvaAndSizes and \
                        self.OPTIONAL_HEADER.DATA_DIRECTORY[dotnet_data_dir].VirtualAddress != 0:
                    result = True
            except IndexError:
                result = False

        return result

    def is_metadata_header_complete_and_valid(self, file_ref: PathLike) -> bool:
        """
        Check if the metadata data is complete according to the values in the Cor20 header
        """
        result = True
        dotnet_data_dir = DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']

        if self.dotnet_anti_metadata['data_directory_hidden']:
            optional_header_offset = self.NT_HEADERS.get_file_offset() + 4 + self.FILE_HEADER.sizeof()
            section_offset = optional_header_offset + self.FILE_HEADER.SizeOfOptionalHeader
            # Get .NET data directory offset by going backwards from the section offset over the reserved (2 * 4 bytes)
            # and .NET (2 x 4 bytes) directories
            dotnet_data_dir_offset = section_offset - 8 - 8
            dotnet_header_rva = self.get_dword_at_rva(rva=dotnet_data_dir_offset)
        else:
            dotnet_header_rva = self.OPTIONAL_HEADER.DATA_DIRECTORY[dotnet_data_dir].VirtualAddress

        # Get metadata RVA from the Cor20 header (Metadata.VirtualAddress), thus we skip the Cb (4 bytes),
        # MajorRuntimeVersion (2 bytes) and MinorRuntimeVersion (2 bytes) fields
        metadata_virtual_address = self.get_dword_at_rva(rva=dotnet_header_rva + 4 + 2 + 2)
        # Get metadata size from the Cor20 header (Metadata.Size), thus we skip the Cb (4 bytes),
        # MajorRuntimeVersion (2 bytes), MinorRuntimeVersion (2 bytes) and Metadata.VirtualAddress (4 bytes) fields
        metadata_size = self.get_dword_at_rva(rva=dotnet_header_rva + 4 + 2 + 2 + 4)
        metadata_offset = self.get_offset_from_rva(metadata_virtual_address)

        if isinstance(file_ref, bytes):
            self.file_size = len(file_ref)
        elif os.path.isfile(file_ref):
            self.file_size = os.path.getsize(file_ref)

        # Check if metadata is incomplete or the metadata signature is not at the beginning of the data
        if metadata_offset + metadata_size > self.file_size or self.get_data(metadata_virtual_address, 4) != b'BSJB':
            result = False

        return result

    def parse_all(self) -> None:
        self.clr_header = self.get_clr_header()
        self.dotnet_metadata_header = self.get_dotnet_metadata_header()
        self.parse_dotnet_stream_headers()
        if self.fast_load == 'header_only':
            tilde_string = '#~' if '#~' in list(self.dotnet_stream_lookup) else '#-'
            self.parse_tilde_stream_header(tilde_string)
        else:
            self.parse_dotnet_streams()
        if self.fast_load in ('normal_resources', ''):
            self.parse_dotnet_resources()

    def parse_dotnet_streams(self) -> None:
        """
        After we parsed the stream headers, let's parse the actual streams themselves
        """
        for stream_name in self.dotnet_stream_lookup:
            if stream_name in ('#~', '#-'):
                if not self.fast_load in ('header_only', None):
                    self.parse_tilde_stream_header(stream_name)
                self.parse_tilde_stream()
            elif stream_name == self.stream_names_map['#Strings']:
                self.parse_strings_stream()
            elif stream_name == self.stream_names_map['#GUID']:
                self.parse_guid_stream()
            elif stream_name == self.stream_names_map['#Blob']:
                self.parse_blob_stream()
            elif stream_name == self.stream_names_map['#US']:
                self.parse_us_stream()
            else:
                self.logger.info(f'unknown stream name: {stream_name}')

    def get_clr_header(self) -> DOTNET_CLR_HEADER:
        clr_header_dir = self.__IMAGE_DATA_DIRECTORY_format__

        if self.dotnet_anti_metadata['data_directory_hidden']:
            number_of_rva_and_sizes = self.OPTIONAL_HEADER.NumberOfRvaAndSizes
            optional_header_offset = self.NT_HEADERS.get_file_offset() + 4 + self.FILE_HEADER.sizeof()
            section_offset = optional_header_offset + self.FILE_HEADER.SizeOfOptionalHeader
            last_offset_data_dir = self.OPTIONAL_HEADER.DATA_DIRECTORY[
                                       number_of_rva_and_sizes - 1].get_file_offset() + 8
            remaining_entries = ((section_offset - last_offset_data_dir) // (2 * 4)) - 1
            offset = last_offset_data_dir
            current_data_directory_id = number_of_rva_and_sizes

            for _ in range(0, remaining_entries):
                if current_data_directory_id == DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']:
                    data = self.get_data(offset, 8)
                    clr_header_dir = self.__unpack_data__(self.__IMAGE_DATA_DIRECTORY_format__, data, file_offset=offset)
                    break
                offset += 8
                current_data_directory_id += 1
        else:
            clr_header_dir = self.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']]

        offset = self.get_offset_from_rva(clr_header_dir.VirtualAddress)
        data_bytes = self.get_data(rva=clr_header_dir.VirtualAddress, length=clr_header_dir.Size)

        return DOTNET_CLR_HEADER(offset, data_bytes)

    def get_dotnet_metadata_header(self) -> Optional[DOTNET_METADATA_HEADER]:
        metadata_stream_rva = self.clr_header.MetaDataDirectoryAddress.value
        metadata_size = self.clr_header.MetaDataDirectorySize.value
        if metadata_stream_rva != 0 and metadata_size != 0:
            metadata_bytes = self.get_data(rva=metadata_stream_rva, length=metadata_size)

            if len(metadata_bytes) == 0:
                self.logger.debug(f'Invalid metadata stream rva: 0x{metadata_stream_rva:x}, giving up on .NET headers')
                return None

            try:
                dotnet_metadata_header = DOTNET_METADATA_HEADER(metadata_stream_rva, metadata_bytes)
                if dotnet_metadata_header.Signature.value == 0x424A5342:
                    return dotnet_metadata_header

            except Exception as e:
                self.logger.info(str(e))

        return None

    @property
    def dotnet_headers_are_valid(self) -> bool:
        if self.dotnet_metadata_header is not None and hasattr(self.dotnet_metadata_header, 'Signature'):
            return self.dotnet_metadata_header.Signature.value == 0x424A5342

        return False

    @property
    def metadata_dir_size(self) -> int:
        return self.clr_header.MetaDataDirectorySize.value

    def parse_dotnet_stream_headers(self) -> None:
        metadata_stream_rva = self.clr_header.MetaDataDirectoryAddress.value
        metadata_hdr_size = self.dotnet_metadata_header.size
        num_streams = self.dotnet_metadata_header.NumberOfStreams.value
        cumulative_size = 0
        # To counteract ConfuserEx that adds invalid streams to the end of the regular ones, we check
        # if a stream was already parsed and skip if positive
        supported_streams = {
            '#~': False,
            '#-': False,
            '#strings': False,
            '#guid': False,
            '#blob': False,
            '#us': False
        }

        for i in range(num_streams):
            curr_stream_rva = metadata_stream_rva + metadata_hdr_size + cumulative_size
            # 0x100 is arbitrary large enough, but it is later trimmed anyway
            current_stream_bytes = self.get_data(curr_stream_rva, length=0x100)
            current_stream_header = DOTNET_STREAM_HEADER(curr_stream_rva, current_stream_bytes)
            current_stream_header.trim_byte_buffer()

            self.dotnet_stream_headers.append(current_stream_header)

            cumulative_size += current_stream_header.size

            current_stream_rva = metadata_stream_rva + current_stream_header.Offset.value
            current_stream_size = current_stream_header.Size.value
            current_stream_header_name = current_stream_header.Name.field_text
            current_stream_header_name_lc = current_stream_header_name.lower()

            current_stream = FileLocation(current_stream_rva, current_stream_header_name, current_stream_size)
            self.dotnet_streams.append(current_stream)

            # e.g "#Strings"
            if current_stream_header_name_lc in supported_streams.keys():
                if not supported_streams[current_stream_header_name_lc]:
                    self.dotnet_stream_header_lookup[current_stream_header_name] = current_stream_header
                    self.dotnet_stream_lookup[current_stream_header_name] = current_stream

                if current_stream_header_name_lc in ['#~', '#-']:
                    supported_streams['#~'] = supported_streams['#-'] = True
                else:
                    supported_streams[current_stream_header_name_lc] = True

                    if current_stream_header_name not in self.stream_names_map.keys():
                        for stream_name in self.stream_names_map.keys():
                            if stream_name.lower() == current_stream_header_name_lc:
                                self.stream_names_map[stream_name] = current_stream_header_name
                        self.dotnet_anti_metadata['has_mixed_case_stream_names'] = True
            else:
                self.dotnet_anti_metadata['has_fake_data_streams'] = True

            self.logger.debug(
                f'parsing stream: {current_stream_header_name} rva: 0x{current_stream_rva:x} '
                f'size: 0x{current_stream_size:x}')

    def _get_metadata_table_rva(self) -> None:
        # This method currently cannot be bound to fast load as the correct table order must be
        # preserved to get the correct table addresses and thus the correct table data. Therefore,
        # we always get all the table RVAs and not just the ones we have selected via fast load.
        metadata_tables = self.dotnet_metadata_stream_header.table_names
        current_row_rva = self.metadata_table_rva

        for table_name in metadata_tables:
            table_rows_num = self.dotnet_metadata_stream_header.table_size_lookup[table_name]

            row_type = get_metadata_row_class_for_table(table_name)
            if row_type is None:
                continue

            # Ugly fixes for the edge(?) cases that a sample doesn't have a Field or Param table that is
            # cross-referenced in the TypeRef or MethodDef table
            if table_name == 'TypeDef' and 'Field' not in self.dotnet_metadata_stream_header.table_names or \
                    table_name == 'MethodDef' and 'Param' not in self.dotnet_metadata_stream_header.table_names:
                table_row_size = 14
            else:
                table_row_size = self.parse_metadata_table_row_size(current_row_rva, row_type)

            table_size = table_row_size * table_rows_num
            self.metadata_tables_rva[table_name] = current_row_rva

            current_row_rva += table_size

    def parse_tilde_stream_header(self, stream_name: str) -> None:
        stream = self.dotnet_stream_lookup[stream_name]
        # max value, later will be trimmed
        metadata_size = self.clr_header.MetaDataDirectorySize.value
        current_stream_bytes = self.get_data(stream.address, metadata_size)

        self.logger.debug(f'parsing metadata header: 0x{stream.address:x}')
        self.dotnet_metadata_stream_header = DOTNET_METADATA_STREAM_HEADER(stream.address, current_stream_bytes)
        self.dotnet_metadata_stream_header.trim_byte_buffer()

        # for table_name in self.dotnet_metadata_stream_header.table_names:
        #     self.logger.debug(table_name)
        # self.logger.debug(self.dotnet_metadata_stream_header.get_structure_as_dict())

        self.dotnet_field_size_info = self.calculate_field_size_info(
            self.dotnet_metadata_stream_header.table_size_lookup)

        metadata_header_size = self.dotnet_metadata_stream_header.size

        # To counteract .NET protectors like ConfuserEx which add extra data at the end of the metadata table header,
        # we add the length of these bytes to achieve proper parsing of the remaining header
        if self.dotnet_metadata_stream_header.table_has_extra_data:
            self.dotnet_anti_metadata['metadata_table_has_extra_data'] = True
            metadata_header_size += 4

        self.metadata_table_rva = stream.address + metadata_header_size
        self.logger.debug(
            f'parsing metadata at raw offset: 0x{self.metadata_table_rva:x} '
            f'metadata header size: 0x{metadata_header_size:x}')

    def parse_tilde_stream(self) -> None:
        if self.fast_load and self.fast_load is not None:
            metadata_tables = []
            for fast_load_table in self.fast_load_tables:
                if fast_load_table in self.dotnet_metadata_stream_header.table_names:
                    metadata_tables.append(fast_load_table)

            for table_name in self.dotnet_metadata_stream_header.table_names:
                if table_name not in metadata_tables:
                    self.full_load_tables.append(table_name)
        else:
            metadata_tables = self.dotnet_metadata_stream_header.table_names

        self._get_metadata_table_rva() # This part currently cannot be bound to fast load (see method)
        self.parse_metadata_tables(metadata_tables)

    def parse_metadata_tables(self, metadata_tables: list) -> None:
        """
        This parses all the metadata tables in the "#~/#-" stream
        """
        for table_name in metadata_tables:
            try:
                table_size = self.dotnet_metadata_stream_header.table_size_lookup[table_name]
                self.logger.debug(f'parsing table {table_name} size: {table_size:d}')
                metadata_table = self.parse_metadata_table(table_name, self.metadata_tables_rva[table_name], table_size)

                if metadata_table is not None:
                    self.metadata_tables.append(metadata_table)
                    self.metadata_tables_lookup[table_name] = metadata_table
                else:
                    raise Exception(f'table not parsed correctly: {table_name}')

            except Exception as e:
                error_string = f'Error attempting to parse metadata table: {table_name}'
                self.logger.info(error_string)
                self.logger.exception(e)
                raise Exception(error_string)

    def parse_metadata_table_row_size(self, table_row_addr: int, row_type: Type[MODULE_TABLE_ROW]) -> int:
        """
        This is a little weird but tables + their rows are dynamically sized, so we don't know how big they are
        till after the objects parse them, so we need to calculate the size based on the first row

        :param table_row_addr: address of the first row of the table
        :param row_type: class of the row
        """
        table_row_bytes = self.get_data(rva=table_row_addr, length=self.metadata_dir_size)
        table_row = row_type(self, table_row_addr, table_row_bytes)
        return table_row.size

    def parse_metadata_table(self, table_name: str, table_rva: int, num_rows: int) -> Optional[MetadataTable]:
        """
        This parses a single metadata table
        """
        table_rows = []
        current_row_rva = table_rva

        row_type = get_metadata_row_class_for_table(table_name)
        if row_type is None:
            return None

        # Ugly fixes for the edge(?) cases that a sample doesn't have a Field or Param table that is cross-referenced
        # in the TypeRef or MethodDef table
        if table_name == 'TypeDef' and 'Field' not in self.dotnet_metadata_stream_header.table_names or \
                table_name == 'MethodDef' and 'Param' not in self.dotnet_metadata_stream_header.table_names:
            table_row_size = 14
        else:
            table_row_size = self.parse_metadata_table_row_size(current_row_rva, row_type)

        all_rows_data = self.get_data(current_row_rva, table_row_size * num_rows)
        for i in range(num_rows):
            table_row_addr = current_row_rva
            table_row_bytes = all_rows_data[current_row_rva - table_rva: current_row_rva - table_rva + table_row_size]
            table_row = row_type(self, table_row_addr, table_row_bytes)
            table_rows.append(table_row)

            current_row_rva += table_row_size

        table_addr = table_rva
        table_size = table_row_size * num_rows
        metadata_table = MetadataTable(table_rows, table_addr, table_name, table_size)

        return metadata_table

    def _get_all_string_references(self) -> Set:
        result = set()

        for metadata_table in self.metadata_tables_lookup.values():
            for table_row in metadata_table.table_rows:
                for string_reference in table_row.string_stream_references.values():
                    result.add(string_reference)

        return result

    def _get_non_standard_strings(self, string_type: str, string_references: List, all_strings_data: bytes) -> None:
        if string_type == 'overlap':
            self.dotnet_overlap_string_lookup = {}
        elif string_type == 'unused':
            self.dotnet_unused_string_lookup = {}

        for string_reference in string_references:
            current_string_bytes = all_strings_data[string_reference:string_reference + MAX_DOTNET_STRING_LENGTH]
            current_string = read_null_terminated_byte_string(current_string_bytes, MAX_DOTNET_STRING_LENGTH)

            # Catch invalid or max length exceeding string entries as added by obfuscators like ConfuserEx
            # (in additional and invalid Assembly/Module table rows)
            if current_string is None:
                if len(current_string_bytes) == MAX_DOTNET_STRING_LENGTH:
                    current_string_bytes = all_strings_data[string_reference:]
                    current_string = read_null_terminated_byte_string(current_string_bytes, len(current_string_bytes))
                else:
                    self.dotnet_anti_metadata['has_invalid_strings_stream_entries'] = True
                    continue

            current_string_size = len(current_string) + 1
            current_string_location = FileLocation(string_reference, current_string, current_string_size)
            current_string_location.string_representation = get_reasonable_display_string_for_bytes(current_string)

            if string_type == 'overlap':
                self.dotnet_overlap_string_lookup[string_reference] = current_string_location
            elif string_type == 'unused':
                self.dotnet_unused_string_lookup[string_reference] = current_string_location

    def _get_strings_stream_data(self) -> bytes:
        stream = self.dotnet_stream_lookup[self.stream_names_map['#Strings']]

        result = self.get_data(stream.address, stream.size)

        # We remove the trailing extra 0-bytes in the strings data except for one belonging to the last string
        result = result.rstrip(b'\x00') + b'\x00'

        return result

    def parse_non_standard_strings(self) -> None:
        all_strings_data = self._get_strings_stream_data()
        all_string_references = self._get_all_string_references()

        # Get overlap strings
        overlap_string_references = sorted(all_string_references - self.non_overlap_string_references)
        self._get_non_standard_strings('overlap', overlap_string_references, all_strings_data)
        # Get unused strings (not referenced anywhere)
        unused_string_references = sorted(self.non_overlap_string_references - all_string_references)
        self._get_non_standard_strings('unused', unused_string_references, all_strings_data)

    def parse_strings_stream(self) -> None:
        stream = self.dotnet_stream_lookup[self.stream_names_map['#Strings']]

        current_string_rva = stream.address
        all_strings_data = self._get_strings_stream_data()

        # Get standard strings from the #Strings stream
        while current_string_rva <= stream.address + stream.size:
            current_start_offset = current_string_rva - stream.address
            current_string_bytes = all_strings_data[current_start_offset:current_start_offset + MAX_DOTNET_STRING_LENGTH]
            current_string = read_null_terminated_byte_string(current_string_bytes, MAX_DOTNET_STRING_LENGTH)

            if current_string is None:
                if len(current_string_bytes) == MAX_DOTNET_STRING_LENGTH:
                    # Maximum string length exceeds value defined in Roslyn compiler, thus that string
                    # was artificially added. While the #C standard does not mention any length limit,
                    # it is effectively set to 1024 characters.
                    self.dotnet_anti_metadata['has_max_len_exceeding_strings'] = True
                    current_string_bytes = all_strings_data[current_start_offset:]
                    current_string = read_null_terminated_byte_string(current_string_bytes, len(current_string_bytes))
                else:
                    current_string_rva += 1
                    continue

            current_string_size = len(current_string) + 1
            current_string_location = FileLocation(current_string_rva, current_string, current_string_size)

            current_string_location.string_representation = get_reasonable_display_string_for_bytes(current_string)

            # It's the offset inside the string stream
            self.dotnet_string_lookup[current_start_offset] = current_string_location
            current_string_rva += current_string_size

            self.non_overlap_string_references.add(current_start_offset)

        self.parse_non_standard_strings()

    @property
    def string_stream_strings(self):
        return self.dotnet_string_lookup.values()

    def parse_guid_stream(self) -> None:
        stream = self.dotnet_stream_lookup[self.stream_names_map['#GUID']]
        current_guid_rva = stream.address
        stream_end_address = stream.address + stream.size

        while current_guid_rva + 0x10 <= stream_end_address:
            current_guid_bytes = self.get_data(current_guid_rva, length=0x10)
            current_guid = binascii.hexlify(current_guid_bytes)
            current_guid_location = FileLocation(current_guid_rva, current_guid, 0x10)

            self.guid_stream_guids.append(current_guid_location)
            current_guid_rva += 0x10

    @staticmethod
    def _get_stream_sequence_length(length_field_buffer: bytes) -> Tuple[int, int]:
        # String length explanation:
        # https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
        # II.24.2.4 #US and #Blob heaps (page 298 or 272)

        # one byte of length
        first_byte = length_field_buffer[0]
        if (first_byte & 0x80) == 0:
            return int(first_byte), 1

        # 2 bytes of length
        elif (first_byte & 0xC0) == 0x80:
            length = struct.unpack('>H', length_field_buffer[:2])[0]
            length &= 0x7FFF
            return length, 2
        # 4 bytes of length
        elif (first_byte & 0xE0) == 0xC0:
            length = struct.unpack('>I', length_field_buffer)[0]
            length &= 0x3FFFFFF
            return length, 4

        # error
        return 0, 1

    def parse_us_stream(self) -> None:
        # From: http://www.ntcore.com/files/dotnetformat.htm
        # US Array of unicode strings. The name stands for User Strings,
        # and these strings are referenced directly by code instructions (ldstr).
        # This stream starts with a null byte exactly like the #Blob one.
        # Each entry of this stream begins with a 7bit encoded integer which
        # tells us the size of the following string (the size is in bytes, not
        # characters). Moreover, there's an additional byte at the end of the
        # string (so that every string size is odd and not even). This last byte
        # tells the framework if any of the characters in the string has its high
        # byte set or if the low byte is any of these particular values:
        #
        # 0x1-0x8,
        # 0x0e-0x1f,
        # 0x27, 0x2D.
        stream = self.dotnet_stream_lookup[self.stream_names_map['#US']]

        # The first byte is always 0 and doesn't get referenced, thus we skip it
        current_string_rva = stream.address + 1

        while current_string_rva < stream.address + stream.size:
            # can be 1-4 bytes
            current_string_length_bytes = self.get_data(current_string_rva, length=4)
            current_string_length, length_field_size = self._get_stream_sequence_length(current_string_length_bytes)
            if current_string_length == 0:
                break

            current_string_size = current_string_length + length_field_size
            current_string_bytes = self.get_data(current_string_rva, current_string_size)

            # For the actual bytes of the string we need to trim the first byte that has the length
            # plus the last byte that has some MS encoded unicode shortcut thingy
            current_string = current_string_bytes[length_field_size:-1]

            if current_string is not None and current_string_size > 1:
                current_string_location = FileLocation(current_string_rva, current_string, current_string_size)
                current_string_name = get_reasonable_display_string_for_bytes(current_string)
                current_string_location.string_representation = current_string_name

                self.dotnet_user_string_lookup[current_string_rva - stream.address] = current_string_location

            current_string_rva += current_string_size

    def parse_blob_stream(self) -> None:
        stream = self.dotnet_stream_lookup[self.stream_names_map['#Blob']]

        # This stream starts with a null byte.
        current_blob_rva = stream.address + 1

        while current_blob_rva < stream.address + stream.size:
            # can be 1-4 bytes
            current_blob_length_bytes = self.get_data(current_blob_rva, length=4)
            current_blob_length, length_field_size = self._get_stream_sequence_length(current_blob_length_bytes)

            current_blob_size = current_blob_length + length_field_size
            current_blob_bytes = self.get_data(current_blob_rva, current_blob_size)

            current_blob_bytes = current_blob_bytes[length_field_size:]

            try:
                current_blob_string = BLOB_SIGNATURES[current_blob_bytes]
            except KeyError:
                current_blob_string = {}

            current_blob_string_location = FileLocation(current_blob_rva, current_blob_string, current_blob_size)
            current_blob_string_location.string_representation = current_blob_string

            self.dotnet_blob_lookup[current_blob_rva - stream.address] = current_blob_string_location
            current_blob_rva += current_blob_size

    @staticmethod
    def get_max_rows(table_size_lookup: Dict[str: int], table_names: List[str]) -> int:
        max_rows = 0
        for table_name in table_names:
            if table_name in table_size_lookup:
                current_size = table_size_lookup[table_name]
                if current_size > max_rows:
                    max_rows = current_size

        return max_rows

    def get_field_size_info(self, table_size_lookup: Dict[str: int], table_names: List[str], encoding_bits) \
            -> Tuple[int, str]:
        two_byte_max_rows = 1 << (16 - encoding_bits)

        max_rows = self.get_max_rows(table_size_lookup, table_names)

        if max_rows > two_byte_max_rows:
            return 4, 'I'

        return 2, 'H'

    def calculate_field_size_info(self, table_size_lookup: Dict[str: int]) -> dict:
        field_size_info = {}

        for field_name in TABLE_ROW_VARIABLE_LENGTH_FIELDS:
            table_names = TABLE_ROW_VARIABLE_LENGTH_FIELDS[field_name]
            # Go read the ntcore write up several times and then this might start making sense
            num_bits = int(floor(log(len(table_names) - 1, 2))) + 1
            size_info = self.get_field_size_info(table_size_lookup, table_names, num_bits)
            field_size_info[field_name] = size_info

        return field_size_info

    def _resources_exist(self) -> bool:
        """
        Check if .NET resources exists.
        """
        result = False

        # Check if the Resources RVA value in the Cor20 header isn't empty. If positive, the file has at least one
        # resource. Additionally, check if the ManifestResource table is present.
        if self.clr_header.ResourcesDirectoryAddress.value and \
                'ManifestResource' in self.dotnet_metadata_stream_header.table_names:
            result = True

        return result

    @staticmethod
    def _read_serialized_string(string: bytes, encoding: str = 'utf-8') -> str:
        result = ''

        if string:
            string_length_size, string_length = read_7bit_encoded_int32(string[:4])
            result = string[string_length_size:string_length_size + string_length].decode(encoding)

        return result

    def _read_resource_data(self, start_rva: int, size: int, resource_type: int) -> Any:
        result, result_length = None, 0

        if resource_type == RESOURCE_TYPE_CODES['Null']:
            pass
        elif resource_type == RESOURCE_TYPE_CODES['String']:
            result = self._read_serialized_string(self.get_data(start_rva, size))
            result_length = len(result)
        elif resource_type == RESOURCE_TYPE_CODES['Boolean']:
            result, result_length = True if ord(self.get_data(start_rva, 1)) else False, 1
        elif resource_type == RESOURCE_TYPE_CODES['Char']:
            result, result_length = chr(unpack('H', self.get_data(start_rva, 2))[0]), 2
        elif resource_type == RESOURCE_TYPE_CODES['Byte']:
            result, result_length = self.get_data(start_rva, 1), 1
        elif resource_type == RESOURCE_TYPE_CODES['SByte']:
            result, result_length = unpack('b', self.get_data(start_rva, 1))[0], 1
        elif resource_type == RESOURCE_TYPE_CODES['Int16']:
            result, result_length = unpack('h', self.get_data(start_rva, 2))[0], 2
        elif resource_type == RESOURCE_TYPE_CODES['UInt16']:
            result, result_length = unpack('H', self.get_data(start_rva, 2))[0], 2
        elif resource_type == RESOURCE_TYPE_CODES['Int32']:
            result, result_length = unpack('i', self.get_data(start_rva, 4))[0], 4
        elif resource_type == RESOURCE_TYPE_CODES['UInt32']:
            result, result_length = unpack('I', self.get_data(start_rva, 4))[0], 4
        elif resource_type == RESOURCE_TYPE_CODES['Int64']:
            result, result_length = unpack('q', self.get_data(start_rva, 8))[0], 8
        elif resource_type == RESOURCE_TYPE_CODES['UInt64']:
            result, result_length = unpack('Q', self.get_data(start_rva, 8))[0], 8
        elif resource_type == RESOURCE_TYPE_CODES['Single']:
            result, result_length = unpack('f', self.get_data(start_rva, 4))[0], 4
        elif resource_type == RESOURCE_TYPE_CODES['Double']:
            result, result_length = unpack('d', self.get_data(start_rva, 8))[0], 8
        elif resource_type == RESOURCE_TYPE_CODES['Decimal']:
            # Get lo, mid, hi and flags part of the decimal value
            result, data = [], self.get_data(start_rva, 16)
            for i in range(0, 16, 4):
                result.append(unpack('i', data[i:i + 4])[0])
            result_length = 16
        elif resource_type == RESOURCE_TYPE_CODES['DateTime']:
            # Return the raw Int64 value as we otherwise loose information when converting to Python datetime format
            result, result_length = unpack('q', self.get_data(start_rva, 8))[0], 8
        elif resource_type == RESOURCE_TYPE_CODES['Timespan']:
            # Return the raw Int64 value as we otherwise loose information when converting to Python datetime format
            result, result_length = unpack('q', self.get_data(start_rva, 8))[0], 8
        elif resource_type == RESOURCE_TYPE_CODES['ByteArray']:
            result = self.get_data(start_rva + 4, size - 4)
            result_length = len(result)
        elif resource_type == RESOURCE_TYPE_CODES['Stream']:
            result = self.get_data(start_rva, size)
            result_length = len(result)
        else:
            result = self.get_data(start_rva, size)
            result_length = len(result)

        return result, result_length

    def parse_dotnet_resources(self) -> None:
        """
        Get resource data with information.
        """
        if self._resources_exist():
            resource_table_rows = self.metadata_tables_lookup['ManifestResource'].table_rows

            for i, table_row in enumerate(resource_table_rows):
                resource_entry = {}

                resource_string_address = table_row.string_stream_references['Name']
                try:
                    resource_name = self.dotnet_string_lookup[resource_string_address].string_representation
                except KeyError:
                    resource_name = self.dotnet_overlap_string_lookup[resource_string_address].string_representation
                resource_entry['Name'] = resource_name
                resource_entry['Visibility'] = 'public' if table_row.Flags.value == 1 else \
                                               'private' if table_row.Flags.value == 2 else \
                                               'unknown'

                if table_row.Implementation.value:
                    self.dotnet_resources.append(resource_entry)
                    continue

                resource_rva = self.clr_header.ResourcesDirectoryAddress.value + table_row.Offset.value
                next_i = i + 1
                if next_i < len(resource_table_rows):
                    resource_end_rva = self.clr_header.ResourcesDirectoryAddress.value + resource_table_rows[
                        next_i].Offset.value
                else:
                    resource_end_rva = self.clr_header.ResourcesDirectoryAddress.value + \
                                       self.clr_header.ResourcesDirectorySize.value

                if self.get_dword_at_rva(resource_rva + 4) == 0xBEEFCACE:
                    # Resource Manager header
                    # Get resource manager header version
                    resource_manager_header_version = self.get_dword_at_rva(resource_rva + 8)

                    # Get the number of bytes to skip to remaining resource manager header (class names of
                    # IResourceReader and ResourceSet)
                    number_skip_bytes = self.get_dword_at_rva(resource_rva + 12)

                    # RuntimeResourceReader header
                    # Get the version for the .resources file
                    resource_reader_header_version = self.get_dword_at_rva(resource_rva + 16 + number_skip_bytes)

                    if resource_reader_header_version == 2:
                        # Get the number of resources in the .resource file
                        number_sub_resources = self.get_dword_at_rva(resource_rva + 16 + number_skip_bytes + 4)

                        if number_sub_resources < 0:
                            self.logger.debug('Invalid number of sub-resources.')
                            break

                        resource_entry['NumberOfSubResources'] = number_sub_resources

                        # Get the number of different types in the .resources file
                        number_types = self.get_dword_at_rva(resource_rva + 16 + number_skip_bytes + 8)

                        if number_types < 0:
                            self.logger.debug('Invalid number of types.')
                            break

                        # Parse string array of serialized type names
                        user_types = []
                        current_string_offset = resource_rva + 16 + number_skip_bytes + 12
                        if number_types:
                            for j in range(number_types):
                                user_type_item = {}

                                try:
                                    current_string_length_size, current_string_length = read_7bit_encoded_int32(
                                        self.get_data(current_string_offset, 4))
                                    current_string = self.get_data(current_string_offset + current_string_length_size,
                                                                   current_string_length).decode('utf-8')
                                except PEFormatError:
                                    self.logger.debug('Invalid type name offset')
                                    break

                                user_type_item['TypeEx'] = current_string
                                user_type_item['TypeCode'] = RESOURCE_TYPE_CODES['UserType'] + j

                                current_string_offset = current_string_offset + current_string_length_size + \
                                    current_string_length
                                user_types.append(user_type_item)

                        # Skip padding bytes for 8-byte aligned (officially 'PAD' string) and get RVA of hash values
                        # array for each resource name
                        alignment_bytes = (current_string_offset - resource_rva - 4) & 7
                        alignment = 0
                        if alignment_bytes:
                            for _ in range(8 - alignment_bytes):
                                alignment += 1

                        current_hash_values_rva = current_string_offset + alignment

                        # Get hash values for each resource name
                        resource_hashes = []
                        for _ in range(number_sub_resources):
                            resource_hashes.append(self.get_dword_at_rva(current_hash_values_rva))
                            current_hash_values_rva += 4

                        # Get virtual offsets of each resource name
                        current_virtual_offset_values_rva = current_hash_values_rva
                        resource_virtual_offsets = []
                        for _ in range(number_sub_resources):
                            resource_virtual_offsets.append(self.get_dword_at_rva(current_virtual_offset_values_rva))
                            current_virtual_offset_values_rva += 4

                        # Get absolute location of data section
                        data_section_location = self.get_dword_at_rva(current_virtual_offset_values_rva)

                        # RuntimeResourceReader name section
                        # Get name and virtual offset pairs of each resource
                        name_offset_pair_rva = current_virtual_offset_values_rva + 4
                        sub_resource_rva = name_offset_pair_rva
                        name_offset_pairs = {}
                        for k in range(number_sub_resources):
                            current_name_offset_pair_rva = name_offset_pair_rva + resource_virtual_offsets[k]

                            try:
                                current_name_length_size, current_name_length = read_7bit_encoded_int32(
                                    self.get_data(current_name_offset_pair_rva, 4))
                                current_name = self._read_serialized_string(self.get_data(
                                    current_name_offset_pair_rva), encoding='utf-16')
                            except PEFormatError:
                                self.logger.debug('Invalid resource name offset')
                                break

                            current_name_offset = self.get_dword_at_rva(
                                current_name_offset_pair_rva + current_name_length_size + current_name_length) + \
                                data_section_location
                            name_offset_pairs[current_name] = current_name_offset

                            sub_resource_rva += current_name_length + current_name_length_size + 4

                        # Sort name<->offset pair list based on the offsets ascending
                        name_offset_pairs_sorted = dict(
                            sorted(name_offset_pairs.items(), key=lambda item: item[1]))

                        # RuntimeResourceReader data section
                        # Get type and value (data) of each resource
                        sub_resources = []
                        for l, (name, offset) in enumerate(name_offset_pairs_sorted.items()):
                            sub_resource_entry = {}
                            sub_resource_start = resource_rva + 4 + offset
                            next_l = l + 1
                            if next_l < len(name_offset_pairs_sorted):
                                next_sub_resource_start = resource_rva + 4 + list(name_offset_pairs_sorted.values())[
                                    next_l]
                            else:
                                next_sub_resource_start = resource_end_rva
                                # We skip the 0x0 alignment bytes between the end of the last sub-resource and the
                                # beginning of the next resource
                                if self.get_data(next_sub_resource_start - 1, 1) == b'\x00':
                                    while 1:
                                        next_sub_resource_start -= 1
                                        if self.get_data(next_sub_resource_start, 1) != b'\x00':
                                            next_sub_resource_start += 1
                                            break

                            try:
                                sub_resource_type_length, sub_resource_type = read_7bit_encoded_uint32(
                                    self.get_data(sub_resource_start, 4))
                            except IndexError:
                                self.logger.info('Sub-resource seems to be corrupt or missing.')
                                continue
                            sub_resource_size_full = next_sub_resource_start - sub_resource_start
                            sub_resource_data, sub_resource_size = self._read_resource_data(
                                sub_resource_start + sub_resource_type_length,
                                sub_resource_size_full - sub_resource_type_length, sub_resource_type)

                            sub_resource_entry['Name'] = name

                            sub_resource_type_name = ''
                            for key, value in RESOURCE_TYPE_CODES.items():
                                if value == sub_resource_type:
                                    sub_resource_type_name = key

                            if sub_resource_type >= RESOURCE_TYPE_CODES['UserType']:
                                sub_resource_entry['Type'] = 'UserType'
                                user_type_details = user_types[sub_resource_type - RESOURCE_TYPE_CODES['UserType']]
                                sub_resource_entry['TypeDetails'] = user_type_details
                            else:
                                sub_resource_entry['Type'] = sub_resource_type_name

                            sub_resource_entry['Size'] = sub_resource_size
                            sub_resource_entry['Data'] = sub_resource_data

                            sub_resources.append(sub_resource_entry)

                        resource_entry['SubResources'] = sub_resources

                    else:
                        self.logger.info(
                            f'.NET resource with reader header version {resource_reader_header_version} not supported.')
                else:
                    resource_size = self.get_dword_at_rva(resource_rva)

                    # Get the data and skip the first 4 bytes that define the size of the subsequent resource
                    resource_data = self.get_data(resource_rva + 4, resource_size)
                    resource_entry['Size'] = len(resource_data)
                    resource_entry['Data'] = resource_data

                self.dotnet_resources.append(resource_entry)
