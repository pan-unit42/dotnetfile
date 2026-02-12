"""
Original author:        Bob Jung - Palo Alto Networks (2016)
Modified/Expanded by:   Yaron Samuel - Palo Alto Networks (2021-2022),
                        Dominik Reichel - Palo Alto Networks (2021-2026)

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

from .util import (read_null_terminated_byte_string, get_reasonable_display_string_for_bytes, FileLocation,
                   read_7bit_encoded_uint32, read_7bit_encoded_int32, get_reasonable_display_unicode_string_for_bytes,
                   get_stream_sequence_length, BlobDataStructure)
from .logger import get_logger
from .structures import DOTNET_CLR_HEADER, DOTNET_METADATA_HEADER, DOTNET_STREAM_HEADER, DOTNET_METADATA_STREAM_HEADER
from .metadata_rows import get_metadata_row_class_for_table, METADATA_TABLE_ROW
from .constants import (TABLE_ROW_VARIABLE_LENGTH_FIELDS, MAX_DOTNET_STRING_LENGTH, BLOB_SIGNATURES, RESOURCE_TYPE_CODES,
                        SIGNATURE_ELEMENT_TYPES, SIGNATURE_ELEMENT_TYPES_REVERSE, CALLING_CONVENTIONS, BlobSignatureType)


PathLike = Union[str, bytes, os.PathLike, PurePath]


class CLRFormatError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class MetadataTable(object):
    def __init__(self, table_rows: List, addr: int = None, string_representation: str = None, size: int = None):
        self.address = addr
        self.string_representation = string_representation
        self.size = size
        self.table_rows = table_rows


class DotNetPEParser(PE):
    def __init__(self, file_ref: PathLike, fast_load: str, fast_load_tables: List, *args, parse: bool = True,
                 log_level: int = logging.INFO, **kwargs):
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
            'has_mixed_case_stream_names': False,
            'stream_name_padding_bytes_patched': False
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
        self.dotnet_blob_lookup: Dict[int, BlobDataStructure] = {}
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
        number_of_rva_and_sizes = self.OPTIONAL_HEADER.NumberOfRvaAndSizes  # pylint: disable=E1101

        try:
            if number_of_rva_and_sizes <= dotnet_dir_number:
                # Calculate the necessary offsets for verification
                optional_header_offset = self.NT_HEADERS.get_file_offset() + 4 + self.FILE_HEADER.sizeof()
                section_offset = optional_header_offset + self.FILE_HEADER.SizeOfOptionalHeader  # pylint: disable=E1101
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
                        self.OPTIONAL_HEADER.DATA_DIRECTORY[dotnet_data_dir].VirtualAddress != 0:  # pylint: disable=E1101
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
                if self.fast_load not in ('header_only', None):
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

    def are_stream_name_padding_bytes_patched(self, stream_name_bytes: bytes) -> None:
        """
        Check if the 0x0 padding/boundary bytes of a stream name were overwritten with random values
        as done by some obfuscators like Spices .Net Obfuscator.
        """
        if not self.dotnet_anti_metadata['stream_name_padding_bytes_patched']:
            try:
                padding_bytes = stream_name_bytes.split(b'\x00', 1)[1]
                if any(x != 0x0 for x in padding_bytes):
                    self.dotnet_anti_metadata['stream_name_padding_bytes_patched'] = True
            except Exception as e:
                self.logger.warning(f'Stream name is invalid, .NET assembly is corrupted - {e}.')

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

        for _ in range(num_streams):
            curr_stream_rva = metadata_stream_rva + metadata_hdr_size + cumulative_size
            # 0x100 is arbitrary large enough, but it is later trimmed anyway
            current_stream_bytes = self.get_data(curr_stream_rva, length=0x100)
            current_stream_header = DOTNET_STREAM_HEADER(curr_stream_rva, current_stream_bytes)
            current_stream_header.trim_byte_buffer()

            # Check if the padding/boundary bytes are overwritten as done by some obfuscators
            self.are_stream_name_padding_bytes_patched(current_stream_header.Name.value)

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

    def _get_metadata_table_row_size(self, current_row_rva: int, row_type: Type[METADATA_TABLE_ROW]) -> int:
        return self.parse_metadata_table_row_size(current_row_rva, row_type)

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

            table_row_size = self._get_metadata_table_row_size(current_row_rva, row_type)

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

        self._get_metadata_table_rva()  # This part currently cannot be bound to fast load (see method)
        self.parse_metadata_tables(metadata_tables)

    def parse_metadata_tables(self, metadata_tables: List) -> None:
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
                raise Exception(error_string)  # pylint: disable=W0707

    def parse_metadata_table_row_size(self, table_row_addr: int, row_type: Type[METADATA_TABLE_ROW]) -> int:
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

        table_row_size = self._get_metadata_table_row_size(current_row_rva, row_type)

        all_rows_data = self.get_data(current_row_rva, table_row_size * num_rows)
        for _ in range(num_rows):
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
            current_string_length, length_field_size = get_stream_sequence_length(current_string_length_bytes)
            if current_string_length == 0:
                break

            current_string_size = current_string_length + length_field_size
            current_string_bytes = self.get_data(current_string_rva, current_string_size)

            # For the actual bytes of the string we need to trim the first byte that has the length
            # plus the last byte that has some MS encoded unicode shortcut thingy
            current_string = current_string_bytes[length_field_size:-1]

            if current_string is not None and current_string_size > 1:
                current_string_location = FileLocation(current_string_rva, current_string, current_string_size)
                current_string_name = get_reasonable_display_unicode_string_for_bytes(current_string)
                current_string_location.string_representation = current_string_name

                self.dotnet_user_string_lookup[current_string_rva - stream.address] = current_string_location

            current_string_rva += current_string_size

    @staticmethod
    def _parse_blob_length(blob_bytes: bytes, offset: int = 0) -> Tuple[Optional[int], Optional[int]]:
        if len(blob_bytes) <= offset:
            return None, None

        first_byte = blob_bytes[offset]

        if (first_byte & 0x80) == 0:
            return int(first_byte), 1
        elif (first_byte & 0xC0) == 0x80:
            if len(blob_bytes) < offset + 2:
                return None, None
            second_byte = blob_bytes[offset + 1]
            length = ((first_byte & 0x3F) << 8) | second_byte
            return length, 2
        elif (first_byte & 0xE0) == 0xC0:
            if len(blob_bytes) < offset + 4:
                return None, None
            second_byte = blob_bytes[offset + 1]
            third_byte = blob_bytes[offset + 2]
            fourth_byte = blob_bytes[offset + 3]
            length = ((first_byte & 0x1F) << 24) | (second_byte << 16) | \
                     (third_byte << 8) | fourth_byte
            return length, 4
        else:
            return 0, 1

    def _parse_ser_string(self, blob_bytes: bytes, offset: int) -> Tuple[Optional[str], int]:
        length, bytes_consumed_by_len = self._parse_blob_length(blob_bytes, offset)
        if length is None:
            return None, 0

        start_data_offset = offset + bytes_consumed_by_len

        if length == 0xFF:
            return None, bytes_consumed_by_len
        elif length == 0x00:
            return '', bytes_consumed_by_len
        else:
            if len(blob_bytes) < start_data_offset + length:
                return None, 0
            try:
                s = blob_bytes[start_data_offset: start_data_offset + length].decode('utf-8')
                return s, bytes_consumed_by_len + length
            except UnicodeDecodeError:
                try:
                    s = blob_bytes[start_data_offset: start_data_offset + length].decode('latin-1')
                    return f'<UTF-8 Decode Error, decoded as Latin-1: {s}>', bytes_consumed_by_len + length
                except UnicodeDecodeError:
                    return f'<Decoding Failed: {blob_bytes[start_data_offset: start_data_offset + length].hex()}>', \
                        bytes_consumed_by_len + length

    def _parse_typedef_or_ref_encoded(self, blob_bytes: bytes, offset: int) -> Tuple[Optional[Dict], int]:
        compressed_val, bytes_consumed = self._parse_blob_length(blob_bytes, offset)
        if compressed_val is None:
            return None, 0

        tag = compressed_val & 0x03
        row_index = compressed_val >> 2

        table_name = None
        if tag == 0:
            table_name = 'TypeDef'
        elif tag == 1:
            table_name = 'TypeRef'
        elif tag == 2:
            table_name = 'TypeSpec'

        decoded_token = {'Table': table_name, 'RowId': row_index}
        return decoded_token, bytes_consumed

    def _parse_elem(self, blob_bytes: bytes, offset: int) -> Tuple[Any, int, str]:
        start_offset = offset
        if len(blob_bytes) <= start_offset:
            return None, 0, 'EMPTY'

        elem_type_byte = blob_bytes[start_offset]
        current_offset = start_offset + 1
        bytes_consumed_by_elem = 1
        elem_type_name = SIGNATURE_ELEMENT_TYPES.get(elem_type_byte, f'UNKNOWN_TYPE_0x{elem_type_byte:02X}')

        if elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('BOOLEAN'):
            if len(blob_bytes) < current_offset + 1:
                return None, 0, elem_type_name
            value = bool(blob_bytes[current_offset])
            bytes_consumed_by_elem += 1
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('CHAR'):
            if len(blob_bytes) < current_offset + 2:
                return None, 0, elem_type_name
            value = chr(struct.unpack('<H', blob_bytes[current_offset:current_offset + 2])[0])
            bytes_consumed_by_elem += 2
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('I1'):
            if len(blob_bytes) < current_offset + 1:
                return None, 0, elem_type_name
            value = struct.unpack('<b', blob_bytes[current_offset:current_offset + 1])[0]
            bytes_consumed_by_elem += 1
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('U1'):
            if len(blob_bytes) < current_offset + 1:
                return None, 0, elem_type_name
            value = blob_bytes[current_offset]
            bytes_consumed_by_elem += 1
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('I2'):
            if len(blob_bytes) < current_offset + 2:
                return None, 0, elem_type_name
            value = struct.unpack('<h', blob_bytes[current_offset:current_offset + 2])[0]
            bytes_consumed_by_elem += 2
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('U2'):
            if len(blob_bytes) < current_offset + 2:
                return None, 0, elem_type_name
            value = struct.unpack('<H', blob_bytes[current_offset:current_offset + 2])[0]
            bytes_consumed_by_elem += 2
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('I4'):
            if len(blob_bytes) < current_offset + 4:
                return None, 0, elem_type_name
            value = struct.unpack('<i', blob_bytes[current_offset:current_offset + 4])[0]
            bytes_consumed_by_elem += 4
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('U4'):
            if len(blob_bytes) < current_offset + 4:
                return None, 0, elem_type_name
            value = struct.unpack('<I', blob_bytes[current_offset:current_offset + 4])[0]
            bytes_consumed_by_elem += 4
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('I8'):
            if len(blob_bytes) < current_offset + 8:
                return None, 0, elem_type_name
            value = struct.unpack('<q', blob_bytes[current_offset:current_offset + 8])[0]
            bytes_consumed_by_elem += 8
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('U8'):
            if len(blob_bytes) < current_offset + 8:
                return None, 0, elem_type_name
            value = struct.unpack('<Q', blob_bytes[current_offset:current_offset + 8])[0]
            bytes_consumed_by_elem += 8
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('R4'):
            if len(blob_bytes) < current_offset + 4:
                return None, 0, elem_type_name
            value = struct.unpack('<f', blob_bytes[current_offset:current_offset + 4])[0]
            bytes_consumed_by_elem += 4
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('R8'):
            if len(blob_bytes) < current_offset + 8:
                return None, 0, elem_type_name
            value = struct.unpack('<d', blob_bytes[current_offset:current_offset + 8])[0]
            bytes_consumed_by_elem += 8
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('STRING'):
            s_val, s_len = self._parse_ser_string(blob_bytes, current_offset)
            if s_val is None and s_len == 0:
                return None, 0, elem_type_name
            value = s_val
            bytes_consumed_by_elem += s_len
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('OBJECT'):
            if len(blob_bytes) < current_offset + 1:
                return None, 0, elem_type_name
            obj_val, obj_len, obj_type_name = self._parse_elem(blob_bytes, current_offset)
            if obj_val is None and obj_len == 0:
                value = f'<Error parsing System.Object at {current_offset}>'
            else:
                value = {'ObjectType': obj_type_name, 'Value': obj_val}
            bytes_consumed_by_elem += obj_len
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('SZARRAY'):
            if len(blob_bytes) < current_offset + 1:
                return None, 0, elem_type_name
            array_elem_type_byte = blob_bytes[current_offset]
            current_offset += 1
            bytes_consumed_by_elem += 1
            array_elem_type_name = SIGNATURE_ELEMENT_TYPES.get(array_elem_type_byte,
                                                               f'UNKNOWN_ARRAY_ELEM_TYPE_0x{array_elem_type_byte:02X}')
            array_len_val, array_len_bytes_consumed = self._parse_blob_length(blob_bytes, current_offset)
            if array_len_val is None:
                return None, 0, elem_type_name
            current_offset += array_len_bytes_consumed
            bytes_consumed_by_elem += array_len_bytes_consumed
            if array_len_val == 0xFFFFFFFF:
                value = None
            else:
                array_elements = []
                for _ in range(array_len_val):
                    if len(blob_bytes) < current_offset + 1:
                        return None, 0, elem_type_name
                    temp_elem_bytes = bytes([array_elem_type_byte]) + blob_bytes[current_offset:]
                    elem_val, elem_len_inner, _ = self._parse_elem(temp_elem_bytes, 0)
                    if elem_val is None and elem_len_inner == 0:
                        return None, 0, elem_type_name
                    array_elements.append(elem_val)
                    current_offset += (elem_len_inner - 1)
                    bytes_consumed_by_elem += (elem_len_inner - 1)
                value = {'ArrayElementType': array_elem_type_name, 'Elements': array_elements}
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('CA_TYPE_System.Type'):
            s_val, s_len = self._parse_ser_string(blob_bytes, current_offset)
            if s_val is None and s_len == 0:
                return None, 0, elem_type_name
            value = {'System.Type': s_val}
            bytes_consumed_by_elem += s_len
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('CA_TYPE_Enum'):
            enum_type_name, enum_type_name_len = self._parse_ser_string(blob_bytes, current_offset)
            if enum_type_name is None and enum_type_name_len == 0:
                return None, 0, elem_type_name
            current_offset += enum_type_name_len
            bytes_consumed_by_elem += enum_type_name_len

            if len(blob_bytes) < current_offset + 4:
                value = {'EnumTypeName': enum_type_name,
                         'Value': f'<Incomplete Enum Value {blob_bytes[current_offset:].hex()}>'}
                bytes_consumed_by_elem += len(
                    blob_bytes) - current_offset
            else:
                enum_value = struct.unpack('<i', blob_bytes[current_offset:current_offset + 4])[0]
                value = {'EnumTypeName': enum_type_name, 'Value': enum_value,
                         'UnderlyingType_Guessed': 'I4'}
                bytes_consumed_by_elem += 4
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('CA_TYPE_BoxedValue'):
            inner_elem_val, inner_elem_len, inner_elem_type_name = self._parse_elem(blob_bytes, current_offset)
            if inner_elem_val is None:
                return None, 0, elem_type_name
            value = {'BoxedType': inner_elem_type_name, 'Value': inner_elem_val}
            bytes_consumed_by_elem += inner_elem_len
        elif elem_type_byte in [
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('VALUETYPE'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('CLASS'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('PTR'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('BYREF'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('CMOD_REQD'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('CMOD_OPT'),
        ]:
            if elem_type_byte in [SIGNATURE_ELEMENT_TYPES_REVERSE.get('PTR'),
                                  SIGNATURE_ELEMENT_TYPES_REVERSE.get('BYREF')]:
                pointed_to_val, pointed_to_len, pointed_to_type_name = self._parse_elem(blob_bytes, current_offset)
                if pointed_to_val is None and pointed_to_len == 0:
                    return None, 0, elem_type_name
                value = {'PointerType': elem_type_name, 'TargetType': pointed_to_val,
                         'TargetTypeName': pointed_to_type_name}
                bytes_consumed_by_elem += pointed_to_len
            else:
                token_val, token_len = self._parse_typedef_or_ref_encoded(blob_bytes, current_offset)
                if token_val is None:
                    return None, 0, elem_type_name
                value = {'Type': elem_type_name, 'Token': token_val}
                bytes_consumed_by_elem += token_len
        elif elem_type_byte in [
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('VAR'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('MVAR')
        ]:
            index_val, index_len = self._parse_blob_length(blob_bytes, current_offset)
            if index_val is None:
                return None, 0, elem_type_name
            value = {'GenericParameterType': elem_type_name, 'Index': index_val}
            bytes_consumed_by_elem += index_len
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('ARRAY'):
            value = f'<UNSUPPORTED_COMPLEX_TYPE: {elem_type_name} (0x{elem_type_byte:02X}) - ArrayShape parsing needed>'
            bytes_to_consume = len(blob_bytes) - current_offset
            if bytes_to_consume < 0:
                bytes_to_consume = 0
            bytes_consumed_by_elem += bytes_to_consume
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('GENERICINST'):
            value = f'<UNSUPPORTED_COMPLEX_TYPE: {elem_type_name} (0x{elem_type_byte:02X}) - Generic Instance parsing needed>'
            if len(blob_bytes) > current_offset:
                current_offset += 1
                bytes_consumed_by_elem += 1

                token_val, token_len = self._parse_typedef_or_ref_encoded(blob_bytes, current_offset)
                if token_val is not None:
                    current_offset += token_len
                    bytes_consumed_by_elem += token_len

                    gen_arg_count_val, gen_arg_count_len = self._parse_blob_length(blob_bytes, current_offset)
                    if gen_arg_count_val is not None:
                        current_offset += gen_arg_count_len
                        bytes_consumed_by_elem += gen_arg_count_len

                        for _ in range(gen_arg_count_val):
                            arg_val, arg_len, _ = self._parse_elem(blob_bytes, current_offset)
                            if arg_val is None:
                                break
                            current_offset += arg_len
                            bytes_consumed_by_elem += arg_len
            value = {'GenericInstance': value, 'RawData': blob_bytes[start_offset:current_offset].hex()}
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('FNPTR'):
            value = f'<UNSUPPORTED_COMPLEX_TYPE: {elem_type_name} (0x{elem_type_byte:02X}) - FunctionPointer signature needed>'
            bytes_to_consume = len(blob_bytes) - current_offset
            if bytes_to_consume < 0:
                bytes_to_consume = 0
            bytes_consumed_by_elem += bytes_to_consume
        elif elem_type_byte == SIGNATURE_ELEMENT_TYPES_REVERSE.get('TYPEDBYREF'):
            value = elem_type_name
        elif elem_type_byte in [SIGNATURE_ELEMENT_TYPES_REVERSE.get('I'), SIGNATURE_ELEMENT_TYPES_REVERSE.get('U')]:
            value = elem_type_name
        elif elem_type_byte in [
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('END'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('VOID'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('INTERNAL'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('MODIFIER'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('SENTINEL'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('PINNED'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('Reserved'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('CA_FIELD'),
            SIGNATURE_ELEMENT_TYPES_REVERSE.get('CA_PROPERTY'),
        ]:
            value = elem_type_name
        else:
            value = f'<UNRECOGNIZED_TYPE: {elem_type_name} (0x{elem_type_byte:02X}) at offset {start_offset}>'
            bytes_to_consume = len(blob_bytes) - start_offset

            if bytes_to_consume < 0:
                bytes_to_consume = 0
            bytes_consumed_by_elem = bytes_to_consume

        return value, bytes_consumed_by_elem, elem_type_name

    def _parse_fixed_arg(self, blob_bytes: bytes, offset: int, expected_type_element_value: int) -> Tuple[Any, int]:
        temp_bytes_for_elem_parsing = bytes([expected_type_element_value]) + blob_bytes[offset:]
        value, consumed_by_elem, _ = self._parse_elem(temp_bytes_for_elem_parsing, 0)

        if value is None and consumed_by_elem == 0:
            return None, 0

        return value, consumed_by_elem - 1

    def _parse_named_arg(self, blob_bytes: bytes, offset: int) -> Tuple[Optional[str], Optional[str], Any, int]:
        start_offset = offset
        if len(blob_bytes) <= start_offset:
            return None, None, None, 0

        member_kind_byte = blob_bytes[offset]
        current_offset = offset + 1
        bytes_consumed_by_named_arg = 1
        member_kind = SIGNATURE_ELEMENT_TYPES.get(member_kind_byte, 'UNKNOWN_MEMBER_KIND')

        if len(blob_bytes) < current_offset + 1:
            return None, None, None, 0
        arg_type_byte = blob_bytes[current_offset]
        current_offset += 1
        bytes_consumed_by_named_arg += 1

        name_val, name_len = self._parse_ser_string(blob_bytes, current_offset)
        if name_val is None and name_len == 0:
            return None, None, None, 0

        current_offset += name_len
        bytes_consumed_by_named_arg += name_len

        temp_bytes_for_elem_parsing = bytes([arg_type_byte]) + blob_bytes[current_offset:]
        value_val, value_len, _ = self._parse_elem(temp_bytes_for_elem_parsing, 0)
        if value_val is None and value_len == 0:
            return None, None, None, 0

        current_offset += (value_len - 1)
        bytes_consumed_by_named_arg += (value_len - 1)

        return member_kind, name_val, value_val, bytes_consumed_by_named_arg

    def parse_custom_attribute_blob(self, blob_data_bytes: bytes, expected_fixed_arg_types: List) -> Dict:
        parsed_content = {
            'Prolog': None,
            'FixedArguments': [],
            'NumNamed': None,
            'NamedArguments': [],
            'RemainingBytes': None,
            'ParseErrors': []
        }
        offset = 0

        if len(blob_data_bytes) >= offset + 2:
            prolog = struct.unpack('<H', blob_data_bytes[offset:offset + 2])[0]
            if prolog != 0x0001:
                parsed_content['ParseErrors'].append(
                    f'Invalid CustomAttribute prolog: expected 0x0001, got 0x{prolog:04X}.')
                return parsed_content
            parsed_content['Prolog'] = prolog
            offset += 2
        else:
            parsed_content['ParseErrors'].append(
                f'Incomplete CustomAttribute blob: Not enough bytes for prolog (expected 2,'
                f' got {len(blob_data_bytes) - offset}).')
            return parsed_content

        for i, expected_type_byte in enumerate(expected_fixed_arg_types):
            if len(blob_data_bytes) <= offset:
                parsed_content['ParseErrors'].append(
                    f'Incomplete CustomAttribute blob: Not enough bytes for fixed argument {i}'
                    f' (expected type 0x{expected_type_byte:02X}).')
                break

            fixed_arg_value, fixed_arg_consumed = self._parse_fixed_arg(blob_data_bytes, offset, expected_type_byte)

            if fixed_arg_value is None and fixed_arg_consumed == 0:
                parsed_content['ParseErrors'].append(
                    f'Failed to parse fixed argument {i} with expected type 0x{expected_type_byte:02X}.'
                    f' Remaining bytes: {blob_data_bytes[offset:].hex()}')
                break

            parsed_content['FixedArguments'].append(fixed_arg_value)
            offset += fixed_arg_consumed

        if len(blob_data_bytes) >= offset + 2:
            num_named = struct.unpack('<H', blob_data_bytes[offset:offset + 2])[0]
            parsed_content['NumNamed'] = num_named
            offset += 2
        elif len(blob_data_bytes) == offset:
            parsed_content['NumNamed'] = 0
        else:
            parsed_content['ParseErrors'].append(
                f'Incomplete CustomAttribute blob: Not enough bytes for NumNamed (expected 2,'
                f' got {len(blob_data_bytes) - offset}).')
            return parsed_content

        for i in range(parsed_content['NumNamed']):
            if len(blob_data_bytes) <= offset:
                parsed_content['ParseErrors'].append(
                    f'Incomplete CustomAttribute blob: Not enough bytes for named argument {i}.'
                    f' Expected {parsed_content["NumNamed"]} named arguments, but blob ended prematurely.')
                break

            member_kind, name, value, consumed = self._parse_named_arg(blob_data_bytes, offset)
            if member_kind is None:
                parsed_content['ParseErrors'].append(
                    f'Failed to parse named argument {i} at offset {offset}. Remaining bytes: '
                    f'{blob_data_bytes[offset:].hex()}')
                break

            parsed_content['NamedArguments'].append({
                'Kind': member_kind,
                'Name': name,
                'Value': value
            })
            offset += consumed

        if len(blob_data_bytes) > offset:
            parsed_content['RemainingBytes'] = blob_data_bytes[offset:].hex()
            if all(b == 0 for b in blob_data_bytes[offset:]):
                parsed_content['ParseErrors'].append('Trailing zero bytes (likely padding).')
            else:
                parsed_content['ParseErrors'].append(
                    f"Unparsed trailing bytes: {parsed_content['RemainingBytes']} (Length: {len(blob_data_bytes) - offset} bytes).")

        return parsed_content

    def _parse_method_signature_blob(self, signature_blob_bytes: bytes) -> list:
        offset = 0

        if len(signature_blob_bytes) < offset + 1:
            return []
        calling_convention_byte = signature_blob_bytes[offset]
        offset += 1

        is_generic = (calling_convention_byte & 0x10) == 0x10

        if is_generic:
            gen_param_count, consumed = self._parse_blob_length(signature_blob_bytes, offset)
            if gen_param_count is None:
                return []
            offset += consumed

        param_count, consumed = self._parse_blob_length(signature_blob_bytes, offset)
        if param_count is None:
            return []
        offset += consumed

        _, ret_type_len, _ = self._parse_elem(signature_blob_bytes, offset)
        offset += ret_type_len

        fixed_arg_element_types = []
        for _ in range(param_count):
            if len(signature_blob_bytes) <= offset:
                break

            param_elem_type_byte = signature_blob_bytes[offset]
            fixed_arg_element_types.append(param_elem_type_byte)

            _, consumed_by_param_type, _ = self._parse_elem(signature_blob_bytes, offset)
            offset += consumed_by_param_type

        return fixed_arg_element_types

    @staticmethod
    def _get_signature_type(signature_blob_bytes: bytes) -> BlobSignatureType:
        """
        Recognizes the type of CLI signature blob based on its initial bytes.
        """
        if not signature_blob_bytes:
            return BlobSignatureType.EMPTY

        # 1. Custom Attribute Prologue (ECMA-335, II.23.3)
        if len(signature_blob_bytes) >= 2 and struct.unpack('<H', signature_blob_bytes[0:2])[0] == 0x0001:
            return BlobSignatureType.CUSTOM_ATTRIBUTE

        first_byte = signature_blob_bytes[0]
        call_kind_mask = 0x0F
        call_conv_kind = first_byte & call_kind_mask

        # 2. Method Signature Blobs (MethodDefSig, MethodRefSig, StandAloneMethodSig)
        if call_conv_kind in [
            CALLING_CONVENTIONS[0x00],
            CALLING_CONVENTIONS[0x01],
            CALLING_CONVENTIONS[0x02],
            CALLING_CONVENTIONS[0x03],
            CALLING_CONVENTIONS[0x04],
            CALLING_CONVENTIONS[0x05]
        ]:
            if (first_byte & CALLING_CONVENTIONS[0x10]) == CALLING_CONVENTIONS[0x10]:
                return BlobSignatureType.METHOD_GENERIC
            else:
                return BlobSignatureType.METHOD_NON_GENERIC

        # 3. FieldSig (ECMA-335, II.23.2.4)
        if first_byte == CALLING_CONVENTIONS[0x06]:
            return BlobSignatureType.FIELD

        # 4. PropertySig (ECMA-335, II.23.2.5)
        if (first_byte & call_kind_mask) == CALLING_CONVENTIONS[0x08]:
            return BlobSignatureType.PROPERTY

        # 5. LocalVarSig (ECMA-335, II.23.2.6)
        if first_byte == CALLING_CONVENTIONS[0x07]:
            return BlobSignatureType.LOCAL_VAR

        # 6. MethodSpecBlob (ECMA-335, II.23.2.15)
        if first_byte == CALLING_CONVENTIONS[0x0A]:
            return BlobSignatureType.METHOD_SPEC

        # 7. TypeSpecBlob (ECMA-335, II.23.2.14)
        if first_byte in [
            SIGNATURE_ELEMENT_TYPES_REVERSE['PTR'],
            SIGNATURE_ELEMENT_TYPES_REVERSE['ARRAY'],
            SIGNATURE_ELEMENT_TYPES_REVERSE['SZARRAY'],
            SIGNATURE_ELEMENT_TYPES_REVERSE['GENERICINST'],
            SIGNATURE_ELEMENT_TYPES_REVERSE['FNPTR'],
            SIGNATURE_ELEMENT_TYPES_REVERSE['CLASS'],
            SIGNATURE_ELEMENT_TYPES_REVERSE['VALUETYPE'],
        ]:
            return BlobSignatureType.TYPE_SPEC

        return BlobSignatureType.UNKNOWN

    def parse_blob_stream(self) -> None:
        stream = self.dotnet_stream_lookup[self.stream_names_map['#Blob']]

        # This stream starts with a null byte.
        current_blob_rva = stream.address + 1

        while current_blob_rva < stream.address + stream.size:
            # can be 1-4 bytes
            current_blob_length_bytes = self.get_data(current_blob_rva, length=4)
            current_blob_length, length_field_size = get_stream_sequence_length(current_blob_length_bytes)

            current_blob_size = current_blob_length + length_field_size
            current_blob_bytes = self.get_data(current_blob_rva, current_blob_size)

            current_blob_bytes = current_blob_bytes[length_field_size:]

            blob_signature = BLOB_SIGNATURES.get(current_blob_bytes)
            if not blob_signature:
                blob_signature = {}

            current_blob_data_structure = BlobDataStructure(
                address=current_blob_rva,
                byte_buffer=current_blob_bytes,
                size=current_blob_size,
                signature_type=self._get_signature_type(current_blob_bytes),
                structure_fields=blob_signature
            )

            self.dotnet_blob_lookup[current_blob_rva - stream.address] = current_blob_data_structure
            current_blob_rva += current_blob_size

        # Skip custom attribute processing if the table doesn't exist
        if 'CustomAttribute' not in self.metadata_tables_lookup:
            return

        # Build lookup dictionary for custom attributes
        ca_table = self.metadata_tables_lookup['CustomAttribute']
        custom_attributes_lookup = {
            row.blob_stream_references['Value']: idx
            for idx, row in enumerate(ca_table.table_rows)
        }

        # Process custom attribute blobs
        for blob_index, blob_item in self.dotnet_blob_lookup.items():
            if blob_item.structure_fields or blob_item.signature_type != BlobSignatureType.CUSTOM_ATTRIBUTE:
                continue

            table_row_idx = custom_attributes_lookup.get(blob_index)
            if table_row_idx is None:
                continue

            try:
                # Get the custom attribute table row
                ca_row = ca_table.table_rows[table_row_idx]
                table_references = getattr(ca_row, 'table_references', None)
                if not table_references:
                    continue

                # Get the method that defines this attribute
                type_ref = table_references.get('Type')
                if not type_ref or type_ref[0] not in ('MethodDef', 'MemberRef'):
                    continue

                # Get method signature to determine expected argument types
                table_name, row_num = type_ref
                method_row = self.metadata_tables_lookup[table_name].table_rows[row_num - 1]
                sig_index = method_row.blob_stream_references['Signature']
                signature_bytes = self.dotnet_blob_lookup[sig_index].buffer

                # Parse the method signature to get expected argument types
                expected_fixed_arg_types = self._parse_method_signature_blob(signature_bytes)

                # Parse the custom attribute blob with the expected argument types
                self.dotnet_blob_lookup[blob_index].structure_fields = self.parse_custom_attribute_blob(
                    blob_item.buffer, expected_fixed_arg_types)
            except Exception as e:
                self.logger.debug(
                    f'Exception while parsing blob item {blob_index}, bytes {blob_item.buffer.hex()} - {e}')

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

    def calculate_field_size_info(self, table_size_lookup: Dict[str: int]) -> Dict:
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

    def _read_serialized_string(self, string: bytes, encoding: str = 'utf-8') -> str:
        encodings = [encoding, 'ISO-8859-1']
        result = ''

        if string:
            string_length_size, string_length = read_7bit_encoded_int32(string[:4])
            for enc in encodings:
                try:
                    result = string[string_length_size:string_length_size + string_length].decode(enc)
                    break
                except UnicodeDecodeError as e:
                    self.logger.info(
                        f'Resource string ({enc}) decoding error, data seems to be corrupted - {e}. '
                        f'Trying the next encoding.')

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
                    resource_manager_header_version = self.get_dword_at_rva(resource_rva + 8)  # noqa: F841 # pylint: disable=W0612

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
                        for l, (name, offset) in enumerate(name_offset_pairs_sorted.items()):  # noqa: E741
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
                                    while True:
                                        next_sub_resource_start -= 1
                                        if self.get_data(next_sub_resource_start, 1) != b'\x00':
                                            next_sub_resource_start += 1
                                            break

                            try:
                                sub_resource_type_length, sub_resource_type = read_7bit_encoded_uint32(
                                    self.get_data(sub_resource_start, 4))
                            except (IndexError, PEFormatError):
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
                                if user_types:
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
