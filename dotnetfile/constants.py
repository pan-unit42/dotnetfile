'''
Part of dotnetfile

Original author:        Bob Jung - Palo Alto Networks (2016)
Modified/Expanded by:   Yaron Samuel - Palo Alto Networks (2021-2022),
                        Dominik Reichel - Palo Alto Networks (2021-2025)
'''

# flake8: noqa

from enum import Enum
from typing import Union, Tuple


# Max string length reference:
# https://github.com/dotnet/roslyn/blob/main/src/Compilers/Core/Portable/PEWriter/MetadataWriter.cs#L51
MAX_DOTNET_STRING_LENGTH = 1024

FAST_LOAD_TABLES_DEFAULT = [
    'Module',
    'TypeRef',
    'TypeDef',
    'MethodDef',
    'MemberRef',
    'CustomAttribute',
    'Event',
    'ModuleRef',
    'ImplMap',
    'Assembly',
    'AssemblyRef',
    'ManifestResource'
]

TABLE_ROW_VARIABLE_LENGTH_FIELDS = {
    'TypeDefOrRef':         ['TypeDef', 'TypeRef', 'TypeSpec'],
    'HasConstant':          ['Field', 'Param', 'Property'],
    'HasCustomAttribute':   ['MethodDef', 'Field', 'TypeRef', 'TypeDef', 'Param', 'InterfaceImpl', 'MemberRef',
                             'Module', 'Permission', 'Property', 'Event', 'StandAloneSig', 'ModuleRef', 'TypeSpec',
                             'Assembly', 'AssemblyRef', 'File', 'ExportedType', 'ManifestResource', 'GenericParam',
                             'GenericParamConstraint', 'MethodSpec'],
    'HasFieldMarshal':      ['Field', 'Param'],
    'HasDeclSecurity':      ['TypeDef', 'MethodDef', 'Assembly'],
    'MemberRefParent':      ['TypeDef', 'TypeRef', 'ModuleRef', 'MethodDef', 'TypeSpec'],
    'HasSemantics':         ['Event', 'Property'],
    'MethodDefOrRef':       ['MethodDef', 'MemberRef'],
    'MemberForwarded':      ['Field', 'MethodDef'],
    'Implementation':       ['File', 'AssemblyRef', 'ExportedType'],
    'CustomAttributeType':  ['MethodDef', 'MethodDef', 'MethodDef', 'MemberRef', 'MethodDef'],
    'ResolutionScope':      ['Module', 'ModuleRef', 'AssemblyRef', 'TypeRef'],
    'TypeOrMethodDef':      ['TypeDef', 'MethodDef']
}

METADATA_TABLE_INDEXES = {
    0:  'Module',
    1:  'TypeRef',
    2:  'TypeDef',
    3:  'FieldPtr',
    4:  'Field',
    5:  'MethodPtr',
    6:  'MethodDef',
    7:  'ParamPtr',
    8:  'Param',
    9:  'InterfaceImpl',
    10: 'MemberRef',
    11: 'Constant',
    12: 'CustomAttribute',
    13: 'FieldMarshal',
    14: 'DeclSecurity',
    15: 'ClassLayout',
    16: 'FieldLayout',
    17: 'StandAloneSig',
    18: 'EventMap',
    19: 'EventPtr',
    20: 'Event',
    21: 'PropertyMap',
    22: 'PropertyPtr',
    23: 'Property',
    24: 'MethodSemantics',
    25: 'MethodImpl',
    26: 'ModuleRef',
    27: 'TypeSpec',
    28: 'ImplMap',
    29: 'FieldRVA',
    30: 'EncLog',
    31: 'EncMap',
    32: 'Assembly',
    33: 'AssemblyProcessor',
    34: 'AssemblyOS',
    35: 'AssemblyRef',
    36: 'AssemblyRefProcessor',
    37: 'AssemblyRefOS',
    38: 'File',
    39: 'ExportedType',
    40: 'ManifestResource',
    41: 'NestedClass',
    42: 'GenericParam',
    43: 'MethodSpec',
    44: 'GenericParamConstraint',
    48: 'Document',
    49: 'MethodDebugInformation',
    50: 'LocalScope',
    51: 'LocalVariable',
    52: 'LocalConstant',
    53: 'ImportScope',
    54: 'StateMachineMethod',
    55: 'CustomDebugInformation'
}

METADATA_TABLE_FLAGS = {
    1:                  'Module',
    2:                  'TypeRef',
    4:                  'TypeDef',
    8:                  'FieldPtr',
    16:                 'Field',
    32:                 'MethodPtr',
    64:                 'MethodDef',
    128:                'ParamPtr',
    256:                'Param',
    512:                'InterfaceImpl',
    1024:               'MemberRef',
    2048:               'Constant',
    4096:               'CustomAttribute',
    8192:               'FieldMarshal',
    16384:              'DeclSecurity',
    32768:              'ClassLayout',
    65536:              'FieldLayout',
    131072:             'StandAloneSig',
    262144:             'EventMap',
    524288:             'EventPtr',
    1048576:            'Event',
    2097152:            'PropertyMap',
    4194304:            'PropertyPtr',
    8388608:            'Property',
    16777216:           'MethodSemantics',
    33554432:           'MethodImpl',
    67108864:           'ModuleRef',
    134217728:          'TypeSpec',
    268435456:          'ImplMap',
    536870912:          'FieldRVA',
    1073741824:         'EncLog',
    2147483648:         'EncMap',
    4294967296:         'Assembly',
    8589934592:         'AssemblyProcessor',
    17179869184:        'AssemblyOS',
    34359738368:        'AssemblyRef',
    68719476736:        'AssemblyRefProcessor',
    137438953472:       'AssemblyRefOS',
    274877906944:       'File',
    549755813888:       'ExportedType',
    1099511627776:      'ManifestResource',
    2199023255552:      'NestedClass',
    4398046511104:      'GenericParam',
    8796093022208:      'MethodSpec',
    17592186044416:     'GenericParamConstraint',
    35184372088832:     'Document',
    70368744177664:     'MethodDebugInformation',
    140737488355328:    'LocalScope',
    281474976710656:    'LocalVariable',
    562949953421312:    'LocalConstant',
    1125899906842624:   'ImportScope',
    2251799813685248:   'StateMachineMethod',
    4503599627370496:   'CustomDebugInformation'
}

METADATA_TOKEN_TABLES = {
    0x00000000: 'Module',
    0x01000000: 'TypeRef',
    0x02000000: 'TypeDef',
    0x04000000: 'Field',
    0x06000000: 'MethodDef',
    0x08000000: 'Param',
    0x09000000: 'InterfaceImpl',
    0x0A000000: 'MemberRef',
    0x0C000000: 'CustomAttribute',
    0x0E000000: 'DeclSecurity',
    0x11000000: 'StandAloneSig',
    0x14000000: 'Event',
    0x17000000: 'Property',
    0x1A000000: 'ModuleRef',
    0x1B000000: 'TypeSpec',
    0x20000000: 'Assembly',
    0x23000000: 'AssemblyRef',
    0x26000000: 'File',
    0x27000000: 'ExportedType',
    0x28000000: 'ManifestResource',
    0x2A000000: 'GenericParam',
    0x2B000000: 'MethodSpec',
    0x2C000000: 'GenericParamConstraint'
}

RESOURCE_TYPE_CODES = {
    'Null':         0,
    'String':       1,
    'Boolean':      2,
    'Char':         3,
    'Byte':         4,
    'SByte':        5,
    'Int16':        6,
    'UInt16':       7,
    'Int32':        8,
    'UInt32':       9,
    'Int64':        10,
    'UInt64':       11,
    'Single':       12,
    'Double':       13,
    'Decimal':      14,
    'DateTime':     15,
    'Timespan':     16,
    'ByteArray':    32,
    'Stream':       33,
    'UserType':     64
}

SIGNATURE_ELEMENT_TYPES = {
    0x00: 'END',
    0x01: 'VOID',
    0x02: 'BOOLEAN',
    0x03: 'CHAR',
    0x04: 'I1',
    0x05: 'U1',
    0x06: 'I2',
    0x07: 'U2',
    0x08: 'I4',
    0x09: 'U4',
    0x0A: 'I8',
    0x0B: 'U8',
    0x0C: 'R4',
    0x0D: 'R8',
    0x0E: 'STRING',
    0x0F: 'PTR',
    0x10: 'BYREF',
    0x11: 'VALUETYPE',
    0x12: 'CLASS',
    0x13: 'VAR',
    0x14: 'ARRAY',
    0x15: 'GENERICINST',
    0x16: 'TYPEDBYREF',
    0x18: 'I',
    0x19: 'U',
    0x1B: 'FNPTR',
    0x1C: 'OBJECT',
    0x1D: 'SZARRAY',
    0x1E: 'MVAR',
    0x1F: 'CMOD_REQD',
    0x20: 'CMOD_OPT',
    0x21: 'INTERNAL',
    0x40: 'MODIFIER',
    0x41: 'SENTINEL',
    0x45: 'PINNED',
    0x50: 'CA_TYPE_System.Type',
    0x51: 'CA_TYPE_BoxedValue',
    0x52: 'Reserved',
    0x53: 'CA_FIELD',
    0x54: 'CA_PROPERTY',
    0x55: 'CA_TYPE_Enum',
}

SIGNATURE_ELEMENT_TYPES_REVERSE = {v: k for k, v in SIGNATURE_ELEMENT_TYPES.items()}


def _blob_signature_helper(hasthis: bool, ret: str, params: Union[Tuple, str] = ()):
    return {
        'hasthis': hasthis,
        'return': ret,
        'parameter': params if isinstance(params, Tuple) else (params,) if params else ()
    }


BLOB_SIGNATURES = {
    b'\x06\x05': _blob_signature_helper(False, 'System.Byte'),
    b'\x06\x07': _blob_signature_helper(False, 'System.UInt16'),
    b'\x06\x08': _blob_signature_helper(False, 'System.Int32'),
    b'\x06\x09': _blob_signature_helper(False, 'System.UInt32'),
    b'\x06\x0B': _blob_signature_helper(False, 'System.UInt64'),
    b'\x00\x00\x01': _blob_signature_helper(False, 'System.Void'),
    b'\x00\x00\x02': _blob_signature_helper(False, 'System.Boolean'),
    b'\x00\x00\x0E': _blob_signature_helper(False, 'System.String'),
    b'\x06\x0F\x05': _blob_signature_helper(False, 'System.Byte*'),
    b'\x06\x0F\x09': _blob_signature_helper(False, 'System.UInt32*'),
    b'\x20\x00\x01': _blob_signature_helper(True, 'System.Void'),
    b'\x20\x00\x02': _blob_signature_helper(True, 'System.Boolean'),
    b'\x20\x00\x08': _blob_signature_helper(True, 'System.Int32'),
    b'\x20\x00\x0A': _blob_signature_helper(True, 'System.Int64'),
    b'\x20\x00\x0E': _blob_signature_helper(True, 'System.String'),
    b'\x00\x01\x01\x08': _blob_signature_helper(False, 'System.Void', 'System.Int32'),
    b'\x00\x01\x01\x18': _blob_signature_helper(False, 'System.Void', 'System.IntPtr'),
    b'\x00\x01\x01\x1C': _blob_signature_helper(False, 'System.Void', 'System.Object'),
    b'\x00\x01\x07\x07': _blob_signature_helper(False, 'System.UInt16', 'System.UInt16'),
    b'\x00\x01\x08\x09': _blob_signature_helper(False, 'System.Int32', 'System.UInt32'),
    b'\x00\x01\x08\x0A': _blob_signature_helper(False, 'System.Int32', 'System.Int64'),
    b'\x00\x01\x09\x02': _blob_signature_helper(False, 'System.UInt32', 'System.Boolean'),
    b'\x00\x01\x18\x08': _blob_signature_helper(False, 'System.IntPtr', 'System.Int32'),
    b'\x00\x01\x18\x09': _blob_signature_helper(False, 'System.IntPtr', 'System.UInt32'),
    b'\x20\x00\x0F\x01': _blob_signature_helper(True, 'System.Void*'),
    b'\x20\x01\x01\x02': _blob_signature_helper(True, 'System.Void', 'System.Boolean'),
    b'\x20\x01\x01\x08': _blob_signature_helper(True, 'System.Void', 'System.Int32'),
    b'\x20\x01\x01\x0A': _blob_signature_helper(True, 'System.Void', 'System.Int64'),
    b'\x20\x01\x01\x0E': _blob_signature_helper(True, 'System.Void', 'System.String'),
    b'\x20\x01\x03\x08': _blob_signature_helper(True, 'System.Char', 'System.Int32'),
    b'\x00\x00\x20\x39\x02': _blob_signature_helper(False, 'System.Boolean'),
    b'\x00\x01\x01\x1D\x0E': _blob_signature_helper(False, 'System.Void', 'System.String[]'),
    b'\x00\x01\x08\x1D\x05': _blob_signature_helper(False, 'System.Int32', 'System.Byte[]'),
    b'\x00\x01\x09\x0F\x05': _blob_signature_helper(False, 'System.UInt32', 'System.Byte*'),
    b'\x00\x01\x0E\x1D\x0E': _blob_signature_helper(False, 'System.String', 'System.String[]'),
    b'\x00\x01\x0F\x01\x18': _blob_signature_helper(False, 'System.Void*', 'System.IntPtr'),
    b'\x00\x01\x12\x51\x0E': _blob_signature_helper(False, 'System.IO.FileStream', 'System.String'),
    b'\x00\x01\x1D\x05\x0E': _blob_signature_helper(False, 'System.Byte[]', 'System.String'),
    b'\x00\x02\x01\x09\x18': _blob_signature_helper(False, 'System.Void', ('System.UInt32', 'System.InPtr')),
    b'\x00\x02\x08\x08\x0E': _blob_signature_helper(False, 'System.Int32', ('System.Int32', 'System.String')),
    b'\x20\x01\x01\x0F\x01': _blob_signature_helper(True, 'System.Void', 'System.Void*'),
    b'\x20\x01\x01\x11\x1D': _blob_signature_helper(True, 'System.Void', 'System.Security.Permissions.SecurityAction'),
    b'\x20\x01\x01\x11\x6D': _blob_signature_helper(True, 'System.Void', 'System.Runtime.InteropServices.LayoutKind'),
    b'\x20\x01\x09\x12\x11': _blob_signature_helper(True, 'System.UInt32', 'System.IAsyncResult'),
    b'\x20\x02\x01\x0E\x0E': _blob_signature_helper(True, 'System.Void', ('System.String', 'System.String')),
    b'\x20\x02\x01\x1C\x18': _blob_signature_helper(True, 'System.Void', ('System.Object', 'System.IntPtr')),
    b'\x00\x01\x12\x41\x11\x45': _blob_signature_helper(False, 'System.Type', 'System.RuntimeTypeHandle'),
    b'\x00\x02\x02\x0E\x0F\x05': _blob_signature_helper(False, 'System.Boolean', ('System.String', 'System.Byte*')),
    b'\x00\x02\x09\x09\x0F\x05': _blob_signature_helper(False, 'System.UInt32', ('System.UInt32', 'System.Byte*')),
    b'\x00\x03\x08\x09\x09\x09': _blob_signature_helper(False, 'System.Int32', ('System.UInt32', 'System.UInt32', 'System.UInt32')),
    b'\x20\x02\x01\x12\x41\x08': _blob_signature_helper(True, 'System.Void', ('System.Type', 'System.Int32')),
    b'\x20\x03\x01\x08\x08\x08': _blob_signature_helper(True, 'System.Void', ('System.Int32', 'System.Int32', 'System.Int32')),
    b'\x20\x03\x09\x09\x09\x09': _blob_signature_helper(True, 'System.UInt32', ('System.UInt32', 'System.UInt32', 'System.UInt32')),
    b'\x00\x02\x01\x12\x61\x11\x65': _blob_signature_helper(False, 'System.Void', ('System.Array', 'System.RuntimeFieldHandle')),
    b'\x00\x02\x12\x49\x18\x12\x41': _blob_signature_helper(False, 'System.Delegate', ('System.IntPtr', 'System.Type')),
    b'\x00\x03\x01\x0F\x05\x05\x09': _blob_signature_helper(False, 'System.Void', ('System.Byte*', 'System.Byte', 'System.UInt32')),
    b'\x00\x04\x09\x09\x09\x09\x09': _blob_signature_helper(False, 'System.UInt32', ('System.UInt32', 'System.UInt32', 'System.UInt32', 'System.UInt32')),
    b'\x20\x03\x08\x1D\x05\x08\x08': _blob_signature_helper(True, 'System.Int32', ('System.Byte[]', 'System.Int32', 'System.Int32')),
    b'\x20\x03\x09\x08\x08\x08\x0D': _blob_signature_helper(True, 'System.UInt32', ('System.Int32', 'System.Int32', 'System.Int32')),
    b'\x00\x03\x01\x0F\x05\x0F\x05\x09': _blob_signature_helper(False, 'System.Void', ('System.Byte*', 'System.Byte*', 'System.UInt32')),
    b'\x00\x03\x0F\x05\x0F\x05\x09\x09': _blob_signature_helper(False, 'System.Byte*', ('System.Byte*', 'System.UInt32', 'System.UInt32')),
    b'\x00\x04\x08\x09\x09\x09\x0F\x09': _blob_signature_helper(False, 'System.Int32', ('System.UInt32', 'System.UInt32', 'System.UInt32*')),
    b'\x20\x05\x12\x11\x09\x09\x09\x12\x15\x1C': _blob_signature_helper(True, 'System.IAsyncResult', ('System.UInt32', 'System.UInt32', 'System.UInt32', 'System.AsyncCallback', 'System.Object'))
}

CALLING_CONVENTIONS = {
    0x00: 'DEFAULT',
    0x01: 'C',
    0x02: 'STDCALL',
    0x03: 'THISCALL',
    0x04: 'FASTCALL',
    0x05: 'VARARG',
    0x06: 'FIELD',
    0x07: 'LOCAL_SIG',
    0x08: 'PROPERTY',
    0x0A: 'GENRICINST_SPEC',
    0x10: 'GENERIC',
    0x20: 'HASTHIS',
    0x40: 'EXPLICITTHIS'
}


class BlobSignatureType(Enum):
    EMPTY = 'Empty'
    CUSTOM_ATTRIBUTE = 'CustomAttribute'
    METHOD_NON_GENERIC = 'Method (Non-Generic)'
    METHOD_GENERIC = 'Method (Generic)'
    FIELD = 'Field'
    PROPERTY = 'Property'
    LOCAL_VAR = 'LocalVar'
    METHOD_SPEC = 'MethodSpec'
    TYPE_SPEC = 'TypeSpec'
    UNKNOWN = 'Unknown'
