
import pytest
from dotnetfile.util import (
    read_reasonable_string,
    make_string_readable,
    read_7bit_encoded_uint32,
    read_7bit_encoded_int32,
    convert_to_unicode
)

def test_read_reasonable_string():
    assert read_reasonable_string(b'Hello\x00World') == 'Hello'
    assert read_reasonable_string(b'Invalid\xffData') is None
    assert read_reasonable_string(b'TooLong' + b'A' * 130, limit=128) is None

def test_make_string_readable():
    assert make_string_readable('Hello\\u0000World') == b'HelloWorld'
    assert make_string_readable('\x00Hello\x00') == b'Hello'

def test_read_7bit_encoded_uint32():
    # 0x7F -> 1 byte, value 127
    assert read_7bit_encoded_uint32(b'\x7f') == (1, 127)
    # 0x80 0x01 -> 2 bytes, value 128
    assert read_7bit_encoded_uint32(b'\x80\x01') == (2, 128)

def test_read_7bit_encoded_int32():
    assert read_7bit_encoded_int32(b'\x7f') == (1, 127)
    assert read_7bit_encoded_int32(b'\x80\x01') == (2, 128)

def test_convert_to_unicode():
    assert convert_to_unicode(b'Hello') == 'Hello'
    # UTF-16 representation of 'Hello'
    assert convert_to_unicode(b'H\x00e\x00l\x00l\x00o\x00') == 'Hello'
