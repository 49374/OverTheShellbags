import OverTheShellbags_test.defined_list.guids as guids

from datetime import datetime, timedelta


timezone = 9
GUID_dic  = guids.GUID
GUID_list = guids.GUID.keys()


def format_parser(_regData, _format_data, _pos=0):
  FORMAT = {}

  for format in _format_data:
    (name, _offset, size, tmp) = format.values()
    offset = _offset - _pos

    if size == 0x00:
      FORMAT[name] = _regData[offset:]
      # return FORMAT, offset

    else:
      FORMAT[name] = _regData[offset:offset+size]
  return FORMAT, offset+size

def return_type(_type_sig, _type_data):
  for type_data in _type_data:
    if _type_sig in type_data["sig"]:
      return type_data["type"]

  return None

def find_end_of_stream(_bytes, _increment, _eos_mark):
  offset = 0
  block_size = len(_eos_mark)

  while offset < len(_bytes):
    if _bytes[offset:offset+block_size] == _eos_mark:
      return offset
    offset += _increment
  return None

def bytes_to_int(_bytes, _order="little"):
  return int.from_bytes(_bytes, byteorder=_order)

def bytes_to_signed_int(_size, _bytes, _order="little"):
  number = bytes_to_int(_bytes, _order)

  if (number >> (1 * _size - 1)) == 1:  # MSB set 1.
    result = 0
    for i in range(0, 1 * _size):
      result += 1 << i
    number = (number - 1) ^ result
    return -number
  return number

def add_hex_paddings(_hex_str):
  hex_str = _hex_str[2:]
  return "0"*(len(hex_str) % 2) + hex_str

def msdos_timestamp(_bytes):
  # ymd-hms : 745-565
  if _bytes == b"\x00\x00\x00\x00":
    return None

  ymd = bytes_to_int(_bytes[0:2])
  hms = bytes_to_int(_bytes[2:4])

  day   = (ymd & 0b0000000000011111)
  month = (ymd & 0b0000000111100000) >> 5
  year  = ((ymd & 0b1111111000000000) >> 9) + 1980

  sec   = (hms & 0b0000000000011111)
  min   = (hms & 0b0000011111100000) >> 5
  hour  = (hms & 0b1111100000000000) >> 11

  return datetime(year, month, day, hour, min, sec) + timedelta(hours=timezone)

def win64_timestamp(_bytes):
  if _bytes == b"\x00\x00\x00\x00\x00\x00\x00\x00":
    return None

  if type(_bytes) is int:
    return datetime(1601, 1, 1) + timedelta(microseconds=_bytes // 10) + timedelta(hours=timezone)

  int_time = bytes_to_int(_bytes)
  return datetime(1601, 1, 1) + timedelta(microseconds=int_time // 10) + timedelta(hours=timezone)

def solve_encoding(_bytes, encoding="UTF-16LE"):
  for char in _bytes:
    if not ((0x20 <= char <= 0x7E) or (char == 0x00)):
      return _bytes.decode(encoding)
  return _bytes.decode()

def bytes_to_guid(_bytes):
  if len(_bytes) != 16:
    pass
# raise Exception("Not 16 Bytes.")

  bytes_guid_list = [
    _bytes[0:4][::-1],
    _bytes[4:6][::-1],
    _bytes[6:8][::-1],
    _bytes[8:10],
    _bytes[10:]
  ]

  result = ""
  for bytes_guid in  bytes_guid_list:
    result += bytes_guid.hex() + "-"

  return result[:-1].upper()

def guid_to_text(_bytes):
  if len(_bytes) != 16:
    return None
  guid = bytes_to_guid(_bytes)

  if guid in GUID_list:
    return guid, GUID_dic[guid]
  return guid, "Unknown GUID"