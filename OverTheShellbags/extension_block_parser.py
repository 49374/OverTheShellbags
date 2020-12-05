import OverTheShellbags_test.defined_list.data_format as data_format

from OverTheShellbags_test import converter as cv
from OverTheShellbags_test import storage_property_parser


def parse(_extension_blocks, _debug=None):
  global regData
  regData = _debug

  if len(_extension_blocks) == 0 or _extension_blocks == b"\x00\x00":
    extension_block_result = None
  else:
    extension_block_result = []
    extension_block_list = split_extension_blocks(_extension_blocks)

    for extension_block in extension_block_list:
      parsed_extension_block = parse_extension_block(extension_block)
      extension_block_result.append(parsed_extension_block)
  return extension_block_result

def split_extension_blocks(_extension_blocks):
  extension_block_list = []
  extension_blocks = _extension_blocks

  while True:
    (EXTENSION_BLOCK_SIG, pos) = cv.format_parser(extension_blocks, data_format.EXTENSION_BLOCK_SIGNATURE_FORMAT, 0)
    block_size       = cv.bytes_to_int(EXTENSION_BLOCK_SIG["extension_size"])
    extension_block  = extension_blocks[:block_size]
    extension_blocks = extension_blocks[block_size:]
    extension_block_list.append(extension_block)

    if extension_blocks[:2] == b"\x00\x00" or extension_blocks == b"":
      return extension_block_list

def parse_extension_block(_extension_block):
  extension_block_result = {
    "extension_sig" : None,
    "mapped_guid"   : None,   # [(guid, name), (guid, name), ...]
    "filesystem"    : None,
    "mft_entry_number": None,
    "mft_sequence_number" : None,
    "ctime" : None,
    "mtime" : None,
    "atime" : None,
    "long_name" : None,
    "localized_name" : None,
    "comment" : None,
    "sps_result" : []
  }

  (EXTENSION_BLOCK_SIGNATURE, pos) = cv.format_parser(_extension_block, data_format.EXTENSION_BLOCK_SIGNATURE_FORMAT, 0)
  extension_size    = cv.bytes_to_int(EXTENSION_BLOCK_SIGNATURE["extension_size"])
  extension_version = cv.bytes_to_int(EXTENSION_BLOCK_SIGNATURE["extension_version"])
  extension_sig     = EXTENSION_BLOCK_SIGNATURE["extension_sig"]
  extension_block_result["extension_sig"] = "0x" + hex(cv.bytes_to_int(extension_sig))[2:].zfill(8)

  if extension_sig in [b"\x00\x00\xef\xbe", b"\x19\x00\xef\xbe"]:
    (EXTENSION_BLOCK_0000, pos) = cv.format_parser(_extension_block, data_format.EXTENSION_BLOCK_0000_FORMAT, 0)

    if extension_size == 14: # Unknown Data
      pass

    elif extension_size == 42:
      mapped_guid1 = cv.guid_to_text(EXTENSION_BLOCK_0000["folder_type_id1"])
      mapped_guid2 = cv.guid_to_text(EXTENSION_BLOCK_0000["folder_type_id2"])

      extension_block_result["mapped_guid"] = [mapped_guid1, mapped_guid2]

    else:
      pass
# raise ExtensionBlockFormatError("New BEEF0000, BEEF0019 block size.")

  elif extension_sig == b"\x03\x00\xef\xbe":
    (EXTENSION_BLOCK_0003, pos) = cv.format_parser(_extension_block, data_format.EXTENSION_BLOCK_0003_FORMAT, 0)

    extension_block_result["mapped_guid"] = cv.guid_to_text(EXTENSION_BLOCK_0003["guid"])

  elif extension_sig == b"\x04\x00\xef\xbe":
    extension_block_result = parse_file_extension_block(_extension_block, extension_version, extension_block_result)

  elif extension_sig == b"\x13\x00\xef\xbe":
    extension_block_result["comment"] = "Unknown extension block."

  elif extension_sig == b"\x26\x00\xef\xbe":
    (EXTENSION_BLOCK_0026, pos) = cv.format_parser(_extension_block, data_format.EXTENSION_BLOCK_0026_FORMAT, 0)

    extension_block_result["ctime"] = cv.win64_timestamp(EXTENSION_BLOCK_0026["win64_ctime"])
    extension_block_result["mtime"] = cv.win64_timestamp(EXTENSION_BLOCK_0026["win64_mtime"])
    extension_block_result["atime"] = cv.win64_timestamp(EXTENSION_BLOCK_0026["win64_atime"])

  elif extension_sig == b"\x27\x00\xef\xbe":
    (EXTENSION_BLOCK, pos) = cv.format_parser(_extension_block, data_format.EXTENSION_BLOCK_SIGNATURE_FORMAT, 0)
    extension_data = EXTENSION_BLOCK["extension_data"]

    # TODO : SPS 파싱 끝나면, 여기에 반영하기.
    storage_property_parser.parse(extension_data)

  else:
    sig = repr(extension_sig)[1:].replace("'", "")
    pass
# raise ExtensionBlockFormatError("New extension block (%s)" %sig)

  return extension_block_result

def parse_file_extension_block(_extension_block, _extension_version, _extension_block_result):
  # TODO : WinXP ~ Win 8 추가 필요.
  (FILE_EXTENSION_BLOCK_COMMON, pos) = cv.format_parser(_extension_block,
                                                        data_format.FILE_EXTENSION_BLOCK_COMMON_FORMAT, 0)
  _extension_block_result["ctime"] = cv.msdos_timestamp(FILE_EXTENSION_BLOCK_COMMON["fat_ctime"])
  _extension_block_result["atime"] = cv.msdos_timestamp(FILE_EXTENSION_BLOCK_COMMON["fat_atime"])

  if _extension_version == 9:       # Win8.1 ~ Win10
    (FILE_EXTENSION_BLOCK_DATA, pos) = cv.format_parser(FILE_EXTENSION_BLOCK_COMMON["data"],
                                                        data_format.FILE_EXTENSION_BLOCK_WIN81_FORMAT, 0)
    mft_reference   = FILE_EXTENSION_BLOCK_DATA["mft_reference"]
    name_size       = cv.bytes_to_int(FILE_EXTENSION_BLOCK_DATA["name_size"])
    dummy_name      = FILE_EXTENSION_BLOCK_DATA["long_name"]
    _extension_block_result["mft_entry_number"] = cv.bytes_to_int(mft_reference[0:4])
    _extension_block_result["mft_sequence_number"] = cv.bytes_to_int(mft_reference[4:6])

    if name_size == 0:
      long_name = dummy_name[:-4].decode("UTF-16LE")
      _extension_block_result["long_name"] = long_name

    elif name_size > 0:
      offset = cv.find_end_of_stream(dummy_name, 2, b"\x00\x00")
      long_name  = dummy_name[:offset].decode("UTF-16LE")
      local_name = dummy_name[offset+2:-4].decode("UTF-16LE")

      _extension_block_result["long_name"]      = long_name
      _extension_block_result["localized_name"] = local_name

    return _extension_block_result