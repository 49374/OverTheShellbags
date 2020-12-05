import OverTheShellbags.defined_list.data_format as data_format
from OverTheShellbags import converter as cv, parser

# TODO : Key 고려해서 개발
# TODO : PropertyNamedValue 구분
# TODO : 구조 순서도 그려보기 (파싱 순서)

regData = ""
sps = ""


def parse(_sps_blocks, _debug=None):
  if _sps_blocks == "":
    sps_block_result = None
  else:
    sps_block_result = []
    sps_block_list = split_property_storage_block(_sps_blocks)

    # for sps_block in sps_block_list:
    for idx, sps_block in enumerate(sps_block_list):
       # print("=========== Property Storage %2d ===========" %idx)
       global sps, regData
       sps = sps_block
       regData = _debug

       parsed_sps_block = parse_property_storage(sps_block)
       sps_block_result.append(parsed_sps_block)
  return sps_block_result


def parse_property_storage(_sps_block):
  (SPS_DATA, pos) = cv.format_parser(_sps_block, data_format.SPS_FORMAT, 0)

  if SPS_DATA["storage_version"] != b"1SPS":
    pass
# raise WindowsPropertyFormatError("New Property Storage Version (Not 1SPS)")

  sps_guid = cv.bytes_to_guid(SPS_DATA["storage_guid"])
  spv_list = split_property_value(SPS_DATA["value_list"])

  spv_result_list = []
  for idx, spv in enumerate(spv_list):
    # print("# Property Value %2d #" % idx)
    # df.PrintHexString(spv)

    spv_result = parse_property_value(sps_guid, idx, spv)
    spv_result_list.append(spv_result)

  return spv_result_list


def parse_property_value(_sps_guid, _idx, _spv, _debug=None):
  spv_result = {
    "value_id"    : None,
    "value"  : None,
    "shell_item_result" : [],
  }

  (SPV, pos) = cv.format_parser(_spv, data_format.SPV_FORMAT, 0)
  value_id   = cv.bytes_to_int(SPV["value_id"])
  value_type = cv.bytes_to_int(SPV["value_type"])
  value_data = SPV["value_data"]
  spv_result["value_id"] = value_id

  # all spv are named property
  if _sps_guid == "D5CDD505-2E9C-101B-9397-08002B2CF9AE":
    spv_data = SPV["value_type"] + SPV["reserved2"] + value_data
    spv_result["value_id"] = spv_data[:value_id-2].decode("UTF-16LE")  # value id is name_size

    value_type = cv.bytes_to_int(spv_data[value_id:value_id+4])
    value_data = spv_data[value_id+4:]

  if value_type == 0x0001:        # VT_NULL
    spv_result["value"] = "NULL"

  elif value_type == 0x0002:      # VT_I2 (signed 16-bit)
    spv_result["value"] = cv.bytes_to_signed_int(16, value_data[:2])

  elif value_type in [0x0003, 0x0016]:  # VT_I4, VT_INT (signed 32-bit)
    spv_result["value"] = cv.bytes_to_signed_int(32, value_data)

  elif value_type == 0x000B:      # VT_BOOL
    if value_data[:2] == b"\xFF\xFF":
      spv_result["value"] = "TRUE"
    elif value_data[:2] == b"\x00\x00":
      spv_result["value"] = "FALSE"
    else:
      pass
# raise WindowsPropertyFormatError("New value_type (VT_BOOL)")

  elif value_type == 0x0010:    # VT_I1 (signed 8-bit)
    spv_result["value"] = cv.bytes_to_signed_int(8, value_data)

  elif value_type == 0x0011:    # VT_UI1 (unsigned 8-bit)
    spv_result["value"] = cv.bytes_to_int(value_data)

  elif value_type == 0x0012:    # VT_UI2 (unsigned 16-bit)
    spv_result["value"] = cv.bytes_to_int(value_data)

  elif value_type in [0x0013, 0x0017, 0x0015]:  # VT_UI4, VT_UINT (unsigned 32-bit), VT_UI8 (unsigned 64-bit)
    spv_result["value"] = cv.bytes_to_int(value_data)

  elif value_type == 0x0014:    # VT_I8 (signed 64-bit)
    spv_result["value"] = cv.bytes_to_signed_int(64, value_data)

  elif value_type == 0x001F:    # VT_LPWSTR (Unicode string)
    str_size = (cv.bytes_to_int(value_data[0:4]) * 2) - 2
    string   = value_data[4:4+str_size].decode("UTF-16LE")
    spv_result["value"] = string

  elif value_type == 0x0040:    # VT_FILETIME (aka. Windows 64-bit timestamp)
    spv_result["value"] = cv.win64_timestamp(value_data)

  elif value_type == 0x0042:    # VT_STREAM
    spv_result["value"] = "VT_STREAM (0x0042)"
    prop_name_size = cv.bytes_to_int(value_data[0x00:0x04])
    prop_name  = value_data[0x04:0x04+prop_name_size].decode("UTF-16LE")
    value_data = value_data[0x04 + prop_name_size:][2:]  # \x00\x00

    if prop_name[:4] != "prop":
      pass
# raise WindowsPropertyFormatError("new value_type (VT_STREAM) : Not a prop~")

    idk_block_size = cv.bytes_to_int(value_data[0x00:0x02])
    idk_block = value_data[:idk_block_size]
    idk_block_guid = cv.guid_to_text(idk_block[0x04:0x04+0x10])

    dummy_shell_item_blocks = idk_block[0x04+0x10+0x24:]
    shell_item_blocks_size  = cv.bytes_to_int(dummy_shell_item_blocks[0x00:0x02])
    shell_item_blocks = dummy_shell_item_blocks[0x02:shell_item_blocks_size] # 0x02 is shell_item_blocks_size
    last_idk_block    = dummy_shell_item_blocks[shell_item_blocks_size:]
    shell_item_result_list = parse_shell_item(shell_item_blocks)
    spv_result["shell_item_result"] = shell_item_result_list

    (LAST_IDK_BLOCK, pos) = cv.format_parser(last_idk_block, data_format.LAST_IDK_BLOCK, 0)
    item_field = LAST_IDK_BLOCK["item_field"]
    offset = cv.find_end_of_stream(item_field, 2, b"\x00\x00")
    str_item = item_field[:offset].decode("UTF-16LE")

    if str_item != "item":
      pass
# raise WindowsPropertyFormatError("new value_type (VT_STREAM) : Not \"item\" in last_idk_block")
    last_idk_block_guid = cv.guid_to_text(LAST_IDK_BLOCK["guid"])

    dummy_search_result = LAST_IDK_BLOCK["search_result"]
    offset = cv.find_end_of_stream(dummy_search_result, 2, "\x00\x00")
    search_result = dummy_search_result[:offset].decode("UTF-16LE")

    # print("#"*100)
    # df.PrintBeauty(shell_item_result_list)
    # print(str_item)
    # print(search_result)


  elif value_type == 0x101F:    # VT_VECTOR(0x1000) | VT_LPWSTR
    vector_count = cv.bytes_to_int(value_data[0:4])
    str_size = (cv.bytes_to_int(value_data[4:8]) * 2) - 2
    string   = value_data[8:8+str_size].decode("UTF-16LE")
    spv_result["value"] = string

    if vector_count != 1:
      pass
# raise WindowsPropertyFormatError("New value_type (0x101F)")

  elif value_type == 0x1011:
    if value_data[5:8] == "\x00\x00\x00":
      vector_count = cv.bytes_to_int(value_data[0:4])
      spv_result["value"] = cv.bytes_to_int(value_data[4:8])

      if vector_count != 1:
        pass
# raise WindowsPropertyFormatError("New value_type (0x1011)")

    else:
      spv_result["value"] = "VT_VECTOR with data (0x011)"

      shell_item_result_list = parse_shell_item(value_data[4:])
      spv_result["shell_item_result"] = shell_item_result_list

  else:
    output_spv_id = "0x" + hex(value_type)[2:].zfill(4)
    pass
# raise WindowsPropertyFormatError("New value_id (Others : %s)" %output_spv_id)

  # df.PrintBeauty(spv_result)

  return spv_result

def parse_shell_item(_shell_item_blocks):
  shell_item_list = split_shell_item(_shell_item_blocks)
  shell_item_result_list = []

  for shell_item in shell_item_list:
    shell_item_result = parser.parse_mru_data(shell_item)
    shell_item_result_list.append(shell_item_result)

  return shell_item_result_list

def split_property_storage_block(_sps_blocks):
  sps_block_list = []
  sps_blocks = _sps_blocks

  while True:
    (SPS_DATA, pos) = cv.format_parser(sps_blocks, data_format.SPS_FORMAT, 0)
    sps_size   = cv.bytes_to_int(SPS_DATA["storage_size"])
    sps_block  = sps_blocks[:sps_size]
    sps_blocks = sps_blocks[sps_size:]
    sps_block_list.append(sps_block)

    if sps_blocks[:4] == b"\x00\x00\x00\x00" or sps_blocks == b"":
      return sps_block_list

def split_property_value(_spv_blocks):
  spv_list = []
  spv_blocks = _spv_blocks

  while True:
    spv_size = cv.bytes_to_int(spv_blocks[0:4])
    spv      = spv_blocks[:spv_size]
    spv_blocks = spv_blocks[spv_size:]
    spv_list.append(spv)

    if spv_blocks[:4] == b"\x00\x00\x00\x00":
      return spv_list

def split_shell_item(_shell_item_blocks):
  shell_item_list = []
  shell_item_blocks  = _shell_item_blocks

  while True:
    shell_item_size = cv.bytes_to_int(shell_item_blocks[0:2])
    shell_item      = shell_item_blocks[:shell_item_size]
    shell_item_blocks = shell_item_blocks[shell_item_size:]
    shell_item_list.append(shell_item)

    if shell_item_blocks[:2] == b"\x00\x00" or shell_item_blocks == b"":
      return shell_item_list