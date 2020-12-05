import OverTheShellbags.defined_list.data_format as data_format
from OverTheShellbags import shell_item_parser as shell_item_parser, converter as cv


def parse_mru_data(_regData):
  shell_item_result = {
    "last_written_time" : None,
    "shell_type"  : None,
    "file_size"   : 0,
    "fat_mtime"   : None,
    "short_name"  : None,
    "full_url" : None,
    "value"    : None,
    "mapped_guid"  : None,
    "unknown_data" : None,
    "extension_block_result" : [],
    "sps_result" : [],          # sps_result can have shell_item_result. so, it can have extension_block_result also.
    "ext_all_time": (None, None, None),
    # "registry_data"  : _regData
  }

  (MRU_DATA, shell_item_pos) = cv.format_parser(_regData, data_format.MRU_DATA_FORMAT, 0)

  shell_item_size = cv.bytes_to_int(MRU_DATA["shell_item_size"])
  shell_item_type = cv.return_type(MRU_DATA["shell_item_type"], data_format.SHELL_ITEM_TYPES)
  shell_item_data = MRU_DATA["shell_item_data"]

  shell_item_info = (shell_item_size, MRU_DATA["shell_item_type"], shell_item_data, shell_item_pos)
  if shell_item_type == "root_folder_shell_item":         # Shell folder (GUID)
    shell_item_result = shell_item_parser.parse_root_folder(_regData, shell_item_result, shell_item_info)

  elif shell_item_type == "volume_shell_item":      # My Computer in Explorer
    shell_item_result = shell_item_parser.parse_volume(_regData, shell_item_result, shell_item_info)

  elif shell_item_type == "file_entry_shell_item":
    shell_item_result = shell_item_parser.parse_file_entry(_regData, shell_item_result, shell_item_info)

  # elif shell_item_type == "network_location_shell_item":
  #   # Never seen.

  elif shell_item_type == "control_panel_shell_item":
    shell_item_result = shell_item_parser.parse_control_panel(_regData, shell_item_result, shell_item_info)

  elif shell_item_type == "control_panel_category_shell_item":
    shell_item_result = shell_item_parser.parse_control_panel_category(_regData, shell_item_result, shell_item_info)

  elif shell_item_type == "users_property_view_shell_item":
    shell_item_result = shell_item_parser.parse_user_property_view(_regData, shell_item_result, shell_item_info)

  elif shell_item_type == "favorite_shell_item":
    shell_item_result = shell_item_parser.parse_user_property_view(_regData, shell_item_result, shell_item_info)
    return None

  elif shell_item_type == "added_shell_item":
    return None
    pass

  else:
    return None
    pass

  if shell_item_result["value"] is None:
    shell_item_result["value"] = "Coming Soon"
    pass

  # df.PrintBeauty(shell_item_result, _sept_count=67)

  return shell_item_result


def parse_mru_list_ex(_regData):
  loop = 0
  result = []

  while loop < len(_regData):
    mru_index_bytes = _regData[loop:loop+0x04]

    if mru_index_bytes == b"\xFF\xFF\xFF\xFF":
      break

    mru_index = cv.bytes_to_int(mru_index_bytes)
    result.append(mru_index)

    loop += 4
  return result
