"""
Binary Ninja plugin - Find Windows device names in kernel drivers.

Detects: \Device\, \DosDevices\, \\.\, \??\  patterns via:
  - bv.strings scan (all defined strings)
  - HLIL text scan in callers of IoCreateSymbolicLink / RtlInitUnicodeString /
    IoDeleteSymbolicLink / IoRegisterDeviceInterface
"""

import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers

DEVICE_INDICATORS = ["\\device\\", "\\dosdevices\\", "\\\\.\\", "\\??\\"]
TARGET_APIS = [
    "IoCreateSymbolicLink", "IoDeleteSymbolicLink",
    "RtlInitUnicodeString", "IoRegisterDeviceInterface",
    "IoCreateDevice",
]


def _is_device_name(s):
    if not s:
        return False
    sl = s.lower()
    return any(ind in sl for ind in DEVICE_INDICATORS)


def find_device_names(bv: BinaryView):
    log_info("[+] Windows driver - scanning for device names: {}".format(bv.file.filename))
    found_any = False

    # Pass 1: all defined strings
    log_info("[*] Scanning binary strings...")
    for s in bv.strings:
        try:
            val = s.value
            if _is_device_name(val):
                log_info("[+] Device name at 0x{:x}: {}".format(s.start, val))
                found_any = True
        except Exception:
            pass

    # Pass 2: HLIL of callers of relevant APIs
    log_info("[*] Analyzing API callers...")
    for api_name in TARGET_APIS:
        for func, ref_addr in get_callers(bv, api_name):
            log_info("[*] {} referenced in {} at 0x{:x}".format(api_name, func.name, ref_addr))
            hlil_text = get_hlil_text(func)
            for match in re.findall(r'"([^"]*)"', hlil_text):
                if _is_device_name(match):
                    log_info("[+] Device name in HLIL of {}: {}".format(func.name, match))
                    found_any = True

    if not found_any:
        log_warn("[!] No device names found - may be dynamically constructed or obfuscated.")
    log_info("[+] Scan complete.")


PluginCommand.register(
    "Windows Driver Analysis\\Find Device Names",
    "Scan for Windows device name strings (\\Device\\, \\DosDevices\\, etc.)",
    find_device_names
)
