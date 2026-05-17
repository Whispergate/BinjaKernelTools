"""
Binary Ninja plugin - Find and decode Windows driver IOCTL codes.

Detection strategy:
  S1 (HLIL pattern): scan for *(param + 0xe0) = ... / MajorFunction[0xe/14] assignments
                     that set IRP_MJ_DEVICE_CONTROL dispatch handler
  S2 (name heuristic): function name contains known dispatch keywords
  S3 (Ioctl caller): function calls >= 2 functions with 'ioctl' in their name
                     (handles C++ class-based drivers like CCommand::kslIoctl*)
  S4 (fallback): return individual Ioctl-named functions directly

CTL_CODE decode:
  bits [31:16] = DeviceType
  bits [15:14] = Access (FILE_ANY/READ/WRITE/READ_WRITE)
  bits [13: 2] = Function
  bits [ 1: 0] = Method (BUFFERED / IN_DIRECT / OUT_DIRECT / NEITHER)
"""

import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

FILE_DEVICE_MAP = {
    0x0:'FILE_DEVICE_UNKNOWN',        0x1:'FILE_DEVICE_BEEP',
    0x2:'FILE_DEVICE_CD_ROM',         0x3:'FILE_DEVICE_CD_ROM_FILE_SYSTEM',
    0x4:'FILE_DEVICE_CONTROLLER',     0x5:'FILE_DEVICE_DATALINK',
    0x6:'FILE_DEVICE_DFS',            0x7:'FILE_DEVICE_DISK',
    0x8:'FILE_DEVICE_DISK_FILE_SYSTEM', 0x9:'FILE_DEVICE_FILE_SYSTEM',
    0xa:'FILE_DEVICE_INPORT_PORT',    0xb:'FILE_DEVICE_KEYBOARD',
    0xc:'FILE_DEVICE_MAILSLOT',       0xd:'FILE_DEVICE_MIDI_IN',
    0xe:'FILE_DEVICE_MIDI_OUT',       0xf:'FILE_DEVICE_MOUSE',
    0x10:'FILE_DEVICE_MULTI_UNC_PROVIDER', 0x11:'FILE_DEVICE_NAMED_PIPE',
    0x12:'FILE_DEVICE_NETWORK',       0x13:'FILE_DEVICE_NETWORK_BROWSER',
    0x14:'FILE_DEVICE_NETWORK_FILE_SYSTEM', 0x15:'FILE_DEVICE_NULL',
    0x16:'FILE_DEVICE_PARALLEL_PORT', 0x17:'FILE_DEVICE_PHYSICAL_NETCARD',
    0x18:'FILE_DEVICE_PRINTER',       0x19:'FILE_DEVICE_SCANNER',
    0x1a:'FILE_DEVICE_SERIAL_MOUSE_PORT', 0x1b:'FILE_DEVICE_SERIAL_PORT',
    0x1c:'FILE_DEVICE_SCREEN',        0x1d:'FILE_DEVICE_SOUND',
    0x1e:'FILE_DEVICE_STREAMS',       0x1f:'FILE_DEVICE_TAPE',
    0x20:'FILE_DEVICE_TAPE_FILE_SYSTEM', 0x21:'FILE_DEVICE_TRANSPORT',
    0x22:'FILE_DEVICE_UNKNOWN',       0x23:'FILE_DEVICE_VIDEO',
    0x24:'FILE_DEVICE_VIRTUAL_DISK',  0x25:'FILE_DEVICE_WAVE_IN',
    0x26:'FILE_DEVICE_WAVE_OUT',      0x27:'FILE_DEVICE_8042_PORT',
    0x28:'FILE_DEVICE_NETWORK_REDIRECTOR', 0x29:'FILE_DEVICE_BATTERY',
    0x2a:'FILE_DEVICE_BUS_EXTENDER',  0x2b:'FILE_DEVICE_MODEM',
    0x2c:'FILE_DEVICE_VDM',           0x2d:'FILE_DEVICE_MASS_STORAGE',
    0x2e:'FILE_DEVICE_SMB',           0x2f:'FILE_DEVICE_KS',
    0x30:'FILE_DEVICE_CHANGER',       0x31:'FILE_DEVICE_SMARTCARD',
    0x32:'FILE_DEVICE_ACPI',          0x33:'FILE_DEVICE_DVD',
    0x34:'FILE_DEVICE_FULLSCREEN_VIDEO', 0x35:'FILE_DEVICE_DFS_FILE_SYSTEM',
    0x36:'FILE_DEVICE_DFS_VOLUME',    0x37:'FILE_DEVICE_SERENUM',
    0x38:'FILE_DEVICE_TERMSRV',       0x39:'FILE_DEVICE_KSEC',
    0x3a:'FILE_DEVICE_FIPS',          0x3b:'FILE_DEVICE_INFINIBAND',
}
METHOD_MAP = {0:'METHOD_BUFFERED', 1:'METHOD_IN_DIRECT', 2:'METHOD_OUT_DIRECT', 3:'METHOD_NEITHER'}
ACCESS_MAP = {0:'FILE_ANY_ACCESS', 1:'FILE_READ_ACCESS', 2:'FILE_WRITE_ACCESS', 3:'FILE_READ_WRITE_ACCESS'}

DISPATCH_PATTERNS = [
    r'\+\s*0xe0\b',
    r'MajorFunction\[(?:0xe|14)\]',
    r'\+\s*0x70\b',
]
# hex-prefixed patterns
_IOCTL_PATS_HEX = [
    r'case\s+0x([0-9A-Fa-f]+)\s*:',
    r'ioControlCode\s*[u]?==\s*0x([0-9A-Fa-f]+)',
    r'(?:if|else\s+if)\s*\([^)]*[u]?==\s*0x([0-9A-Fa-f]+)',
    r'\w+\s*[u]?==\s*0x([0-9A-Fa-f]+)',
]
# bare decimal patterns - floor 0x200000 == 2097152 (7 digits)
_IOCTL_PATS_DEC = [
    r'case\s+(\d{7,})\s*:',
    r'(?:if|else\s+if)\s*\([^)]*[u]?==\s*(\d{7,})\b',
    r'\w+\s*[u]?==\s*(\d{7,})\b',
]
# keep old name as alias so win_vuln_finder copy still works independently
IOCTL_PATTERNS = _IOCTL_PATS_HEX
NAME_HINTS = [
    'devicecontrol', 'dispatchio', 'ioctlhandler', 'ioctldispatch',
    'dispatchioctl', 'irpdevicecontrol', 'ioctlrouter', 'ioctldispatcher',
]


# ---------------------------------------------------------------------------
# CTL_CODE helpers
# ---------------------------------------------------------------------------

def _ctl_decode(v):
    v = v & 0xFFFFFFFF
    return {
        'raw':      v,
        'device':   (v >> 16) & 0xFFFF,
        'access':   (v >> 14) & 0x3,
        'function': (v >> 2)  & 0xFFF,
        'method':   v & 0x3,
    }


def _plausible_ioctl(v):
    d = _ctl_decode(v)
    return d['method'] in (0, 1, 2, 3) and d['function'] != 0 and d['device'] != 0


def _format_ioctl(code):
    d = _ctl_decode(code)
    device = FILE_DEVICE_MAP.get(d['device'], "0x{:X}".format(d['device']))
    method = METHOD_MAP.get(d['method'], str(d['method']))
    access = ACCESS_MAP.get(d['access'], str(d['access']))
    return (
        "0x{:08X}  Device={} (0x{:X})  Function=0x{:X}  "
        "Method={}  Access={}".format(
            d['raw'], device, d['device'], d['function'], method, access)
    )


# ---------------------------------------------------------------------------
# Dispatch routine discovery
# ---------------------------------------------------------------------------

def _find_dispatch_routines(bv: BinaryView):
    routines = []
    seen = set()

    # S1: HLIL MajorFunction assignment
    for func in bv.functions:
        hlil_text = get_hlil_text(func)
        for line in hlil_text.splitlines():
            for pat in DISPATCH_PATTERNS:
                if not re.search(pat, line, re.IGNORECASE):
                    continue
                m = re.search(r'=\s*(?:&\s*)?([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+)', line)
                if not m:
                    continue
                target = m.group(1)
                tgt_func = None
                if target.startswith('0x'):
                    try:
                        tgt_func = bv.get_function_at(int(target, 16))
                    except Exception:
                        pass
                else:
                    syms = bv.get_symbols_by_name(target)
                    if syms:
                        tgt_func = bv.get_function_at(syms[0].address)
                if tgt_func and tgt_func.start not in seen:
                    seen.add(tgt_func.start)
                    routines.append(tgt_func)
                    log_info("[S1] Dispatch: {} -> {} (0x{:x})".format(
                        func.name, tgt_func.name, tgt_func.start))

    # S2: name heuristic - only include if the function actually contains IOCTL codes.
    # Leaf handlers (BufferOverflowStackIoctlHandler etc.) match the name but contain
    # no switch/case on IOCTL codes - filtering them prevents O(N) false-positive noise.
    for func in bv.functions:
        if any(h in func.name.lower() for h in NAME_HINTS) and func.start not in seen:
            if _find_ioctls(func):
                seen.add(func.start)
                routines.append(func)
                log_info("[S2] Dispatch by name: {} (0x{:x})".format(func.name, func.start))

    # S3: caller of >= 2 ioctl-named functions (C++ class dispatch pattern).
    # Exclude DriverEntry and init-style functions - they call IoctlHandlers to *register*
    # them in MajorFunction[], not to dispatch IRPs. Also require the candidate itself
    # contains IOCTL codes so pure setup functions don't pollute the list.
    _ENTRY_EXCLUDE = {'driverentry', 'dllmain', 'winmain', '_start', 'driverunload'}
    callee_counts = {}
    for func in bv.functions:
        if 'ioctl' in func.name.lower():
            for ref in bv.get_code_refs(func.start):
                if ref.function:
                    callee_counts[ref.function.start] = callee_counts.get(ref.function.start, 0) + 1
    for addr, count in sorted(callee_counts.items(), key=lambda x: -x[1]):
        if count >= 2 and addr not in seen:
            f = bv.get_function_at(addr)
            if f and f.name.lower() not in _ENTRY_EXCLUDE:
                if _find_ioctls(f):
                    seen.add(addr)
                    routines.append(f)
                    log_info("[S3] Dispatch (calls {} ioctl fns): {} (0x{:x})".format(
                        count, f.name, addr))

    # S4: fallback - individual ioctl-named functions
    if not routines:
        log_warn("[!] No dispatcher found via S1/S2/S3 - falling back to ioctl-named functions")
        for func in bv.functions:
            if 'ioctl' in func.name.lower() and func.start not in seen:
                seen.add(func.start)
                routines.append(func)

    return routines


def _find_ioctls_in_text(hlil_text):
    codes = set()
    normalized = re.sub(r'\s+', ' ', hlil_text)
    for pat in _IOCTL_PATS_HEX:
        for m in re.finditer(pat, normalized, re.IGNORECASE | re.DOTALL):
            try:
                val = int(m.group(1), 16)
                if val >= 0x200000 and _plausible_ioctl(val):
                    codes.add(val & 0xFFFFFFFF)
            except Exception:
                pass
    for pat in _IOCTL_PATS_DEC:
        for m in re.finditer(pat, normalized, re.IGNORECASE | re.DOTALL):
            try:
                val = int(m.group(1), 10)
                if val >= 0x200000 and _plausible_ioctl(val):
                    codes.add(val & 0xFFFFFFFF)
            except Exception:
                pass
    return sorted(codes)


def _collect_switch_cases(instr, codes):
    """Recursively walk one HLIL instruction node, collecting switch case values."""
    try:
        if instr.operation.name == 'HLIL_SWITCH':
            for case in instr.cases:
                for v in case.values:
                    v = int(v) & 0xFFFFFFFF
                    if v >= 0x200000 and _plausible_ioctl(v):
                        codes.add(v)
        for operand in getattr(instr, 'operands', []):
            if hasattr(operand, 'operation'):
                _collect_switch_cases(operand, codes)
            elif hasattr(operand, '__iter__') and not isinstance(operand, (str, bytes)):
                for item in operand:
                    if hasattr(item, 'operation'):
                        _collect_switch_cases(item, codes)
    except Exception:
        pass


def _find_ioctls_via_ast(func):
    """Walk HLIL AST to extract switch case values - catches cases text scan misses."""
    codes = set()
    try:
        hlil = func.hlil
        if not hlil:
            return codes
        for block in hlil:
            for instr in block:
                _collect_switch_cases(instr, codes)
    except Exception:
        pass
    return codes


def _find_ioctls(func):
    """Combined: AST walk (primary) + text scan (fallback). Returns sorted list."""
    codes = _find_ioctls_via_ast(func)
    codes |= set(_find_ioctls_in_text(get_hlil_text(func)))
    return sorted(codes)


# ---------------------------------------------------------------------------
# Plugin entry
# ---------------------------------------------------------------------------

def find_ioctls(bv: BinaryView):
    log_info("[+] Windows driver IOCTL enumeration: {}".format(bv.file.filename))

    routines = _find_dispatch_routines(bv)
    if not routines:
        log_warn("[-] No dispatch routine found. Manually identify IRP_MJ_DEVICE_CONTROL handler.")
        return

    log_info("[+] Found {} dispatch routine(s)".format(len(routines)))
    total = 0

    for func in routines:
        log_info("\n[*] Dispatch routine: {} at 0x{:x}".format(func.name, func.start))
        codes = _find_ioctls(func)
        if not codes:
            log_warn("    [-] No IOCTLs found in {}".format(func.name))
            continue
        for code in codes:
            total += 1
            d = _ctl_decode(code)
            log_info("  [{:02d}] {}".format(total, _format_ioctl(code)))
            if d['method'] == 3:
                log_info("        *** METHOD_NEITHER - no kernel buffering, raw user pointer ***")

    log_info("\n[+] Found {} valid IOCTL(s) total".format(total))


PluginCommand.register(
    "Windows Driver Analysis\\Find IOCTLs",
    "Find and decode Windows driver IOCTL codes (CTL_CODE) from dispatch routines",
    find_ioctls
)
