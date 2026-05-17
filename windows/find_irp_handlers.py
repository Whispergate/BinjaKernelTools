"""
Binary Ninja plugin - Windows IRP major function dispatch table enumeration
and METHOD_NEITHER deep analysis.

Enumerates all 28 IRP_MJ_* dispatch handlers from DRIVER_OBJECT.MajorFunction[],
assesses each handler's security relevance, and performs deep analysis on
METHOD_NEITHER IOCTL handlers - the highest-risk transfer method because the
driver receives a raw unvalidated user-space pointer with no kernel buffering.

DRIVER_OBJECT.MajorFunction[] layout (x86_64, offset from object base):
  MajorFunction[i] = 0x70 + (8 * i)
  MajorFunction[0]  = 0x70  IRP_MJ_CREATE
  MajorFunction[3]  = 0x88  IRP_MJ_READ
  MajorFunction[4]  = 0x90  IRP_MJ_WRITE
  MajorFunction[14] = 0xe0  IRP_MJ_DEVICE_CONTROL
  MajorFunction[15] = 0xe8  IRP_MJ_INTERNAL_DEVICE_CONTROL
  MajorFunction[27] = 0x148 IRP_MJ_PNP

METHOD_NEITHER vulnerability pattern:
  - Driver receives Type3InputBuffer as raw user-mode pointer
  - MUST wrap access in __try/__except
  - MUST call ProbeForRead/ProbeForWrite before dereference
  - MUST validate OutputBufferLength before writing response
  - Any of these missing = read/write primitive from kernel context
"""

import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, nearby_has_check

# ---------------------------------------------------------------------------
# IRP major function table (index → (name, risk_level, notes))
# ---------------------------------------------------------------------------

IRP_MJ = {
    0x00: ('IRP_MJ_CREATE',                   'MEDIUM', 'File/device open; check SecurityContext, access mask handling'),
    0x01: ('IRP_MJ_CREATE_NAMED_PIPE',         'HIGH',   'Named pipe creation; check pipe attributes for arbitrary pipe creation'),
    0x02: ('IRP_MJ_CLOSE',                     'LOW',    'Close; cleanup only; low risk unless object state corrupted'),
    0x03: ('IRP_MJ_READ',                      'HIGH',   'Read from device; UserBuffer / SystemBuffer - check METHOD'),
    0x04: ('IRP_MJ_WRITE',                     'HIGH',   'Write to device; UserBuffer / SystemBuffer - check METHOD'),
    0x05: ('IRP_MJ_QUERY_INFORMATION',         'MEDIUM', 'File info query; potential info leak if struct not zeroed'),
    0x06: ('IRP_MJ_SET_INFORMATION',           'HIGH',   'File info set; FileEndOfFileInformation / rename can be exploited'),
    0x07: ('IRP_MJ_QUERY_EA',                  'MEDIUM', 'Extended attributes query'),
    0x08: ('IRP_MJ_SET_EA',                    'HIGH',   'Extended attributes set; length validation critical'),
    0x09: ('IRP_MJ_FLUSH_BUFFERS',             'LOW',    'Flush; typically safe'),
    0x0a: ('IRP_MJ_QUERY_VOLUME_INFORMATION',  'MEDIUM', 'Volume info; check output buffer size'),
    0x0b: ('IRP_MJ_SET_VOLUME_INFORMATION',    'HIGH',   'Volume info set; privileged operation'),
    0x0c: ('IRP_MJ_DIRECTORY_CONTROL',         'MEDIUM', 'Dir enumeration; IRP_MN_QUERY_DIRECTORY output bounds'),
    0x0d: ('IRP_MJ_FILE_SYSTEM_CONTROL',       'HIGH',   'FSCTL; user-mode FsControlCode like IOCTL - same attack surface'),
    0x0e: ('IRP_MJ_DEVICE_CONTROL',            'HIGH',   'User-mode IOCTLs - primary attack surface (see win_find_ioctls.py)'),
    0x0f: ('IRP_MJ_INTERNAL_DEVICE_CONTROL',   'HIGH',   'Kernel-mode IOCTLs; called by other drivers - trust boundary issue'),
    0x10: ('IRP_MJ_SHUTDOWN',                  'MEDIUM', 'System shutdown notification'),
    0x11: ('IRP_MJ_LOCK_CONTROL',              'MEDIUM', 'File locking'),
    0x12: ('IRP_MJ_CLEANUP',                   'LOW',    'Handle count → 0; check for UAF on cancel'),
    0x13: ('IRP_MJ_CREATE_MAILSLOT',           'HIGH',   'Mailslot creation'),
    0x14: ('IRP_MJ_QUERY_SECURITY',            'MEDIUM', 'Security descriptor query'),
    0x15: ('IRP_MJ_SET_SECURITY',              'HIGH',   'Security descriptor set - arbitrary DACL modification risk'),
    0x16: ('IRP_MJ_POWER',                     'HIGH',   'Power management; driver may execute arbitrary code on power event'),
    0x17: ('IRP_MJ_SYSTEM_CONTROL',            'MEDIUM', 'WMI; check MOF definitions for information disclosure'),
    0x18: ('IRP_MJ_DEVICE_CHANGE',             'MEDIUM', 'Device change notification'),
    0x19: ('IRP_MJ_QUERY_QUOTA',               'MEDIUM', 'Quota query; output buffer bounds'),
    0x1a: ('IRP_MJ_SET_QUOTA',                 'HIGH',   'Quota set; length validation'),
    0x1b: ('IRP_MJ_PNP',                       'HIGH',   'PnP; IRP_MN_QUERY_INTERFACE exposes driver interfaces to user'),
}

# MajorFunction[i] offset in DRIVER_OBJECT (x86_64)
def _irp_offset(idx):
    return 0x70 + 8 * idx

# Risk order for sorting
_RISK_ORDER = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}

# CTL_CODE decode helpers (duplicated locally to avoid cross-module state)
def _ctl_decode(v):
    v = v & 0xFFFFFFFF
    return {
        'raw': v, 'device': (v >> 16) & 0xFFFF,
        'access': (v >> 14) & 0x3, 'function': (v >> 2) & 0xFFF, 'method': v & 0x3,
    }

METHOD_MAP = {0: 'METHOD_BUFFERED', 1: 'METHOD_IN_DIRECT', 2: 'METHOD_OUT_DIRECT', 3: 'METHOD_NEITHER'}

_IOCTL_PATS = [
    r'case\s+0x([0-9A-Fa-f]+)\s*:',
    r'ioControlCode\s*==\s*0x([0-9A-Fa-f]+)',
    r'\w+\s*==\s*0x([0-9A-Fa-f]+)',
]


def _plausible_ioctl(v):
    d = _ctl_decode(v)
    return d['method'] in (0, 1, 2, 3) and d['function'] != 0 and d['device'] != 0


def _extract_ioctls(hlil_text):
    codes = set()
    normalized = re.sub(r'\s+', ' ', hlil_text)
    for pat in _IOCTL_PATS:
        for m in re.finditer(pat, normalized, re.IGNORECASE):
            try:
                val = int(m.group(1), 16)
                if val >= 0x200000 and _plausible_ioctl(val):
                    codes.add(val & 0xFFFFFFFF)
            except Exception:
                pass
    return sorted(codes)


# ---------------------------------------------------------------------------
# IRP dispatch table discovery
# ---------------------------------------------------------------------------

def _find_irp_assignments(bv: BinaryView):
    """
    Scan HLIL for MajorFunction[i] assignments:
      *(drv_obj + 0xNN) = &SomeHandler
    Returns dict: irp_index → list of (handler_func, setter_func_name)
    """
    result = {}
    # Build offset → index map
    offset_to_idx = {_irp_offset(i): i for i in range(0x1c)}

    assign_pat = re.compile(
        r'\*\s*\(.*?\+\s*(0x[0-9a-fA-F]+)\s*\)\s*=\s*(?:&\s*)?([A-Za-z_][A-Za-z0-9_]*)',
        re.IGNORECASE
    )

    for func in bv.functions:
        dt = get_hlil_text(func)
        for m in assign_pat.finditer(dt):
            try:
                offset = int(m.group(1), 16)
                target_name = m.group(2)
            except Exception:
                continue
            irp_idx = offset_to_idx.get(offset)
            if irp_idx is None:
                continue
            # Resolve target function
            handler = None
            syms = bv.get_symbols_by_name(target_name)
            if syms:
                handler = bv.get_function_at(syms[0].address)
            if not handler and target_name.startswith('0x'):
                try:
                    handler = bv.get_function_at(int(target_name, 16))
                except Exception:
                    pass
            if handler:
                result.setdefault(irp_idx, []).append((handler, func.name))

    return result


# ---------------------------------------------------------------------------
# METHOD_NEITHER deep analysis
# ---------------------------------------------------------------------------

_PROBE_APIS   = ['ProbeForRead', 'ProbeForWrite', 'ProbeForReadSmallStructure']
_EXCEPT_PATS  = ['__try', 'try {', '_SEH_TRY', 'except (']
_OUT_LEN_KEYS = ['OutputBufferLength', 'IoStatus.Information', 'Parameters.DeviceIoControl.OutputBufferLength']


def _analyze_method_neither_handler(bv, func):
    """
    Deep analysis of a METHOD_NEITHER IOCTL handler.
    Checks: ProbeFor*, __try/__except, OutputBufferLength validation before write-back.
    """
    dt = get_hlil_text(func)
    fn = func.name
    findings = []

    has_probe   = any(p in dt for p in _PROBE_APIS)
    has_try     = any(p in dt for p in _EXCEPT_PATS)
    has_outlen  = any(k in dt for k in _OUT_LEN_KEYS)

    type3 = 'Type3InputBuffer' in dt or 'Parameters.DeviceIoControl.Type3InputBuffer' in dt

    if type3 or not has_probe:
        if not has_probe:
            findings.append("CRITICAL: No ProbeForRead/ProbeForWrite - "
                            "Type3InputBuffer dereferenced without kernel validation of user pointer")
        if not has_try:
            findings.append("CRITICAL: No __try/__except - "
                            "invalid user pointer will BSOD; missing structured exception handling")
        if type3 and not has_outlen:
            findings.append("HIGH: Type3InputBuffer handler - "
                            "OutputBufferLength not validated before write-back; "
                            "user controls output size → kernel stack/pool overflow")

    # Check for direct memcpy from Type3InputBuffer without ProbeFor
    if 'memcpy' in dt or 'RtlCopyMemory' in dt:
        copy_idx = dt.find('memcpy') if 'memcpy' in dt else dt.find('RtlCopyMemory')
        if not nearby_has_check(dt, copy_idx, _PROBE_APIS + _EXCEPT_PATS, window=400):
            findings.append("HIGH: memcpy/RtlCopyMemory near METHOD_NEITHER handler without ProbeFor - "
                            "arbitrary kernel read/write primitive if user pointer is crafted")

    return findings


# ---------------------------------------------------------------------------
# Main plugin entry
# ---------------------------------------------------------------------------

def find_irp_handlers(bv: BinaryView):
    log_info("[+] Windows IRP dispatch table enumeration: {}".format(bv.file.filename))

    irp_map = _find_irp_assignments(bv)

    if not irp_map:
        log_warn("[-] No MajorFunction[] assignments found via HLIL pattern.")
        log_warn("    Driver may set handlers via WDF framework, indirect assignment,")
        log_warn("    or table is in data section. Check DriverEntry manually.")
        return

    log_info("[+] Found {} IRP handler(s) across {} IRP_MJ_* slots".format(
        sum(len(v) for v in irp_map.values()), len(irp_map)))

    # Sort by risk then index for clean output
    sorted_indices = sorted(irp_map.keys(),
                            key=lambda i: (_RISK_ORDER.get(IRP_MJ.get(i, ('?','LOW',''))[1], 9), i))

    neither_handlers = []

    for irp_idx in sorted_indices:
        name, risk, notes = IRP_MJ.get(irp_idx, ('IRP_MJ_UNKNOWN_0x{:02x}'.format(irp_idx), 'MEDIUM', ''))
        handlers = irp_map[irp_idx]
        log_info("\n[{}] [{}] MajorFunction[0x{:x}] = {} (offset 0x{:x})".format(
            risk, irp_idx, irp_idx, name, _irp_offset(irp_idx)))
        log_info("  Notes: {}".format(notes))

        for handler, setter in handlers:
            log_info("  Handler: {} (0x{:x}) - set in {}".format(handler.name, handler.start, setter))

            # For DEVICE_CONTROL and INTERNAL_DEVICE_CONTROL - enumerate IOCTLs and flag METHOD_NEITHER
            if irp_idx in (0x0e, 0x0f):
                dt = get_hlil_text(handler)
                codes = _extract_ioctls(dt)
                for code in codes:
                    d = _ctl_decode(code)
                    method_str = METHOD_MAP.get(d['method'], str(d['method']))
                    log_info("    IOCTL 0x{:08X}  Function=0x{:X}  Method={}".format(
                        d['raw'], d['function'], method_str))
                    if d['method'] == 3:
                        log_info("    *** METHOD_NEITHER - queued for deep analysis ***")
                        neither_handlers.append((handler, code))

            # For READ/WRITE - check buffer origin
            if irp_idx in (0x03, 0x04):
                dt = get_hlil_text(handler)
                has_probe = any(p in dt for p in _PROBE_APIS)
                has_try   = any(p in dt for p in _EXCEPT_PATS)
                if 'UserBuffer' in dt or 'Irp->UserBuffer' in dt:
                    if not has_probe:
                        log_info("    [!!!] HIGH: UserBuffer accessed without ProbeForRead/Write")
                    if not has_try:
                        log_info("    [!!!] HIGH: No __try/__except around UserBuffer dereference")

    # METHOD_NEITHER deep analysis
    if neither_handlers:
        log_info("\n" + "=" * 60)
        log_info("[+] METHOD_NEITHER Deep Analysis ({} handler/IOCTL pair(s))".format(len(neither_handlers)))
        log_info("=" * 60)

        seen = set()
        for handler, code in neither_handlers:
            if handler.start in seen:
                continue
            seen.add(handler.start)
            log_info("\n  Handler: {} (0x{:x})".format(handler.name, handler.start))
            findings = _analyze_method_neither_handler(bv, handler)
            if findings:
                for f in findings:
                    log_info("    [!] {}".format(f))
            else:
                log_info("    No critical METHOD_NEITHER issues detected (verify manually)")

    log_info("\n[+] IRP dispatch analysis complete.")


PluginCommand.register(
    "Windows Driver Analysis\\Find IRP Handlers",
    "Enumerate all IRP_MJ_* dispatch handlers and deep-analyze METHOD_NEITHER IOCTLs",
    find_irp_handlers
)
