"""
Binary Ninja plugin - Windows kernel driver vulnerability triage.

Surfaces:
  - DriverEntry location (exact or heuristic)
  - Device names (\Device\, \DosDevices\, etc.)
  - Pool tags (ExAllocatePool* argument scanning via MLIL)
  - Dangerous opcodes: rdpmc / rdmsr / wrmsr
  - Dangerous C functions: sprintf / memcpy / memmove / RtlCopyMemory / strcat / strcpy
  - Windows kernel API inventory (Mm*, Zw*, Io*, Flt*, ProbeFor*, Rtl*, Ob*)
  - IOCTL enumeration (dispatch routine heuristic - see win_find_ioctls.py)
  - Physical memory / IO space: MmMapIoSpace, MmCopyMemory, ZwOpenSection, etc.
  - General vuln patterns:
      * Uninstrumented copies: memcpy/RtlCopyMemory near user buffer without ProbeFor
      * Integer-overflow allocations: ExAllocatePool near user input without safe arithmetic
      * Missing privilege gate: sensitive ops in IOCTL path without SeSinglePrivilegeCheck

Output: Binary Ninja log + report at ~/lkdrv-<name>-win-vulns.txt
"""

import re
import os
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers, looks_user_driven, nearby_has_check

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_OPCODE_SEVERITY = {'rdpmc': 'HIGH', 'rdmsr': 'HIGH', 'wrmsr': 'HIGH'}

_C_FUNCS = ['sprintf', 'swprintf', 'snprintf', 'vsprintf',
            'memcpy', 'memmove', 'RtlCopyMemory',
            'strcpy', 'strcat', 'wcscpy', 'wcscat']

_WINAPI_PREFIXES = [
    'ProbeFor', 'Rtl', 'Ob', 'Zw', 'Mm',
    'IofCallDriver', 'Io', 'Flt', 'ExAllocatePool', 'Se',
]

_DRIVER_INDICATORS = [
    'IoCreateDevice', 'IoCreateSymbolicLink', 'IoRegisterDeviceInterface',
    'FltRegisterFilter', 'FltStartFiltering', 'RtlInitUnicodeString',
]

_PHYSMEM_APIS = [
    'ZwOpenSection', 'ZwMapViewOfSection',
    'MmCopyMemory', 'MmMapIoSpace', 'MmMapIoSpaceEx',
    'MmGetPhysicalAddress', 'MmAllocateContiguousMemory',
    'MmProbeAndLockPages', 'MmMapLockedPagesSpecifyCache',
    'MmGetSystemAddressForMdlSafe',
]

_ALLOC_NAMES = [
    'ExAllocatePool', 'ExAllocatePoolWithTag',
    'ExAllocatePool2', 'ExAllocatePoolWithTagPriority',
]
_FREE_NAMES  = ['ExFreePoolWithTag', 'ExFreePool']

_STRING_COPY_NAMES = ['memcpy', 'memmove', 'RtlCopyMemory', 'RtlCopyUnicodeString']

_PRIV_GUARD_APIS = [
    'SeSinglePrivilegeCheck', 'SeAccessCheck',
    'ZwQueryInformationToken', 'IoIsSystemThread',
    'PsGetCurrentProcess', 'SeTokenIsAdmin',
]

_DEVICE_INDICATORS = ["\\device\\", "\\dosdevices\\", "\\\\.\\", "\\??\\"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_ioctl_context(dt):
    return ('IRP_MJ_DEVICE_CONTROL' in dt or 'IoControlCode' in dt or
            'Parameters.DeviceIoControl' in dt)


def _looks_user_driven_win(dt):
    keys = [
        'Parameters.DeviceIoControl.InputBufferLength',
        'Parameters.DeviceIoControl.OutputBufferLength',
        'Parameters.DeviceIoControl.Type3InputBuffer',
        'Irp->AssociatedIrp.SystemBuffer',
        'Irp->UserBuffer',
        'MdlAddress',
    ]
    return any(k in dt for k in keys)


def _decode_pooltag(val):
    v = val & 0xFFFFFFFF
    return ''.join(chr((v >> (8 * i)) & 0xFF) for i in range(4))


def _likely_pooltag_dword(val):
    s = _decode_pooltag(val)
    return all(32 <= ord(c) <= 126 for c in s) and sum(c.isalnum() for c in s) >= 2


# ---------------------------------------------------------------------------
# Pool tag collection via MLIL
# ---------------------------------------------------------------------------

def _collect_pooltags(bv: BinaryView):
    tags = {}
    for alloc_name in _ALLOC_NAMES:
        for func, ref_addr in get_callers(bv, alloc_name):
            try:
                mlil = func.mlil
                if not mlil:
                    continue
                idx = mlil.get_instruction_start(ref_addr)
                if idx is None:
                    continue
                instr = mlil[idx]
                for param in getattr(instr, 'params', []):
                    try:
                        val = param.constant & 0xFFFFFFFF
                        if _likely_pooltag_dword(val):
                            tag = ''.join(
                                c if 32 <= ord(c) <= 126 else '.'
                                for c in _decode_pooltag(val)
                            )
                            tags.setdefault(tag, set()).add(func.name)
                    except Exception:
                        pass
            except Exception:
                pass
    return tags


# ---------------------------------------------------------------------------
# Dispatch and IOCTL discovery (shared with win_find_ioctls.py)
# ---------------------------------------------------------------------------

_DISPATCH_PATTERNS = [
    r'\+\s*0xe0\b',
    r'MajorFunction\[(?:0xe|14)\]',
    r'\+\s*0x70\b',
]
_IOCTL_PATTERNS = [
    r'case\s+0x([0-9A-Fa-f]+)\s*:',
    r'ioControlCode\s*==\s*0x([0-9A-Fa-f]+)',
    r'(?:if|else\s+if)\s*\([^)]*==\s*0x([0-9A-Fa-f]+)',
    r'\w+\s*==\s*0x([0-9A-Fa-f]+)',
]
_NAME_HINTS = [
    'devicecontrol', 'dispatchio', 'ioctlhandler', 'ioctldispatch',
    'dispatchioctl', 'irpdevicecontrol', 'ioctlrouter',
]

FILE_DEVICE_MAP = {
    0x0:'FILE_DEVICE_UNKNOWN', 0x7:'FILE_DEVICE_DISK',
    0x9:'FILE_DEVICE_FILE_SYSTEM', 0x12:'FILE_DEVICE_NETWORK',
    0x22:'FILE_DEVICE_UNKNOWN', 0x23:'FILE_DEVICE_VIDEO',
}
METHOD_MAP = {0:'METHOD_BUFFERED', 1:'METHOD_IN_DIRECT', 2:'METHOD_OUT_DIRECT', 3:'METHOD_NEITHER'}
ACCESS_MAP = {0:'FILE_ANY_ACCESS', 1:'FILE_READ_ACCESS', 2:'FILE_WRITE_ACCESS', 3:'FILE_READ_WRITE_ACCESS'}


def _ctl_decode(v):
    v = v & 0xFFFFFFFF
    return {
        'raw': v, 'device': (v >> 16) & 0xFFFF,
        'access': (v >> 14) & 0x3, 'function': (v >> 2) & 0xFFF, 'method': v & 0x3,
    }


def _plausible_ioctl(v):
    d = _ctl_decode(v)
    return d['method'] in (0, 1, 2, 3) and d['function'] != 0 and d['device'] != 0


def _find_dispatch_routines(bv):
    routines = []
    seen = set()
    for func in bv.functions:
        dt = get_hlil_text(func)
        for line in dt.splitlines():
            for pat in _DISPATCH_PATTERNS:
                if not re.search(pat, line, re.IGNORECASE):
                    continue
                m = re.search(r'=\s*(?:&\s*)?([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+)', line)
                if not m:
                    continue
                target = m.group(1)
                tgt = None
                if target.startswith('0x'):
                    try:
                        tgt = bv.get_function_at(int(target, 16))
                    except Exception:
                        pass
                else:
                    syms = bv.get_symbols_by_name(target)
                    if syms:
                        tgt = bv.get_function_at(syms[0].address)
                if tgt and tgt.start not in seen:
                    seen.add(tgt.start)
                    routines.append(tgt)
    # S2: name heuristic — only include if function actually contains IOCTL codes
    for func in bv.functions:
        if any(h in func.name.lower() for h in _NAME_HINTS) and func.start not in seen:
            hlil_text = get_hlil_text(func)
            if _find_ioctls_in_text(hlil_text):
                seen.add(func.start)
                routines.append(func)

    # S3: caller of >= 2 ioctl-named functions — exclude entry points and require IOCTL codes
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
                hlil_text = get_hlil_text(f)
                if _find_ioctls_in_text(hlil_text):
                    seen.add(addr)
                    routines.append(f)

    # S4: fallback — individual ioctl-named functions
    if not routines:
        for func in bv.functions:
            if 'ioctl' in func.name.lower() and func.start not in seen:
                seen.add(func.start)
                routines.append(func)
    return routines


def _find_ioctls_in_text(hlil_text):
    codes = set()
    normalized = re.sub(r'\s+', ' ', hlil_text)
    for pat in _IOCTL_PATTERNS:
        for m in re.finditer(pat, normalized, re.IGNORECASE | re.DOTALL):
            try:
                val = int(m.group(1), 16)
                if val >= 0x200000 and _plausible_ioctl(val):
                    codes.add(val & 0xFFFFFFFF)
            except Exception:
                pass
    return sorted(codes)


def _fmt_ioctl_row(addr, code):
    d = _ctl_decode(code)
    device = FILE_DEVICE_MAP.get(d['device'], "0x{:X}".format(d['device']))
    method = METHOD_MAP.get(d['method'], str(d['method']))
    access = ACCESS_MAP.get(d['access'], str(d['access']))
    return "0x{:016x}  0x{:06X}  {:35s}  0x{:X}  0x{:<8X}  {}  {}".format(
        addr, d['raw'], device, d['device'], d['function'], method, access)


# ---------------------------------------------------------------------------
# Main plugin entry
# ---------------------------------------------------------------------------

def find_driver_vulns(bv: BinaryView):
    lines = [
        "=== Windows Kernel Driver Vulnerability Report ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]

    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir  = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-win-vulns.txt')

    def emit(line):
        lines.append(line)
        log_info(line)

    # ---- DriverEntry discovery ----
    emit("[>] Locating DriverEntry...")
    driver_entry = None
    for func in bv.functions:
        nm = func.name
        if nm == 'DriverEntry' or nm.lower().endswith('driverentry'):
            driver_entry = func
            break

    if not driver_entry:
        best, best_score = None, -1
        for func in bv.functions:
            dt = get_hlil_text(func)
            score = sum(1 for ind in _DRIVER_INDICATORS if ind in dt)
            if dt.count('RtlInitUnicodeString') >= 2:
                score += 1
            if 'IoCreateDevice' in dt and 'IoCreateSymbolicLink' in dt:
                score += 2
            if 'FltRegisterFilter' in dt:
                score += 2
            if score > best_score:
                best, best_score = func, score
        if best and best_score >= 2:
            driver_entry = best

    if driver_entry:
        emit("[+] DriverEntry: {} at 0x{:x}".format(driver_entry.name, driver_entry.start))
    else:
        emit("[-] DriverEntry: NOT FOUND")

    # ---- Device names ----
    emit("[>] Device names...")
    devices = set()
    for s in bv.strings:
        try:
            val = s.value
            if any(k in val.lower() for k in _DEVICE_INDICATORS):
                devices.add(val)
        except Exception:
            pass
    for d in sorted(devices):
        emit("    {}".format(d))
    if not devices:
        emit("    (none)")

    # ---- Pool tags ----
    emit("[>] Pool tags...")
    pooltags = _collect_pooltags(bv)
    for tag in sorted(pooltags):
        emit("    {} - called by: {}".format(tag, ', '.join(sorted(pooltags[tag]))))
    if not pooltags:
        emit("    (none)")

    # ---- Opcodes ----
    emit("[>] Dangerous opcodes (rdpmc/rdmsr/wrmsr)...")
    opcode_hits = []
    for func in bv.functions:
        try:
            for block in func.basic_blocks:
                for dl in block.disassembly_text:
                    if not dl.tokens:
                        continue
                    mnem = dl.tokens[0].text.lower().strip()
                    if mnem in _OPCODE_SEVERITY:
                        opcode_hits.append((mnem, func.name, "0x{:x}".format(dl.address)))
        except Exception:
            pass
    for mnem, fn, addr in sorted(opcode_hits):
        emit("    [{}] {} in {} at {}".format(_OPCODE_SEVERITY[mnem], mnem, fn, addr))
    if not opcode_hits:
        emit("    (none)")

    # ---- Dangerous C functions ----
    emit("[>] Dangerous C/C++ functions...")
    c_hits = set()
    for sym in bv.get_symbols():
        sname = sym.name
        matched = next((c for c in _C_FUNCS if sname == c or sname.startswith(c + '@')), None)
        if not matched:
            continue
        for ref in bv.get_code_refs(sym.address):
            if ref.function:
                c_hits.add((sname, ref.function.name, "0x{:x}".format(ref.address)))
    for name, fn, addr in sorted(c_hits):
        emit("    {} in {} at {}".format(name, fn, addr))
    if not c_hits:
        emit("    (none)")

    # ---- Windows kernel APIs ----
    emit("[>] Kernel API inventory...")
    api_hits = set()
    for sym in bv.get_symbols():
        sname = sym.name
        if not any(sname.startswith(p) for p in _WINAPI_PREFIXES):
            continue
        for ref in bv.get_code_refs(sym.address):
            if ref.function:
                api_hits.add((sname, ref.function.name, "0x{:x}".format(ref.address)))
    for name, fn, addr in sorted(api_hits, key=lambda x: (x[0].lower(), x[1])):
        emit("    {} in {} at {}".format(name, fn, addr))

    driver_type = "Mini-Filter" if any(n.startswith('Flt') for n, _, _ in api_hits) else "Standard WDM"
    emit("[+] Driver type: {}".format(driver_type))

    # ---- IOCTLs ----
    emit("[>] IOCTL enumeration...")
    ioctl_rows = []
    seen_ioctls = set()
    for df in _find_dispatch_routines(bv):
        try:
            ct = get_hlil_text(df)
            for code in _find_ioctls_in_text(ct):
                key = (df.start, code)
                if key in seen_ioctls:
                    continue
                seen_ioctls.add(key)
                row = _fmt_ioctl_row(df.start, code)
                ioctl_rows.append(row)
                d = _ctl_decode(code)
                if d['method'] == 3:
                    ioctl_rows.append("  *** METHOD_NEITHER - raw user pointer, high risk ***")
        except Exception:
            pass
    for r in sorted(set(ioctl_rows)):
        emit("    " + r)
    if not ioctl_rows:
        emit("    (none)")

    # ---- Physical memory / IO space ----
    emit("[>] Physical memory / IO space patterns...")
    for func in bv.functions:
        dt = get_hlil_text(func)
        if not dt:
            continue
        in_ioctl = _is_ioctl_context(dt)

        if '\\Device\\PhysicalMemory' in dt:
            sev = 'HIGH' if in_ioctl else 'MEDIUM'
            emit("[{}] PhysicalMemory section usage in {}".format(sev, func.name))

        if 'MmCopyMemory' in dt:
            sev = 'HIGH' if in_ioctl else 'MEDIUM'
            detail = "MmCopyMemory"
            if in_ioctl and _looks_user_driven_win(dt):
                detail += " with user-driven source/size"
            emit("[{}] Physical copy in {} :: {}".format(sev, func.name, detail))

        for api in ('MmMapIoSpaceEx', 'MmMapIoSpace'):
            if api in dt:
                idx = dt.find(api)
                risky = _looks_user_driven_win(dt) and not nearby_has_check(dt, idx, ['ProbeFor'])
                sev = 'HIGH' if (in_ioctl and risky) else ('MEDIUM' if in_ioctl else 'LOW')
                emit("[{}] IO space mapping in {} :: {} - verify PA/size origin".format(
                    sev, func.name, api))

        if 'MmMapLockedPagesSpecifyCache' in dt:
            idx = dt.find('MmMapLockedPagesSpecifyCache')
            usermap = 'UserMode' in dt[idx:idx + 200] or ', 1,' in dt[idx:idx + 200]
            sev = 'HIGH' if (in_ioctl and usermap) else 'MEDIUM'
            emit("[{}] MDL mapped to UserMode in {} :: MmMapLockedPagesSpecifyCache".format(
                sev, func.name))

        if in_ioctl:
            for prefix in ('READ_PORT_', 'WRITE_PORT_', 'READ_REGISTER_', 'WRITE_REGISTER_'):
                if prefix in dt:
                    emit("[HIGH] Port/Register IO from IOCTL in {} :: {} - verify privilege".format(
                        func.name, prefix))

    # ---- General vuln heuristics ----
    emit("[>] General vulnerability patterns...")
    for func in bv.functions:
        dt = get_hlil_text(func)
        if not dt:
            continue
        in_ioctl = _is_ioctl_context(dt)

        for name in _STRING_COPY_NAMES:
            if name in dt:
                idx = dt.find(name)
                if _looks_user_driven_win(dt) and not nearby_has_check(dt, idx, ['ProbeForRead', 'ProbeForWrite']):
                    sev = 'HIGH' if in_ioctl else 'MEDIUM'
                    emit("[{}] User copy without validation in {} :: {} near user buffer lacks ProbeFor".format(
                        sev, func.name, name))

        for an in _ALLOC_NAMES:
            if an in dt:
                idx = dt.find(an)
                if _looks_user_driven_win(dt) and not nearby_has_check(dt, idx, ['RtlULong', 'RtlSizeT']):
                    sev = 'HIGH' if in_ioctl else 'MEDIUM'
                    emit("[{}] Potential integer overflow in allocation in {} :: {} may use user-derived size".format(
                        sev, func.name, an))

        if in_ioctl:
            sensitive = any(k in dt for k in [
                'MmMapIoSpace', 'MmCopyMemory', 'ZwOpenSection', 'ZwMapViewOfSection',
                'READ_PORT_', 'WRITE_PORT_', 'READ_REGISTER_', 'WRITE_REGISTER_',
            ])
            if sensitive and not any(api in dt for api in _PRIV_GUARD_APIS):
                emit("[HIGH] Missing privilege gate in {} :: Sensitive ops in IOCTL path without SeSinglePrivilegeCheck".format(
                    func.name))

    # ---- Finalize ----
    emit("")
    emit("[+] Analysis complete.")

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        emit('[+] Report saved to: {}'.format(report_path))
    except Exception as e:
        log_warn("Could not write report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\Vulnerability Finder",
    "Static triage of Windows kernel drivers for vulnerability patterns",
    find_driver_vulns
)
