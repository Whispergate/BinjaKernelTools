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

_OPCODE_SEVERITY = {
    'rdpmc': 'HIGH', 'rdmsr': 'HIGH', 'wrmsr': 'HIGH',
    'in': 'HIGH', 'out': 'HIGH', 'hlt': 'HIGH',
    'cli': 'MEDIUM', 'sti': 'MEDIUM',
    'invd': 'HIGH', 'wbinvd': 'MEDIUM',
    'lgdt': 'HIGH', 'lidt': 'HIGH',
    'swapgs': 'HIGH', 'xsetbv': 'HIGH',
}

# Binja lifts privileged opcodes as HLIL intrinsics. Map substring -> severity.
# Substring match catches __in_al_dx, __out_dx_eax, __readcr0, etc.
_INTRINSIC_OPCODES = {
    '__rdmsr': 'HIGH', '__wrmsr': 'HIGH',
    '_rdpmc': 'HIGH', '__rdpmc': 'HIGH',
    '__in_': 'HIGH', '__out_': 'HIGH',
    '__halt': 'HIGH', 'trap(0xd)': 'HIGH',
    '__readcr': 'HIGH', '__writecr': 'HIGH',
    '__readdr': 'HIGH', '__writedr': 'HIGH',
    '__lgdt': 'HIGH', '__lidt': 'HIGH',
    '__sgdt': 'MEDIUM', '__sidt': 'MEDIUM',
    '__swapgs': 'HIGH', '__invd': 'HIGH', '__wbinvd': 'MEDIUM',
    '__cli': 'MEDIUM', '__sti': 'MEDIUM',
    '__cpuid': 'LOW',
}

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
    'HalGetBusDataByOffset', 'HalSetBusDataByOffset',
    'HalGetBusData', 'HalSetBusData',
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
    # Typed fields (post-DRIVER_OBJECT typing)
    if any(k in dt for k in (
        'IRP_MJ_DEVICE_CONTROL', 'IoControlCode',
        'Parameters.DeviceIoControl',
        'Tail.Overlay',                     # IO_STACK_LOCATION via overlay
        'AssociatedIrp.MasterIrp',          # SystemBuffer alias
        'AssociatedIrp.SystemBuffer',
    )):
        return True
    # Untyped offset fallback: dispatcher reads IRP at +0xb8 (CurrentStackLocation)
    # and IoControlCode at IO_STACK_LOCATION +0x18.
    return ('+ 0xb8)' in dt or '+ 0xB8)' in dt) and ('+ 0x18)' in dt or 'MajorFunction' in dt)


def _looks_user_driven_win(dt):
    keys = [
        'Parameters.DeviceIoControl.InputBufferLength',
        'Parameters.DeviceIoControl.OutputBufferLength',
        'Parameters.DeviceIoControl.Type3InputBuffer',
        'Irp->AssociatedIrp.SystemBuffer',
        'AssociatedIrp.SystemBuffer',
        'AssociatedIrp.MasterIrp',
        'Irp->UserBuffer',
        'UserBuffer',
        'MdlAddress',
        # Untyped offset forms (IO_STACK_LOCATION fields)
        '+ 0x8)',   # InputBufferLength / OutputBufferLength
        '+ 0x10)',  # OutputBufferLength / IoControlCode neighbor
        '+ 0x18)',  # IoControlCode
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
    r'\+\s*0xe0\b',                          # untyped: *(arg + 0xe0) = handler
    r'MajorFunction\[(?:0xe|14)\]',          # typed: arg1->MajorFunction[0xe]
    r'MajorFunction\[',                       # any MajorFunction slot assignment
    r'\+\s*0x70\b',                          # untyped: MajorFunction[0]
    r'\[0x1c\]\s*=',                         # int64_t*[28] subscript (0xE0/8)
    r'\[28\]\s*=',                            # decimal subscript form
]
_IOCTL_PATS_HEX = [
    r'case\s+0x([0-9A-Fa-f]+)\s*:',
    r'ioControlCode\s*[u]?==\s*0x([0-9A-Fa-f]+)',
    r'(?:if|else\s+if)\s*\([^)]*[u]?==\s*0x([0-9A-Fa-f]+)',
    r'\w+\s*[u]?==\s*0x([0-9A-Fa-f]+)',
    r'[u]?==\s*0x([0-9A-Fa-f]{5,})',
]
_IOCTL_PATS_DEC = [
    r'case\s+(\d{7,})\s*:',
    r'(?:if|else\s+if)\s*\([^)]*[u]?==\s*(\d{7,})\b',
    r'\w+\s*[u]?==\s*(\d{7,})\b',
    r'[u]?==\s*(\d{7,})\b',
]
_IOCTL_PATTERNS = _IOCTL_PATS_HEX  # backward-compat alias
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
    v &= 0xFFFFFFFF
    # Reject all-bits-set sentinels (e.g. -1 / 0xFFFFFFFF used as refcount compare)
    if v == 0xFFFFFFFF or (v >> 16) == 0xFFFF:
        return False
    d = _ctl_decode(v)
    return d['method'] in (0, 1, 2, 3) and d['function'] != 0 and d['device'] != 0


def _extract_const(node):
    """Extract integer from HLIL/MLIL node, int, or wrapped value."""
    if isinstance(node, int):
        return node
    for attr in ('constant',):
        try:
            c = getattr(node, attr, None)
            if isinstance(c, int):
                return c
        except Exception:
            pass
    # .value may be RegisterValue / PossibleValueSet / int
    try:
        v = getattr(node, 'value', None)
        if isinstance(v, int):
            return v
        if v is not None:
            inner = getattr(v, 'value', None)
            if isinstance(inner, int):
                return inner
    except Exception:
        pass
    try:
        return int(node)
    except Exception:
        return None


def _find_dispatch_routines(bv):
    routines = []
    seen = set()
    s1_lines_scanned = 0
    for func in bv.functions:
        dt = get_hlil_text(func)
        if not dt:
            continue
        for line in dt.splitlines():
            s1_lines_scanned += 1
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
                    log_info("[S1] Dispatch via HLIL pattern in {}: -> {} (0x{:x}) line='{}'".format(
                        func.name, tgt.name, tgt.start, line.strip()[:120]))
    log_info("[dispatch] S1 scanned {} HLIL lines, found {} routines".format(s1_lines_scanned, len(routines)))
    # S2: name heuristic - only include if function actually contains IOCTL codes.
    # Normalize by removing underscores/hyphens so device_control matches 'devicecontrol'
    # and C++ mangled names like ?device_control@ns@... still match after stripping.
    for func in bv.functions:
        name_norm = func.name.lower().replace('_', '').replace('-', '')
        if any(h in name_norm for h in _NAME_HINTS) and func.start not in seen:
            if _find_ioctls(func):
                seen.add(func.start)
                routines.append(func)

    # S3: caller of >= 2 ioctl-named functions - exclude entry points and require IOCTL codes
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

    # S4: fallback - individual ioctl-named functions
    if not routines:
        for func in bv.functions:
            if 'ioctl' in func.name.lower() and func.start not in seen:
                seen.add(func.start)
                routines.append(func)

    # S5 (bulletproof fallback): IOCTL-density scan.
    # Any function with >= 3 plausible IOCTL constants in HLIL is a dispatcher,
    # regardless of how Binja rendered the DriverEntry assignments. Catches
    # cases where S1's text-pattern misses (subscript form, exotic typing, etc).
    if not routines:
        for func in bv.functions:
            if func.start in seen:
                continue
            codes = _find_ioctls(func)
            if len(codes) >= 3:
                seen.add(func.start)
                routines.append(func)
                log_info("[S5] Dispatcher by IOCTL-density ({} codes): {} (0x{:x})".format(
                    len(codes), func.name, func.start))
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


def _iter_case_consts(case):
    """Yield integer constants for a HLIL switch case across Binja API variants."""
    # New API: case.values is list of HLIL_CONST instructions
    vals = getattr(case, 'values', None)
    if vals is not None:
        try:
            for v in vals:
                c = _extract_const(v)
                if c is not None:
                    yield c & 0xFFFFFFFF
            return
        except Exception:
            pass
    # Older API: singular .value
    sv = getattr(case, 'value', None)
    if sv is not None:
        c = _extract_const(sv)
        if c is not None:
            yield c & 0xFFFFFFFF


def _collect_switch_cases(instr, codes):
    try:
        if instr.operation.name == 'HLIL_SWITCH':
            for case in instr.cases:
                for v in _iter_case_consts(case):
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
    codes = set()
    try:
        hlil = func.hlil
        if hlil:
            for block in hlil:
                for instr in block:
                    _collect_switch_cases(instr, codes)
    except Exception:
        pass
    return codes


def _find_ioctls(func):
    codes = _find_ioctls_via_ast(func)
    codes |= set(_find_ioctls_in_text(get_hlil_text(func)))
    return sorted(codes)


def _fmt_ioctl_row(addr, code):
    d = _ctl_decode(code)
    device = FILE_DEVICE_MAP.get(d['device'], "0x{:X}".format(d['device']))
    method = METHOD_MAP.get(d['method'], str(d['method']))
    access = ACCESS_MAP.get(d['access'], str(d['access']))
    return "0x{:016x}  0x{:06X}  {:35s}  0x{:X}  0x{:<8X}  {}  {}".format(
        addr, d['raw'], device, d['device'], d['function'], method, access)


# ---------------------------------------------------------------------------
# IOCTL <-> Vulnerable Function cross-reference
# ---------------------------------------------------------------------------

# Substring -> short label used in IOCTL handler reports
_VULN_API_LABELS = {
    'MmMapIoSpace': 'MmMapIoSpace',
    'MmMapIoSpaceEx': 'MmMapIoSpaceEx',
    'MmUnmapIoSpace': 'MmUnmapIoSpace',
    'MmCopyMemory': 'MmCopyMemory',
    'MmGetPhysicalAddress': 'MmGetPhysicalAddress',
    'MmMapLockedPagesSpecifyCache': 'MmMapLockedPagesSpecifyCache',
    'ZwOpenSection': 'ZwOpenSection', 'ZwMapViewOfSection': 'ZwMapViewOfSection',
    'HalGetBusDataByOffset': 'HalGetBusDataByOffset',
    'HalSetBusDataByOffset': 'HalSetBusDataByOffset',
    'memcpy': 'memcpy', 'memmove': 'memmove', 'RtlCopyMemory': 'RtlCopyMemory',
}

_VULN_INTRINSIC_LABELS = {
    '__rdmsr': 'rdmsr', '__wrmsr': 'wrmsr',
    '_rdpmc': 'rdpmc', '__rdpmc': 'rdpmc',
    '__in_': 'in (port-IO read)', '__out_': 'out (port-IO write)',
    '__halt': 'hlt', 'trap(0xd)': 'hlt/trap',
    '__readcr': 'mov from CRx', '__writecr': 'mov to CRx',
    '__readdr': 'mov from DRx', '__writedr': 'mov to DRx',
    '__swapgs': 'swapgs', '__invd': 'invd', '__wbinvd': 'wbinvd',
}


def _scan_text_for_vulns(text):
    """Return set of vuln labels found in given HLIL text."""
    hits = set()
    for needle, label in _VULN_API_LABELS.items():
        if needle in text:
            hits.add(label)
    for needle, label in _VULN_INTRINSIC_LABELS.items():
        if needle in text:
            hits.add(label)
    return hits


def _walk_collect_calls(instr, callee_starts):
    """Recursively collect call destination addresses from one HLIL instr."""
    try:
        opname = instr.operation.name
        if opname in ('HLIL_CALL', 'HLIL_TAILCALL', 'HLIL_CALL_SSA', 'HLIL_TAILCALL_SSA'):
            dest = getattr(instr, 'dest', None)
            if dest is not None:
                cval = getattr(dest, 'constant', None)
                if cval is not None:
                    try:
                        callee_starts.add(int(cval))
                    except Exception:
                        pass
                else:
                    dval = getattr(dest, 'value', None)
                    inner = getattr(dval, 'value', None) if dval is not None else None
                    if inner is not None:
                        try:
                            callee_starts.add(int(inner))
                        except Exception:
                            pass
        for operand in getattr(instr, 'operands', []):
            if hasattr(operand, 'operation'):
                _walk_collect_calls(operand, callee_starts)
            elif hasattr(operand, '__iter__') and not isinstance(operand, (str, bytes)):
                for item in operand:
                    if hasattr(item, 'operation'):
                        _walk_collect_calls(item, callee_starts)
    except Exception:
        pass


def _walk_collect_text(instr, parts):
    """Collect string forms of every nested instruction."""
    try:
        parts.append(str(instr))
        for operand in getattr(instr, 'operands', []):
            if hasattr(operand, 'operation'):
                _walk_collect_text(operand, parts)
            elif hasattr(operand, '__iter__') and not isinstance(operand, (str, bytes)):
                for item in operand:
                    if hasattr(item, 'operation'):
                        _walk_collect_text(item, parts)
    except Exception:
        pass


_MAX_CLASSIFY_DEPTH = 3
_MAX_CALLEES_PER_LEVEL = 12


def _walk_callees_recursive(bv, start_addr, depth, visited):
    """Yield (callee_func, name_chain) pairs up to depth levels deep."""
    if depth <= 0 or start_addr in visited:
        return
    visited.add(start_addr)
    f = bv.get_function_at(start_addr)
    if not f:
        return
    try:
        hlil = f.hlil
        if not hlil:
            return
    except Exception:
        return
    sub_callees = set()
    try:
        for block in hlil:
            for instr in block:
                _walk_collect_calls(instr, sub_callees)
    except Exception:
        return
    count = 0
    for caddr in sub_callees:
        if count >= _MAX_CALLEES_PER_LEVEL:
            break
        count += 1
        sub_f = bv.get_function_at(caddr)
        if sub_f:
            yield sub_f
        yield from _walk_callees_recursive(bv, caddr, depth - 1, visited)


def _classify_branch_vulns(bv, instrs):
    """Given list of HLIL instructions forming a handler branch, return vuln labels.

    Walks call graph up to _MAX_CLASSIFY_DEPTH deep so wrappers like
    HEVD's Handler -> Trigger -> primitive chain are caught.
    """
    text_parts = []
    direct_callees = set()
    for instr in instrs:
        _walk_collect_text(instr, text_parts)
        _walk_collect_calls(instr, direct_callees)
    branch_text = "\n".join(text_parts)
    vulns = _scan_text_for_vulns(branch_text)

    visited = set()
    for caddr in direct_callees:
        for sub_f in _walk_callees_recursive(bv, caddr, _MAX_CLASSIFY_DEPTH, visited):
            try:
                ctext = get_hlil_text(sub_f)
            except Exception:
                continue
            for v in _scan_text_for_vulns(ctext):
                vulns.add("{} (via {})".format(v, sub_f.name))

    name_hint_vulns = _scan_callee_names_for_vulns(bv, direct_callees, visited)
    vulns |= name_hint_vulns
    return vulns, direct_callees


# HEVD-style + common kernel-vuln name patterns -> primitive label.
# Matched against function names anywhere in the call chain.
# Generic substring -> primitive label. Covers HEVD plus broad driver-naming
# conventions seen across BYOVD / signed-driver corpora.
_NAME_HINTS = {
    'bufferoverflowstack':        'Stack BoF (name)',
    'bufferoverflownonpagedpool': 'Pool BoF (name)',
    'bufferoverflowpagedpool':    'Pool BoF (name)',
    'stackoverflow':              'Stack BoF (name)',
    'heapoverflow':               'Heap/Pool BoF (name)',
    'pooloverflow':               'Pool BoF (name)',
    'integeroverflow':            'Integer Overflow (name)',
    'arbitrarywrite':             'Arbitrary Write (name)',
    'arbitraryread':              'Arbitrary Read (name)',
    'arbitraryincrement':         'Arbitrary Increment (name)',
    'arbitraryreadwrite':         'Arb R/W primitive (name)',
    'arbwrite':                   'Arbitrary Write (name)',
    'arbread':                    'Arbitrary Read (name)',
    'readkernel':                 'Arbitrary Kernel Read (name)',
    'writekernel':                'Arbitrary Kernel Write (name)',
    'readvirtual':                'Virtual Mem Read (name)',
    'writevirtual':               'Virtual Mem Write (name)',
    'readmemory':                 'Memory Read (name)',
    'writememory':                'Memory Write (name)',
    'readprocessmemory':          'Process Mem Read (name)',
    'writeprocessmemory':         'Process Mem Write (name)',
    'writenull':                  'Write to NULL (name)',
    'nullpointer':                'NULL Deref (name)',
    'nullderef':                  'NULL Deref (name)',
    'uninitialized':              'Uninitialized Mem (name)',
    'uninit':                     'Uninitialized Mem (name)',
    'memorydisclosure':           'Memory Disclosure (name)',
    'infoleak':                   'Info Leak (name)',
    'typeconfusion':              'Type Confusion (name)',
    'uafobject':                  'Use-After-Free (name)',
    'useafterfree':               'Use-After-Free (name)',
    'doublefree':                 'Double Free (name)',
    'doublefetch':                'Double-Fetch (name)',
    'racecondition':              'Race Condition (name)',
    'insecurekernelfileaccess':   'Insecure File Access (name)',
    'fakeobject':                 'Fake Object / Type Confusion (name)',
    # privileged-intrinsic primitives
    'rdmsr':                      'MSR Read (name)',
    'wrmsr':                      'MSR Write (name)',
    'readmsr':                    'MSR Read (name)',
    'writemsr':                   'MSR Write (name)',
    'msrread':                    'MSR Read (name)',
    'msrwrite':                   'MSR Write (name)',
    'readioport':                 'Port IO Read (name)',
    'writeioport':                'Port IO Write (name)',
    'readport':                   'Port IO Read (name)',
    'writeport':                  'Port IO Write (name)',
    'inport':                     'Port IN (name)',
    'outport':                    'Port OUT (name)',
    'readphysical':               'Phys Mem Read (name)',
    'writephysical':              'Phys Mem Write (name)',
    'mapphysical':                'Phys Mem Map (name)',
    'physmem':                    'Phys Mem Access (name)',
    'physicalmemory':             'Phys Mem Access (name)',
    'mapmemory':                  'Memory Map (name)',
    'mapio':                      'IO Space Map (name)',
    'pciconfig':                  'PCI Config (name)',
    'readpci':                    'PCI Read (name)',
    'writepci':                   'PCI Write (name)',
    'readcr':                     'CRx Read (name)',
    'writecr':                    'CRx Write (name)',
    'readdr':                     'DRx Read (name)',
    'writedr':                    'DRx Write (name)',
    'gdt':                        'GDT Access (name)',
    'idt':                        'IDT Access (name)',
    # ring-0 exec / shellcode
    'shellcode':                  'Ring-0 Shellcode (name)',
    'execpayload':                'Ring-0 Exec (name)',
    'kernelexec':                 'Ring-0 Exec (name)',
    'callkernel':                 'Ring-0 Exec (name)',
    # process / token tampering
    'terminateprocess':           'Process Kill (name)',
    'killprocess':                'Process Kill (name)',
    'suspendprocess':             'Process Suspend (name)',
    'protectprocess':             'Process Protection (name)',
    'unprotectprocess':           'Process Protection (name)',
    'stealtoken':                 'Token Steal (name)',
    'swaptoken':                  'Token Swap (name)',
    'elevatetoken':               'Token Elevation (name)',
    'tokenswap':                  'Token Swap (name)',
    # callback / ETW / SSDT
    'disablecallback':            'Callback Removal (name)',
    'removecallback':             'Callback Removal (name)',
    'unregistercallback':         'Callback Removal (name)',
    'patchetw':                   'ETW Tampering (name)',
    'disableetw':                 'ETW Tampering (name)',
    'ssdt':                       'SSDT Tampering (name)',
    'hookssdt':                   'SSDT Hook (name)',
    'patchssdt':                  'SSDT Hook (name)',
    # file / registry
    'kernelfileread':             'Kernel File Access (name)',
    'kernelfilewrite':            'Kernel File Access (name)',
    'kernelregistry':             'Kernel Registry Access (name)',
    # driver / section
    'loaddriver':                 'Driver Load Primitive (name)',
    'mapdriver':                  'Driver Map Primitive (name)',
    'opensection':                'Section Open (name)',
    'mapsection':                 'Section Map (name)',
}

# Don't match on stub names that carry no info
_NAME_HINT_SKIP_PREFIX = ('sub_', 'nullsub_', 'j_')


def _scan_callee_names_for_vulns(bv, direct_callees, visited_extra):
    """Name-pattern fallback - HEVD names its handlers literally after the bug class."""
    hits = set()
    all_names = set()
    visited = set(visited_extra)
    for caddr in direct_callees:
        f = bv.get_function_at(caddr)
        if f:
            all_names.add(f.name)
        for sub_f in _walk_callees_recursive(bv, caddr, _MAX_CLASSIFY_DEPTH, visited):
            all_names.add(sub_f.name)
    for nm in all_names:
        if not nm or nm.startswith(_NAME_HINT_SKIP_PREFIX):
            continue
        nl = nm.lower().replace('_', '').replace('-', '')
        for needle, label in _NAME_HINTS.items():
            if needle in nl:
                hits.add("{} via {}".format(label, nm))
    return hits


def _ioctl_branches_for_dispatcher(dispatcher):
    """
    Return list of (ioctl_const, [HLIL instrs in branch], compare_addr).
    Handles both HLIL_SWITCH cases and HLIL_IF (== const) bodies.
    """
    out = []
    try:
        hlil = dispatcher.hlil
        if not hlil:
            return out
    except Exception:
        return out

    def _all_under(instr, bucket):
        try:
            bucket.append(instr)
            for op in getattr(instr, 'operands', []):
                if hasattr(op, 'operation'):
                    _all_under(op, bucket)
                elif hasattr(op, '__iter__') and not isinstance(op, (str, bytes)):
                    for it in op:
                        if hasattr(it, 'operation'):
                            _all_under(it, bucket)
        except Exception:
            pass

    def _const_from_condition(cond):
        """If cond is `var == const`, return int(const). Walk OR chains too."""
        results = []
        try:
            opname = cond.operation.name
            if opname in ('HLIL_CMP_E', 'HLIL_CMP_NE'):
                for op in cond.operands:
                    c = _extract_const(op)
                    if c is None:
                        continue
                    v = c & 0xFFFFFFFF
                    if v >= 0x200000 and _plausible_ioctl(v):
                        results.append(v)
            elif opname in ('HLIL_OR', 'HLIL_AND'):
                for op in cond.operands:
                    if hasattr(op, 'operation'):
                        results.extend(_const_from_condition(op))
        except Exception:
            pass
        return results

    def _visit(instr):
        try:
            opname = instr.operation.name
            if opname == 'HLIL_SWITCH':
                for case in instr.cases:
                    case_consts = []
                    for cv in _iter_case_consts(case):
                        if cv >= 0x200000 and _plausible_ioctl(cv):
                            case_consts.append(cv)
                    body_instrs = []
                    body = getattr(case, 'body', None)
                    if body is not None:
                        _all_under(body, body_instrs)
                    for cv in case_consts:
                        out.append((cv, body_instrs, "0x{:x}".format(instr.address)))
            elif opname == 'HLIL_IF':
                consts = _const_from_condition(instr.condition)
                if consts:
                    body_instrs = []
                    if instr.true:
                        _all_under(instr.true, body_instrs)
                    for cv in consts:
                        out.append((cv, body_instrs, "0x{:x}".format(instr.address)))
            for op in getattr(instr, 'operands', []):
                if hasattr(op, 'operation'):
                    _visit(op)
                elif hasattr(op, '__iter__') and not isinstance(op, (str, bytes)):
                    for it in op:
                        if hasattr(it, 'operation'):
                            _visit(it)
        except Exception:
            pass

    try:
        for block in hlil:
            for instr in block:
                _visit(instr)
    except Exception:
        pass
    return out


def _resolve_callee_name(bv, addr):
    """Resolve an address to its function/symbol name, following IAT thunks."""
    f = bv.get_function_at(addr)
    if f and f.name and not f.name.startswith('sub_'):
        return f.name
    # Try symbol at address (covers import thunks pointing at IAT slot)
    sym = bv.get_symbol_at(addr)
    if sym and sym.name:
        return sym.name
    # Try data symbol - import thunk jumps to data ref of the IAT entry
    try:
        for ref in bv.get_data_refs_from(addr):
            ds = bv.get_symbol_at(ref)
            if ds and ds.name:
                return ds.name
    except Exception:
        pass
    if f:
        return f.name
    return "0x{:x}".format(addr)


def _emit_ioctl_vuln_map(bv, emit):
    """Map each IOCTL constant in each dispatcher to vuln APIs/intrinsics in its handler branch."""
    dispatchers = _find_dispatch_routines(bv)
    if not dispatchers:
        emit("    (no dispatcher)")
        return
    rows = []  # (ioctl, dispatcher_name, vuln_label_set, callees)
    for df in dispatchers:
        branches = _ioctl_branches_for_dispatcher(df)
        # Aggregate by ioctl_const (cases with same constant unify)
        by_code = {}
        for entry in branches:
            code, instrs = entry[0], entry[1]
            by_code.setdefault(code, []).extend(instrs)
        for code, instrs in by_code.items():
            vulns, callees = _classify_branch_vulns(bv, instrs)
            callee_names = sorted({_resolve_callee_name(bv, c) for c in callees})
            rows.append((code, df.name, vulns, callee_names))
    if not rows:
        emit("    (none)")
        return
    for code, dname, vulns, callees in sorted(rows, key=lambda x: x[0]):
        d = _ctl_decode(code)
        method = METHOD_MAP.get(d['method'], str(d['method']))
        vlabel = ", ".join(sorted(vulns)) if vulns else "(no dangerous calls/intrinsics)"
        clabel = ", ".join(callees) if callees else "inline"
        sev = "HIGH" if vulns else "INFO"
        emit("    [{}] IOCTL 0x{:08X} ({}) in {}  ->  calls: {}  ::  {}".format(
            sev, code, method, dname, clabel, vlabel))


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
    emit("[>] Dangerous opcodes (raw mnemonic + HLIL intrinsic)...")
    opcode_hits = []
    seen_op = set()
    for func in bv.functions:
        # Raw disassembly token scan
        try:
            for block in func.basic_blocks:
                for dl in block.disassembly_text:
                    if not dl.tokens:
                        continue
                    # First non-whitespace token is the mnemonic
                    mnem = None
                    for tok in dl.tokens:
                        t = tok.text.strip().lower()
                        if t:
                            mnem = t
                            break
                    if mnem and mnem in _OPCODE_SEVERITY:
                        key = (mnem, func.start, dl.address)
                        if key not in seen_op:
                            seen_op.add(key)
                            opcode_hits.append(
                                (_OPCODE_SEVERITY[mnem], mnem, func.name, "0x{:x}".format(dl.address)))
        except Exception:
            pass
        # HLIL intrinsic scan (catches Binja-lifted privileged ops)
        try:
            dt = get_hlil_text(func)
            if not dt:
                continue
            for needle, sev in _INTRINSIC_OPCODES.items():
                if needle in dt:
                    key = (needle, func.start, 0)
                    if key not in seen_op:
                        seen_op.add(key)
                        opcode_hits.append((sev, needle, func.name, "(intrinsic)"))
        except Exception:
            pass
    for sev, mnem, fn, addr in sorted(opcode_hits):
        emit("    [{}] {} in {} at {}".format(sev, mnem, fn, addr))
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
            for code in _find_ioctls(df):
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

    # ---- IOCTL <-> Vulnerable Functions cross-reference ----
    emit("[>] IOCTL <-> Vulnerable Functions...")
    _emit_ioctl_vuln_map(bv, emit)

    # ---- Device-creation ACL hygiene ----
    emit("[>] Device-creation ACL...")
    has_create = any(s.name == 'IoCreateDevice'       for s in bv.get_symbols())
    has_secure = any(s.name == 'IoCreateDeviceSecure' for s in bv.get_symbols())
    has_symlnk = any(s.name == 'IoCreateSymbolicLink' for s in bv.get_symbols())
    if has_create and not has_secure:
        sev = 'HIGH' if has_symlnk else 'MEDIUM'
        emit("    [{}] IoCreateDevice without IoCreateDeviceSecure - default ACL likely permits non-admin open{}".format(
            sev, ' (symbolic link exposed to Win32)' if has_symlnk else ''))
    else:
        emit("    (ok)")

    # ---- PCI config space access (Hal*BusData*) ----
    emit("[>] PCI config space (HalGetBusDataByOffset / HalSetBusDataByOffset)...")
    pci_hit = False
    for api in ('HalGetBusDataByOffset', 'HalSetBusDataByOffset', 'HalGetBusData', 'HalSetBusData'):
        for func, addr in get_callers(bv, api):
            pci_hit = True
            dt = get_hlil_text(func)
            sev = 'HIGH' if _is_ioctl_context(dt) and _looks_user_driven_win(dt) else 'MEDIUM'
            emit("    [{}] {} in {} at 0x{:x}".format(sev, api, func.name, addr))
    if not pci_hit:
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
