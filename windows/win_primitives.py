"""
Binary Ninja plugin - Windows kernel exploit primitive detection.

Surfaces exploit primitives per IOCTL handler:
  - Write-What-Where (arbitrary kernel write)
  - Arbitrary Read (kernel pointer deref -> user)
  - Stack Buffer Overflow (memcpy to stack with user-controlled len)
  - Pool Buffer Overflow (memcpy to ExAllocatePool buffer)
  - NULL pointer dereference (deref w/o check after alloc / lookup)
  - Token-swap primitive enabler (PsLookupProcessByProcessId + Token offset)
  - Type Confusion (ObReferenceObjectByHandle w/o ObjectType)
  - IORING-relevant patterns (IoRing*, NtSubmitIoRing, registered buffer abuse)
  - Double-fetch TOCTOU (same user pointer fetched 2+ times)
  - Uninitialized stack/pool leak (memcpy to user from unzero'd buffer)

References:
  - connormcgarr.github.io (Win kernel exploit techniques)
  - knifecoat.com IORING arbitrary R/W
  - windows-internals.com IORING primitive
  - whiteknightlabs.com arbitrary access primitives
  - r0keb pool internals + LFH
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, nearby_has_check
from .win_vuln_finder import (
    _find_dispatch_routines, _ioctl_branches_for_dispatcher,
    _walk_collect_text, _walk_collect_calls, _ctl_decode, METHOD_MAP,
    _resolve_callee_name, _looks_user_driven_win,
)

_TOKEN_OFFSETS = ['0x4b8', '0x358', '0x208', '+ 0x4b8', '+ 0x358']
_IORING_NAMES = [
    'IoRingCreate', 'NtCreateIoRing', 'NtSubmitIoRing',
    'IoRingRegisterBuffers', 'IoRingRegisterFiles',
    'IopIoRingDispatch', 'IoRingSubmit',
]
_OBJECT_LOOKUP = [
    'ObReferenceObjectByHandle', 'ObReferenceObjectByHandleWithTag',
    'ObReferenceObjectByPointer', 'PsLookupProcessByProcessId',
    'PsLookupThreadByThreadId',
]
_PROBE_NAMES = ['ProbeForRead', 'ProbeForWrite']


def _branch_text(instrs):
    parts = []
    for ins in instrs:
        _walk_collect_text(ins, parts)
    return "\n".join(parts)


def _branch_callees(bv, instrs):
    starts = set()
    for ins in instrs:
        _walk_collect_calls(ins, starts)
    return starts


_MAX_DEEP_CALLEES = 16


def _deep_text(bv, instrs, max_depth=3):
    """Branch text + recursive callee text up to max_depth.

    Catches wrapper chains like HEVD's IrpHandler -> Trigger -> primitive.
    """
    t = _branch_text(instrs)
    seen = set()
    frontier = list(_branch_callees(bv, instrs))
    depth = 0
    while frontier and depth < max_depth:
        next_frontier = []
        count = 0
        for caddr in frontier:
            if count >= _MAX_DEEP_CALLEES:
                break
            if caddr in seen:
                continue
            seen.add(caddr)
            count += 1
            f = bv.get_function_at(caddr)
            if not f:
                continue
            try:
                t += "\n; --- callee " + f.name + " ---\n" + get_hlil_text(f)
            except Exception:
                continue
            try:
                hlil = f.hlil
                if hlil:
                    sub = set()
                    for block in hlil:
                        for instr in block:
                            _walk_collect_calls(instr, sub)
                    next_frontier.extend(sub - seen)
            except Exception:
                pass
        frontier = next_frontier
        depth += 1
    return t


# Generic substring -> (severity, primitive label).
# Covers HEVD plus broad driver-naming conventions seen across BYOVD corpora.
# Match is case-insensitive on name with _/- stripped.
_NAME_PRIM_HINTS = {
    # HEVD-style (memory corruption)
    'bufferoverflowstack':        ('HIGH',     'Stack Buffer Overflow (name)'),
    'bufferoverflownonpagedpool': ('HIGH',     'Pool Buffer Overflow (name)'),
    'bufferoverflowpagedpool':    ('HIGH',     'Pool Buffer Overflow (name)'),
    'stackoverflow':              ('HIGH',     'Stack Buffer Overflow (name)'),
    'heapoverflow':               ('HIGH',     'Heap/Pool Overflow (name)'),
    'pooloverflow':               ('HIGH',     'Pool Overflow (name)'),
    'integeroverflow':            ('HIGH',     'Integer Overflow (name)'),
    'uafobject':                  ('HIGH',     'Use-After-Free (name)'),
    'useafterfree':               ('HIGH',     'Use-After-Free (name)'),
    'doublefree':                 ('HIGH',     'Double Free (name)'),
    'doublefetch':                ('HIGH',     'Double-Fetch TOCTOU (name)'),
    'racecondition':              ('HIGH',     'Race Condition (name)'),
    'typeconfusion':              ('HIGH',     'Type Confusion (name)'),
    'fakeobject':                 ('HIGH',     'Type Confusion / Fake Object (name)'),
    'uninitializedmemory':        ('MEDIUM',   'Uninitialized Memory Leak (name)'),
    'uninit':                     ('MEDIUM',   'Uninitialized Memory Leak (name)'),
    'memorydisclosure':           ('MEDIUM',   'Memory Disclosure (name)'),
    'infoleak':                   ('MEDIUM',   'Info Leak (name)'),
    'nullpointer':                ('MEDIUM',   'NULL Pointer Deref (name)'),
    'nullderef':                  ('MEDIUM',   'NULL Pointer Deref (name)'),
    'writenull':                  ('HIGH',     'Write to NULL (name)'),

    # Arbitrary R/W primitives (broad conventions)
    'arbitrarywrite':             ('CRITICAL', 'Write-What-Where (name)'),
    'arbitraryread':              ('CRITICAL', 'Arbitrary Kernel Read (name)'),
    'arbitraryreadwrite':         ('CRITICAL', 'Arb R/W Primitive (name)'),
    'arbitraryincrement':         ('HIGH',     'Arbitrary Increment (name)'),
    'arbwrite':                   ('CRITICAL', 'Write-What-Where (name)'),
    'arbread':                    ('CRITICAL', 'Arbitrary Kernel Read (name)'),
    'readkernel':                 ('CRITICAL', 'Arbitrary Kernel Read (name)'),
    'writekernel':                ('CRITICAL', 'Arbitrary Kernel Write (name)'),
    'readvirtual':                ('CRITICAL', 'Virtual Memory Read (name)'),
    'writevirtual':               ('CRITICAL', 'Virtual Memory Write (name)'),
    'readmemory':                 ('HIGH',     'Memory Read (name)'),
    'writememory':                ('HIGH',     'Memory Write (name)'),
    'readprocessmemory':          ('HIGH',     'Process Memory Read (name)'),
    'writeprocessmemory':         ('HIGH',     'Process Memory Write (name)'),

    # MSR
    'rdmsr':                      ('CRITICAL', 'MSR Read (name)'),
    'wrmsr':                      ('CRITICAL', 'MSR Write (name)'),
    'readmsr':                    ('CRITICAL', 'MSR Read (name)'),
    'writemsr':                   ('CRITICAL', 'MSR Write (name)'),
    'msrread':                    ('CRITICAL', 'MSR Read (name)'),
    'msrwrite':                   ('CRITICAL', 'MSR Write (name)'),

    # Port IO
    'readioport':                 ('CRITICAL', 'Port IO Read (name)'),
    'writeioport':                ('CRITICAL', 'Port IO Write (name)'),
    'readport':                   ('CRITICAL', 'Port IO Read (name)'),
    'writeport':                  ('CRITICAL', 'Port IO Write (name)'),
    'inport':                     ('CRITICAL', 'Port IN (name)'),
    'outport':                    ('CRITICAL', 'Port OUT (name)'),
    'ioread':                     ('HIGH',     'IO Read (name)'),
    'iowrite':                    ('HIGH',     'IO Write (name)'),

    # Physical memory
    'readphysical':               ('CRITICAL', 'Physical Memory Read (name)'),
    'writephysical':              ('CRITICAL', 'Physical Memory Write (name)'),
    'mapphysical':                ('CRITICAL', 'Physical Memory Map (name)'),
    'physmem':                    ('CRITICAL', 'Physical Memory Access (name)'),
    'physicalmemory':             ('CRITICAL', 'Physical Memory Access (name)'),
    'mapmemory':                  ('HIGH',     'Memory Map (name)'),
    'mapio':                      ('HIGH',     'IO Space Map (name)'),

    # PCI / Hal
    'pciconfig':                  ('HIGH',     'PCI Config Access (name)'),
    'readpci':                    ('HIGH',     'PCI Read (name)'),
    'writepci':                   ('HIGH',     'PCI Write (name)'),
    'halgetbus':                  ('HIGH',     'PCI Bus Access (name)'),
    'halsetbus':                  ('HIGH',     'PCI Bus Access (name)'),

    # Control / Debug registers
    'readcr':                     ('CRITICAL', 'CRx Read (name)'),
    'writecr':                    ('CRITICAL', 'CRx Write (name)'),
    'readdr':                     ('HIGH',     'DRx Read (name)'),
    'writedr':                    ('HIGH',     'DRx Write (name)'),
    'gdt':                        ('HIGH',     'GDT Access (name)'),
    'idt':                        ('HIGH',     'IDT Access (name)'),

    # Ring-0 exec / shellcode
    'shellcode':                  ('CRITICAL', 'Ring-0 Shellcode (name)'),
    'execpayload':                ('CRITICAL', 'Ring-0 Exec (name)'),
    'kernelexec':                 ('CRITICAL', 'Ring-0 Exec (name)'),
    'callkernel':                 ('CRITICAL', 'Ring-0 Exec (name)'),

    # Process / token tampering
    'terminateprocess':           ('HIGH',     'Process Kill (name)'),
    'killprocess':                ('HIGH',     'Process Kill (name)'),
    'suspendprocess':             ('HIGH',     'Process Suspend (name)'),
    'protectprocess':             ('HIGH',     'Process Protection Toggle (name)'),
    'unprotectprocess':           ('HIGH',     'Process Protection Toggle (name)'),
    'stealtoken':                 ('CRITICAL', 'Token Steal (name)'),
    'swaptoken':                  ('CRITICAL', 'Token Swap (name)'),
    'elevatetoken':               ('CRITICAL', 'Token Elevation (name)'),
    'tokenswap':                  ('CRITICAL', 'Token Swap (name)'),

    # Kernel callback / ETW / SSDT tampering
    'disablecallback':            ('HIGH',     'Callback Removal (name)'),
    'removecallback':             ('HIGH',     'Callback Removal (name)'),
    'unregistercallback':         ('HIGH',     'Callback Removal (name)'),
    'patchetw':                   ('HIGH',     'ETW Tampering (name)'),
    'disableetw':                 ('HIGH',     'ETW Tampering (name)'),
    'ssdt':                       ('HIGH',     'SSDT Tampering (name)'),
    'hookssdt':                   ('HIGH',     'SSDT Hook (name)'),
    'patchssdt':                  ('HIGH',     'SSDT Hook (name)'),

    # File / registry from kernel ctx
    'insecurekernelfileaccess':   ('HIGH',     'Insecure File Access (name)'),
    'kernelfileread':             ('HIGH',     'Kernel File Access (name)'),
    'kernelfilewrite':            ('HIGH',     'Kernel File Access (name)'),
    'kernelregistry':             ('HIGH',     'Kernel Registry Access (name)'),

    # Driver load / section
    'loaddriver':                 ('HIGH',     'Driver Load Primitive (name)'),
    'mapdriver':                  ('HIGH',     'Driver Map Primitive (name)'),
    'opensection':                ('HIGH',     'Section Open (name)'),
    'mapsection':                 ('HIGH',     'Section Map (name)'),
}


def _detect_name_hints(bv, instrs):
    """Walk callees + match descriptive names. Returns list of (sev,label).

    Skips sub_* / nullsub_* unnamed functions (no info). Strips _/- before match.
    """
    hits = []
    seen = set()
    frontier = list(_branch_callees(bv, instrs))
    depth = 0
    while frontier and depth < 3:
        next_frontier = []
        for caddr in frontier:
            if caddr in seen:
                continue
            seen.add(caddr)
            f = bv.get_function_at(caddr)
            if not f:
                continue
            nm = f.name
            if not nm or nm.startswith('sub_') or nm.startswith('nullsub_') or nm.startswith('j_'):
                pass
            else:
                nl = nm.lower().replace('_', '').replace('-', '')
                for needle, sev_label in _NAME_PRIM_HINTS.items():
                    if needle in nl:
                        sev, label = sev_label
                        hits.append((sev, label + ' :: ' + nm))
                        break
            try:
                hlil = f.hlil
                if hlil:
                    sub = set()
                    for block in hlil:
                        for instr in block:
                            _walk_collect_calls(instr, sub)
                    next_frontier.extend(sub - seen)
            except Exception:
                pass
        frontier = next_frontier
        depth += 1
    return hits


def _has_any(text, needles):
    return any(n in text for n in needles)


def _detect_write_what_where(text):
    """User-controlled destination AND user-controlled value pattern."""
    if not _has_any(text, ['SystemBuffer', '+ 0x18)', 'Type3InputBuffer', 'UserBuffer']):
        return False
    # Common pattern: *user_ptr_a = user_val_b
    patterns = [
        r'\*\s*\(\s*\*\s*\([^)]*(SystemBuffer|Type3InputBuffer|UserBuffer)',
        r'\*\s*\w+\s*=\s*\*\s*\w+\s*;',
        r'\*\(int(?:32|64)?_t\s*\*\)\s*\(?\*',
    ]
    for p in patterns:
        if re.search(p, text):
            return True
    return False


def _detect_arb_read(text):
    """memcpy(out_user, *user_ptr, len) - kernel read controlled by user ptr."""
    if 'memcpy' not in text and 'RtlCopyMemory' not in text:
        return False
    return bool(re.search(r'(?:memcpy|RtlCopyMemory)\s*\([^,]+,\s*\*\s*\(', text))


def _detect_stack_bof(text):
    """memcpy/strcpy to stack-allocated buffer with user-controlled length."""
    if not _has_any(text, ['memcpy', 'RtlCopyMemory', 'strcpy', 'wcscpy']):
        return False
    has_user_len = _has_any(text, [
        'InputBufferLength', 'OutputBufferLength', '+ 0x8)', '+ 0x10)',
    ])
    has_stack = bool(re.search(r'var_[0-9a-f]+', text))
    return has_user_len and has_stack


def _detect_pool_bof(text):
    if 'ExAllocatePool' not in text:
        return False
    return _has_any(text, ['memcpy', 'RtlCopyMemory']) and _has_any(text, [
        'InputBufferLength', 'OutputBufferLength',
    ])


def _detect_null_deref(text):
    """ExAllocatePool* result deref without NULL check."""
    m = re.search(r'(?:Ex)?AllocatePool\w*\([^)]*\)', text)
    if not m:
        return False
    tail = text[m.end(): m.end() + 600]
    if not re.search(r'\*\s*\w+|->\w+', tail):
        return False
    return not re.search(r'if\s*\(\s*!?\w+\s*(?:==|!=)?\s*(?:0|NULL|nullptr)?\s*\)', tail[:200])


def _detect_token_swap_enabler(text):
    if 'PsLookupProcessByProcessId' not in text and 'PsGetCurrentProcess' not in text:
        return False
    return any(off in text for off in _TOKEN_OFFSETS)


def _detect_type_confusion(text):
    if 'ObReferenceObjectByHandle' not in text:
        return False
    # 3rd arg ObjectType - if literal 0 / NULL, no type enforcement
    return bool(re.search(r'ObReferenceObjectByHandle\s*\([^,]+,[^,]+,\s*(?:0|NULL|nullptr)\s*,', text))


def _detect_ioring(text):
    return [n for n in _IORING_NAMES if n in text]


def _detect_double_fetch(text):
    """Same user pointer expression dereferenced 2+ times in different statements."""
    refs = re.findall(r'\*\s*\(\s*(?:int\d*_t|void)\s*\*\s*\)\s*(\*\s*\([^)]+SystemBuffer[^)]*\))', text)
    if len(refs) < 2:
        return False
    return len(set(refs)) < len(refs)


def _detect_msr_rw(text):
    return '__rdmsr' in text or '__wrmsr' in text or 'Rdmsr' in text or 'Wrmsr' in text


def _detect_port_io(text):
    return ('__in_' in text or '__out_' in text or
            'READ_PORT_' in text or 'WRITE_PORT_' in text)


def _detect_phys_mem(text):
    return ('MmMapIoSpace' in text or 'MmMapIoSpaceEx' in text or
            'MmGetPhysicalAddress' in text or 'MmCopyMemory' in text or
            '\\Device\\PhysicalMemory' in text)


def _detect_cr_access(text):
    return ('__readcr' in text or '__writecr' in text or
            '__readdr' in text or '__writedr' in text)


def _detect_pci_config(text):
    return 'HalGetBusData' in text or 'HalSetBusData' in text


def _detect_ring0_exec(text):
    """Capcom-style: user-supplied function pointer called in kernel ctx."""
    return bool(re.search(r'\(\s*\*\s*\(\s*\w+\s*\*\s*\)\s*SystemBuffer\s*\)\s*\(', text))


def _detect_uninit_leak(text):
    """ExAllocatePool (not zero variant) -> memcpy to user without RtlZeroMemory."""
    has_nonzero_alloc = bool(re.search(r'ExAllocatePool(?:WithTag)?\b', text)) and \
                        'ExAllocatePool2' not in text
    if not has_nonzero_alloc:
        return False
    if 'RtlZeroMemory' in text or 'memset' in text:
        return False
    return _has_any(text, ['SystemBuffer', 'UserBuffer', 'Type3InputBuffer'])


_DETECTORS = [
    ('Write-What-Where',          'CRITICAL', _detect_write_what_where),
    ('Arbitrary Kernel Read',     'CRITICAL', _detect_arb_read),
    ('MSR Read/Write Primitive',  'CRITICAL', _detect_msr_rw),
    ('Port IO Primitive',         'CRITICAL', _detect_port_io),
    ('Physical Memory Map',       'CRITICAL', _detect_phys_mem),
    ('Control/Debug Register Access', 'CRITICAL', _detect_cr_access),
    ('Ring-0 Exec (Capcom-style)','CRITICAL', _detect_ring0_exec),
    ('PCI Config Space Access',   'HIGH',     _detect_pci_config),
    ('Stack Buffer Overflow',     'HIGH',     _detect_stack_bof),
    ('Pool Buffer Overflow',      'HIGH',     _detect_pool_bof),
    ('NULL Pointer Deref',        'MEDIUM',   _detect_null_deref),
    ('Token-Swap Primitive',      'CRITICAL', _detect_token_swap_enabler),
    ('Type Confusion (Object)',   'HIGH',     _detect_type_confusion),
    ('Double-Fetch TOCTOU',       'HIGH',     _detect_double_fetch),
    ('Uninitialized Pool Leak',   'MEDIUM',   _detect_uninit_leak),
]


def find_exploit_primitives(bv: BinaryView):
    lines = [
        "=== Windows Kernel Exploit Primitive Report ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-primitives.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    dispatchers = _find_dispatch_routines(bv)
    if not dispatchers:
        emit("[-] No IOCTL dispatcher found. Falling back to whole-binary scan.")
        whole = ""
        for f in bv.functions:
            whole += "\n" + get_hlil_text(f)
        for name, sev, det in _DETECTORS:
            if det(whole):
                emit("    [{}] {} (binary-wide)".format(sev, name))
        _emit_ioring_imports(bv, emit)
        _save(report_path, lines, emit)
        return

    emit("[>] Dispatchers: {}".format(", ".join(d.name for d in dispatchers)))
    emit("")

    findings_by_ioctl = {}
    for df in dispatchers:
        branches = _ioctl_branches_for_dispatcher(df)
        by_code = {}
        for code, instrs, _addr in branches:
            by_code.setdefault(code, []).extend(instrs)
        for code, instrs in by_code.items():
            text = _deep_text(bv, instrs, max_depth=3)
            hits = []
            for name, sev, det in _DETECTORS:
                try:
                    if det(text):
                        hits.append((sev, name))
                except Exception as e:
                    log_warn("detector {} failed: {}".format(name, e))
            ioring = _detect_ioring(text)
            for n in ioring:
                hits.append(('HIGH', 'IORING reference: ' + n))
            for sev, label in _detect_name_hints(bv, instrs):
                hits.append((sev, label))
            # Dedup
            hits = list(dict.fromkeys(hits))
            if hits:
                d = _ctl_decode(code)
                method = METHOD_MAP.get(d['method'], str(d['method']))
                callees = sorted({_resolve_callee_name(bv, c)
                                  for c in _branch_callees(bv, instrs)})
                findings_by_ioctl[(df.name, code)] = (method, hits, callees)

    if not findings_by_ioctl:
        emit("[+] No primitives detected in handlers.")
    else:
        emit("[>] Primitives per IOCTL handler...")
        for (dname, code), (method, hits, callees) in sorted(findings_by_ioctl.items()):
            emit("  IOCTL 0x{:08X} ({}) in {}".format(code, method, dname))
            for sev, name in sorted(hits):
                emit("    [{}] {}".format(sev, name))
            if callees:
                emit("    calls: {}".format(", ".join(callees[:8])))

    _emit_ioring_imports(bv, emit)

    # Probe missing per dispatcher (METHOD_NEITHER is dangerous without probe)
    emit("")
    emit("[>] Probe coverage on METHOD_NEITHER IOCTLs...")
    for df in dispatchers:
        dt = get_hlil_text(df)
        has_probe = any(p in dt for p in _PROBE_NAMES)
        neither = False
        for code, _i, _a in _ioctl_branches_for_dispatcher(df):
            if _ctl_decode(code)['method'] == 3:
                neither = True
                break
        if neither and not has_probe:
            emit("    [CRITICAL] {} dispatches METHOD_NEITHER without ProbeForRead/Write".format(df.name))

    _save(report_path, lines, emit)


def _emit_ioring_imports(bv, emit):
    found = []
    for sym in bv.get_symbols():
        if any(n in sym.name for n in _IORING_NAMES):
            found.append(sym.name)
    if found:
        emit("")
        emit("[>] IORING symbols present (read knifecoat.com / windows-internals.com):")
        for n in sorted(set(found)):
            emit("    {}".format(n))


def _save(report_path, lines, emit):
    try:
        with open(report_path, 'w') as f:
            f.write("\n".join(lines))
        emit("[+] Report saved to: {}".format(report_path))
    except Exception as e:
        log_warn("Could not write primitive report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\Exploit Primitive Finder",
    "Detect arb-R/W, write-what-where, token swap, IORING, double-fetch primitives",
    find_exploit_primitives,
)
