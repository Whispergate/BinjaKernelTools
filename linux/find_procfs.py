"""
Binary Ninja plugin - Find Linux kernel procfs / sysfs / debugfs interfaces.

These pseudo-filesystem interfaces accept user-controlled data via write/store
callbacks and are a common source of vulnerabilities:

  1. Uncapped count in write handler — copy_from_user(kbuf, user, count) where count
     is not bounded against kbuf size → stack/heap overflow
  2. kmalloc(count) in write handler — user controls allocation size → integer overflow
     or allocation of a huge buffer
  3. Missing kstrtol/kstrtoul return value check — subsequent logic uses garbage value
  4. Sysfs .store() trusting count without PAGE_SIZE cap
  5. debugfs handlers with missing access_ok / capability check
  6. Uninitialized stack var passed to seq_show/seq_printf → info leak

Detection targets:
  S1: proc_create / proc_create_data / proc_create_net callers
  S2: sysfs_create_file / device_create_file / class_create_file callers
  S3: debugfs_create_file / debugfs_create_u32 / debugfs_create_blob callers
  S4: Functions named *_write / *_store / *_proc_write matching callback signatures
  S5: seq_file show() callbacks via seq_open callers
"""

import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers, nearby_has_check, looks_user_driven

# ---------------------------------------------------------------------------
# Registration APIs
# ---------------------------------------------------------------------------

_PROC_APIS     = ['proc_create', 'proc_create_data', 'proc_create_net',
                  'proc_create_net_data', 'proc_mkdir', 'proc_symlink',
                  'create_proc_entry']
_SYSFS_APIS    = ['sysfs_create_file', 'device_create_file', 'class_create_file',
                  'bus_create_file', 'driver_create_file', 'sysfs_create_group']
_DEBUGFS_APIS  = ['debugfs_create_file', 'debugfs_create_u8', 'debugfs_create_u16',
                  'debugfs_create_u32', 'debugfs_create_u64', 'debugfs_create_blob',
                  'debugfs_create_bool', 'debugfs_create_str']
_SEQ_APIS      = ['seq_open', 'single_open', 'single_open_net']

# Write/store handler keywords for name-based discovery
_WRITE_NAME_HINTS = ['_write', '_store', '_proc_write', '_set', 'write_proc']
_SHOW_NAME_HINTS  = ['_show', '_read', '_seq_show', 'read_proc']

# Safe bounded copy patterns
_SAFE_SIZE_CHECKS = [
    '> sizeof', '> PAGE_SIZE', '>= sizeof', '> MAX', '> BUF',
    '< sizeof', '<= sizeof', 'if (count', 'if (len', 'min(', 'min_t(',
    'clamp(', 'clamp_val(', 'strnlen',
]


# ---------------------------------------------------------------------------
# Callback resolution
# ---------------------------------------------------------------------------

def _resolve_fops_from_call(bv, func, ref_addr, fops_arg_index):
    """
    Try to find file_operations or proc_ops struct addr from call argument,
    then extract .write pointer.
    """
    try:
        mlil = func.mlil
        if not mlil:
            return None
        idx = mlil.get_instruction_start(ref_addr)
        if idx is None:
            return None
        instr = mlil[idx]
        params = list(getattr(instr, 'params', []))
        if fops_arg_index < len(params):
            try:
                struct_addr = params[fops_arg_index].constant
                # file_operations.write is at +0x18; proc_ops.proc_write at +0x20
                for write_offset in (0x18, 0x20, 0x28):
                    ptr = bv.read_int(struct_addr + write_offset, 8, False)
                    if ptr:
                        f = bv.get_function_at(ptr)
                        if f:
                            return f
            except Exception:
                pass
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Write handler vulnerability checks
# ---------------------------------------------------------------------------

_KSTR_APIS = ['kstrtol', 'kstrtoul', 'kstrtoint', 'kstrtoull', 'kstrtobool',
              'kstrtou8', 'kstrtou16', 'kstrtou32', 'kstrtou64']

def _check_write_handler(bv, func, source_label):
    dt = get_hlil_text(func)
    fn = func.name
    issues = []

    # Issue 1: copy_from_user without size cap
    if 'copy_from_user' in dt or '__copy_from_user' in dt:
        idx = dt.find('copy_from_user')
        if not nearby_has_check(dt, idx, _SAFE_SIZE_CHECKS, window=400):
            issues.append("HIGH: copy_from_user — count not bounded (stack/heap overflow if kbuf is fixed-size)")

    # Issue 2: kmalloc(count) where count = third parameter of write handler
    # write(file*, user_buf, count, loff_t*) — count is arg2
    for api in ['kmalloc', 'kzalloc', '__kmalloc']:
        if api not in dt:
            continue
        idx = dt.find(api)
        alloc_window = dt[idx:idx + 200]
        # If the alloc size looks like it might be the raw count parameter
        if re.search(r'{}[\s(]+(?:arg2|count|len|size)\b'.format(re.escape(api)), alloc_window) or \
           re.search(r'{}[\s(]+\w+\s*[+\-\*]'.format(re.escape(api)), alloc_window):
            if not nearby_has_check(dt, idx, _SAFE_SIZE_CHECKS, window=300):
                issues.append("HIGH: {} — allocation may be sized from raw user count without bounds check".format(api))

    # Issue 3: kstrto* return value not checked
    for api in _KSTR_APIS:
        if api not in dt:
            continue
        for m in re.finditer(r'([^\n]*' + re.escape(api) + r'[^\n]*)', dt):
            line = m.group(1)
            if not re.search(r'\w+\s*=\s*' + re.escape(api), line) and \
               not re.search(r'if\s*\(' + re.escape(api), line):
                issues.append("MEDIUM: {} return value not checked — subsequent logic may use stale value".format(api))
                break

    # Issue 4: missing capability check for privileged write
    has_cap = 'capable(' in dt or 'ns_capable(' in dt
    if not has_cap:
        issues.append("INFO: No capability check — any user with write permission can trigger handler")

    # Issue 5: PAGE_SIZE not used as cap in sysfs .store (max count is PAGE_SIZE in sysfs)
    is_sysfs_store = 'store' in fn.lower() or 'sysfs' in source_label.lower()
    if is_sysfs_store and 'PAGE_SIZE' not in dt and 'copy_from_user' in dt:
        issues.append("MEDIUM: sysfs .store() does not cap count at PAGE_SIZE")

    if issues:
        log_info("\n  [Write handler] {} (0x{:x}) — from {}".format(fn, func.start, source_label))
        for issue in issues:
            log_info("    [!] {}".format(issue))
    else:
        log_info("  [Write handler] {} (0x{:x}) — no obvious issues".format(fn, func.start))


def _check_show_handler(bv, func, source_label):
    """Check seq_file show handlers for kernel pointer / info leaks."""
    dt = get_hlil_text(func)
    fn = func.name
    issues = []

    # seq_printf with %p or user-controlled format string
    if 'seq_printf' in dt or 'seq_puts' in dt:
        if re.search(r'seq_printf\s*\([^,]+,\s*\w+\s*[^"]\)', dt):
            issues.append("MEDIUM: seq_printf with non-literal format string — potential format string injection")
        if re.search(r'%p[^KkS]', dt):
            issues.append("MEDIUM: seq_printf with %%p — leaks kernel virtual address to unprivileged reader")

    if issues:
        log_info("\n  [Show handler] {} (0x{:x}) — from {}".format(fn, func.start, source_label))
        for issue in issues:
            log_info("    [!] {}".format(issue))


# ---------------------------------------------------------------------------
# Main analysis passes
# ---------------------------------------------------------------------------

def _scan_proc_create(bv):
    log_info("[*] Scanning proc_create / proc_create_data callers...")
    for api in _PROC_APIS:
        for func, ref_addr in get_callers(bv, api):
            log_info("[*] {} in {} at 0x{:x}".format(api, func.name, ref_addr))
            # proc_create(name, mode, parent, fops) — fops is arg3
            write_fn = _resolve_fops_from_call(bv, func, ref_addr, 3)
            if write_fn:
                log_info("  [+] Resolved write handler: {} (0x{:x})".format(write_fn.name, write_fn.start))
                _check_write_handler(bv, write_fn, api)
            else:
                log_info("  [-] Could not statically resolve fops write pointer")


def _scan_sysfs(bv):
    log_info("[*] Scanning sysfs / device_create_file callers...")
    for api in _SYSFS_APIS:
        for func, ref_addr in get_callers(bv, api):
            log_info("[*] {} in {} at 0x{:x}".format(api, func.name, ref_addr))


def _scan_debugfs(bv):
    log_info("[*] Scanning debugfs_create_file callers...")
    for func, ref_addr in get_callers(bv, 'debugfs_create_file'):
        log_info("[*] debugfs_create_file in {} at 0x{:x}".format(func.name, ref_addr))
        write_fn = _resolve_fops_from_call(bv, func, ref_addr, 4)
        if write_fn:
            log_info("  [+] Resolved write handler: {} (0x{:x})".format(write_fn.name, write_fn.start))
            _check_write_handler(bv, write_fn, 'debugfs')
        else:
            log_info("  [-] Could not statically resolve fops write pointer")


def _scan_by_name(bv):
    log_info("[*] Scanning functions by name for write/store handlers...")
    for func in bv.functions:
        fn_lower = func.name.lower()
        if any(hint in fn_lower for hint in _WRITE_NAME_HINTS):
            dt = get_hlil_text(func)
            # Confirm this actually copies from user — otherwise not a user-driven handler
            if looks_user_driven(dt):
                _check_write_handler(bv, func, "name heuristic")
        elif any(hint in fn_lower for hint in _SHOW_NAME_HINTS):
            _check_show_handler(bv, func, "name heuristic")


# ---------------------------------------------------------------------------
# Plugin entry
# ---------------------------------------------------------------------------

def find_procfs_interfaces(bv: BinaryView):
    log_info("[+] Linux procfs/sysfs/debugfs interface analysis: {}".format(bv.file.filename))

    _scan_proc_create(bv)
    _scan_sysfs(bv)
    _scan_debugfs(bv)
    _scan_by_name(bv)

    log_info("[+] procfs/sysfs/debugfs analysis complete.")


PluginCommand.register(
    "Linux Driver Analysis\\Find Procfs/Sysfs Interfaces",
    "Find procfs/sysfs/debugfs write handlers and detect missing bounds checks",
    find_procfs_interfaces
)
