"""
Binary Ninja plugin - Find and decode Linux kernel driver IOCTL codes.

Detection strategy:
  S1 (name):     functions whose name contains 'ioctl'
  S2 (fops):     find unlocked_ioctl / compat_ioctl callers via file_operations
                 symbol scan (looks for data symbols with ioctl-named entries)
  S3 (sig):      functions that switch / compare on their second parameter
                 against values that decode as plausible Linux IOCTL codes
  S4 (fallback): if nothing found, scan ALL functions for plausible IOCTL constants

Linux _IOC layout (x86_64 / arm64):
  bits [ 0: 7] = nr   (command number, 0-255)
  bits [ 8:15] = type (driver magic, often printable ASCII)
  bits [16:29] = size (payload sizeof, 0 for _IO)
  bits [30:31] = dir  (0=_IO 1=_IOW 2=_IOR 3=_IOWR)

Macro equivalents:
  _IO(type,nr)         -> dir=0, size=0
  _IOW(type,nr,T)      -> dir=1, size=sizeof(T)
  _IOR(type,nr,T)      -> dir=2, size=sizeof(T)
  _IOWR(type,nr,T)     -> dir=3, size=sizeof(T)
"""

import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, plausible_linux_ioctl, format_ioctl, decode_linux_ioctl

# ---------------------------------------------------------------------------
# Regex patterns for IOCTL constants in HLIL text
# ---------------------------------------------------------------------------
_IOCTL_PATS = [
    r'case\s+0x([0-9A-Fa-f]+)\s*:',
    r'==\s*0x([0-9A-Fa-f]+)',
    r'!=\s*0x([0-9A-Fa-f]+)',
    r'arg[01]\s*==\s*0x([0-9A-Fa-f]+)',
    r'\bcmd\b\s*==\s*0x([0-9A-Fa-f]+)',
]

# Name hints for IOCTL dispatch functions
_IOCTL_NAME_HINTS = [
    'ioctl', 'unlocked_ioctl', 'compat_ioctl',
    'ioctl_handler', 'ioctl_dispatch', 'cmd_handler',
    'device_control',
]


def _extract_ioctls_from_text(hlil_text):
    """Return sorted list of plausible IOCTL codes found in HLIL text."""
    codes = set()
    normalized = re.sub(r'\s+', ' ', hlil_text)
    for pat in _IOCTL_PATS:
        for m in re.finditer(pat, normalized, re.IGNORECASE):
            try:
                val = int(m.group(1), 16)
                if plausible_linux_ioctl(val):
                    codes.add(val & 0xFFFFFFFF)
            except Exception:
                pass
    return sorted(codes)


def _analyze_ioctl_handler(hlil_text, code):
    """
    Best-effort extraction of per-IOCTL handler details:
    - copy_from_user / copy_to_user presence
    - size checks (== 0x... constants in range 1..4096)
    - called kernel APIs
    - whether access_ok / capable is nearby
    """
    result = {
        'code':           hex(code),
        'has_copy_from':  False,
        'has_copy_to':    False,
        'has_access_ok':  False,
        'has_capable':    False,
        'size_checks':    [],
        'kernel_calls':   [],
    }

    code_hex = hex(code)
    # Try to isolate the case block for this IOCTL
    block_pat = r'(?:case\s+{0}|==\s*{0})[^{{]*{{([^}}]*)'.format(re.escape(code_hex))
    m = re.search(block_pat, hlil_text, re.DOTALL | re.IGNORECASE)
    block = m.group(1) if m else hlil_text

    result['has_copy_from'] = 'copy_from_user' in block or '__copy_from_user' in block
    result['has_copy_to']   = 'copy_to_user' in block or '__copy_to_user' in block
    result['has_access_ok'] = 'access_ok' in block
    result['has_capable']   = 'capable(' in block or 'ns_capable(' in block

    for sz in re.findall(r'==\s*0x([0-9a-fA-F]+)', block):
        try:
            v = int(sz, 16)
            if 1 <= v <= 0x10000:
                result['size_checks'].append(v)
        except Exception:
            pass

    known_prefixes = ('kmalloc', 'kzalloc', 'kfree', 'vmalloc', 'copy_from_user',
                      'copy_to_user', 'get_user', 'put_user', 'memcpy', 'memset',
                      'capable', 'printk', 'mutex_lock', 'spin_lock', 'remap_pfn')
    for call in re.findall(r'([a-z_][a-z0-9_]*)\s*\(', block, re.IGNORECASE):
        if any(call.lower().startswith(p) for p in known_prefixes):
            result['kernel_calls'].append(call)

    return result


def _print_ioctl(idx, code, analysis):
    d = decode_linux_ioctl(code)
    type_ch = chr(d['type']) if 0x20 <= d['type'] <= 0x7E else '?'
    log_info("\n  [{:02d}] {}".format(idx, format_ioctl(code)))
    flags = []
    if not analysis['has_copy_from'] and not analysis['has_copy_to']:
        flags.append("no user copy detected")
    if analysis['has_copy_from'] and not analysis['has_access_ok']:
        flags.append("WARN: copy_from_user without access_ok")
    if not analysis['has_capable']:
        flags.append("no capability check")
    if analysis['size_checks']:
        flags.append("size checks: {}".format(', '.join(hex(x) for x in analysis['size_checks'])))
    if analysis['kernel_calls']:
        flags.append("calls: {}".format(', '.join(sorted(set(analysis['kernel_calls'])))))
    for f in flags:
        log_info("        {}".format(f))


def _find_ioctl_handlers(bv: BinaryView):
    handlers = []
    seen = set()

    # S1: name heuristic
    for func in bv.functions:
        fl = func.name.lower()
        if any(h in fl for h in _IOCTL_NAME_HINTS) and func.start not in seen:
            seen.add(func.start)
            handlers.append(func)
            log_info("[*] [S1] IOCTL handler by name: {} (0x{:x})".format(func.name, func.start))

    # S2: data symbols with 'ioctl' in name pointing to functions
    for sym in bv.get_symbols():
        if 'ioctl' in sym.name.lower():
            f = bv.get_function_at(sym.address)
            if f and f.start not in seen:
                seen.add(f.start)
                handlers.append(f)
                log_info("[*] [S2] IOCTL handler via symbol '{}': {} (0x{:x})".format(
                    sym.name, f.name, f.start))

    # S3: functions that compare second parameter against plausible IOCTL codes
    if not handlers:
        log_info("[*] [S3] Scanning all functions for IOCTL code switch patterns...")
        for func in bv.functions:
            if func.start in seen:
                continue
            dt = get_hlil_text(func)
            if _extract_ioctls_from_text(dt):
                seen.add(func.start)
                handlers.append(func)
                log_info("[*] [S3] IOCTL handler by constant pattern: {} (0x{:x})".format(
                    func.name, func.start))

    return handlers


def find_ioctls(bv: BinaryView):
    log_info("[+] Linux IOCTL enumeration: {}".format(bv.file.filename))

    handlers = _find_ioctl_handlers(bv)
    if not handlers:
        log_warn("[-] No IOCTL handlers found via any strategy.")
        log_warn("    Consider manually identifying unlocked_ioctl from file_operations struct.")
        return

    log_info("[+] Found {} IOCTL handler(s)".format(len(handlers)))
    total = 0

    for handler in handlers:
        log_info("\n[*] Analyzing: {} at 0x{:x}".format(handler.name, handler.start))
        hlil_text = get_hlil_text(handler)
        codes = _extract_ioctls_from_text(hlil_text)

        if not codes:
            log_warn("    [-] No plausible IOCTL codes found in HLIL")
            log_info("    Possible reasons: codes are defined-constant names (not hex literals),")
            log_info("    or handler delegates to sub-functions. Check callees manually.")
            continue

        log_info("    Found {} IOCTL code(s):".format(len(codes)))
        for code in codes:
            total += 1
            analysis = _analyze_ioctl_handler(hlil_text, code)
            _print_ioctl(total, code, analysis)

    log_info("\n[+] Total: {} IOCTL code(s) across {} handler(s)".format(total, len(handlers)))


PluginCommand.register(
    "Linux Driver Analysis\\Find IOCTLs",
    "Find and decode Linux driver IOCTL codes (_IOC dir/type/nr/size)",
    find_ioctls
)
