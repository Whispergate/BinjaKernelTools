"""
Binary Ninja plugin - Find Linux kernel netlink and generic netlink interfaces.

Netlink is a high-value attack surface: many drivers expose sockets for user-kernel
IPC with weaker validation discipline than syscall paths.

Vulnerability classes unique to netlink:
  1. Missing nlmsg_ok() before payload access - OOB read on truncated message
  2. nla_parse() / nla_parse_nested() with NULL policy - no attr type/length validation
  3. Attribute accessed (nla_get_*) without prior validation in nla_policy table
  4. Missing capability check (CAP_NET_ADMIN / CAP_SYS_ADMIN) in privileged handler
  5. nlmsg_len field trusted directly for pointer arithmetic without bounds check
  6. nla_data() result dereferenced without length check after nla_parse NULL-policy
  7. Missing error return check on nla_parse - stale/NULL tb[] entries used

Detection targets:
  S1: netlink_kernel_create - classic netlink; locate input() callback
  S2: genl_register_family / __genl_register_family - generic netlink family reg
  S3: genl_ops / genl_small_ops - find .doit / .dumpit handler functions
  S4: nla_parse / nla_parse_nested callers - flag NULL policy argument
  S5: nlmsg_hdr() callers - check for missing nlmsg_ok() near each call site
"""

import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers, nearby_has_check

# ---------------------------------------------------------------------------
# Known netlink registration APIs
# ---------------------------------------------------------------------------

_CLASSIC_NL_APIS  = ['netlink_kernel_create', '__netlink_kernel_create']
_GENL_APIS        = ['genl_register_family', '__genl_register_family',
                     'genl_register_family_with_ops']
_NLA_PARSE_APIS   = ['nla_parse', 'nla_parse_nested', 'nla_parse_nested_deprecated',
                     '__nla_parse', 'nlmsg_parse', 'nlmsg_parse_deprecated']
_CAPABILITY_APIS  = ['capable(', 'ns_capable(', 'netlink_capable(', 'netlink_net_capable(']
_NLMSG_VALIDATE   = ['nlmsg_ok', 'nlmsg_len', 'nlmsg_validate']

# Attribute accessor functions - all assume the attribute was validated by policy
_NLA_GET_APIS = [
    'nla_get_u8', 'nla_get_u16', 'nla_get_u32', 'nla_get_u64',
    'nla_get_s8', 'nla_get_s16', 'nla_get_s32', 'nla_get_s64',
    'nla_get_be16', 'nla_get_be32', 'nla_get_be64',
    'nla_data', 'nla_len',
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_capability_check(dt):
    return any(c in dt for c in _CAPABILITY_APIS)


def _null_policy_nla_parse(hlil_text):
    """
    Detect nla_parse(..., NULL, NULL) - sixth and seventh args both NULL
    meaning no policy validation and no extack error reporting.
    HLIL renders this as: nla_parse(..., 0, 0) or nla_parse(..., NULL, NULL)
    """
    # Match: nla_parse(anything, then two trailing NULL/0 args)
    patterns = [
        r'nla_parse\s*\([^)]*,\s*(?:NULL|0)\s*,\s*(?:NULL|0)\s*\)',
        r'nla_parse_nested\s*\([^)]*,\s*(?:NULL|0)\s*,\s*(?:NULL|0)\s*\)',
        r'nlmsg_parse\s*\([^)]*,\s*(?:NULL|0)\s*,\s*(?:NULL|0)\s*\)',
    ]
    for p in patterns:
        if re.search(p, hlil_text, re.IGNORECASE):
            return True
    return False


def _resolve_callback(bv, func, ref_addr, param_index):
    """Try to get a function pointer constant from MLIL call at ref_addr."""
    try:
        mlil = func.mlil
        if not mlil:
            return None
        idx = mlil.get_instruction_start(ref_addr)
        if idx is None:
            return None
        instr = mlil[idx]
        params = list(getattr(instr, 'params', []))
        if param_index < len(params):
            try:
                addr = params[param_index].constant
                return bv.get_function_at(addr)
            except Exception:
                pass
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Analysis passes
# ---------------------------------------------------------------------------

def _analyze_handler(bv, handler_func, source_label):
    """Run all vulnerability checks on a resolved netlink message handler."""
    if not handler_func:
        return
    dt = get_hlil_text(handler_func)
    fn = handler_func.name
    issues = []

    # Check 1: missing nlmsg_ok / nlmsg_validate before payload access
    accesses_payload = 'nlmsg_data' in dt or 'nlmsg_hdr' in dt or 'genlmsg_data' in dt
    if accesses_payload and not any(v in dt for v in _NLMSG_VALIDATE):
        issues.append("MISSING nlmsg_ok() - payload accessed without message length validation")

    # Check 2: nla_parse with NULL policy
    if _null_policy_nla_parse(dt):
        issues.append("nla_parse() with NULL policy - no attribute type/length enforcement")

    # Check 3: nla_get_* used but nla_parse result not checked
    uses_nla_get = any(a in dt for a in _NLA_GET_APIS)
    if uses_nla_get and 'nla_parse' in dt:
        if 'if (' not in dt[dt.find('nla_parse'):dt.find('nla_parse') + 300]:
            issues.append("nla_parse return value unchecked - tb[] entries may be NULL before nla_get_*")

    # Check 4: missing capability check
    if not _has_capability_check(dt):
        issues.append("No capability check (CAP_NET_ADMIN / netlink_capable) in handler")

    # Check 5: nlmsg_len / nla_len directly trusted for copy/memcpy sizing
    if ('nlmsg_len' in dt or 'nla_len' in dt) and 'memcpy' in dt:
        idx = dt.find('memcpy')
        nearby = dt[max(0, idx - 200):idx + 200]
        if 'nlmsg_len' in nearby or 'nla_len' in nearby:
            issues.append("memcpy sized by nlmsg_len/nla_len - verify length validated before copy")

    if issues:
        log_info("\n  Handler: {} (0x{:x}) - from {}".format(fn, handler_func.start, source_label))
        for issue in issues:
            log_info("    [!] {}".format(issue))
    else:
        log_info("  Handler: {} (0x{:x}) - no obvious issues".format(fn, handler_func.start))


def _find_classic_netlink(bv):
    log_info("[*] Scanning for classic netlink sockets (netlink_kernel_create)...")
    for api in _CLASSIC_NL_APIS:
        for func, ref_addr in get_callers(bv, api):
            log_info("[*] {} in {} at 0x{:x}".format(api, func.name, ref_addr))
            # input() callback is the 3rd argument (index 2) of netlink_kernel_cfg struct
            # or the 3rd arg in older 2-arg style. Try to find via name scan in caller HLIL.
            dt = get_hlil_text(func)
            # Look for function pointer assignments nearby
            for m in re.finditer(r'\.input\s*=\s*(?:&\s*)?([A-Za-z_]\w*)', dt):
                cb_name = m.group(1)
                syms = bv.get_symbols_by_name(cb_name)
                if syms:
                    cb = bv.get_function_at(syms[0].address)
                    if cb:
                        log_info("  [+] input() callback: {} (0x{:x})".format(cb.name, cb.start))
                        _analyze_handler(bv, cb, "netlink_kernel_create.input")


def _find_generic_netlink(bv):
    log_info("[*] Scanning for generic netlink families (genl_register_family)...")
    for api in _GENL_APIS:
        for func, ref_addr in get_callers(bv, api):
            log_info("[*] {} in {} at 0x{:x}".format(api, func.name, ref_addr))
            dt = get_hlil_text(func)
            # genl_ops handlers appear as .doit / .dumpit assignments
            for field in ('doit', 'dumpit', 'start'):
                for m in re.finditer(r'\.{}\s*=\s*(?:&\s*)?([A-Za-z_]\w*)'.format(field), dt):
                    cb_name = m.group(1)
                    syms = bv.get_symbols_by_name(cb_name)
                    if syms:
                        cb = bv.get_function_at(syms[0].address)
                        if cb:
                            log_info("  [+] genl_ops.{}: {} (0x{:x})".format(field, cb.name, cb.start))
                            _analyze_handler(bv, cb, "genl_ops.{}".format(field))


def _find_nla_parse_callers(bv):
    log_info("[*] Scanning nla_parse / nlmsg_parse callers for NULL policy...")
    for api in _NLA_PARSE_APIS:
        for func, ref_addr in get_callers(bv, api):
            dt = get_hlil_text(func)
            if _null_policy_nla_parse(dt):
                log_info("[!!!] HIGH: {} in {} at 0x{:x} - NULL nla_policy, no attribute validation".format(
                    api, func.name, ref_addr))
            # Also check nla_get_* used after a potentially-NULL tb[] entry
            if any(a in dt for a in _NLA_GET_APIS):
                idx = dt.find(api)
                post = dt[idx:idx + 500]
                if not re.search(r'if\s*\(.*tb\[', post) and not re.search(r'tb\[.*\]\s*!=', post):
                    log_info("[!]  MEDIUM: {} caller {} - tb[] entries not NULL-checked before nla_get_*".format(
                        api, func.name))


def _find_nlmsg_hdr_callers(bv):
    log_info("[*] Scanning nlmsg_hdr() callers for missing nlmsg_ok()...")
    for func, ref_addr in get_callers(bv, 'nlmsg_hdr'):
        dt = get_hlil_text(func)
        if not any(v in dt for v in _NLMSG_VALIDATE):
            log_info("[!!!] HIGH: {} (0x{:x}) - nlmsg_hdr() used without nlmsg_ok() validation".format(
                func.name, func.start))


# ---------------------------------------------------------------------------
# Plugin entry
# ---------------------------------------------------------------------------

def find_netlink(bv: BinaryView):
    log_info("[+] Linux netlink interface analysis: {}".format(bv.file.filename))

    _find_classic_netlink(bv)
    _find_generic_netlink(bv)
    _find_nla_parse_callers(bv)
    _find_nlmsg_hdr_callers(bv)

    # Scan all functions with genl / netlink in their name for quick vuln check
    log_info("[*] Scanning netlink-named functions directly...")
    for func in bv.functions:
        fn = func.name.lower()
        if any(k in fn for k in ('netlink', 'genl_', '_nl_', 'nla_', 'nlmsg')):
            _analyze_handler(bv, func, "name pattern")

    log_info("[+] Netlink analysis complete.")


PluginCommand.register(
    "Linux Driver Analysis\\Find Netlink Interfaces",
    "Find netlink/generic-netlink handlers and detect missing attribute validation",
    find_netlink
)
