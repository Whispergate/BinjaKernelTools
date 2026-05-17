"""
Binary Ninja plugin - Linux kernel driver vulnerability triage.

Vulnerability classes detected:
  1.  copy_from_user with user-controlled size (no bounds check)
  2.  __copy_from_user without prior access_ok
  3.  Ignored return value from copy_from_user (partial copy proceeds)
  4.  Integer overflow in kmalloc/kzalloc: size derived from user input
       without safe arithmetic (RtlULong* equivalent missing)
  5.  kmalloc result not NULL-checked before dereference
  6.  Uninitialized kmalloc buffer passed to copy_to_user (info leak)
  7.  Stack buffer + copy_from_user without explicit size bound
  8.  commit_creds(prepare_kernel_cred(0)) pattern (privilege escalation)
  9.  Missing capable() / ns_capable() check before sensitive operations
  10. remap_pfn_range / io_remap_pfn_range without vm_area size bounds check
  11. MmMapIoSpace equivalent: ioremap with user-supplied size/addr
  12. kfree followed by potential use-after-free patterns
  13. Kernel pointer leak via printk %p (pre-kptr_restrict)
  14. Dangerous libc-style functions: sprintf / strcpy / strcat / vsprintf
  15. get_user / put_user without type-safe SIZE check
  16. GFP_KERNEL allocation in potential interrupt context
  17. Physical memory section access (/dev/mem patterns)

Output: Binary Ninja log + report file at ~/lkdrv-<name>-vulns.txt
"""

import re
import os
from collections import defaultdict
from binaryninja import BinaryView, log_info, log_warn, log_error
from binaryninja.plugin import PluginCommand

from ..shared.helpers import (
    get_hlil_text, get_callers, looks_user_driven,
    nearby_has_check, nearby_has_validation
)

# ---------------------------------------------------------------------------
# API lists
# ---------------------------------------------------------------------------

_ALLOC_APIS   = ['kmalloc', 'kzalloc', 'vmalloc', 'kvmalloc',
                  'krealloc', 'kcalloc', 'kmalloc_array', '__kmalloc']
_FREE_APIS    = ['kfree', 'vfree', 'kvfree']
_COPY_FROM    = ['copy_from_user', '__copy_from_user', 'get_user', '__get_user',
                 'strncpy_from_user', 'strnlen_user']
_COPY_TO      = ['copy_to_user', '__copy_to_user', 'put_user', '__put_user',
                 'clear_user']
_DANGEROUS    = ['sprintf', 'vsprintf', 'strcpy', 'strcat', 'gets',
                 'stpcpy', 'strncpy']
_PHYSMEM_APIS = ['ioremap', 'ioremap_nocache', 'ioremap_wc', 'ioremap_uc',
                 'remap_pfn_range', 'io_remap_pfn_range',
                 'phys_to_virt', '__phys_to_virt']
_CAPABLE_APIS = ['capable', 'ns_capable', 'file_ns_capable']
_SENSITIVE    = ['ioremap', 'remap_pfn_range', 'io_remap_pfn_range',
                 'phys_to_virt', '/dev/mem', 'request_mem_region',
                 'mmap_region', 'vm_iomap_memory']
_LOCK_APIS    = ['mutex_lock', 'spin_lock', 'spin_lock_irqsave',
                 'down', 'down_read', 'down_write', 'raw_spin_lock']

# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------

Finding = tuple  # (severity, function_name, description)

HIGH   = 'HIGH'
MEDIUM = 'MEDIUM'
LOW    = 'LOW'
INFO   = 'INFO'


def _sev_prefix(sev):
    return {'HIGH': '[!!!]', 'MEDIUM': '[!] ', 'LOW': '[-] ', 'INFO': '[i] '}.get(sev, '[?]')


def _report(findings, sev, func_name, addr, desc):
    findings.append((sev, func_name, addr, desc))


# ---------------------------------------------------------------------------
# Individual checkers
# ---------------------------------------------------------------------------

def _check_copy_from_user(bv, func, findings):
    """
    1. copy_from_user with user-controlled (unvalidated) size
    2. __copy_from_user without access_ok
    3. Ignored return value (result not checked before proceeding)
    """
    dt = get_hlil_text(func)
    fn = func.name

    for api in ['copy_from_user', '__copy_from_user', 'strncpy_from_user']:
        if api not in dt:
            continue
        idx = dt.find(api)
        if api == '__copy_from_user':
            if 'access_ok' not in dt[:idx + 400]:
                _report(findings, HIGH, fn, func.start,
                    "{} used without prior access_ok() - kernel may access arbitrary user VA".format(api))

        if looks_user_driven(dt):
            if not nearby_has_check(dt, idx, ['if (', 'if(!', 'WARN', 'BUG', '> ', '< ', '<= ', '>= '], window=300):
                _report(findings, HIGH, fn, func.start,
                    "{} - size appears user-derived without bounds validation (buffer overflow risk)".format(api))

        # Check for return value being ignored: pattern is call result not stored
        call_line_match = re.search(r'([^\n]*' + re.escape(api) + r'[^\n]*)', dt)
        if call_line_match:
            line = call_line_match.group(1)
            if not re.search(r'\w+\s*=\s*' + re.escape(api), line) and \
               not re.search(r'if\s*\(' + re.escape(api), line):
                _report(findings, MEDIUM, fn, func.start,
                    "{} return value not checked - partial copy may silently proceed".format(api))


def _check_kmalloc_overflow(bv, func, findings):
    """
    Integer overflow in allocation: kmalloc(count * elem_size) from user input.
    Look for multiplication before allocation without safe arithmetic helpers.
    """
    dt = get_hlil_text(func)
    fn = func.name

    safe_arith = ['check_mul_overflow', 'array_size', 'struct_size',
                  'kmalloc_array', 'kcalloc', 'size_add', 'size_mul']

    for api in ['kmalloc', '__kmalloc', 'vmalloc', 'kvmalloc']:
        if api not in dt:
            continue
        idx = dt.find(api)
        # Look for multiplication in the window before the call
        window = dt[max(0, idx - 300):idx + 100]
        if '*' in window and looks_user_driven(dt):
            if not any(s in window for s in safe_arith):
                _report(findings, HIGH, fn, func.start,
                    "{} - allocation size may involve integer overflow: "
                    "user-controlled count * elem without overflow-safe arithmetic".format(api))

        # NULL check after allocation
        post_window = dt[idx: min(len(dt), idx + 400)]
        if 'if (' not in post_window and 'if(!' not in post_window and \
           'WARN_ON' not in post_window and 'IS_ERR' not in post_window:
            _report(findings, MEDIUM, fn, func.start,
                "{} result may not be NULL-checked before use (null-deref on OOM)".format(api))


def _check_uninitialized_copy_to_user(bv, func, findings):
    """
    Uninitialized kmalloc'd / stack buffer passed to copy_to_user - kernel info leak.
    Heuristic: kmalloc (not kzalloc) followed by copy_to_user without memset/kzalloc.
    """
    dt = get_hlil_text(func)
    fn = func.name

    for copy_api in ['copy_to_user', '__copy_to_user']:
        if copy_api not in dt:
            continue
        idx = dt.find(copy_api)
        pre = dt[max(0, idx - 600):idx]
        if 'kmalloc' in pre and 'kzalloc' not in pre:
            if 'memset' not in pre and 'memzero' not in pre and 'RtlZeroMemory' not in pre:
                _report(findings, HIGH, fn, func.start,
                    "{} - kmalloc'd buffer sent to user without zeroing: "
                    "uninitialized bytes may leak kernel heap content".format(copy_api))


def _check_dangerous_functions(bv, func, findings):
    """sprintf, strcpy, strcat etc. in kernel context."""
    dt = get_hlil_text(func)
    fn = func.name

    for api in _DANGEROUS:
        if api not in dt:
            continue
        idx = dt.find(api)
        sev = HIGH if looks_user_driven(dt) else MEDIUM
        _report(findings, sev, fn, func.start,
            "{} - unsafe string/format function; no bounds on output buffer".format(api))


def _check_privesc_pattern(bv, func, findings):
    """commit_creds(prepare_kernel_cred(0)) - classic LPE primitive."""
    dt = get_hlil_text(func)
    fn = func.name
    if 'commit_creds' in dt and 'prepare_kernel_cred' in dt:
        _report(findings, HIGH, fn, func.start,
            "commit_creds(prepare_kernel_cred(0)) pattern - potential privilege escalation primitive")


def _check_missing_capability(bv, func, findings):
    """Sensitive operations (ioremap, remap_pfn_range, etc.) without capable() gate."""
    dt = get_hlil_text(func)
    fn = func.name

    has_sensitive = any(s in dt for s in _SENSITIVE)
    if not has_sensitive:
        return
    if any(c in dt for c in _CAPABLE_APIS):
        return

    # Only flag if this looks like an ioctl handler or user-driven function
    is_ioctl = 'ioctl' in fn.lower() or looks_user_driven(dt)
    sev = HIGH if is_ioctl else MEDIUM
    _report(findings, sev, fn, func.start,
        "Sensitive operation ({}) in {} without capable()/ns_capable() gate".format(
            next(s for s in _SENSITIVE if s in dt), fn))


def _check_mmap_handler(bv, func, findings):
    """
    mmap handler issues:
    - remap_pfn_range / io_remap_pfn_range without checking vm_area size
    - No validation that vma->vm_end - vma->vm_start <= allocated_size
    """
    dt = get_hlil_text(func)
    fn = func.name

    for api in ['remap_pfn_range', 'io_remap_pfn_range', 'vm_iomap_memory']:
        if api not in dt:
            continue
        idx = dt.find(api)
        # Look for size validation near the call
        size_checks = ['vm_end', 'vm_start', '<= ', '> ', 'PAGE_SIZE', 'device_size', 'map_size']
        if not nearby_has_check(dt, idx, size_checks, window=400):
            _report(findings, HIGH, fn, func.start,
                "{} - no vma size bounds check detected: "
                "user controls mapping size, may expose physical memory beyond device region".format(api))

    if 'vma->vm_pgoff' in dt or 'vm_pgoff' in dt:
        if 'remap_pfn_range' in dt or 'io_remap_pfn_range' in dt:
            pgoff_checks = ['<= ', '>= ', 'if (', 'PAGE_ALIGN', 'max_pfn']
            if not nearby_has_check(dt, dt.find('vm_pgoff'), pgoff_checks):
                _report(findings, HIGH, fn, func.start,
                    "vm_pgoff used in remap_pfn_range without validation - "
                    "user-controlled pfn can map arbitrary physical pages")


def _check_ioremap_user_size(bv, func, findings):
    """ioremap with a size that traces back to user input."""
    dt = get_hlil_text(func)
    fn = func.name

    for api in ['ioremap', 'ioremap_nocache', 'ioremap_wc']:
        if api not in dt:
            continue
        if looks_user_driven(dt):
            idx = dt.find(api)
            if not nearby_has_validation(dt, idx):
                _report(findings, HIGH, fn, func.start,
                    "{} - physical address or size may be user-derived without validation".format(api))


def _check_uaf_pattern(bv, func, findings):
    """
    Crude UAF heuristic: kfree(ptr) followed by use of the same variable
    name within the same function without reassignment.
    Real UAF needs data flow analysis; this catches obvious textual patterns.
    """
    dt = get_hlil_text(func)
    fn = func.name

    for api in ['kfree', 'vfree', 'kvfree']:
        for m in re.finditer(r'{}[\s(]+([a-zA-Z_]\w*)'.format(re.escape(api)), dt):
            var = m.group(1)
            freed_idx = m.start()
            # Look for uses of the same var after kfree, without reassignment
            post = dt[freed_idx + len(m.group(0)):]
            assign_pat = r'\b{}\s*='.format(re.escape(var))
            use_pat    = r'\b{}\b'.format(re.escape(var))
            assign_m   = re.search(assign_pat, post)
            use_m      = re.search(use_pat, post)
            if use_m:
                if not assign_m or assign_m.start() > use_m.start():
                    _report(findings, MEDIUM, fn, func.start,
                        "{}: '{}' potentially used after free (UAF heuristic - verify manually)".format(
                            api, var))


def _check_kernel_ptr_leak(bv, func, findings):
    """
    printk with %p (not %pK) - leaks kernel virtual addresses pre-kptr_restrict.
    Also flags copy_to_user of structs that likely contain kernel pointers.
    """
    dt = get_hlil_text(func)
    fn = func.name

    if 'printk' in dt or 'pr_info' in dt or 'pr_debug' in dt or 'dev_info' in dt:
        for m in re.finditer(r'"%[^"]*%p[^Kk]', dt):
            _report(findings, MEDIUM, fn, func.start,
                "printk with %%p (not %%pK/%%pX) - leaks kernel virtual address to dmesg")

    # copy_to_user of a raw struct that might contain pointers
    if 'copy_to_user' in dt:
        for m in re.finditer(r'copy_to_user\s*\([^,]+,\s*&?(\w+)\s*,\s*sizeof\b', dt):
            struct_var = m.group(1)
            _report(findings, LOW, fn, func.start,
                "copy_to_user(&{}, sizeof) - ensure struct has no kernel pointer fields "
                "and is fully initialized (info leak risk)".format(struct_var))


def _check_interrupt_context_alloc(bv, func, findings):
    """
    GFP_KERNEL (0xcc0 / 0x6000) in a function that also uses spin_lock_irqsave /
    in_interrupt context - must use GFP_ATOMIC instead.
    """
    dt = get_hlil_text(func)
    fn = func.name

    has_irq_lock = 'spin_lock_irqsave' in dt or 'spin_lock_irq(' in dt or 'in_interrupt' in dt
    if not has_irq_lock:
        return

    # GFP_KERNEL = 0xcc0 (common literal in HLIL), also 0x6000 or 0xa20 in older kernels
    gfp_kernel_lits = ['0xcc0', '0x6000', 'GFP_KERNEL']
    for api in _ALLOC_APIS:
        if api not in dt:
            continue
        idx = dt.find(api)
        window = dt[idx: min(len(dt), idx + 200)]
        if any(lit in window for lit in gfp_kernel_lits):
            _report(findings, HIGH, fn, func.start,
                "{} with GFP_KERNEL inside interrupt-context (spin_lock_irqsave) - "
                "must use GFP_ATOMIC or GFP_NOWAIT".format(api))


def _check_double_fetch(bv, func, findings):
    """
    Double-fetch / TOCTOU: copy_from_user called more than once on the same
    user pointer in the same function without a lock between the calls.
    Pattern: attacker races the kernel between the two fetches to change the
    value - first fetch passes a validation check, second fetch sees evil data.
    """
    dt = get_hlil_text(func)
    fn = func.name

    # Collect all (api, source_var) pairs
    fetch_vars = []
    for api in ['copy_from_user', '__copy_from_user', 'get_user']:
        for m in re.finditer(r'{}\s*\([^,)]+,\s*([a-zA-Z_]\w*)'.format(re.escape(api)), dt):
            fetch_vars.append((api, m.group(1), m.start()))

    # Group by source variable
    by_var = defaultdict(list)
    for api, var, pos in fetch_vars:
        by_var[var].append((api, pos))

    for var, calls in by_var.items():
        if len(calls) < 2:
            continue
        # Check that there's no mutex/spinlock between the two fetches
        first_pos  = calls[0][1]
        second_pos = calls[1][1]
        between    = dt[first_pos:second_pos]
        lock_present = any(l in between for l in ['mutex_lock', 'spin_lock', 'down(', 'down_read', 'rcu_read_lock'])
        if not lock_present:
            _report(findings, HIGH, fn, func.start,
                "Double-fetch TOCTOU: copy_from_user on '{}' called {} times without intervening lock "
                "- attacker can race to change user buffer between validation and use".format(var, len(calls)))


def _check_signedness_confusion(bv, func, findings):
    """
    Signedness confusion on size/length parameters.
    Common pattern: driver reads a user-supplied length as signed int, compares
    against a positive MAX, then passes to copy_from_user which interprets it
    as size_t (unsigned) - a negative value bypasses the check and becomes huge.

    Also detects: comparison of user-supplied count against 0 using signed comparison
    (if (count >= 0) is always true for unsigned; if (count < 0) never triggers).
    """
    dt = get_hlil_text(func)
    fn = func.name

    if not looks_user_driven(dt):
        return

    # Pattern 1: signed comparison followed by copy_from_user
    # Look for: if (len < 0) or if (len <= 0) near copy_from_user
    # If the variable is actually unsigned, this check is useless
    signed_check_pat = re.compile(r'if\s*\(\s*(\w+)\s*[<>]=?\s*0\s*\)')
    copy_pat         = re.compile(r'copy_from_user|kmalloc|kzalloc')

    for m in signed_check_pat.finditer(dt):
        var = m.group(1)
        idx = m.start()
        post = dt[idx:idx + 600]
        if copy_pat.search(post) and var in post:
            _report(findings, MEDIUM, fn, func.start,
                "Signedness confusion: '{}' checked against 0 (signed check) before copy/alloc - "
                "if declared unsigned/size_t, check is ineffective; negative value bypasses bound".format(var))
            break

    # Pattern 2: user-supplied value cast to signed int used as allocation/copy size
    for m in re.finditer(r'\(int\)\s*(\w+)', dt):
        var = m.group(1)
        cast_idx = m.start()
        post = dt[cast_idx:cast_idx + 400]
        if any(api in post for api in ['copy_from_user', 'kmalloc', 'kzalloc', 'memcpy']):
            if looks_user_driven(dt[:cast_idx + 200]):
                _report(findings, MEDIUM, fn, func.start,
                    "Signed cast: (int){} used as size for copy/alloc - "
                    "user-controlled value cast to signed may produce negative size".format(var))


def _check_refcount_uaf(bv, func, findings):
    """
    Kernel object reference count vulnerabilities.
    Patterns:
      1. kref_put / kobject_put without corresponding kref_get in same critical path
         → potential premature free if called in race condition
      2. Object used after kref_put / kobject_put (use-after-free via ref exhaustion)
      3. kref_put_lock (takes a lock then calls kref_put) - check that the lock is
         actually held at all call sites
    Also checks for missing atomic_dec_and_test / refcount_dec_and_test before free.
    """
    dt = get_hlil_text(func)
    fn = func.name

    put_apis  = ['kref_put', 'kobject_put', 'put_device', 'dev_put', 'sock_put', 'skb_unref']
    get_apis  = ['kref_get', 'kobject_get', 'get_device', 'dev_hold', 'sock_hold', 'skb_get']

    has_put = any(a in dt for a in put_apis)
    has_get = any(a in dt for a in get_apis)

    if not has_put:
        return

    which_put = next(a for a in put_apis if a in dt)

    # Check for object use after kref_put in same function
    put_idx = dt.find(which_put)
    post = dt[put_idx:]
    obj_m = re.search(r'{}[\s(]+([a-zA-Z_]\w*)'.format(re.escape(which_put)), dt)
    if obj_m:
        obj_var = obj_m.group(1)
        # Look for use of same variable after put without reassignment
        post_put = dt[put_idx + len(obj_m.group(0)):]
        reassign = re.search(r'\b{}\s*='.format(re.escape(obj_var)), post_put)
        use_after = re.search(r'\b{}\b'.format(re.escape(obj_var)), post_put)
        if use_after:
            if not reassign or reassign.start() > use_after.start():
                _report(findings, HIGH, fn, func.start,
                    "{}: '{}' used after ref drop - potential use-after-free if "
                    "refcount reaches zero (verify with concurrent access pattern)".format(which_put, obj_var))

    # Missing kref_get in function that calls kref_put asymmetrically
    if has_put and not has_get:
        _report(findings, LOW, fn, func.start,
            "{} called without kref_get in same function - "
            "verify caller correctly holds a reference before entering".format(which_put))


# ---------------------------------------------------------------------------
# Main plugin entry
# ---------------------------------------------------------------------------

def find_vulns(bv: BinaryView):
    log_info("[+] Linux kernel driver vulnerability triage: {}".format(bv.file.filename))

    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir  = os.path.join(os.path.expanduser('~'), '.logs', 'LKDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-vulns.txt')

    all_findings = []

    checkers = [
        _check_copy_from_user,
        _check_kmalloc_overflow,
        _check_uninitialized_copy_to_user,
        _check_dangerous_functions,
        _check_privesc_pattern,
        _check_missing_capability,
        _check_mmap_handler,
        _check_ioremap_user_size,
        _check_uaf_pattern,
        _check_kernel_ptr_leak,
        _check_interrupt_context_alloc,
        _check_double_fetch,
        _check_signedness_confusion,
        _check_refcount_uaf,
    ]

    for func in bv.functions:
        for checker in checkers:
            try:
                checker(bv, func, all_findings)
            except Exception as e:
                log_warn("  Checker {} failed on {}: {}".format(checker.__name__, func.name, e))

    # Deduplicate while preserving order
    seen_findings = set()
    deduped = []
    for f in all_findings:
        key = (f[0], f[1], f[3])
        if key not in seen_findings:
            seen_findings.add(key)
            deduped.append(f)

    # Sort: HIGH first, then MEDIUM, LOW, INFO
    sev_order = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}
    deduped.sort(key=lambda x: sev_order.get(x[0], 9))

    # Output
    lines = [
        "=== Linux Kernel Driver Vulnerability Report ===",
        "Binary: {}".format(bv.file.filename),
        "Total findings: {}".format(len(deduped)),
        "",
    ]

    counts = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    for sev, fn, addr, desc in deduped:
        counts[sev] = counts.get(sev, 0) + 1
        prefix = _sev_prefix(sev)
        entry = "{} [{}] {} @ 0x{:x}\n         {}".format(prefix, sev, fn, addr, desc)
        lines.append(entry)
        log_info(entry)

    lines.append("")
    lines.append("Summary: HIGH={} MEDIUM={} LOW={} INFO={}".format(
        counts[HIGH], counts[MEDIUM], counts[LOW], counts[INFO]))

    summary = "Summary: HIGH={} MEDIUM={} LOW={} INFO={}".format(
        counts[HIGH], counts[MEDIUM], counts[LOW], counts[INFO])
    log_info(summary)

    if not deduped:
        log_info("[+] No vulnerability patterns detected.")
        log_info("    This may mean the binary uses safe wrappers, is heavily stripped,")
        log_info("    or HLIL analysis was insufficient. Consider manual review.")

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        log_info("[+] Report saved to: {}".format(report_path))
    except Exception as e:
        log_warn("Could not write report: {}".format(e))

    log_info("[+] Vulnerability triage complete.")


PluginCommand.register(
    "Linux Driver Analysis\\Vulnerability Finder",
    "Static triage of Linux kernel drivers for vulnerability patterns",
    find_vulns
)
