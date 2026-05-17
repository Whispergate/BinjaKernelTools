"""
Binary Ninja plugin - Find Linux character device registrations and
recover file_operations function pointer tables.

Detection strategy:
  1. Find callers of register_chrdev / cdev_add / misc_register / alloc_chrdev_region
  2. Trace the fops argument (3rd for register_chrdev, 2nd for cdev_init,
     offset +0x10 for misc_register via miscdevice struct) to a data address
  3. Read function pointers from the struct at known x86_64 offsets and
     cross-reference them to functions, annotating each with its role
  4. Report open / release / read / write / unlocked_ioctl / compat_ioctl /
     mmap / poll / fasync handlers

file_operations layout (x86_64, Linux 5.x / 6.x):
  +0x00  owner
  +0x08  llseek
  +0x10  read
  +0x18  write
  +0x20  read_iter
  +0x28  write_iter
  +0x30  iterate
  +0x38  iterate_shared
  +0x40  poll
  +0x48  unlocked_ioctl   <-- primary target
  +0x50  compat_ioctl
  +0x58  mmap
  +0x68  open
  +0x70  flush
  +0x78  release
  +0x80  fsync
  +0x88  fasync
"""

from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers, get_call_params_at, const_value

# ---------------------------------------------------------------------------
# file_operations field offsets (x86_64 Linux 5.x / 6.x)
# ---------------------------------------------------------------------------
FOPS_FIELDS = [
    (0x00,  'owner',           False),
    (0x08,  'llseek',          True),
    (0x10,  'read',            True),
    (0x18,  'write',           True),
    (0x20,  'read_iter',       True),
    (0x28,  'write_iter',      True),
    (0x30,  'iterate',         True),
    (0x38,  'iterate_shared',  True),
    (0x40,  'poll',            True),
    (0x48,  'unlocked_ioctl',  True),
    (0x50,  'compat_ioctl',    True),
    (0x58,  'mmap',            True),
    (0x68,  'open',            True),
    (0x70,  'flush',           True),
    (0x78,  'release',         True),
    (0x80,  'fsync',           True),
    (0x88,  'fasync',          True),
]

# miscdevice.fops is at +0x10 (after minor:int32 + pad + name:ptr)
MISCDEVICE_FOPS_OFFSET = 0x10

# cdev.ops is at +0x20 (after kobject[0x18] + module ptr)
CDEV_OPS_OFFSET = 0x20


# ---------------------------------------------------------------------------

def _try_read_ptr(bv, addr):
    """Read a 64-bit pointer from bv at addr; return None on failure."""
    try:
        val = bv.read_int(addr, 8, False)
        return val if val else None
    except Exception:
        return None


def _resolve_fops(bv, fops_addr):
    """
    Given the address of a file_operations struct in binary data,
    read each function-pointer field and return a list of
    (offset, field_name, func_addr, func_object_or_None).
    """
    results = []
    for off, name, is_fn in FOPS_FIELDS:
        if not is_fn:
            continue
        ptr = _try_read_ptr(bv, fops_addr + off)
        if ptr:
            func = bv.get_function_at(ptr)
            results.append((off, name, ptr, func))
    return results


def _trace_arg_to_addr(bv, func, ref_addr, param_index):
    """
    Attempt to resolve call argument param_index to a constant address via MLIL.
    Returns the address or None.
    """
    params = get_call_params_at(func, ref_addr)
    if param_index < len(params):
        return const_value(params[param_index])
    return None


def _find_fops_via_data_scan(bv, fops_addr):
    """
    Validate that fops_addr looks like a file_operations struct by checking that
    at least two of the expected function-pointer slots are valid code addresses.
    """
    if not fops_addr:
        return False
    valid = 0
    for off, _, is_fn in FOPS_FIELDS:
        if not is_fn:
            continue
        ptr = _try_read_ptr(bv, fops_addr + off)
        if ptr and bv.get_function_at(ptr):
            valid += 1
        if valid >= 2:
            return True
    return False


def _report_fops(bv, fops_addr, source_label):
    log_info("  [fops @ 0x{:x}]  from: {}".format(fops_addr, source_label))
    fields = _resolve_fops(bv, fops_addr)
    if not fields:
        log_warn("    (no function pointers resolved - may be wrong offset or stripped)")
        return
    for off, name, ptr, func in fields:
        fname = func.name if func else "???"
        log_info("    +0x{:02x}  {:20s} -> 0x{:x}  ({})".format(off, name, ptr, fname))
        # Tag the function with its role if it has a generated name
        if func and func.name.startswith('sub_'):
            try:
                func.name = "fops_{}".format(name)
            except Exception:
                pass


def find_char_devices(bv: BinaryView):
    log_info("[+] Linux character device analysis: {}".format(bv.file.filename))
    found_any = False

    # -----------------------------------------------------------------------
    # register_chrdev(major, name, fops)  - fops is arg[2]
    # -----------------------------------------------------------------------
    for func, ref_addr in get_callers(bv, 'register_chrdev') + get_callers(bv, '__register_chrdev'):
        log_info("\n[*] register_chrdev called in {} at 0x{:x}".format(func.name, ref_addr))
        fops_addr = _trace_arg_to_addr(bv, func, ref_addr, 2)
        if fops_addr and _find_fops_via_data_scan(bv, fops_addr):
            _report_fops(bv, fops_addr, "register_chrdev arg[2]")
            found_any = True
        else:
            log_warn("    Could not statically resolve fops pointer (may be runtime-computed)")

    # -----------------------------------------------------------------------
    # cdev_init(cdev, fops)  - fops is arg[1]
    # -----------------------------------------------------------------------
    for func, ref_addr in get_callers(bv, 'cdev_init'):
        log_info("\n[*] cdev_init called in {} at 0x{:x}".format(func.name, ref_addr))
        fops_addr = _trace_arg_to_addr(bv, func, ref_addr, 1)
        if fops_addr and _find_fops_via_data_scan(bv, fops_addr):
            _report_fops(bv, fops_addr, "cdev_init arg[1]")
            found_any = True
        else:
            log_warn("    Could not statically resolve fops pointer")

    # -----------------------------------------------------------------------
    # alloc_chrdev_region - device name + major; fops set separately via cdev_init
    # -----------------------------------------------------------------------
    for func, ref_addr in get_callers(bv, 'alloc_chrdev_region') + get_callers(bv, 'register_chrdev_region'):
        log_info("\n[*] alloc_chrdev_region called in {} at 0x{:x}".format(func.name, ref_addr))

    # -----------------------------------------------------------------------
    # misc_register(miscdevice*)  - miscdevice.fops is at +0x10 from struct base
    # -----------------------------------------------------------------------
    for func, ref_addr in get_callers(bv, 'misc_register'):
        log_info("\n[*] misc_register called in {} at 0x{:x}".format(func.name, ref_addr))
        misc_addr = _trace_arg_to_addr(bv, func, ref_addr, 0)
        if misc_addr:
            fops_ptr_addr = misc_addr + MISCDEVICE_FOPS_OFFSET
            fops_addr = _try_read_ptr(bv, fops_ptr_addr)
            if fops_addr and _find_fops_via_data_scan(bv, fops_addr):
                _report_fops(bv, fops_addr, "misc_register miscdevice+0x10")
                found_any = True
            else:
                log_warn("    misc_register: could not resolve miscdevice.fops at 0x{:x}".format(
                    fops_ptr_addr))
        else:
            log_warn("    misc_register: could not resolve miscdevice pointer")

    # -----------------------------------------------------------------------
    # Fallback: scan all global data for plausible file_operations structs
    # Look for data symbols containing "fops" or "file_operations"
    # -----------------------------------------------------------------------
    log_info("\n[*] Scanning data symbols for file_operations...")
    for sym in bv.get_symbols():
        sname = sym.name.lower()
        if 'fops' in sname or 'file_op' in sname or 'file_operations' in sname:
            addr = sym.address
            if _find_fops_via_data_scan(bv, addr):
                log_info("[+] Data symbol '{}' at 0x{:x} looks like file_operations".format(
                    sym.name, addr))
                _report_fops(bv, addr, "symbol '{}'".format(sym.name))
                found_any = True

    if not found_any:
        log_warn("[!] No character device registrations found or fops could not be resolved.")
        log_warn("    Try loading with kernel type library or set fops struct manually.")

    log_info("[+] Character device analysis complete.")


PluginCommand.register(
    "Linux Driver Analysis\\Find Character Devices",
    "Find char device registrations and enumerate file_operations callbacks",
    find_char_devices
)
