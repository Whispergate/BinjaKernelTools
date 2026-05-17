"""
Binary Ninja plugin - Find Linux kernel module entry and exit points.

Detection strategy:
  1. Exact symbol lookup: init_module / cleanup_module
  2. Section heuristic: functions whose code lives in .init.text / .exit.text
  3. API heuristic: function that calls the most kernel registration APIs
     (register_chrdev, cdev_add, misc_register, platform_driver_register,
      pci_register_driver, usb_register, netdev_register, etc.)
  4. Driver type inference from which registration APIs are called

Output: Binary Ninja log listing entry point(s), exit point, driver type,
and a summary of which registration APIs were found.
"""

from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers

# ---------------------------------------------------------------------------
# Kernel module registration APIs - used for heuristic scoring and type detection
# ---------------------------------------------------------------------------

_CHRDEV_APIS    = ['register_chrdev', 'alloc_chrdev_region', 'register_chrdev_region',
                   '__register_chrdev', 'cdev_init', 'cdev_add']
_MISC_APIS      = ['misc_register']
_PLATFORM_APIS  = ['platform_driver_register', '__platform_driver_register',
                   'platform_device_register']
_PCI_APIS       = ['pci_register_driver', '__pci_register_driver']
_USB_APIS       = ['usb_register', 'usb_register_driver', 'usb_register_dev']
_NET_APIS       = ['register_netdev', 'register_netdevice', 'alloc_netdev',
                   'register_netdev_many']
_INPUT_APIS     = ['input_register_device', 'input_register_handler']
_BLOCK_APIS     = ['add_disk', '__add_disk', 'register_blkdev']
_FILTER_APIS    = []  # Linux doesn't have a direct equivalent of WDM mini-filters

ALL_INIT_APIS = (
    _CHRDEV_APIS + _MISC_APIS + _PLATFORM_APIS + _PCI_APIS +
    _USB_APIS + _NET_APIS + _INPUT_APIS + _BLOCK_APIS
)

_MODULE_SETUP_APIS = [
    'kmalloc', 'kzalloc', 'vmalloc', 'ioremap', 'ioremap_nocache',
    'request_irq', 'request_mem_region', 'pci_enable_device',
    'device_create', 'class_create', 'proc_create', 'debugfs_create_dir',
    'kobject_create_and_add',
]

# ---------------------------------------------------------------------------

def _score_init_candidate(bv, func):
    """
    Score a function as a potential init_module by counting known API calls.
    Returns (score, matched_apis).
    """
    dt = get_hlil_text(func)
    matched = []
    score = 0
    for api in ALL_INIT_APIS:
        if api in dt:
            score += 3
            matched.append(api)
    for api in _MODULE_SETUP_APIS:
        if api in dt:
            score += 1
            matched.append(api)
    return score, matched


def _infer_driver_type(apis):
    if any(a in apis for a in _MISC_APIS):
        return 'Misc device (miscdevice)'
    if any(a in apis for a in _CHRDEV_APIS):
        return 'Character device (cdev / register_chrdev)'
    if any(a in apis for a in _PCI_APIS):
        return 'PCI driver'
    if any(a in apis for a in _USB_APIS):
        return 'USB driver'
    if any(a in apis for a in _NET_APIS):
        return 'Network driver'
    if any(a in apis for a in _PLATFORM_APIS):
        return 'Platform driver'
    if any(a in apis for a in _INPUT_APIS):
        return 'Input device driver'
    if any(a in apis for a in _BLOCK_APIS):
        return 'Block device driver'
    return 'Unknown'


def _section_of(bv, addr):
    for sec in bv.sections.values():
        if sec.start <= addr < sec.start + sec.length:
            return sec.name
    return ''


def find_module_entry(bv: BinaryView):
    log_info("[+] Linux kernel module entry analysis: {}".format(bv.file.filename))

    # --- Strategy 1: exact symbol names ---
    init_func    = None
    cleanup_func = None

    for sym_name in ('init_module', 'module_init'):
        syms = bv.get_symbols_by_name(sym_name)
        if syms:
            f = bv.get_function_at(syms[0].address)
            if f:
                init_func = f
                log_info("[+] [S1] init_module symbol at 0x{:x} ({})".format(f.start, f.name))
                break

    for sym_name in ('cleanup_module', 'exit_module'):
        syms = bv.get_symbols_by_name(sym_name)
        if syms:
            f = bv.get_function_at(syms[0].address)
            if f:
                cleanup_func = f
                log_info("[+] [S1] cleanup_module symbol at 0x{:x} ({})".format(f.start, f.name))
                break

    # --- Strategy 2: .init.text / .exit.text section scan ---
    init_section_funcs  = []
    exit_section_funcs  = []
    for func in bv.functions:
        sec = _section_of(bv, func.start)
        if sec in ('.init.text', '__init'):
            init_section_funcs.append(func)
        elif sec in ('.exit.text', '__exit'):
            exit_section_funcs.append(func)

    if init_section_funcs:
        log_info("[*] [S2] Functions in .init.text: {}".format(
            ', '.join("{} (0x{:x})".format(f.name, f.start) for f in init_section_funcs)))
        if not init_func and len(init_section_funcs) == 1:
            init_func = init_section_funcs[0]
            log_info("[+] [S2] init_module candidate (sole .init.text fn): {} (0x{:x})".format(
                init_func.name, init_func.start))

    if exit_section_funcs:
        log_info("[*] [S2] Functions in .exit.text: {}".format(
            ', '.join("{} (0x{:x})".format(f.name, f.start) for f in exit_section_funcs)))
        if not cleanup_func and len(exit_section_funcs) == 1:
            cleanup_func = exit_section_funcs[0]

    # --- Strategy 3: API heuristic scoring ---
    best_score   = 0
    best_matched = []
    best_func    = None

    if not init_func:
        log_info("[*] [S3] Scoring all functions for init_module heuristic...")
        for func in bv.functions:
            score, matched = _score_init_candidate(bv, func)
            if score > best_score:
                best_score   = score
                best_matched = matched
                best_func    = func

        if best_func and best_score >= 3:
            init_func = best_func
            log_info("[+] [S3] init_module heuristic: {} (0x{:x})  score={}".format(
                init_func.name, init_func.start, best_score))
        else:
            log_warn("[!] No init_module candidate found via any strategy")

    # --- Collect APIs from confirmed init_func ---
    if init_func and not best_matched:
        _, best_matched = _score_init_candidate(bv, init_func)

    # --- Driver type inference ---
    driver_type = _infer_driver_type(best_matched)

    # --- Summary ---
    log_info("")
    log_info("=== Module Entry Summary ===")
    if init_func:
        log_info("[+] init_module  : {} at 0x{:x}".format(init_func.name, init_func.start))
    else:
        log_info("[-] init_module  : NOT FOUND")

    if cleanup_func:
        log_info("[+] cleanup_module: {} at 0x{:x}".format(cleanup_func.name, cleanup_func.start))
    else:
        log_info("[-] cleanup_module: NOT FOUND")

    log_info("[+] Driver type  : {}".format(driver_type))

    if best_matched:
        log_info("[+] Registration APIs detected:")
        for api in sorted(set(best_matched)):
            log_info("      - {}".format(api))

    # --- Per-API caller summary ---
    log_info("")
    log_info("[*] Registration API callers:")
    for api in ALL_INIT_APIS:
        callers = get_callers(bv, api)
        if callers:
            for func, addr in callers:
                log_info("    {} called by {} at 0x{:x}".format(api, func.name, addr))

    log_info("[+] Module entry analysis complete.")


PluginCommand.register(
    "Linux Driver Analysis\\Find Module Entry",
    "Detect init_module / cleanup_module and infer Linux driver type",
    find_module_entry
)
