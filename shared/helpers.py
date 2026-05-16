"""
Shared helpers for Linux Kernel Driver Analysis plugins.
"""

import re
from binaryninja import BinaryView


# ---------------------------------------------------------------------------
# HLIL / MLIL text extraction
# ---------------------------------------------------------------------------

def get_hlil_text(func):
    lines = []
    try:
        hlil = func.hlil
        if hlil:
            for block in hlil:
                for instr in block:
                    lines.append(str(instr))
    except Exception:
        pass
    return "\n".join(lines)


def get_mlil_text(func):
    lines = []
    try:
        mlil = func.mlil
        if mlil:
            for block in mlil:
                for instr in block:
                    lines.append(str(instr))
    except Exception:
        pass
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Cross-reference helpers
# ---------------------------------------------------------------------------

def get_callers(bv: BinaryView, sym_name: str):
    """Return list of (caller_func, ref_addr) for every call to sym_name."""
    results = []
    for sym in bv.get_symbols_by_name(sym_name):
        for ref in bv.get_code_refs(sym.address):
            if ref.function:
                results.append((ref.function, ref.address))
    return results


def get_symbol_address(bv: BinaryView, name: str):
    syms = bv.get_symbols_by_name(name)
    return syms[0].address if syms else None


# ---------------------------------------------------------------------------
# MLIL call-parameter extraction
# ---------------------------------------------------------------------------

def get_call_params_at(func, ref_addr):
    """Return the MLIL params list for the call instruction at ref_addr, or []."""
    try:
        mlil = func.mlil
        if not mlil:
            return []
        idx = mlil.get_instruction_start(ref_addr)
        if idx is None:
            return []
        instr = mlil[idx]
        return list(getattr(instr, 'params', []))
    except Exception:
        return []


def const_value(param):
    """Try to extract a constant integer from an MLIL parameter."""
    try:
        return param.constant
    except Exception:
        pass
    try:
        # handle MLIL_CONST_PTR wrapping
        if hasattr(param, 'operands'):
            for op in param.operands:
                try:
                    return op.constant
                except Exception:
                    pass
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Heuristic text checks
# ---------------------------------------------------------------------------

def nearby_has_check(text, idx, checks, window=400):
    """True if any string in checks appears within window chars of idx in text."""
    chunk = text[max(0, idx - window): min(len(text), idx + window)]
    return any(c in chunk for c in checks)


# User-space data indicators in HLIL text
_USER_KEYS = [
    'copy_from_user', '__copy_from_user', 'get_user', '__get_user',
    'copy_to_user', '__copy_to_user', 'put_user',
    'arg',      # common ioctl third parameter name
    'uarg', 'ubuf', 'user_buf', 'user_data', 'user_ptr',
    'from_user', 'to_user',
]

def looks_user_driven(text):
    return any(k in text for k in _USER_KEYS)


_VALIDATION_CHECKS = [
    'access_ok', 'verify_area',
    'check_mem_region',
    'capable(', 'ns_capable(',
    'if (', 'if(!', 'if (!',
    'WARN_ON', 'BUG_ON',
]

def nearby_has_validation(text, idx, window=400):
    return nearby_has_check(text, idx, _VALIDATION_CHECKS, window)


# ---------------------------------------------------------------------------
# Linux IOCTL _IOC decode
# ---------------------------------------------------------------------------
# bits [ 0: 7] = nr   (command number within driver)
# bits [ 8:15] = type (driver magic, often printable ASCII)
# bits [16:29] = size (sizeof payload struct, 0 for _IO)
# bits [30:31] = dir  (0=none 1=write 2=read 3=rdwr)

_IOC_NRSHIFT   = 0
_IOC_TYPESHIFT = 8
_IOC_SIZESHIFT = 16
_IOC_DIRSHIFT  = 30

IOC_DIR_NAMES = {0: '_IO (none)', 1: '_IOW (write→drv)', 2: '_IOR (read←drv)', 3: '_IOWR (read+write)'}


def decode_linux_ioctl(code):
    code = code & 0xFFFFFFFF
    return {
        'raw':  code,
        'nr':   (code >> _IOC_NRSHIFT)   & 0xFF,
        'type': (code >> _IOC_TYPESHIFT)  & 0xFF,
        'size': (code >> _IOC_SIZESHIFT)  & 0x3FFF,
        'dir':  (code >> _IOC_DIRSHIFT)   & 0x3,
    }


def plausible_linux_ioctl(code):
    """Heuristic: does this 32-bit constant look like a Linux IOCTL code?"""
    code = code & 0xFFFFFFFF
    if code < 0x100:
        return False
    d = decode_linux_ioctl(code)
    # type byte: printable ASCII is the strong convention; 0 is also allowed
    type_ok = (d['type'] == 0) or (0x20 <= d['type'] <= 0x7E)
    # size must be realistic (struct sizes don't exceed 4 KiB in practice)
    size_ok = d['size'] <= 4096
    return type_ok and size_ok


def format_ioctl(code):
    d = decode_linux_ioctl(code)
    type_ch = chr(d['type']) if 0x20 <= d['type'] <= 0x7E else '?'
    dir_str = IOC_DIR_NAMES.get(d['dir'], str(d['dir']))
    return (
        "0x{:08X}  dir={} ({})  type=0x{:02X} ('{}')  nr=0x{:02X} ({})  size={} bytes".format(
            d['raw'], d['dir'], dir_str,
            d['type'], type_ch,
            d['nr'], d['nr'],
            d['size']
        )
    )
