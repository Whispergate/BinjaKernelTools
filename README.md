# BinjaKernelTools

Static analysis plugins for Binary Ninja targeting Linux and Windows kernel driver vulnerability research.

## Installation

Copy the `BinjaKernelTools/` directory into your Binary Ninja plugins folder:

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\Binary Ninja\plugins\` |
| Linux | `~/.binaryninja/plugins/` |
| macOS | `~/Library/Application Support/Binary Ninja/plugins/` |

Requires Binary Ninja >= 3164 with Python 3 API.

## Plugin Reference

### Linux Driver Analysis

Commands registered under **Linux Driver Analysis\\**

---

#### Find Module Entry
**`linux/find_module_entry.py`**

Locates `init_module` / `cleanup_module` and infers driver type.

- Symbol lookup (`init_module`, `cleanup_module`)
- Section scan (`.init.text`, `.exit.text`)
- API scoring heuristic - ranks all functions by registration API calls
- Driver type inference: char device, misc, PCI, USB, network, platform, block, input

---

#### Find Character Devices
**`linux/find_char_dev.py`**

Enumerates character device registrations and recovers `file_operations` function pointer tables.

- Traces `register_chrdev`, `cdev_init`, `misc_register` arguments to `file_operations` struct
- Reads all function pointer slots at known x86_64 offsets (`+0x48` `unlocked_ioctl`, etc.)
- Renames `sub_*` functions to `fops_<field>` where resolved
- Data symbol scan for structs named `*fops*` / `*file_operations*`

---

#### Find IOCTLs
**`linux/find_ioctls.py`**

Enumerates IOCTL handlers and decodes Linux `_IOC(dir, type, nr, size)` codes.

- Multi-strategy handler detection: name pattern → data symbol → switch constant scan
- Full `_IOC` decode: direction (`_IO`/`_IOR`/`_IOW`/`_IOWR`), type byte, nr, size
- Per-IOCTL: flags `copy_from_user` without `access_ok`, missing `capable()` check

---

#### Find Netlink Interfaces
**`linux/find_netlink.py`**

Finds classic netlink and generic netlink handlers; detects attribute validation failures.

- `netlink_kernel_create` → `.input()` callback resolution
- `genl_register_family` → `genl_ops.doit` / `.dumpit` enumeration
- `nla_parse()` with NULL policy - no attribute type/length enforcement
- Missing `nlmsg_ok()` before payload access (OOB read on truncated message)
- `nla_get_*` on unchecked `tb[]` entries after failed / unchecked `nla_parse`
- Missing `CAP_NET_ADMIN` / `netlink_capable()` gate in privileged handlers

---

#### Find Procfs/Sysfs Interfaces
**`linux/find_procfs.py`**

Finds procfs, sysfs, and debugfs write/store/show handlers; detects missing bounds checks.

- `proc_create` / `proc_create_data` / `debugfs_create_file` handler resolution
- `sysfs_create_file` / `device_create_file` registration tracking
- Write handler: `copy_from_user` without count cap → stack/heap overflow
- Write handler: `kmalloc(count)` without bound → user-controlled allocation size
- `kstrtol` / `kstrtoul` return value ignored → stale value in subsequent logic
- sysfs `.store()` missing PAGE_SIZE cap on `count`
- `seq_printf` with non-literal format string → format string injection

---

#### Vulnerability Finder
**`linux/vuln_finder.py`**

Comprehensive static triage across all functions. Saves report to `~/.logs/LKDriverVulns/`.

| # | Check | Severity |
|---|---|---|
| 1 | `copy_from_user` with user-controlled size, no bounds check | HIGH |
| 2 | `__copy_from_user` without prior `access_ok()` | HIGH |
| 3 | `copy_from_user` return value ignored | MEDIUM |
| 4 | Integer overflow in `kmalloc`: `count * size` without safe arithmetic | HIGH |
| 5 | `kmalloc` result not NULL-checked before dereference | MEDIUM |
| 6 | `kmalloc` (not `kzalloc`) buffer passed to `copy_to_user` - info leak | HIGH |
| 7 | `commit_creds(prepare_kernel_cred(0))` - privilege escalation primitive | HIGH |
| 8 | Sensitive ops without `capable()` / `ns_capable()` gate | HIGH/MEDIUM |
| 9 | `remap_pfn_range` without `vm_area` size bounds check | HIGH |
| 10 | `vm_pgoff` in `remap_pfn_range` without validation - arbitrary pfn | HIGH |
| 11 | `ioremap` with user-derived size/address | HIGH |
| 12 | `kfree` followed by potential use of freed pointer | MEDIUM |
| 13 | `printk %p` (not `%pK`) - kernel address leak to dmesg | MEDIUM |
| 14 | `copy_to_user(&struct, sizeof)` - padding/pointer field leak | LOW |
| 15 | Dangerous functions: `sprintf`, `strcpy`, `strcat`, `vsprintf` | HIGH/MEDIUM |
| 16 | `GFP_KERNEL` inside `spin_lock_irqsave` context - must use `GFP_ATOMIC` | HIGH |
| 17 | Double-fetch TOCTOU: same user pointer fetched 2+ times without lock | HIGH |
| 18 | Signedness confusion: `(int)user_len` or signed `< 0` check before copy/alloc | MEDIUM |
| 19 | `kref_put` / `kobject_put` followed by object use - refcount UAF | HIGH/LOW |

---

### Windows Driver Analysis

Commands registered under **Windows Driver Analysis\\**

---

#### Find Device Names
**`windows/win_find_device_name.py`**

Scans for Windows device name strings.

- Binary string scan: `\Device\`, `\DosDevices\`, `\\.\`, `\??\`
- HLIL scan in callers of `IoCreateSymbolicLink`, `RtlInitUnicodeString`, `IoCreateDevice`

---

#### Find IOCTLs
**`windows/win_find_ioctls.py`**

Enumerates `IRP_MJ_DEVICE_CONTROL` dispatch routines and decodes `CTL_CODE`.

- 4-strategy dispatch detection: HLIL `MajorFunction[0xe]` assignment → name heuristic → C++ class pattern → fallback
- Full `CTL_CODE` decode: `DeviceType`, `Access`, `Function`, `Method`
- `METHOD_NEITHER` flagged explicitly - raw user pointer, no kernel buffering

---

#### Find IRP Handlers
**`windows/find_irp_handlers.py`**

Enumerates all 28 `IRP_MJ_*` dispatch slots and performs deep `METHOD_NEITHER` analysis.

- Scans HLIL for `*(drv_obj + 0xNN) = &handler` at all `MajorFunction[]` offsets
- Risk-ranked output per IRP type with security notes
- `IRP_MJ_READ` / `IRP_MJ_WRITE`: flags `UserBuffer` access without `ProbeForRead/Write`
- **METHOD_NEITHER deep analysis:**
  - Missing `ProbeForRead` / `ProbeForWrite` on `Type3InputBuffer`
  - Missing `__try` / `__except` - invalid pointer causes BSOD
  - `OutputBufferLength` not validated before write-back - kernel overflow
  - `memcpy` / `RtlCopyMemory` from `Type3InputBuffer` without probe

---

#### Vulnerability Finder
**`windows/win_vuln_finder.py`**

Full static triage for Windows kernel drivers. Saves report to `~/.logs/WinDriverVulns/`.

- DriverEntry detection (exact + heuristic scoring)
- Device name discovery
- Pool tag extraction via MLIL argument analysis
- Dangerous opcodes: `rdmsr`, `wrmsr`, `rdpmc`
- Dangerous C functions: `sprintf`, `strcpy`, `memcpy`, `RtlCopyMemory`
- Windows kernel API inventory: `Mm*`, `Zw*`, `Io*`, `Flt*`, `Se*`, `ProbeFor*`
- IOCTL enumeration (dispatch heuristic)
- Physical memory / IO space: `MmMapIoSpace`, `MmCopyMemory`, `ZwOpenSection`, MDL mapping
- Port/register IO from IOCTL context: `READ_PORT_*`, `WRITE_PORT_*`
- User copy without `ProbeForRead/Write`: `memcpy` / `RtlCopyMemory` near user buffers
- Integer overflow in `ExAllocatePool` sizing from user input without `RtlULong*`
- Missing `SeSinglePrivilegeCheck` / `SeAccessCheck` before sensitive operations
- Driver type detection: Standard WDM vs Mini-Filter
- Recursive call-graph classification (depth 3, ~12 callees/level) - catches HEVD-style `Handler -> Trigger -> Primitive` wrapper chains; each finding tagged `(via <fn>)`
- Name-hint fallback across call chain. Function names like `TriggerStackOverflow`, `ArbitraryWrite`, `ReadMsr`, `WriteCR4`, `MapPhysicalMemory`, `StealToken`, `DisableEtw`, `RemoveCallback`, `LoadDriver`, `OpenSection` flagged even when HLIL pattern misses

---

#### Exploit Primitive Finder
**`windows/win_primitives.py`**

Per-IOCTL detection of arbitrary R/W and exploit primitives. References Connor McGarr, knifecoat IORING, windows-internals.com, whiteknightlabs.

| Primitive | Severity |
|---|---|
| Write-What-Where (user-controlled dst + value) | CRITICAL |
| Arbitrary Kernel Read (`memcpy(out, *user_ptr, len)`) | CRITICAL |
| Token-Swap Primitive (`PsLookupProcessByProcessId` + Token offset 0x4b8/0x358) | CRITICAL |
| Stack Buffer Overflow (user-len `memcpy` to `var_*`) | HIGH |
| Pool Buffer Overflow (`ExAllocatePool` + user-len copy) | HIGH |
| Type Confusion (`ObReferenceObjectByHandle` ObjectType=NULL) | HIGH |
| Double-Fetch TOCTOU (same user ptr deref 2+ times no Probe) | HIGH |
| Uninitialized Pool Leak (non-zero alloc -> user, no `RtlZeroMemory`) | MEDIUM |
| NULL Pointer Deref (unchecked alloc result) | MEDIUM |
| IORING reference (`IoRingCreate`, `NtSubmitIoRing`, ...) | HIGH |
| METHOD_NEITHER dispatcher with no `ProbeForRead/Write` | CRITICAL |
| MSR Read/Write Primitive (`__rdmsr` / `__wrmsr` reachable from IOCTL) | CRITICAL |
| Port IO Primitive (`READ_PORT_*` / `WRITE_PORT_*`, `__in_*` / `__out_*`) | CRITICAL |
| Physical Memory Map (`MmMapIoSpace[Ex]`, `MmCopyMemory`, `\Device\PhysicalMemory`) | CRITICAL |
| Control/Debug Register Access (`__readcr*` / `__writecr*` / `__readdr*` / `__writedr*`) | CRITICAL |
| Ring-0 Exec / Capcom-style (`(*(fn*)SystemBuffer)()` user-pointer call in kernel) | CRITICAL |
| PCI Config Space Access (`HalGetBusData` / `HalSetBusData`) | HIGH |

Name-hint pass walks IOCTL handler callees (depth 3, dedup, skips `sub_*` / `nullsub_*` / `j_*`) and matches descriptive function names against ~80 BYOVD primitive patterns: `ReadKernel`, `WriteVirtual`, `ArbitraryIncrement`, `TerminateProcess`, `ProtectProcess`, `SwapToken`, `PatchEtw`, `HookSsdt`, `MapDriver`, `MapSection`, etc. Each hit emitted with severity + `:: <fn name>` for triage.

---

#### HEVD Vulnerability Classifier
**`windows/win_hevd_classes.py`**

Classifies each IOCTL handler against the HackSysExtremeVulnerableDriver bug-class taxonomy: StackOverflow, StackOverflowGS, PoolOverflow, UseAfterFree, DoubleFree, TypeConfusion, ArbitraryOverwrite, InsecureKernelResourceAccess, NullPointerDereference, UninitializedStack/Heap, IntegerOverflow, DoubleFetch, MemoryDisclosure, RaceCondition, GdiBitmapPolymorphism.

Extended privileged-primitive classes (BYOVD coverage): **MSRReadWrite**, **PortIO**, **PhysicalMemoryMap**, **ControlRegisterAccess**, **Ring0Exec**, plus name-hint classes **TokenManipulation**, **ProcessTampering**, **CallbackTampering**, **EtwTampering**, **SsdtTampering**, **DriverLoadPrimitive**, **PciConfigAccess**.

- HLIL pattern detectors + recursive callee walk (depth 3, ~16/level)
- Name-hint pass against ~70 substrings - matches handler names like `TriggerArbitraryWrite`, `MsrWrite64`, `WriteCr4`, `MapPhysicalAddress`, `EnableShellcodeExec`, `UnregisterCallback`, `DisableThreatIntel`

Useful for CTFs, training, and triaging unknown drivers against known exploit classes (ref: p.ost2.fyi).

---

#### LOLDrivers Check
**`windows/win_loldrivers.py`**

Cross-references binary against [loldrivers.io](https://www.loldrivers.io/) dataset:

- SHA256 file-hash lookup against live API (cached 7d at `~/.cache/loldrivers/drivers.json`)
- Original-filename / on-disk filename match
- IOCTL-overlap match against embedded curated DB (~25 high-impact entries: RTCore64, gdrv, AsrDrv, dbutil_2_3, Capcom, mhyprot2, WinRing0, iqvw64, Dell PCDoctor, ...)
- Device-name lexical match to known vulnerable drivers
- Fallback to embedded mini-DB if network + cache unavailable

---

#### Generate POC (C + Python)
**`windows/win_poc_gen.py`**

Emits compilable C user-mode POC + Python `ctypes` harness for each discovered IOCTL:

- Output: `~/.logs/WinDriverPOCs/<driver>-poc.c` and `<driver>-poc.py`
- Auto-detects device path from `\Device\` / `\DosDevices\` strings
- Per-IOCTL stub with METHOD-aware buffer sizing (BUFFERED / NEITHER / DIRECT)
- Primitive-aware payload comments covering ~30 primitive layouts: write-what-where, arb-read, arb-increment, process R/W, MSR R/W, port IO, phys-mem, PCI config, CR/DR access, ring-0 exec (Capcom), token swap, process kill/protect, callback removal, ETW/SSDT tamper, driver load, section map, IORING chain
- Deep classification (depth-3 callee walk + name hints) so wrapper-style handlers still get tagged
- CLI verbs:
  - `poc.exe` (no args) - `probe_all` sanity sweep: send zero buffer to every IOCTL, report success/winerr
  - `poc.exe list` - print index -> IOCTL + tags
  - `poc.exe <index>` - trigger single IOCTL
  - `poc.exe fuzz [iters]` - structured fuzzer (interesting sizes + value patterns mixed with `os.urandom`)
  - `poc.exe shell` / `cmd` - spawn `cmd.exe` after sending payloads (post-exploit hook)
- Per-call telemetry: target device banner, IOCTL + in/out sizes per send, detected primitives printed per trigger
- Python harness: `trigger(h, idx, payload=None, out_size=None)` accepts custom bytes and sizes; structured exception printing + `pause_exit` so double-click runs don't vanish

---

## License

BSD 2-Clause - Copyright (c) 2026, Whispergate
