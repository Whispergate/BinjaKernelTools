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
- API scoring heuristic — ranks all functions by registration API calls
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
- `nla_parse()` with NULL policy — no attribute type/length enforcement
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
| 6 | `kmalloc` (not `kzalloc`) buffer passed to `copy_to_user` — info leak | HIGH |
| 7 | `commit_creds(prepare_kernel_cred(0))` — privilege escalation primitive | HIGH |
| 8 | Sensitive ops without `capable()` / `ns_capable()` gate | HIGH/MEDIUM |
| 9 | `remap_pfn_range` without `vm_area` size bounds check | HIGH |
| 10 | `vm_pgoff` in `remap_pfn_range` without validation — arbitrary pfn | HIGH |
| 11 | `ioremap` with user-derived size/address | HIGH |
| 12 | `kfree` followed by potential use of freed pointer | MEDIUM |
| 13 | `printk %p` (not `%pK`) — kernel address leak to dmesg | MEDIUM |
| 14 | `copy_to_user(&struct, sizeof)` — padding/pointer field leak | LOW |
| 15 | Dangerous functions: `sprintf`, `strcpy`, `strcat`, `vsprintf` | HIGH/MEDIUM |
| 16 | `GFP_KERNEL` inside `spin_lock_irqsave` context — must use `GFP_ATOMIC` | HIGH |
| 17 | Double-fetch TOCTOU: same user pointer fetched 2+ times without lock | HIGH |
| 18 | Signedness confusion: `(int)user_len` or signed `< 0` check before copy/alloc | MEDIUM |
| 19 | `kref_put` / `kobject_put` followed by object use — refcount UAF | HIGH/LOW |

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
- `METHOD_NEITHER` flagged explicitly — raw user pointer, no kernel buffering

---

#### Find IRP Handlers
**`windows/find_irp_handlers.py`**

Enumerates all 28 `IRP_MJ_*` dispatch slots and performs deep `METHOD_NEITHER` analysis.

- Scans HLIL for `*(drv_obj + 0xNN) = &handler` at all `MajorFunction[]` offsets
- Risk-ranked output per IRP type with security notes
- `IRP_MJ_READ` / `IRP_MJ_WRITE`: flags `UserBuffer` access without `ProbeForRead/Write`
- **METHOD_NEITHER deep analysis:**
  - Missing `ProbeForRead` / `ProbeForWrite` on `Type3InputBuffer`
  - Missing `__try` / `__except` — invalid pointer causes BSOD
  - `OutputBufferLength` not validated before write-back — kernel overflow
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

---

## License

BSD 2-Clause — Copyright (c) 2026, Whispergate
