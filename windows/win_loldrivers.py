"""
Binary Ninja plugin - LOLDrivers fingerprint check.

Cross-references the loaded binary against the loldrivers.io dataset:
  1) SHA256 lookup (file hash -> known bad)
  2) Original-filename match (PE OriginalFilename -> known bad)
  3) Device-name + IOCTL pattern match (offline curated list)

Strategy:
  - Try local cache: ~/.cache/loldrivers/drivers.json
  - If stale (>7d) or missing, fetch from https://www.loldrivers.io/api/drivers.json
  - Fall back to embedded mini-database (~50 high-impact entries) if network fails.

Embedded list is a heuristic safety net only - not authoritative.

Ref: loldrivers.io, MagicSword project.
"""

import os
import json
import hashlib
import time
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

_CACHE_DIR = os.path.join(os.path.expanduser('~'), '.cache', 'loldrivers')
_CACHE_FILE = os.path.join(_CACHE_DIR, 'drivers.json')
_CACHE_TTL = 7 * 24 * 3600
_LOL_URL = 'https://www.loldrivers.io/api/drivers.json'

# Curated offline mini-DB: well-known vulnerable signed drivers
# Schema: filename_lower -> {tags, notable_ioctls, exploit_note}
_EMBEDDED = {
    'rtcore64.sys': {
        'tags': ['MSI Afterburner', 'arbitrary MSR R/W', 'phys mem'],
        'ioctls': [0x80002048, 0x80002050, 0x80002040, 0x80002044],
        'note': 'CVE-2019-16098. ReadMsr/WriteMsr/PhysAddr. Used by RobbinHood, GhostEngine.',
    },
    'gdrv.sys': {
        'tags': ['Gigabyte', 'phys mem R/W', 'MSR R/W'],
        'ioctls': [0xC3502808, 0xC3502804, 0xC350280C, 0xC3502580, 0xC3502588],
        'note': 'CVE-2018-19320. Phys R/W, used by RobbinHood, DeathRansom.',
    },
    'asrdrv101.sys': {
        'tags': ['ASRock', 'MSR R/W', 'phys mem'],
        'ioctls': [0x222880, 0x222884, 0x226040, 0x222988],
        'note': 'CVE-2020-15368. AsrOmgDrv.',
    },
    'msio64.sys': {
        'tags': ['MSI', 'phys mem R/W'],
        'ioctls': [0x80102040, 0x80102044, 0x80102048, 0x8010204C],
        'note': 'CVE-2019-18845 family.',
    },
    'pcdsrvc_x64.pkms': {
        'tags': ['Dell', 'arbitrary R/W'],
        'ioctls': [0x9C402090],
        'note': 'Dell PC-Doctor. CVE-2019-12280.',
    },
    'dbutil_2_3.sys': {
        'tags': ['Dell BIOSUtil', 'phys R/W', 'IOPL'],
        'ioctls': [0x9B0C1EC4, 0x9B0C1EC8, 0x9B0C1F40],
        'note': 'CVE-2021-21551. SeManageVolumePrivilege required pre-exploit.',
    },
    'aswarpot.sys': {
        'tags': ['Avast', 'arbitrary write'],
        'ioctls': [0xB3B8C094, 0xB3B8C0A0],
        'note': 'CVE-2022-26522/26523.',
    },
    'iqvw64.sys': {
        'tags': ['Intel NAL', 'phys R/W'],
        'ioctls': [0x80862004, 0x80862007, 0x80862008],
        'note': 'CVE-2015-2291 (Slingshot, Turla).',
    },
    'iqvw64e.sys': {
        'tags': ['Intel NAL', 'phys R/W'],
        'ioctls': [0x80862004, 0x80862007, 0x80862008],
        'note': 'CVE-2015-2291 variant.',
    },
    'ntiolib.sys': {
        'tags': ['MSI', 'phys R/W'],
        'ioctls': [0xF1002048, 0xF100204C],
        'note': 'Common in BYOVD chains.',
    },
    'winring0x64.sys': {
        'tags': ['OpenLibSys', 'MSR R/W', 'phys', 'port IO'],
        'ioctls': [0x9C402088, 0x9C40208C, 0x9C402608],
        'note': 'Ubiquitous (CPU-Z, OpenHWMonitor). MSR/PhysMem primitives.',
    },
    'amifldrv64.sys': {
        'tags': ['AMI firmware', 'phys R/W'],
        'ioctls': [0x222040, 0x222044, 0x222080],
        'note': 'AMI BIOS toolkit driver.',
    },
    'kprocesshacker.sys': {
        'tags': ['Process Hacker 2', 'arbitrary process'],
        'ioctls': [0x9988C094],
        'note': 'EDR/AV bypass; pre-2.39.',
    },
    'procexp.sys': {
        'tags': ['Sysinternals', 'kernel handle ops'],
        'ioctls': [0x83350804],
        'note': 'CVE-2023-29360 lineage; abused for handle steal.',
    },
    'truesight.sys': {
        'tags': ['RentDrag', 'EDR kill'],
        'ioctls': [0x22E044, 0x22E048],
        'note': 'Used to kill EDR processes (BlackCat/AvosLocker).',
    },
    'mhyprot2.sys': {
        'tags': ['genshin anticheat', 'arbitrary R/W'],
        'ioctls': [0x81034000, 0x81034040],
        'note': 'CVE-2020-36603. Abused by ransomware (Trigona).',
    },
    'capcom.sys': {
        'tags': ['Capcom', 'ring-0 exec'],
        'ioctls': [0xAA013044],
        'note': 'Direct user->kernel exec primitive. Classic BYOVD.',
    },
    'asusio.sys': {
        'tags': ['ASUS', 'port IO'],
        'ioctls': [0xA040208C, 0xA0402084],
        'note': 'Old ATK0110.',
    },
    'cpuz141.sys': {
        'tags': ['CPU-Z', 'MSR R/W'],
        'ioctls': [0x9C402480, 0x9C402484],
        'note': 'CPU-Z bundled driver.',
    },
    'speedfan.sys': {
        'tags': ['SpeedFan', 'port IO', 'phys'],
        'ioctls': [0x9C402420],
        'note': 'CVE-2007-5633.',
    },
    'viragtlt.sys': {
        'tags': ['VirtualGuard', 'arbitrary R/W'],
        'ioctls': [0x9C40A1C0, 0x9C40A1C4],
        'note': 'Abused by Lazarus (BYOVD).',
    },
    'ene.sys': {
        'tags': ['ENE Tech', 'phys/MSR'],
        'ioctls': [0x80102040, 0x80102050],
        'note': 'BYOVD candidate.',
    },
    'gmer.sys': {
        'tags': ['GMER', 'kernel hooks'],
        'ioctls': [],
        'note': 'Anti-rootkit; abused defensively.',
    },
    'segwindrvx64.sys': {
        'tags': ['Segger J-Link', 'phys R/W'],
        'ioctls': [0x9C400A48, 0x9C400A4C],
        'note': 'Phys-mem primitives.',
    },
    'phymemx64.sys': {
        'tags': ['phys memory'],
        'ioctls': [0x9C402AC0, 0x9C402AC4, 0x9C402AC8],
        'note': 'PhyMem.sys / variants.',
    },
}


def _ensure_cache():
    os.makedirs(_CACHE_DIR, exist_ok=True)


def _load_cache():
    if not os.path.isfile(_CACHE_FILE):
        return None
    try:
        if time.time() - os.path.getmtime(_CACHE_FILE) > _CACHE_TTL:
            return None
        with open(_CACHE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def _fetch_remote():
    try:
        try:
            from urllib.request import urlopen
        except ImportError:
            from urllib2 import urlopen  # py2 fallback (Binja old)
        log_info("[loldrivers] fetching {}".format(_LOL_URL))
        with urlopen(_LOL_URL, timeout=15) as resp:
            data = resp.read().decode('utf-8', errors='replace')
        parsed = json.loads(data)
        _ensure_cache()
        with open(_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(parsed, f)
        return parsed
    except Exception as e:
        log_warn("[loldrivers] fetch failed: {}".format(e))
        return None


def _index_remote(db):
    """Build sha256 -> entry and filename -> entry from LOL JSON."""
    by_sha, by_name = {}, {}
    if not isinstance(db, list):
        return by_sha, by_name
    for entry in db:
        try:
            tags = entry.get('Tags', [])
            cves = entry.get('KnownVulnerableSamples', []) or []
            for samp in cves:
                sha = (samp.get('SHA256') or '').lower()
                if sha:
                    by_sha[sha] = entry
                fn = (samp.get('Filename') or '').lower()
                if fn:
                    by_name.setdefault(fn, []).append(entry)
            for nm in entry.get('CommandLines', []) or []:
                pass
        except Exception:
            continue
    return by_sha, by_name


def _file_sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _pe_original_filename(bv):
    # Try Binja's metadata first
    try:
        md = bv.metadata
        if md and 'OriginalFilename' in md:
            return str(md['OriginalFilename']).lower()
    except Exception:
        pass
    # Scan VS_VERSION_INFO strings (UTF-16LE 'OriginalFilename')
    try:
        for s in bv.strings:
            v = s.value
            if 'OriginalFilename' in v:
                # Adjacent string is the value; just return raw - caller treats as hint
                return v.lower()
    except Exception:
        pass
    return None


def _collect_ioctls(bv):
    from .win_vuln_finder import _find_dispatch_routines, _find_ioctls
    codes = set()
    for df in _find_dispatch_routines(bv):
        for c in _find_ioctls(df):
            codes.add(c & 0xFFFFFFFF)
    return codes


def _device_names(bv):
    names = set()
    for s in bv.strings:
        try:
            v = s.value.lower()
            if v.startswith('\\device\\') or v.startswith('\\dosdevices\\') or v.startswith('\\??\\'):
                names.add(v)
        except Exception:
            pass
    return names


def check_loldrivers(bv: BinaryView):
    lines = [
        "=== LOLDrivers Fingerprint Check ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report = os.path.join(log_dir, drv + '-loldrivers.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    # ---- Load DB ----
    db = _load_cache()
    if db is None:
        db = _fetch_remote()
    if db is None:
        emit("[!] Network + cache unavailable. Using embedded mini-DB only.")
        by_sha, by_name = {}, {}
    else:
        by_sha, by_name = _index_remote(db)
        emit("[+] LOL DB entries: sha256={}, filenames={}".format(len(by_sha), len(by_name)))

    # ---- Match by sha256 ----
    path = bv.file.original_filename or bv.file.filename
    sha = _file_sha256(path)
    if sha:
        emit("[>] File SHA256: {}".format(sha))
        if sha in by_sha:
            e = by_sha[sha]
            emit("    [HIT] LOLDrivers entry: {}".format(e.get('Id', '?')))
            emit("          Tags: {}".format(", ".join(e.get('Tags', []) or [])))
            emit("          CVEs: {}".format(", ".join(e.get('CVE', []) or [])))
        else:
            emit("    (no sha256 match)")

    # ---- Match by original filename / on-disk filename ----
    candidates = set()
    on_disk = os.path.basename(path).lower()
    if on_disk:
        candidates.add(on_disk)
    orig = _pe_original_filename(bv)
    if orig:
        candidates.add(orig)
    emit("[>] Filename candidates: {}".format(", ".join(sorted(candidates))))
    for cand in candidates:
        if cand in by_name:
            for e in by_name[cand]:
                emit("    [HIT] LOL by name '{}': {}".format(cand, e.get('Id', '?')))
                emit("          Tags: {}".format(", ".join(e.get('Tags', []) or [])))
        if cand in _EMBEDDED:
            e = _EMBEDDED[cand]
            emit("    [HIT] Embedded DB '{}': {}".format(cand, ", ".join(e['tags'])))
            emit("          Note: {}".format(e['note']))
            emit("          Known IOCTLs: {}".format(
                ", ".join("0x{:08X}".format(c) for c in e['ioctls'])))

    # ---- IOCTL overlap with embedded curated list ----
    found_ioctls = _collect_ioctls(bv)
    emit("[>] Driver IOCTLs discovered: {}".format(len(found_ioctls)))
    overlaps = []
    for fn, e in _EMBEDDED.items():
        overlap = found_ioctls & set(e['ioctls'])
        if overlap:
            overlaps.append((fn, e, overlap))
    if overlaps:
        emit("[>] IOCTL overlap with known vulnerable drivers (possible clone/repack):")
        for fn, e, overlap in overlaps:
            emit("    {} overlap {} -> tags: {}".format(
                fn, ["0x{:08X}".format(c) for c in sorted(overlap)],
                ", ".join(e['tags'])))
    else:
        emit("    (no IOCTL overlap)")

    # ---- Device-name overlap ----
    dnames = _device_names(bv)
    if dnames:
        emit("[>] Device names: {}".format(", ".join(sorted(dnames))))
        suspicious = [n for n in dnames if any(
            kw in n for kw in ['rtcore', 'gdrv', 'asrdrv', 'mhyprot', 'capcom',
                               'winring0', 'phymem', 'speedfan', 'dbutil', 'iqvw'])]
        if suspicious:
            emit("    [WARN] Device-name lexical match to known vuln drivers: {}".format(
                ", ".join(suspicious)))

    try:
        with open(report, 'w') as f:
            f.write("\n".join(lines))
        emit("[+] Report: {}".format(report))
    except Exception as e:
        log_warn("write fail: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\LOLDrivers Check",
    "Match binary against loldrivers.io DB (sha256 + filename + IOCTL pattern)",
    check_loldrivers,
)
