"""Read-only admission of schema-34 iocage static shared-IP jails.

The persistent authority is the mounted pool/iocage dataset, defaults.json and
each jail's config.json, never /var/run/jail.ioc-*.conf or the iocage CLI (even
its getters can migrate configuration). See freebsd/iocage tag 1.13,
ioc_json.py:get_full_config/get_pool_and_iocroot and ioc_start.py:__start_jail__.
"""

import ipaddress
import json
import os
from pathlib import Path
import re
import stat


_ZFS_COLUMNS = "name,mountpoint,mounted,org.freebsd.ioc:active"
_LIMIT = 65536
_HOST_HOOKS = ("exec_prestart", "exec_poststart", "exec_prestop",
               "exec_poststop", "exec_created")
_BOOLEANS = set("""
bpf template host_time basejail dhcp vnet rtsold jail_zfs hostid_strict_check boot
exec_clean mount_linprocfs mount_procfs allow_vmm allow_tun allow_socket_af
allow_quotas allow_mount_zfs allow_mount_tmpfs allow_mount_procfs allow_mount_nullfs
allow_mount_fusefs allow_mount_devfs allow_mount_fdescfs allow_mount_linprocfs
allow_mount_linsysfs allow_mount allow_mlock allow_chflags allow_raw_sockets
allow_sysvipc allow_set_hostname allow_nfsd mount_fdescfs mount_devfs ip6_saddrsel
ip4_saddrsel ip_hostname assign_localhost nat
""".split())
# Schema keys, not package-version eligibility or a copy of upstream defaults.
# Unknown native/reflected jail parameters must not silently bypass admission.
_KEYS = set("""
CONFIG_VERSION CONFIG_TYPE interfaces host_domainname exec_fib ip4_addr
ip4_saddrsel ip4 ip6_addr ip6_saddrsel ip6 defaultrouter defaultrouter6 resolver
mac_prefix vnet0_mac vnet1_mac vnet2_mac vnet3_mac vnet_default_interface
devfs_ruleset exec_start exec_stop exec_prestart exec_poststart exec_prestop
exec_poststop exec_created exec_clean exec_timeout stop_timeout exec_jail_user
exec_system_jail_user exec_system_user mount_devfs mount_fdescfs enforce_statfs
children_max login_flags securelevel sysvmsg sysvsem sysvshm allow_set_hostname
allow_sysvipc allow_raw_sockets allow_chflags allow_mlock allow_mount
allow_mount_devfs allow_mount_fdescfs allow_mount_fusefs allow_mount_nullfs
allow_mount_procfs allow_mount_linprocfs allow_mount_linsysfs allow_mount_tmpfs
allow_mount_zfs allow_quotas allow_socket_af allow_tun allow_vmm allow_nfsd
cpuset rlimits memoryuse memorylocked vmemoryuse maxproc cputime pcpu datasize
stacksize coredumpsize openfiles pseudoterminals swapuse nthr msgqqueued msgqsize
nmsgq nsem nsemop nshm shmsize wallclock readbps writebps readiops writeiops
type bpf dhcp boot notes owner priority last_started template hostid
hostid_strict_check jail_zfs jail_zfs_mountpoint mount_procfs mount_linprocfs
count vnet basejail comment host_time sync_state sync_target sync_tgt_zpool
compression origin quota mountpoint compressratio available used dedup reservation
depends vnet_interfaces rtsold ip_hostname assign_localhost localhost_ip nat
nat_prefix nat_interface nat_backend nat_forwards plugin_name plugin_repository
min_dyn_devfs_ruleset vnet0_mtu vnet1_mtu vnet2_mtu vnet3_mtu vnet_default_mtu
host_hostname host_hostuuid release cloned_release jail_zfs_dataset source_template
""".split())


def _refuse(path, reason):
    raise ValueError(f"Cannot inspect iocage configuration {path}: {reason}; "
                     "administrator review of the persistent configuration is required, then Recheck")


def _text(path):
    from .host import _safe_path
    _safe_path(path, limit=_LIMIT)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or info.st_nlink != 1 or info.st_size > _LIMIT):
            _refuse(path, "opened input is not a bounded root-owned single-link regular file")
        try:
            text = stream.read(_LIMIT + 1)
        except UnicodeError:
            _refuse(path, "input is not UTF-8")
    if len(text.encode("utf-8")) > _LIMIT:
        _refuse(path, "input exceeds the size limit")
    return text


def _config(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _refuse(path, "duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(_text(path), object_pairs_hook=pairs)
    except (json.JSONDecodeError, RecursionError):
        _refuse(path, "invalid JSON object")
    if not isinstance(value, dict) or not value or set(value) - _KEYS:
        _refuse(path, "unknown schema properties or non-object configuration")
    for key, item in value.items():
        if item is None and key == "hostid":
            continue
        if type(item) not in (str, int, bool):
            _refuse(path, f"invalid property type: {key}")
        if key in _BOOLEANS:
            if str(item).lower() not in ("0", "off", "no", "false", "1", "on", "yes", "true"):
                _refuse(path, f"invalid boolean property: {key}")
        elif not isinstance(item, str):
            _refuse(path, f"expected a string property: {key}")
        if isinstance(item, str) and (len(item) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in item)):
            _refuse(path, f"invalid property text: {key}")
    return value


def _parameters(defaults, override, path):
    """Merge stored defaults exactly; never synthesize missing manager defaults."""
    kind = override.get("CONFIG_TYPE", "THIN")
    if (defaults.get("CONFIG_VERSION") != "34" or kind not in ("THIN", "THICK")
            or ("CONFIG_VERSION" in override and override["CONFIG_VERSION"] != "34")
            or (kind == "THICK" and override.get("CONFIG_VERSION") != "34")):
        _refuse(path, "unsupported schema (requires stored schema 34 defaults and compatible thin/thick overrides)")
    config = {**defaults, **override}
    def require(key, allowed):
        value = config.get(key)
        if value not in allowed or type(value) not in (str, int, bool):
            _refuse(path, f"unsupported or missing {key}")
    for key in ("basejail", "template", "vnet", "nat", "dhcp", "rtsold",
                "ip_hostname", "assign_localhost", "jail_zfs", "allow_mount",
                "allow_mount_zfs", "mount_procfs", "mount_linprocfs"):
        # ioc_common.check_truthy accepts case-insensitive strings. Reject
        # unrecognized values instead of interpreting malformed data as false.
        value = config.get(key)
        if type(value) not in (str, int, bool) or str(value).lower() not in ("0", "off", "no", "false"):
            _refuse(path, f"{key} must be explicitly disabled")
    require("type", ("jail",))
    require("children_max", ("0", 0))
    require("ip4", ("new",))
    require("ip6", ("new", "disable"))
    require("ip6_addr", ("none",))
    require("vnet_interfaces", ("none",))
    for key in ("sysvmsg", "sysvsem", "sysvshm"):
        require(key, ("new", "inherit", "disable"))
    # These strings are interpolated into iocage's native jail.conf without
    # escaping. Inspect their actual syntax, not just the absence of extra keys.
    for key in ("exec_timeout", "stop_timeout", "securelevel", "enforce_statfs"):
        value = config.get(key)
        pattern = r"-?[0-9]+" if key == "securelevel" else r"[0-9]+"
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            _refuse(path, f"invalid native numeric property: {key}")
    domain = config.get("host_domainname")
    if not isinstance(domain, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{0,253}", domain):
        _refuse(path, "invalid static domain name")
    for key in _HOST_HOOKS:
        require(key, ("/usr/bin/true",))
    # exec_start/exec_stop execute inside the jail, unlike the hooks above.
    # Their rc defaults are not host hooks and are never run by this inspector.
    name = path.parent.name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name) or config.get("host_hostuuid") != name:
        _refuse(path, "directory and host_hostuuid do not identify one jail")
    hostname = config.get("host_hostname")
    if not isinstance(hostname, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", hostname):
        _refuse(path, "invalid static hostname")
    addresses = config.get("ip4_addr")
    if not isinstance(addresses, str) or not addresses or len(addresses.split(",")) > 64:
        _refuse(path, "missing or excessive static IPv4 addresses")
    seen = set()
    for address in addresses.split(","):
        interface, separator, address = address.rpartition("|")
        if separator and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,14}", interface):
            _refuse(path, "invalid static address interface")
        try:
            ip = ipaddress.IPv4Interface(address)
        except ValueError:
            _refuse(path, "IPv4 addresses must be static literals")
        if ip.ip.is_unspecified or ip.ip.is_multicast or str(ip.ip) in seen:
            _refuse(path, "invalid or duplicate static IPv4 address")
        seen.add(str(ip.ip))
    number = config.get("devfs_ruleset")
    if type(number) not in (str, int) or not str(number).isdigit() or not 0 <= int(number) <= 65535:
        _refuse(path, "invalid devfs ruleset")
    return {"name": "ioc-" + name.replace(".", "_"), "path": str(path.parent / "root"),
            "host.hostname": hostname, "vnet": "inherit", "ip4": "new",
            "ip4.addr": addresses, "ip6": config["ip6"], "devfs_ruleset": str(number)}


def inventory(runner):
    """Return [(config Path, native jail parameter dict)], including stopped jails.

    Only trusted host zfs/mount queries and bounded owned-file reads are used.
    Query failures propagate; no package/CLI probe decides whether jails exist.
    """
    from .host import _safe_path
    datasets = {}
    for line in runner.output("zfs", "list", "-H", "-t", "filesystem", "-o", _ZFS_COLUMNS).splitlines():
        row = line.split("\t")
        if len(row) != 4 or row[0] in datasets or not row[0] or row[2] not in ("yes", "no"):
            _refuse("ZFS", "invalid dataset inventory")
        datasets[row[0]] = row[1:]
    if not datasets:
        _refuse("ZFS", "empty dataset inventory cannot establish absence of iocage")
    roots = [name for name in datasets if name.endswith("/iocage") and name.count("/") == 1]
    active = [name for name, row in datasets.items() if "/" not in name and row[2] == "yes"]
    if not roots and not active:
        return []
    if len(roots) != 1 or active != [roots[0].split("/")[0]]:
        _refuse("ZFS", "missing, inactive or ambiguous pool/iocage root")
    # get_pool_and_iocroot also recognizes the legacy pool comment. Do not
    # overlook a second authority or invoke iocage to convert that marker.
    pools = {}
    for line in runner.output("zpool", "list", "-H", "-o", "name,comment").splitlines():
        row = line.split("\t")
        if len(row) != 2 or row[0] in pools:
            _refuse("ZFS", "invalid pool inventory")
        pools[row[0]] = row[1]
    if (set(pools) != {name for name in datasets if "/" not in name}
            or any(comment == "iocage" and name != active[0] for name, comment in pools.items())):
        _refuse("ZFS", "changed pool inventory or ambiguous legacy iocage pool marker")
    dataset = roots[0]
    root = Path(datasets[dataset][0])
    mounts = [line.split() for line in runner.output("mount", "-p").splitlines()]
    if any(len(row) != 6 for row in mounts):
        _refuse(root, "invalid native mount inventory")

    def mounted(name, path):
        if (not path.is_absolute() or str(path) != datasets.get(name, [None])[0]
                or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path))
                or datasets[name][1] != "yes"):
            _refuse(path, "expected an exactly mounted dataset at a safe absolute path")
        _safe_path(path, directory=True)
        matches = [row for row in mounts if row[1] == str(path) or row[0] == name]
        if len(matches) != 1 or matches[0][:3] != [name, str(path), "zfs"]:
            _refuse(path, "dataset identity differs from the actual mount")

    def plain_file(path):
        if any(row[1] == str(path) for row in mounts):
            _refuse(path, "configuration file has an overriding mount")

    mounted(dataset, root)
    mounted(dataset + "/jails", root / "jails")
    plain_file(root / "defaults.json")
    defaults = _config(root / "defaults.json")
    if defaults.get("CONFIG_VERSION") != "34":
        _refuse(root / "defaults.json", "unsupported schema (requires stored schema 34)")
    paths = sorted((root / "jails").iterdir())
    if len(paths) > 1024:
        _refuse(root, "too many jail directories for bounded inspection")
    # Cross-check both directions so a hidden/unmounted stopped root cannot
    # disappear just because its mountpoint directory is empty or absent.
    jail_prefix = dataset + "/jails/"
    dataset_names = {name[len(jail_prefix):].split("/")[0]
                     for name in datasets if name.startswith(jail_prefix)}
    if dataset_names != {path.name for path in paths}:
        _refuse(root / "jails", "jail directories differ from the persistent dataset inventory")
    result, names = [], set()
    for path in paths:
        jail_dataset = jail_prefix + path.name
        if any(name.startswith(jail_dataset + "/") and name != jail_dataset + "/root" for name in datasets):
            _refuse(path, "only the ordinary jail/root dataset layout is supported")
        mounted(jail_dataset, path)
        mounted(jail_dataset + "/root", path / "root")
        for file in (path / "config.json", path / "fstab"):
            plain_file(file)
        parameters = _parameters(defaults, _config(path / "config.json"), path / "config.json")
        if parameters["name"] in names:
            _refuse(path, "jail names collide after iocage dot-to-underscore normalization")
        names.add(parameters["name"])
        if any(line.split("#", 1)[0].strip() for line in _text(path / "fstab").splitlines()):
            _refuse(path / "fstab", "only an empty/comment-only fstab is supported")
        # The supported thick root has no foreign nullfs/child data mounts.
        # iocage's standard kernel pseudo-filesystems are not host data aliases.
        for row in mounts:
            destination = Path(row[1])
            if path / "root" in destination.parents:
                allowed = {(str(path / "root/dev"), "devfs"),
                           (str(path / "root/dev/fd"), "fdescfs")}
                if (row[1], row[2]) not in allowed:
                    _refuse(path, "unsupported mount below the jail root")
        result.append((path / "config.json", parameters))
    return result
