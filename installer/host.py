"""FreeBSD host inspection, private state I/O and explicit command execution.

Importing this module has no side effects. No application command belongs on the
host: those commands run through Bastille in the two jail workers.
"""

import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import time

from .config import (STATE_DIR, IngressBinding, binding_conflicts, datasets,
                     ingress_bindings, ingress_conflicts, validate_talk_public_ip)
from .state import Registry, atomic_write, private_json


PF_FILE = "/etc/pf.cloud-installer.conf"
from .bastille import CONFIG_PATH as BASTILLE_CONF
SHARED_KEYS = ("pool", "external_interface", "management_network", "management_port", "host_reserved_mb")
NETWORK_SYSCTLS = {"net.inet.ip.forwarding": "1", "net.link.bridge.pfil_bridge": "1",
                   "net.link.bridge.pfil_member": "0", "net.link.bridge.pfil_local_phys": "0",
                   "net.link.bridge.pfil_onlyip": "1"}


class Runner:
    def run(self, *args, capture=True, check=True, timeout=3600, input=None, hide_output=False, progress_label=None):
        # Workers can echo private stdin even on success. Never inherit their
        # output streams, or include their diagnostics in an exception.
        private = input is not None or hide_output
        capture = capture or private
        try:
            options = {"text": True, "stdout": subprocess.PIPE if capture else None,
                       "stderr": subprocess.PIPE if capture else None, "umask": 0o022}
            command = [str(arg) for arg in args]
            if progress_label is None:
                result = subprocess.run(command, input=input, timeout=timeout, check=False, **options)
            else:
                result = self._with_progress(command, input, timeout, str(progress_label), options)
        except (subprocess.SubprocessError, OSError, UnicodeError) as error:
            if not private:
                raise
            message = "Private command timed out" if isinstance(error, subprocess.TimeoutExpired) else "Private command could not complete"
            # TimeoutExpired contains captured output. Suppress the exception
            # chain as well as its message; retained logs must not reveal it.
            if isinstance(error, (subprocess.TimeoutExpired, subprocess.CalledProcessError)):
                error.output = error.stderr = None
            raise RuntimeError(message) from None
        if check and result.returncode:
            if private:
                raise RuntimeError(f"Private command failed (exit status {result.returncode})")
            # Arguments are operational data only. Passwords/JWT never enter argv.
            detail = (result.stderr or "").strip()
            raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(map(str, args))}\n{detail}")
        return result

    @staticmethod
    def _with_progress(command, input, timeout, label, options):
        """A real elapsed-time heartbeat, without exposing private worker output."""
        started = time.monotonic()
        with subprocess.Popen(command, stdin=subprocess.PIPE if input is not None else None,
                              start_new_session=True, **options) as process:
            try:
                while True:
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    try:
                        stdout, stderr = process.communicate(input=input, timeout=min(30, remaining))
                        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                    except subprocess.TimeoutExpired:
                        input = None  # communicate retains its unsent input on retry.
                        elapsed = int(time.monotonic() - started)
                        print(f"  {label}: still running ({elapsed}s elapsed); private output is not displayed.", flush=True)
            except BaseException:
                # This unreaped child owns a private process group. Bound cleanup
                # even if a command descendant inherited the capture pipes.
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
                    process.wait(timeout=5)
                raise

    def output(self, *args):
        return self.run(*args).stdout.strip()


def require_host(runner):
    if os.geteuid() != 0 or runner.output("uname", "-s") != "FreeBSD":
        raise ValueError("Run the installer as root on the target FreeBSD host, not a development workstation")
    from .versions import load_policy, release_base, target
    release = release_base(runner.output("freebsd-version", "-u"))
    target(load_policy(), release, runner.output("uname", "-m"))
    if release_base(runner.output("freebsd-version", "-r")) != release:
        raise ValueError("Boot the matching updated FreeBSD kernel before installing jails")
    if runner.output("sysctl", "-n", "security.jail.jailed") != "0":
        raise ValueError("The entry point must run on the host, never inside a jail")


def inspect_host(runner):
    require_host(runner)
    pools = runner.output("zpool", "list", "-H", "-o", "name").splitlines()
    if not pools:
        raise ValueError("An existing ZFS pool is required; this installer never creates or formats pools")
    route = runner.output("route", "-n", "get", "default")
    match = re.search(r"^\s*interface:\s*(\S+)", route, re.MULTILINE)
    if not match:
        raise ValueError("Configure the host's IPv4 default route first")
    interface = match.group(1)
    addresses = re.findall(r"\binet\s+([0-9.]+)", runner.output("ifconfig", interface, "inet"))
    if not addresses:
        raise ValueError("The uplink needs an IPv4 address")
    dns = ""
    for line in Path("/etc/resolv.conf").read_text().splitlines():
        value = line.split()
        if len(value) >= 2 and value[0] == "nameserver":
            try:
                address = ipaddress.IPv4Address(value[1])
                if not address.is_loopback:
                    dns = str(address)
                    break
            except ValueError:
                continue
    ssh = os.environ.get("SSH_CONNECTION", "").split()
    if ssh and len(ssh) != 4:
        raise ValueError("Malformed SSH_CONNECTION; use a normal IPv4 SSH login or the local console")
    peer = ssh[0] if len(ssh) == 4 else ""
    if peer and ipaddress.ip_address(peer).version != 4:
        raise ValueError("Use an IPv4 SSH connection or local console; the initial managed policy does not support IPv6 ingress")
    if peer and (not 1 <= int(ssh[1]) <= 65535 or not 1 <= int(ssh[3]) <= 65535):
        raise ValueError("Invalid SSH connection ports")
    memory = int(runner.output("sysctl", "-n", "hw.physmem")) // (1024 * 1024)
    if memory <= 0:
        raise ValueError("Host memory inventory is invalid")
    storage = {pool: inspect_storage(runner, pool) for pool in pools}
    available = {pool: storage[pool]["datasets"][pool]["available"] // 1024 ** 3 for pool in pools}
    return {"freebsd_release": runner.output("freebsd-version", "-u").split("-p")[0],
            "architecture": runner.output("uname", "-m"),
            "pools": pools, "available_gib": available, "storage": storage,
            "interface": interface, "address": addresses[0],
            "interface_addresses": addresses, "dns": dns,
            "listener_bindings": inspect_ingress_listeners(runner),
            "memory_mb": memory, "ssh_peer": peer, "ssh_server": ssh[2] if peer else "", "ssh_connection": ssh or None,
            "management_network": peer + "/32" if peer else "",
            "ssh_port": int(ssh[3]) if len(ssh) == 4 else 22}


def inspect_storage(runner, pool):
    """Native, read-only sizing evidence; never sum recursive parent usage."""
    row = runner.output("zpool", "list", "-Hp", "-o", "size,allocated,free,health", pool).split()
    if len(row) != 4 or not all(value.isdigit() for value in row[:3]):
        raise ValueError(f"Cannot inspect pool capacity: {pool}")
    properties = ("used", "available", "referenced", "usedbysnapshots", "quota",
                  "refquota", "reservation", "refreservation")
    result = {"size": int(row[0]), "allocated": int(row[1]), "free": int(row[2]),
              "health": row[3], "datasets": {}}
    # Only inspect sizing parents on this destination, not a recursive inventory
    # of application/jail datasets or any remembered test-machine capacity.
    parents = [pool]
    for suffix in ("cloud-installer", "cloud-installer/instances",
                   "cloud-installer/bastille", "cloud-installer/bastille/jails"):
        name = pool + "/" + suffix
        if _zfs_exists(runner, name):
            parents.append(name)
    text = runner.output("zfs", "list", "-Hp", "-t", "filesystem", "-o",
                         "name," + ",".join(properties), *parents)
    for line in text.splitlines():
        values = line.split()
        if len(values) != len(properties) + 1:
            raise ValueError(f"Cannot inspect dataset capacity: {pool}")
        name = values[0]
        if name not in parents:
            raise ValueError(f"Unexpected sizing dataset: {name}")
        if name in result["datasets"] or not all(value.isdigit() for value in values[1:]):
            raise ValueError(f"Cannot inspect dataset capacity: {name}")
        result["datasets"][name] = dict(zip(properties, map(int, values[1:])))
    if set(result["datasets"]) != set(parents):
        raise ValueError(f"Missing destination sizing capacity: {pool}")
    return result


def write_private(path, contents, *, replace=False, mode=0o600):
    path = Path(path)
    if replace:
        atomic_write(path, contents, mode=mode)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    flags |= os.O_EXCL
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "w") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def read_private(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError(f"{path} must be an owner-only regular file owned by the invoking user")
    return path.read_text()


def state_directory(*, create=True):
    if STATE_DIR.exists() or STATE_DIR.is_symlink():
        info = STATE_DIR.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError(f"Unsafe state directory: {STATE_DIR}")
    elif create:
        STATE_DIR.mkdir(mode=0o700)
    else:
        raise ValueError("No installer state exists on this host")
    return STATE_DIR


def _exists(path):
    path = Path(path)
    return path.exists() or path.is_symlink()


def _safe_path(path, *, directory=False, private=False, limit=None):
    """Inspect host inputs without following symlinks, including their parents."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Expected an absolute path without parent traversal: {path}")
    try:
        for parent in reversed(path.parents):
            info = parent.lstat()
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or (info.st_mode & 0o022 and not sticky)):
                raise ValueError(f"Unsafe parent directory: {parent}")
        info = path.lstat()
        kind = stat.S_ISDIR if directory else stat.S_ISREG
        if not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o077 if private else 0o022):
            raise ValueError(f"Expected a safe root-owned {'directory' if directory else 'regular file'}: {path}")
        if limit is not None and info.st_size > limit:
            raise ValueError(f"Input exceeds its {limit}-byte limit: {path}")
        if not os.access(path, os.R_OK | (os.X_OK if directory else 0)):
            raise ValueError(f"Input is not readable: {path}")
    except OSError:
        raise ValueError(f"Cannot inspect readable host input: {path}") from None
    return path


def verify_certificate(config, runner):
    if config.ca_file:
        ca = _safe_path(config.ca_file, limit=1024 * 1024)
        if "PRIVATE KEY" in ca.read_text():
            raise ValueError("The CA trust bundle must never contain a private key")
        try:
            ssl.create_default_context(cafile=str(ca))
        except (OSError, ssl.SSLError):
            raise ValueError("The CA trust bundle is not a usable PEM certificate bundle") from None
    if config.tls_mode != "provided":
        return
    _safe_path(config.certificate_file, limit=1024 * 1024)
    _safe_path(config.private_key_file, private=True, limit=1024 * 1024)
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(config.certificate_file,
                                                             config.private_key_file, password="")
    except (OSError, ssl.SSLError):
        raise ValueError("The supplied certificate and unencrypted private key must form a valid matching pair") from None
    runner.run("openssl", "x509", "-in", config.certificate_file, "-noout", "-checkend", "604800",
               "-checkhost", config.public_hostname)
    command = ["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", config.public_hostname,
               "-untrusted", config.certificate_file]
    if config.ca_file:
        command.extend(["-CAfile", config.ca_file])
    runner.run(*command, config.certificate_file)


def verify_managed_network(registry, runner):
    """Read-only check of the committed transaction; return its resolved path.

    Preserve PF indentation and spaces: only trailing newlines are insignificant.
    Missing state is an error here; preflight decides whether a fresh host is OK.
    """
    from .firewall import verify_custom_children, verify_parent
    verify_parent(runner)
    root = Path(registry.root).resolve(strict=True)
    transactions = root / "transactions"
    active = root / "network/active"
    if not active.is_symlink() or transactions.is_symlink() or (root / "network").is_symlink():
        raise ValueError("Managed PF needs an active symlink into the registry transactions directory")
    try:
        target = active.resolve(strict=True)
        if transactions not in target.parents or not target.is_dir():
            raise ValueError("Active PF transaction escapes the registry transactions directory")
        directories = [root, root / "network", transactions]
        directories.extend(parent for parent in reversed(target.parents) if transactions in parent.parents)
        for directory in (*directories, target):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError(f"Unsafe managed network state directory: {directory}")
        read_private(target / "firewall-confirmed")
        if _exists(target / "firewall-rolled-back"):
            raise ValueError("Active PF transaction is marked rolled back")
        expected = {name: read_private(target / f"pf-{name}.expected")
                    for name in ("filter", "nat", "jails", "noninternet")}
        record = private_json(target / "firewall-transition.json")
        network = record.get("network") if isinstance(record, dict) else None
        if not isinstance(network, dict):
            raise ValueError("Committed PF policy source is missing or invalid")
        policy = network.get("pf_rules")
        if (record.get("architecture") != "coexistence-v1"
                or network.get("pf_file") != str(PF_FILE) or not isinstance(policy, str)
                or not policy.strip() or "\0" in policy):
            raise ValueError("Committed PF policy source is missing or invalid")
        if read_private(Path(PF_FILE)) != policy:
            raise ValueError("Managed PF disk policy differs from its committed source; restore that exact policy before continuing")
    except (OSError, RuntimeError):
        raise ValueError("Managed PF has no readable committed transaction; inspect the retained network journal") from None
    if runner.run("pfctl", "-s", "Running", check=False).returncode:
        raise ValueError("The committed managed PF policy is not running")
    for name, args in (("filter", ("-sr",)), ("nat", ("-sn",)),
                       ("jails", ("-t", "cloud_jails", "-T", "show")),
                       ("noninternet", ("-t", "cloud_noninternet", "-T", "show"))):
        actual = runner.run("pfctl", "-a", "nextcloudonfreebsd", *args).stdout or ""
        if actual.rstrip("\n") != expected[name].rstrip("\n"):
            raise ValueError(f"Managed PF {name} differs from its committed snapshot; restore the managed policy before continuing")
    verify_custom_children(network, runner, files=True)
    for name, value in NETWORK_SYSCTLS.items():
        if runner.output("sysctl", "-n", name) != value:
            raise ValueError(f"Managed network sysctl changed: {name} must be {value}")
    return target


def _registry_plan(c, facts, registry, resume):
    registry.require_ownership()
    entries = [(other.validate(), status) for other, status in registry.entries() if status["state"] != "removed"]
    host = registry.host()
    if host is not None:
        if (not isinstance(host, dict) or host.get("schema_version") != c.schema_version
                or host.get("bastille_root") != c.bastille_root):
            raise ValueError("Managed host registry schema/Bastille root is inconsistent; no automatic migration is available")
        for key in SHARED_KEYS:
            if host.get(key) != getattr(c, key):
                raise ValueError(f"Shared host setting differs from the registry: {key}")
    saved = [(other, status) for other, status in entries if other.instance == c.instance]
    if resume and not saved:
        raise ValueError("Resume requires this instance's saved configuration and ownership journal")
    if saved:
        other, status = saved[0]
        if other != c:
            raise ValueError("Saved instance configuration differs; resume must use the unchanged registered configuration")
        if not resume and status["state"] != "configured":
            raise ValueError("Instance is already allocated; use Resume instead of a new installation")
    others = [other for other, _ in entries if other.instance != c.instance]
    names = {c.public_hostname, *(endpoint.hostname for endpoint in c.network_endpoints),
             *(endpoint.name for endpoint in c.network_endpoints)}
    if c.native_office:
        names.add(c.onlyoffice_host)
    elif c.has_office:
        from .office_vm import candidate_vm_names
        names.add(candidate_vm_names(c.instance)['vm'])
    for other in others:
        for key in SHARED_KEYS:
            if getattr(other, key) != getattr(c, key):
                raise ValueError(f"Shared host setting {key} conflicts with registered instance {other.instance}")
        if c.network.overlaps(other.network):
            raise ValueError(f"Private network overlaps registered instance {other.instance}")
        if set(c.bridges) & set(other.bridges):
            raise ValueError(f"Bridge name conflicts with registered instance {other.instance}")
        other_names = {other.public_hostname, *(endpoint.hostname for endpoint in other.network_endpoints),
                       *(endpoint.name for endpoint in other.network_endpoints)}
        if other.native_office:
            other_names.add(other.onlyoffice_host)
        elif other.has_office:
            from .office_vm import candidate_vm_names
            other_names.add(candidate_vm_names(other.instance)['vm'])
        if names & other_names:
            raise ValueError(f"Jail/public hostname conflicts with registered instance {other.instance}")
        if ingress_conflicts(c, other):
            raise ValueError(f"Ingress address/port conflicts with registered instance {other.instance}")
    bindings = ingress_bindings(c)
    reservations = list(facts.get("ingress_reservations", ())) + list(facts.get("listener_bindings", ()))
    reservations.append(IngressBinding("*", "tcp", c.management_port, c.management_port, "host SSH"))
    for left in bindings:
        for right in reservations:
            if binding_conflicts(left, right):
                raise ValueError(f"Ingress interval conflicts with host listener/reservation: "
                                 f"{left.address} {left.protocol} {left.start}-{left.end} ({left.role}) "
                                 f"conflicts with {right.role} {right.address} {right.start}-{right.end}. "
                                 "Choose a free address/port in Edit settings, or correct the host reservation "
                                 "in another session and Recheck; no service is rebound automatically.")
    configs = others + [c]
    memory = c.host_reserved_mb + sum(item.memory_budget_mb - item.host_reserved_mb for item in configs)
    if memory > facts["memory_mb"]:
        raise ValueError(f"Aggregate memory budgets ({memory} MiB, including one host reserve) exceed installed RAM ({facts['memory_mb']} MiB)")
    return host, entries, configs


def _ownership_journal(registry, c, status):
    if status["state"] in ("configured", "removed"):
        return False
    path = registry.instance_path(c.instance) / "deployment.json"
    if not _exists(path):
        return False
    journal = private_json(path)
    if (not isinstance(journal, dict) or journal.get("schema_version") != c.schema_version
            or journal.get("config_sha256") != registry.deployment_config_digest(c.instance)
            or not isinstance(journal.get("steps"), dict) or not journal["steps"]):
        raise ValueError(f"Invalid ownership journal for {c.instance}; inspect the retained instance state")
    return True


def _zfs_exists(runner, name):
    return runner.run("zfs", "list", "-H", name, check=False).returncode == 0


def _owned_dataset(runner, name, mountpoint, instance):
    for property_name, expected in (("org.cloud-installer:owner", "cloud-installer"),
                                    ("org.cloud-installer:instance", instance), ("mountpoint", mountpoint)):
        if runner.output("zfs", "get", "-H", "-o", "value", property_name, name) != expected:
            raise ValueError(f"Dataset ownership/mountpoint mismatch: {name} ({property_name}); existing data is never adopted")
    path = Path(mountpoint)
    if path.is_symlink() or (_exists(path) and (not path.is_dir() or path.resolve() != path)):
        raise ValueError(f"Unsafe dataset mountpoint: {path}")
    if instance == "shared" and _exists(path):
        _safe_path(path, directory=True)
    mounted = runner.output("zfs", "get", "-H", "-o", "value", "mounted", name)
    if mounted == "yes":
        rows = runner.output("df", "-P", mountpoint).splitlines()
        if not rows or not rows[-1].split() or rows[-1].split()[0] != name:
            raise ValueError(f"Dataset is not the actual filesystem at its managed mountpoint: {name}")
    elif mounted != "no" or (_exists(path) and any(path.iterdir())):
        raise ValueError(f"Unmounted managed dataset has an occupied/uncertain mountpoint: {name}")


def _zfs_number(runner, name, property_name):
    value = runner.output("zfs", "get", "-Hp", "-o", "value", property_name, name)
    if value in ("none", "-"):
        return 0
    if not value.isdigit():
        raise ValueError(f"Cannot account for dataset {property_name}: {name}")
    return int(value)


def _headroom(runner, name, planned):
    # Pool available already excludes used blocks. Reserve only remaining growth,
    # not the full quota again. Parent quotas include their children exactly once.
    quota = _zfs_number(runner, name, "quota")
    refquota = _zfs_number(runner, name, "refquota")
    used = _zfs_number(runner, name, "used")
    if not quota and not refquota:
        raise ValueError(f"Managed allocation has no quota/refquota: {name}; finish or repair its storage phase before resuming")
    return max(0, max(planned, quota, refquota) - used)


def _uncapped_dataset(runner, name):
    if any(_zfs_number(runner, name, prop) for prop in ("quota", "refquota")):
        raise ValueError(f"Expected intentionally uncapped dataset has a quota/refquota: {name}; inspect without changing saved settings")


def _ancestor_available(runner, name):
    """Find effective available space even before the planned dataset exists."""
    while "/" in name and not _zfs_exists(runner, name):
        name = name.rsplit("/", 1)[0]
    return _zfs_number(runner, name, "available")


def _check_storage(c, configs, owned, managed, resume, runner):
    shared = ((f"{c.pool}/cloud-installer", "/srv/cloud-installer"),
              (f"{c.pool}/cloud-installer/instances", "/srv/cloud-installer/instances"),
              (c.bastille_dataset, c.bastille_root))
    if any(item.has_office and not item.native_office for item in configs):
        from .office_vm import vm_paths
        paths=vm_paths(next(item for item in configs if item.has_office and not item.native_office))
        shared+=((paths['manager_dataset'],paths['manager_root']),)
    for name, mountpoint in shared:
        if _zfs_exists(runner, name):
            if not managed:
                raise ValueError(f"Shared dataset exists without the managed host registry: {name}; no automatic adoption")
            _owned_dataset(runner, name, mountpoint, "shared")
        elif _exists(mountpoint):
            raise ValueError(f"Existing shared mount path has no owned dataset: {mountpoint}")
    if _exists("/srv"):
        _safe_path("/srv", directory=True)
    required = 0
    jail_roots = {}
    for item in configs:
        permitted = item.instance in owned and (item.instance != c.instance or resume)
        storage = datasets(item)
        if len({value.name for value in storage}) != len(storage) or len({value.mountpoint for value in storage}) != len(storage):
            raise ValueError("Dataset/mountpoint collision in the deployment plan")
        existing = set()
        for dataset in storage:
            if _zfs_exists(runner, dataset.name):
                if not permitted:
                    raise ValueError(f"Existing dataset {dataset.name} requires Resume and its registered ownership journal")
                _owned_dataset(runner, dataset.name, dataset.mountpoint, item.instance)
                existing.add(dataset.name)
                if item.storage_policy == "optional":
                    if dataset.quota_gib:
                        # Retain refusal of missing expected caps. Caps are not
                        # reservations or a bound on uncapped sibling growth.
                        _headroom(runner, dataset.name, dataset.quota_gib * 1024 ** 3)
                    else:
                        _uncapped_dataset(runner, dataset.name)
            elif _exists(dataset.mountpoint):
                raise ValueError(f"Existing instance mount path has no owned dataset: {dataset.mountpoint}")
        planned = storage[0].quota_gib * 1024 ** 3
        if item.dataset_root in existing and _exists(item.mount_root):
            _safe_path(item.mount_root, directory=True)
        if item.storage_policy == "optional":
            if _ancestor_available(runner, item.dataset_root) <= 0:
                raise ValueError("No available space at the destination application storage parent")
        else:
            required += _headroom(runner, item.dataset_root, planned) if item.dataset_root in existing else planned
        for jail in item.jails:
            parent = f"{item.bastille_dataset}/jails/{jail}"
            root = f"{item.bastille_root}/jails/{jail}/root"
            share = item.jail_root_quota_gib(jail)
            planned = share * 1024 ** 3
            present = _zfs_exists(runner, parent)
            root_present = _zfs_exists(runner, parent + "/root")
            if present or root_present or _exists(Path(root).parent):
                if not permitted:
                    raise ValueError(f"Existing Bastille jail {jail} has no resumable registered ownership")
                reservation = owned[item.instance] / (jail + ".creating.json")
                if not _exists(reservation) or private_json(reservation) != {"name": jail, "root": root, "release": c.release}:
                    raise ValueError(f"Bastille jail {jail} has no matching creation reservation; refusing adoption")
                if present:
                    _owned_dataset(runner, parent, str(Path(root).parent), item.instance)
                if root_present:
                    _owned_dataset(runner, parent + "/root", root, item.instance)
                    # A refquota on the thick root can be tighter than its parent;
                    # inspect it as well without adding the same allocation twice.
                    root_quota = _zfs_number(runner, parent + "/root", "refquota")
                    if item.storage_policy == "optional" and not share:
                        _uncapped_dataset(runner, parent + "/root")
                    elif root_quota > planned:
                        raise ValueError(f"Jail root refquota exceeds its registered system budget: {jail}")
                    jail_roots[jail] = root
                elif _exists(root):
                    raise ValueError(f"Bastille jail root lacks its tagged ZFS dataset: {jail}; inspect/remove the incomplete instance")
            if item.storage_policy == "optional":
                if present:
                    if share:
                        _headroom(runner, parent, planned)
                    else:
                        _uncapped_dataset(runner, parent)
            else:
                required += _headroom(runner, parent, planned) if present else planned
        if item.storage_policy == "optional" and _ancestor_available(runner, item.bastille_dataset + "/jails") <= 0:
            raise ValueError("No available space at the destination jail storage parent")
    free = _zfs_number(runner, c.pool, "available")
    if required * 10 > free * 9:
        raise ValueError("Dataset quota headroom plus configured reservations exceeds 90% of currently available pool capacity; reduce reservations or free pool space")
    return jail_roots


def _inet_addresses(text):
    for address, mask in re.findall(r"\binet\s+([0-9.]+)\s+netmask\s+(0x[0-9a-fA-F]+|[0-9.]+)", text):
        mask = str(ipaddress.IPv4Address(int(mask, 16))) if mask.startswith("0x") else mask
        yield address, ipaddress.IPv4Network(address + "/" + mask, strict=False)


def _check_bridges(c, configs, owned, jail_roots, resume, runner, *, registry=None):
    allowed = {}
    for item in configs:
        endpoints = [(endpoint.bridge, endpoint.gateway, endpoint.name if endpoint.kind == "jail" else None)
                     for endpoint in item.network_endpoints]
        for bridge,gateway,jail in endpoints:
            result = runner.run("ifconfig", bridge, check=False)
            if result.returncode:
                continue
            if item.instance not in owned or (item.instance == c.instance and not resume):
                raise ValueError(f"Bridge already exists without resumable ownership: {bridge}")
            expected = (gateway, ipaddress.IPv4Network(gateway + "/30", strict=False))
            text = result.stdout or ""
            if list(_inet_addresses(text)) != [expected] or not re.search(rf"(?m)^{re.escape(bridge)}:", text):
                raise ValueError(f"Managed bridge {bridge} must have exactly its planned gateway/30")
            members = re.findall(r"\bmember:\s+(\S+)", text)
            if jail is None:
                from .office_vm import candidate_vm_names, native_vm_identity
                if len(members)>1 or any(not re.fullmatch(r'tap[0-9]+',member) for member in members):
                    raise ValueError(f'Managed VM bridge {bridge} has a foreign member/physical uplink')
                if members:
                    if registry is None:
                        raise ValueError('VM bridge inspection requires its private registry context')
                    from types import SimpleNamespace
                    from .resolution import _plan_inventory
                    plan=private_json(registry.evidence_path(item.instance,'versions.json'))
                    _plan_inventory(plan)
                    target=native_vm_identity(SimpleNamespace(config=item,state=owned[item.instance],registry=registry,runner=runner,versions=plan))
                    if not target['state'].startswith('Running ('):
                        raise ValueError('VM bridge has an active tap without its verified running VM')
                    name=candidate_vm_names(item.instance)['vm']
                    nic=runner.output('ifconfig',members[0])
                    descriptions=[line.strip() for line in nic.splitlines() if line.strip().startswith('description:')]
                    if descriptions!=['description: vmnet/'+name+'/0/'+name]:
                        raise ValueError('VM bridge tap identity differs from the selected runtime')
            elif any(member != "e0a_" + jail for member in members):
                raise ValueError(f"Managed bridge {bridge} has a foreign member/physical uplink")
            if jail is not None and members and jail not in jail_roots:
                raise ValueError(f"Managed bridge {bridge} has a member without its registered tagged jail root")
            if item.instance == c.instance:
                allowed[bridge] = expected
    return allowed


def _check_interface_routes(c, facts, allowed, runner):
    info = runner.output("ifconfig", c.external_interface, "inet")
    uplink_addresses = re.findall(r"\binet\s+([0-9.]+)", info)
    if c.ingress_address not in uplink_addresses:
        raise ValueError("Ingress IPv4 address is not assigned to the selected uplink")
    interface_config = runner.run("sysrc", "-n", "ifconfig_" + c.external_interface, check=False).stdout or ""
    if "DHCP" in interface_config.upper():
        raise ValueError("Configure a static uplink IPv4 address before installing jails")
    interface = None
    for line in runner.output("ifconfig", "-a", "inet").splitlines():
        match = re.match(r"^(\S+):", line)
        if match:
            interface = match.group(1)
        for address, network in _inet_addresses(line):
            if c.network.overlaps(network) and allowed.get(interface) != (address, network):
                raise ValueError("Private jail network overlaps a host interface network outside its owned bridges")
    for line in runner.output("netstat", "-rn", "-f", "inet").splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] == "default":
            continue
        try:
            # FreeBSD may abbreviate route destinations, e.g. 10/8.
            address, slash, prefix = fields[0].partition("/")
            if slash:
                address += ".0" * (4 - len(address.split(".")))
            network = ipaddress.IPv4Network(address + (slash + prefix if slash else "/32"), strict=False)
        except ValueError:
            continue
        if not network.prefixlen or not c.network.overlaps(network):
            continue
        direct = fields[1].startswith("link#")
        own_route = any(network == expected[1] and bridge in fields[3:] and direct
                        for bridge, expected in allowed.items())
        # Each bridge also installs a host route for its own local gateway.
        own_local = (network.prefixlen == 32 and "lo0" in fields[3:] and direct
                     and str(network.network_address) in {value[0] for value in allowed.values()})
        if not own_route and not own_local:
            raise ValueError("Private jail network overlaps an existing IPv4 route outside its owned bridges")
    if facts.get("ssh_peer"):
        if (ipaddress.IPv4Address(facts["ssh_peer"]) not in ipaddress.IPv4Network(c.management_network, strict=False)
                or c.management_port != facts["ssh_port"] or facts["ssh_server"] not in uplink_addresses):
            raise ValueError("The configured management network/port/uplink would not preserve this SSH connection")


def _check_jails(c, configs, owned, jail_roots, runner):
    import shlex
    from .bastille import HOST_HOOKS, inspect_vnet, static_settings
    selected = {jail for item in configs for jail in item.jails}
    bridges = {endpoint.bridge for item in configs for endpoint in item.network_endpoints}
    hostnames = {endpoint.hostname.lower().rstrip(".") for item in configs for endpoint in item.network_endpoints}
    reserved_paths = {Path("/srv/cloud-installer"), *(Path(item.mount_root) for item in configs),
                      *(Path(item.bastille_root) for item in configs)}
    def overlaps_storage(value):
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("External jail root must be absolute without traversal")
        # Include aliases through existing parent symlinks even when a stopped
        # jail's final root does not exist yet. Never reserve our future storage
        # under a second lexical path and then create over that reservation.
        paths = (path, path.resolve())
        return any(candidate == reserved or reserved in candidate.parents or candidate in reserved.parents
                   for candidate in paths for reserved in reserved_paths)
    declarations, vnets = {}, set()
    boot = Path("/usr/local/etc/rc.d") / ("cloud_" + c.instance + "_jails")
    if _exists(boot):
        _safe_path(boot)
        if c.instance not in owned:
            raise ValueError(f"Project jail boot service path is already occupied: {boot}")
    directories = {Path("/usr/local/bastille/jails")}
    native = {Path("/etc/jail.conf"), *Path("/etc/jail.conf.d").glob("*.conf")}
    # Read each administrator namespace without invoking its Bastille commands.
    for conf in Path("/usr/local/etc/bastille").glob("*.conf"):
        if str(conf) == BASTILLE_CONF:
            continue
        _safe_path(conf)
        static_settings(conf, bastille=True)
        value = runner.run("sysrc", "-f", str(conf), "-n", "bastille_jailsdir", check=False)
        if value.returncode or not value.stdout.strip().startswith("/"):
            raise ValueError(f"Cannot determine configured Bastille jail directory: {conf}; administrator review required")
        directories.add(Path(value.stdout.strip()))
    for directory in directories:
        if directory == Path(c.bastille_root, "jails"):
            raise ValueError("Administrator Bastille configuration points at the project jail directory")
        if _exists(directory):
            _safe_path(directory, directory=True)
            for path in directory.iterdir():
                if path.name in selected:
                    raise ValueError(f"Jail name is already configured in another Bastille namespace: {path.name}")
                if _exists(path / "jail.conf"):
                    native.add(path / "jail.conf")
    # Native jail -e expands includes/variables without creating or running jails.
    # Limit inspection to the native rc configuration and jail.conf.d locations.
    configured = runner.run("sysrc", "-n", "-s", "jail", "jail_conf", check=False).stdout.strip()
    if configured:
        if not configured.startswith("/"):
            raise ValueError("Native jail_conf must have an inspectable absolute path")
        native.add(Path(configured))
    configured_jails = []
    for conf in native:
        if not _exists(conf):
            continue
        _safe_path(conf)
        expanded = runner.run("jail", "-f", str(conf), "-e", "\t", check=False)
        # jail -e exits after load_config/show_jails, without running hooks. Its
        # exit status alone does not report every variable-expansion diagnostic.
        if expanded.returncode or expanded.stderr:
            raise ValueError(f"Cannot expand configured jail identities unambiguously: {conf}")
        for row in expanded.stdout.splitlines():
            try:
                fields = shlex.split(row)
            except ValueError:
                raise ValueError(f"Cannot inspect configured jail identities in {conf}") from None
            parameters = {}
            for field in fields:
                key, _, value = field.partition("=")
                if key in parameters:
                    raise ValueError(f"Duplicate expanded jail parameter in {conf}")
                parameters[key] = value
            configured_jails.append((conf, parameters))
    from .iocage import inventory as iocage_inventory
    iocage_jails = iocage_inventory(runner)
    iocage_names = {parameters["name"] for _, parameters in iocage_jails}
    if iocage_names & {parameters.get("name") for _, parameters in configured_jails}:
        raise ValueError("An iocage jail also has a native/Bastille declaration; make its persistent authority unambiguous, then Recheck")
    for conf, parameters in configured_jails + iocage_jails:
        if parameters.get("name") in selected:
            raise ValueError(f"Jail name is already configured in {conf}: {parameters['name']}")
        if parameters.get("host.hostname", "").lower().rstrip(".") in hostnames:
            raise ValueError(f"Jail hostname is already configured in {conf}")
        root = parameters.get("path", "")
        if overlaps_storage(root):
            raise ValueError(f"Configured foreign jail uses a project path: {conf}")
        name = parameters.get("name", "")
        if not name:
            raise ValueError(f"Configured foreign jail has no exact name: {conf}")
        if name in declarations and declarations[name] != parameters:
            raise ValueError(f"Conflicting configured foreign jail declarations: {name}; "
                             "make its persistent identity unambiguous, then Recheck")
        declarations[name] = parameters
        for key in ("interface", "vnet.interface"):
            if set(parameters.get(key, "").split(",")) & bridges:
                raise ValueError(f"Configured foreign jail reserves a project bridge: {conf}")
        if parameters.get("ip4.addr"):
            for address in parameters["ip4.addr"].split(","):
                interface, separator, address = address.rpartition("|")
                if separator and interface in bridges:
                    raise ValueError(f"Configured foreign jail reserves a project bridge: {conf}")
                try:
                    network = ipaddress.IPv4Network(address, strict=False)
                except ValueError:
                    raise ValueError(f"Configured jail address cannot be resolved statically: {conf}; administrator review required") from None
                if any(item.network.overlaps(network) for item in configs):
                    raise ValueError(f"Configured foreign jail address overlaps a project private network: {conf}")
        if "vnet" in parameters and parameters["vnet"] not in ("off", "false", "0", "disabled", "inherit"):
            inspect_vnet(parameters, configs)
            vnets.add(parameters["name"])
        elif any(parameters.get(key) for key in HOST_HOOKS):
            raise ValueError(f"External jail host hooks in {conf} are outside the reviewed static network declarations")
    directory = Path(c.bastille_root, "jails")
    if _exists(directory):
        _safe_path(directory, directory=True)
        # _check_storage has already checked each existing path's exact creation
        # reservation. A stray JSON file must not reserve arbitrary jail names.
        reserved = {jail for item in configs if item.instance in owned
                     for jail in item.jails}
        for path in directory.iterdir():
            if path.name not in reserved or path.is_symlink() or not path.is_dir():
                raise ValueError(f"Unmanaged or unsafe Bastille jail path: {path}")
    lines = runner.output("jls", "-h", "jid", "name", "path").splitlines()
    for line in lines:
        values = line.split()
        if values == ["jid", "name", "path"]:
            continue
        if not values:
            continue
        if len(values) != 3 or not values[0].isdigit() or int(values[0]) < 1:
            raise ValueError("Cannot interpret running jail name/root inventory")
        name, root = values[1:]
        if name in selected and jail_roots.get(name) != root:
            raise ValueError(f"Running jail name conflicts with the project reservation: {name}")
        if name not in selected and (overlaps_storage(root) or root in jail_roots.values()):
            raise ValueError(f"Foreign running jail occupies a project path: {name}")
        if name not in selected:
            declaration = declarations.get(name)
            if declaration is None:
                raise ValueError(f"Running foreign jail has no inspected persistent declaration: {name}; "
                                 "provide a supported static jail configuration or stop it, then Recheck")
            if root != declaration["path"]:
                raise ValueError(f"Running foreign jail root differs from its inspected configuration: {name}; "
                                 "correct the live/configured identity, then Recheck")
            # FreeBSD15.1's vnet is an E,jailsys parameter: new or inherit.
            # A restarted jail with the same name/root may have a different
            # namespace than its persistent declaration; never infer it here.
            args = ("jls", "-j", values[0], "-h", "jid", "name", "path", "vnet", "host.hostname")
            before = runner.output(*args).splitlines()
            rows = [row.split() for row in before if row.strip()]
            if (len(rows) != 2 or rows[0] != ["jid", "name", "path", "vnet", "host.hostname"]
                    or len(rows[1]) != 5 or rows[1][:3] != values):
                raise ValueError("External jail identity changed during read-only inspection")
            if rows[1][3] != ("new" if name in vnets else "inherit"):
                raise ValueError("External jail live network namespace differs from its inspected configuration")
            if rows[1][4].lower().rstrip(".") in hostnames:
                raise ValueError("Running foreign jail hostname conflicts with a project hostname")
            if name in iocage_names:
                # Host jls exports address arrays as comma-separated literals.
                # Never run a foreign binary to discover its live shared IPs.
                observed = runner.output(*args, "ip4.addr", "ip6.addr").splitlines()
                live = [row.split() for row in observed if row.strip()]
                if (len(live) != 2 or live[0] != rows[0] + ["ip4.addr", "ip6.addr"]
                        or len(live[1]) != 7 or live[1][:5] != rows[1]
                        or runner.output(*args).splitlines() != before):
                    raise ValueError("External iocage identity changed during read-only inspection")
                expected = {str(ipaddress.IPv4Interface(value.rsplit("|", 1)[-1]).ip)
                            for value in declaration["ip4.addr"].split(",")}
                try:
                    addresses = [str(ipaddress.IPv4Address(value)) for value in live[1][5].split(",")]
                except ValueError:
                    raise ValueError("Cannot interpret running iocage IPv4 inventory") from None
                # jls special_print uses '-' for empty arrays without -n/-q.
                if (live[1][4] != declaration["host.hostname"]
                        or set(addresses) != expected or len(addresses) != len(expected)
                        or live[1][6] != "-"):
                    raise ValueError("External iocage live hostname/address configuration differs from its persistent declaration")
        if name in vnets:
            # Host routes do not expose manual in-jail address changes.
            # FreeBSD 15.1 ifconfig -j inspects through the trusted HOST binary;
            # never execute a foreign jail's /sbin/ifconfig during preflight.
            observed = runner.run("/sbin/ifconfig", "-j", values[0], "-a", "inet", hide_output=True)
            if runner.output(*args).splitlines() != before:
                raise ValueError("External VNET identity changed during read-only inspection")
            addresses = list(_inet_addresses(observed.stdout))
            if (not re.search(r"(?m)^\S+: flags=", observed.stdout)
                    or len(re.findall(r"\binet\s", observed.stdout)) != len(addresses)):
                raise ValueError("Cannot interpret running external VNET IPv4 inventory")
            for _, network in addresses:
                if any(item.network.overlaps(network) for item in configs):
                    raise ValueError(f"Running external VNET address overlaps a project private network: {name}")


def _manager_ownership(c, registry, entries, owned, resume, runner):
    """The durable journal precedes pkg/sysrc, unlike host.json alone.

    Keep completed manager evidence after an instance is removed: Bastille and
    the shared hierarchy intentionally outlive the last pair of jails.
    """
    completed = partial = False
    for item, _ in registry.entries(include_removed=True):
        path = registry.instance_path(item.instance) / "deployment.json"
        if not _exists(path):
            continue
        data = private_json(path)
        if (not isinstance(data, dict) or data.get("schema_version") != item.schema_version
                or data.get("config_sha256") != registry.deployment_config_digest(item.instance)
                or not isinstance(data.get("steps"), dict)):
            raise ValueError(f"Invalid manager ownership journal for {item.instance}")
        steps = data["steps"]
        phase = steps.get("host prerequisites", {}).get("state")
        shared_complete = steps.get("shared ZFS hierarchy", {}).get("state") == "complete"
        completed |= shared_complete and phase == "complete"
        partial |= (item.instance == c.instance and item.instance in owned and resume and shared_complete
                    and phase in ("running", "failed"))
    if not completed and not partial:
        return False, False
    shared = (f"{c.pool}/cloud-installer", f"{c.pool}/cloud-installer/instances", c.bastille_dataset)
    # _check_storage already validated the ownership properties of every present
    # shared dataset. All three must exist before pkg can belong to our phase.
    if not all(_zfs_exists(runner, name) for name in shared):
        return False, False
    other_allocated = any(item.instance != c.instance and status["state"] not in ("configured", "removed")
                          for item, status in entries)
    partial = partial and not completed and not other_allocated and not _exists(registry.root / "network/active")
    return completed or partial, partial


def _check_host_policy(c, registry, managed, runner, *, manager_owned=False, manager_partial=False):
    installed = runner.run("pkg", "query", "%v", "bastille", check=False)
    if installed.returncode == 0:
        from .versions import manager_supported
        if not manager_supported((installed.stdout or "").strip()):
            raise ValueError("Installed Bastille is outside the reviewed command-layout policy; no implicit manager upgrade is allowed")
    if _exists(BASTILLE_CONF):
        if not managed or not manager_owned:
            raise ValueError("Existing Bastille configuration has no manager ownership journal; manual review is required")
        from .bastille import configuration, owned_text, ruleset
        if owned_text(BASTILLE_CONF) != configuration(c, ruleset(registry.host())):
            raise ValueError("Project Bastille configuration differs; inspect before resuming")
    elif manager_owned and not manager_partial:
        raise ValueError("Completed project Bastille configuration is missing; inspect before continuing")
    from .bastille import check_devfs
    check_devfs(runner, registry.host())
    active = Path(registry.root) / "network/active"
    committed = _exists(active)
    if committed:
        if not managed:
            raise ValueError("Active PF transaction has no managed host registry")
        verify_managed_network(registry, runner)
    from .firewall import BOOT_SCRIPT, verify_parent
    verify_parent(runner)
    if not committed:
        for args in (("-sr",), ("-sn",), ("-s", "Anchors"), ("-s", "Tables")):
            if runner.output("pfctl", "-a", "nextcloudonfreebsd", *args):
                raise ValueError("The project PF anchor is occupied without a committed ownership record; "
                                 "use the retained installer or correct the collision before Recheck")
    from .firewall import _starter_firewalls_clear
    if not _starter_firewalls_clear(runner):
        raise ValueError("IPFW/IPFilter/IPNAT is loaded, configured or cannot be inspected; "
                         "coexistence with another firewall is unsupported. Correct it before Recheck")
    for path, directory in ((PF_FILE, False), ("/usr/local/etc/cloud-jails", True),
                            ("/usr/local/etc/rc.d/cloud_jails_guard", False), (str(BOOT_SCRIPT), False)):
        if _exists(path):
            _safe_path(path, directory=directory, private=path == PF_FILE)
            if not managed and not (path == PF_FILE and all(
                    not line.split("#", 1)[0].strip() for line in Path(path).read_text().splitlines())):
                raise ValueError(f"Existing managed-resource path has no host ownership record: {path}")
    _check_devfs(managed, runner)


def _check_devfs(managed, runner):
    # The registry-aware check in _check_host_policy validates the reservation.
    # Retain this legacy callable seam without assuming ownership from a bool.
    from .bastille import check_devfs
    if not managed:
        check_devfs(runner)


def parse_ingress_listeners(text):
    """FreeBSD 15.1 sockstat default columns; no Linux ss/netstat fixtures.

    Provenance: freebsd-src releng/15.1 usr.bin/sockstat/{sockstat.1,main.c}.
    -46w -P tcp,udp includes connected and unconnected UDP (both bind ports);
    -w prevents address truncation. Default columns have USER COMMAND
    PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS (addresses occupy one token).
    """
    lines = text.splitlines()
    if not lines or lines[0].split() != ["USER", "COMMAND", "PID", "FD", "PROTO", "LOCAL", "ADDRESS", "FOREIGN", "ADDRESS"]:
        raise ValueError("Cannot determine host TCP/UDP listeners: unexpected FreeBSD sockstat header")
    result = []
    for line in lines[1:]:
        columns = line.split()
        if not columns:
            continue
        if len(columns) != 7 or columns[4] not in ("tcp4", "tcp6", "tcp46", "udp4", "udp6", "udp46"):
            raise ValueError("Cannot determine host TCP/UDP listener ownership")
        address, separator, port = columns[5].rpartition(":")
        address = address.strip("[]")
        if not separator:
            raise ValueError("Cannot determine host listener address/port")
        if address != "*":
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
            if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
                address = str(parsed.ipv4_mapped)
        # FreeBSD formataddr() emits '*' for port zero: an unbound socket does
        # not reserve any selected ingress port. Do not mistake it for all ports.
        if port == "*":
            continue
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("Cannot determine host listener address/port")
        result.append(IngressBinding(address, columns[4][:3], int(port), int(port), "host listener"))
    return tuple(result)


def inspect_ingress_listeners(runner):
    # No -j filter: host VNET PCBs include shared-IP jails; independent VNET
    # PCBs require jail_attach and are not host ingress reservations. In
    # particular, -j 0 would incorrectly omit shared-IP jail listeners.
    return parse_ingress_listeners(runner.output("sockstat", "-46w", "-P", "tcp,udp"))


def parse_redirect_reservations(text):
    """Bounded canonical pfctl output, not a PF policy interpreter.

    Simple numeric IPv4 TCP/UDP rdr destinations are reservations regardless of
    source restrictions. Unknown redirections/binat refuse, never imply free ports.
    Recursive output includes anchor braces; only our exact top-level anchor is
    excluded. Dynamic interfaces/tables/IPv6/comparisons need administrator review.
    """
    anchors, result = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        anchor = re.fullmatch(r'(?:nat|rdr|binat)-anchor "([^"\n]+)"(?: .*?)? \{', line)
        if anchor:
            anchors.append(anchor[1])
            continue
        if line == "}":
            if not anchors:
                raise ValueError("Cannot establish PF redirection reservations: unbalanced anchor output")
            anchors.pop()
            continue
        if anchors and anchors[0] == "nextcloudonfreebsd":
            continue
        if line.startswith(("nat ", "no nat ")):
            continue
        # Empty/nonexpanded calls cannot prove the target contains no redirects.
        match = re.fullmatch(
            r"rdr(?: on [A-Za-z0-9_.:-]+)? inet proto (tcp|udp) from .+? to "
            r"([0-9.]+)(?:/32)? port (?:= )?([0-9]+)(?::([0-9]+))? -> .+", line)
        if match is None:
            raise ValueError("Cannot safely establish foreign PF redirection reservations: "
                             "supported rdr uses numeric IPv4 destination and TCP/UDP port/range. "
                             "Review ambiguous rdr/binat/anchor rules with the administrator, then Recheck.")
        protocol, address, low, high = match.groups()
        address = str(ipaddress.IPv4Address(address))
        low, high = int(low), int(high or low)
        if not 1 <= low <= high <= 65535:
            raise ValueError("Invalid foreign PF redirection interval; administrator review required")
        result.append(IngressBinding(address, protocol, low, high, "foreign PF redirection"))
    if anchors:
        raise ValueError("Cannot establish PF redirection reservations: incomplete anchor output")
    return tuple(result)


def _check_ingress(c, runner):
    from .firewall import PF_ANCHOR, verify_persistent_parent
    import shlex
    parent = verify_persistent_parent(runner)
    persistent = []
    for line in runner.output("cat", parent).splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if words[0] == "rdr-anchor" and words[1:] != [PF_ANCHOR]:
            raise ValueError("Foreign rdr-anchor reservations cannot be established from this bounded "
                             "parent contract. Use explicit numeric IPv4 TCP/UDP redirections in the "
                             "parent RDR section, then reload and Recheck; no anchor is changed automatically")
        if words[0] in ("rdr", "binat") or words[:2] in (["no", "rdr"], ["no", "binat"]):
            # Admission covers configured-but-not-yet-loaded reservations too.
            # Literal roots only: do not interpret arbitrary PF macros/includes.
            persistent.extend(parse_redirect_reservations(" ".join(words)))
    reservations = (*inspect_ingress_listeners(runner),
                    *parse_redirect_reservations(runner.output("pfctl", "-a", "*", "-sn")),
                    *persistent)
    for binding in ingress_bindings(c):
        for other in reservations:
            if binding_conflicts(binding, other):
                raise ValueError(f"{other.role} reserves {other.address} {other.protocol} "
                                 f"{other.start}-{other.end}, conflicting with selected {binding.role} "
                                 f"{binding.address} {binding.start}-{binding.end}. "
                                 "Choose a free address/port in Edit settings or have the administrator "
                                 "correct the reservation, then Recheck; no service will be rebound.")


def _check_dns(c):
    """Retained call seam: public DNS is operator-managed, not host admission."""


def check_vm_disk_capacity(config, runner):
    """Admission against effective current ZFS headroom, not a reservation."""
    from .office_vm import vm_paths
    available = _ancestor_available(runner, vm_paths(config)['dataset'])
    if config.office_quota_gib:
        available = min(available, config.office_quota_gib * 1024**3)
    if available < config.office_vm_disk_gib * 1024**3:
        raise ValueError('Effective VM storage ancestor/selected dataset cap cannot accommodate guest disk capacity')


def preflight_vm(config, facts, runner, *, registry, resume=False):
    """Selected-only, read-only bhyve/resource checks; never load modules here."""
    if config.backend not in ('eurooffice','collabora'):
        return
    from .versions import vm_resource_policy
    from .office_vm import vm_paths, VM_RC_CONFIG, VM_RC_DIRECTORY, _vm_rc_context, _vm_rc_text
    minimum=vm_resource_policy(config)['minimum']
    if (config.office_vm_cpus<minimum['cpus'] or config.office_memory_mb<minimum['memory_mb']
            or config.office_vm_disk_gib<minimum['disk_gib']):
        raise ValueError('Selected VM allocation is below reviewed guest/container resource policy')
    cpus=runner.output('sysctl','-n','hw.ncpu')
    if not cpus.isdigit() or not 1<=config.office_vm_cpus<=int(cpus):
        raise ValueError('VM CPU allocation exceeds the inspected host capacity')
    if not resume:
        available=facts['available_gib'][config.pool]
        if config.office_quota_gib: available=min(available,config.office_quota_gib)
        if available<config.office_vm_disk_gib:
            raise ValueError('Current pool/selected VM dataset cap cannot accommodate guest disk capacity')
        check_vm_disk_capacity(config, runner)
    text=runner.run('dmesg',hide_output=True,timeout=10).stdout
    if not re.search(r'(?:SVM:[^\n]*\bNP\b|VT-x:[^\n]*\bEPT\b)',text):
        raise ValueError('Hardware/nested virtualization with second-level paging is unavailable on this target')
    loaded=runner.run('kldstat','-q','-m','vmm',check=False).returncode==0
    required='/dev/vmmctl' if loaded else '/boot/kernel/vmm.ko'
    if runner.run('/bin/test','-e',required,check=False).returncode:
        raise ValueError('Reviewed FreeBSD VMM control device/module is unavailable')
    paths=vm_paths(config)
    if VM_RC_DIRECTORY not in _vm_rc_context(runner):
        raise ValueError('VM rc startup directory is not enabled on this host')
    marker=(registry.host() or {}).get('vm_manager')
    configured=runner.run('sysrc','-n','vm_dir',check=False,hide_output=True)
    enabled=runner.run('sysrc','-n','vm_enable',check=False,hide_output=True)
    if marker is None and (configured.returncode==0 or enabled.returncode==0 or VM_RC_CONFIG.exists() or VM_RC_CONFIG.is_symlink()):
        raise ValueError('Refusing a foreign vm-bhyve manager configuration')
    if marker is not None:
        rc=_vm_rc_text(paths)
        import hashlib
        expected={'dataset':paths['manager_dataset'],'mountpoint':paths['manager_root'],
                  'rc_file':str(VM_RC_CONFIG),'rc_sha256':hashlib.sha256(rc.encode()).hexdigest()}
        if (not isinstance(marker,dict) or set(marker)!=set(expected)|{'guid'}
                or any(marker.get(key)!=value for key,value in expected.items())
                or not isinstance(marker.get('guid'),str) or not re.fullmatch(r'[1-9][0-9]{0,19}',marker['guid'])):
            raise ValueError('Shared VM manager ownership record differs from this host')
        if configured.returncode==0 or enabled.returncode==0:
            raise ValueError('Global VM configuration overrides the owned manager RC file')
        if VM_RC_CONFIG.exists() or VM_RC_CONFIG.is_symlink():
            if read_private(VM_RC_CONFIG)!=rc:
                raise ValueError('Owned VM manager RC settings changed')
        elif not resume:
            raise ValueError('Owned VM manager RC file is missing; explicitly resume its setup')
        for prop,value in (('guid',marker['guid']),('mountpoint',paths['manager_root']),
                           ('mounted','yes'),('org.cloud-installer:instance','shared')):
            if runner.output('zfs','get','-Hp','-o','value',prop,paths['manager_dataset'])!=value:
                raise ValueError('Shared VM manager dataset identity changed')


def preflight(config, facts, runner, *, registry=None, resume=False):
    """Validate a proposed/resumed instance without writes or resource adoption.

    Configured entries reserve names, networks, ports, memory and disk budget.
    Only registered journals and tagged datasets establish existing ownership.
    Success returns None; errors identify the conflicting resource/repair needed.
    """
    c = config.validate_provisioning()
    if c.talk and not c.talk_media_hostname:
        validate_talk_public_ip(c.talk_public_ip, live=True)
    c.require_jail_backend("Host preflight")
    if c.native_office and facts.get('memory_mb',8192) < 8192:
        raise ValueError("At least 8 GiB RAM is required for this combined deployment; 16 GiB or more is recommended")
    from .versions import load_policy, target
    environment = target(load_policy(), c.release, c.arch)
    if (facts.get("freebsd_release", c.release) != c.release
            or facts.get("architecture", c.arch) != c.arch):
        raise ValueError("Selected FreeBSD target differs from the detected host; no OS upgrade is performed")
    registry = registry if registry is not None else Registry()
    host, entries, configs = _registry_plan(c, facts, registry, resume)
    for item in configs:
        item.require_jail_backend("Shared host preflight")
    if _exists("/var/db/nextcloud-jails-installer"):
        raise ValueError("Legacy /var/db/nextcloud-jails-installer state exists; no automatic migration/adoption is supported")
    if c.pool not in facts["pools"] or runner.output("zpool", "list", "-H", "-o", "health", c.pool) != "ONLINE":
        raise ValueError("Select an ONLINE ZFS pool")
    preflight_vm(c,facts,runner,registry=registry,resume=resume)
    owned = {item.instance: registry.instance_path(item.instance) for item, status in entries
             if _ownership_journal(registry, item, status)}
    jail_roots = _check_storage(c, configs, owned, host is not None, resume, runner)
    for item in configs:
        guard = Path(f"/usr/local/libexec/{item.instance}-storage-guard")
        if _exists(guard):
            if item.instance not in owned or (item.instance == c.instance and not resume):
                raise ValueError(f"Existing storage guard has no resumable instance ownership: {guard}")
            _safe_path(guard)
    if not Path("/usr/share/zoneinfo", c.timezone).is_file():
        raise ValueError("Timezone is not present in the host zoneinfo database")
    for path in environment["pkgbase_keys"]:
        if not Path(path).is_file():
            raise ValueError("Install the selected FreeBSD release's trusted pkgbase keys from the OS distribution before bootstrapping jails")
    bridges = _check_bridges(c, configs, owned, jail_roots, resume, runner,registry=registry)
    _check_interface_routes(c, facts, bridges, runner)
    _check_jails(c, configs, owned, jail_roots, runner)
    manager_owned, manager_partial = _manager_ownership(c, registry, entries, owned, resume, runner)
    _check_host_policy(c, registry, host is not None, runner,
                       manager_owned=manager_owned, manager_partial=manager_partial)
    _check_ingress(c, runner)
    verify_certificate(c, runner)
    if c.jail_ssh:
        _safe_path(c.ssh_key_file, limit=1024 * 1024)
        runner.run("ssh-keygen", "-l", "-f", c.ssh_key_file, hide_output=True)
    if c.additional_fonts_dir:
        directory = _safe_path(c.additional_fonts_dir, directory=True)
        count = size = 0
        for path in directory.rglob("*"):
            _safe_path(path, directory=path.is_dir())
            if path.is_file():
                count += 1
                size += path.lstat().st_size
                if count > 4096 or size > 512 * 1024 ** 2:
                    raise ValueError("Additional fonts exceed 4096 files or the 512 MiB staging limit")


def write_json(path, value, *, replace=False):
    write_private(path, json.dumps(value, indent=2) + "\n", replace=replace)
