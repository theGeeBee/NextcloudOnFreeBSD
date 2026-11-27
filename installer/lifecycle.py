"""Explicitly confirmed removal. No data deletion is part of install/resume."""

import json
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from .deploy import OWNER
from .bastille import BASTILLE
from .state import Journal, atomic_json, config_digest, private_json
from .service_deadlines import require_resolved, run_jail_action


RUNTIME_STEPS = ("disable boot and stop instance", "withdraw instance firewall access",
                 "remove owned jail roots", "remove private bridges")
# Installer grace budget after stop, separate from the native stop-command
# deadline. Observed dying prisons outlasted 10s; 180s is a finite policy choice,
# not a FreeBSD clearance guarantee. Only verified kernel absence permits removal.
JAIL_TEARDOWN_SECONDS = 180
JAIL_POLL_SECONDS = 0.25
CONFIG_CLEANUP_STEP = "remove exact owned host configuration"


def _owned_file(path, *, digest=None, mode=None, remove_identity=None):
    """Read/unlink one bound regular file, never follow even a parent symlink.

    A missing leaf/parent is absence, not authority over a later replacement.
    The caller journals the returned identity BEFORE requesting unlink.
    """
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Owned helper requires an exact absolute path")
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    def identity(info):
        # Reading can legitimately update atime; all structural/write metadata
        # remains pinned, including sub-second timestamps.
        return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns]
    try:
        for component in path.parts[1:-1]:
            info = os.fstat(directory)
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                # Private workstation fixtures may have the system sticky /tmp
                # ancestor; no installed helper is ever placed in that directory.
                if not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                    raise ValueError("Unprotected owned-helper parent; cleanup refused")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            raise ValueError("Unprotected owned-helper directory; cleanup refused")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or info.st_mode & 0o022 or info.st_size > 131072
                    or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
                raise ValueError("Unsafe owned helper; cleanup refused")
            data = stream.read(131073)
            expected_identity = identity(info)
            parent = os.stat(path.parent, follow_symlinks=False)
            bound = os.fstat(directory)
            if (len(data) != info.st_size or (digest is not None and hashlib.sha256(data).hexdigest() != digest)
                    or identity(os.fstat(stream.fileno())) != expected_identity
                    or identity(os.stat(path.name, dir_fd=directory, follow_symlinks=False)) != expected_identity
                    or (parent.st_dev, parent.st_ino) != (bound.st_dev, bound.st_ino)
                    or path.parent.resolve() != path.parent):
                raise ValueError("Owned helper changed; cleanup refused")
            if remove_identity is not None:
                if expected_identity != remove_identity:
                    raise ValueError("Owned helper was replaced; cleanup refused")
                os.unlink(path.name, dir_fd=directory)
                os.fsync(directory)
            return data, expected_identity
    except FileNotFoundError:
        return None
    finally:
        os.close(directory)


def _remove_owned_file(journal, key, path, digest, *, mode=0o755):
    """Reconcile unlink interruption, but never adopt a post-cleanup replacement."""
    files = journal.data.setdefault("files", {})
    prior = files.get(key)
    current = _owned_file(path, digest=digest, mode=mode)
    if prior is not None and (not isinstance(prior, dict) or prior.get("path") != str(path)
                              or prior.get("sha256") != digest
                              or prior.get("state") not in ("authorized", "removed", "absent")):
        raise ValueError("Owned-helper cleanup checkpoint changed")
    if current is not None:
        if prior is not None and (prior.get("state") != "authorized" or prior.get("identity") != current[1]):
            raise ValueError("Owned helper reappeared/was replaced; cleanup refused")
        if prior is None:
            files[key] = dict(path=str(path), sha256=digest, state="authorized", identity=current[1])
            journal.save()
        _owned_file(path, digest=digest, mode=mode, remove_identity=files[key]["identity"])
    files[key] = dict(path=str(path), sha256=digest, state="removed" if current or prior else "absent")
    journal.save()


_NATIVE_CONTROL = '''. /etc/rc.subr
load_rc_config
case "$1:$2" in
    mysql-server:onestatus|mysql-server:onestop) ;;
    *) exit 70 ;;
esac
expected=/usr/local/etc/rc.d/mysql-server
found=0
for directory in /etc/rc.d $local_startup; do
    if [ -x "$directory/$1" ]; then
        [ "$directory/$1" = "$expected" ] || exit 70
        found=1; break
    fi
done
[ "$found" = 1 ] || exit 70
/usr/sbin/service "$@" < /dev/null > /dev/null 2>&1
native_status=$?
case "$native_status:$2" in 0:*) exit 0 ;; 1:onestatus) exit 42 ;; *) exit 70 ;; esac'''
_PROCESS_PROBE = '''/usr/bin/pgrep "$@" < /dev/null > /dev/null 2>&1
native_status=$?
case "$native_status" in 0) exit 0 ;; 1) exit 42 ;; *) exit 70 ;; esac'''
_MYSQL_WRAPPER = r"^/bin/sh /usr/local/bin/(mariadbd-safe|mysqld_safe)( |$)"


def _bounded_native(deployment, script, args, seconds):
    result = deployment.jail(deployment.config.nextcloud_jail,
        "/usr/bin/timeout", "-f", "-k", "5s", str(seconds) + "s", "/bin/sh", "-c", script,
        "removal-control", *args, check=False, hide_output=True, input="", timeout=seconds + 15)
    if result.returncode not in (0, 42):
        raise RuntimeError("Native shutdown outcome uncertain; roots/data retained")
    return result.returncode


def _processes_closed(deployment, *args, seconds=10):
    return _bounded_native(deployment, _PROCESS_PROBE, args, seconds) == 42


def _wait_database_closure(deployment, root):
    # rc waits for mariadbd, not the short-lived safe-wrapper's final cleanup.
    # Observe it finishing; never kill it or race a second stop command.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        server_closed = _processes_closed(deployment, "-x", "mariadbd|mysqld", seconds=min(10, remaining))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        wrapper_closed = _processes_closed(deployment, "-f", _MYSQL_WRAPPER, seconds=min(10, remaining))
        socket = root / "var/run/mysql/mysql.sock"
        if (time.monotonic() < deadline and server_closed and wrapper_closed
                and not socket.exists() and not socket.is_symlink()):
            return
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    raise RuntimeError("Database process/socket closure unconfirmed")


def _shutdown_nextcloud(deployment):
    """Observe native DB stop/closure; the following jail stop handles other services.

    This is not a quiesced application backup: HTTP/PHP can still be present until
    native jail shutdown. No database authentication or implicit start is needed.
    """
    root = deployment.jail_root(deployment.config.nextcloud_jail)
    try:
        socket = root / "var/run/mysql/mysql.sock"
        if (_processes_closed(deployment, "-x", "mariadbd|mysqld")
                and _processes_closed(deployment, "-f", _MYSQL_WRAPPER)
                and not socket.exists() and not socket.is_symlink()):
            # Packages/rc files can precede database configuration/initialization.
            # Proven absence permits partial removal, never invented clean history.
            return "unverified"
        script = _owned_file(root / "usr/local/etc/rc.d/mysql-server")
        if script is None or not script[1][4] & stat.S_IXUSR:
            raise RuntimeError("Database runtime exists without its owned executable stop script")
        clean = _bounded_native(deployment, _NATIVE_CONTROL, ("mysql-server", "onestatus"), 10) == 0
        if clean:
            if _bounded_native(deployment, _NATIVE_CONTROL, ("mysql-server", "onestop"), 180) != 0:
                raise RuntimeError("Native database stop failed")
        if _bounded_native(deployment, _NATIVE_CONTROL, ("mysql-server", "onestatus"), 10) != 42:
            raise RuntimeError("Native database service closure unconfirmed")
        _wait_database_closure(deployment, root)
        return "clean" if clean else "unverified"
    except Exception:
        raise RuntimeError("Nextcloud/database shutdown unconfirmed; roots/data retained; inspect privately before retry") from None


def _cleanup_owned_config(deployment, guard_sha256=None):
    from . import service_deadlines
    from .config import datasets
    from .network import storage_guard
    c = deployment.config
    journal = Journal(deployment.state / "removal-config.json", c, deployment.progress)
    def cleanup():
        from .bastille import cleanup_boot_service
        cleanup_boot_service(deployment, journal)
        if c.has_office and not c.native_office:
            from .office_vm import cleanup_vm_boot_service
            cleanup_vm_boot_service(deployment, journal=journal)
        path = Path(service_deadlines.GUARD_DIRECTORY) / (c.instance + "-storage-guard")
        digest = guard_sha256 or hashlib.sha256(storage_guard(c, datasets(c), deployment.registry.root).encode()).hexdigest()
        # attach_storage publishes this private executable as 0700; rc hooks
        # are 0755, but must not dictate the storage guard's different contract.
        _remove_owned_file(journal, "storage_guard", path, digest, mode=0o700)
    # Even completed cleanup MUST inspect a reappearing/replaced file.
    journal.run(((CONFIG_CLEANUP_STEP, cleanup),), checks={CONFIG_CLEANUP_STEP: cleanup})


def _removal_summary(deployment, retained):
    shutdown = "unverified"
    for filename in ("removal.json", "purge.json"):
        path = deployment.state / filename
        if path.exists() and private_json(path).get("database_shutdown") == "clean":
            shutdown = "clean"
    return {"data_retained": retained, "database_shutdown": shutdown, "owned_config_cleanup": "complete"}


def _kernel_jail(runner, name, root, *, timeout=2):
    """Absence requires a successful complete FreeBSD15.1 kernel inventory."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate kernel inventory field")
            value[key] = item
        return value

    try:
        result = runner.run("jls", "--libxo", "json", "-d", "jid", "name", "path", "dying",
                            check=False, timeout=timeout)
        if (result.returncode or not isinstance(result.stderr, str) or result.stderr or not isinstance(result.stdout, str)
                or len(result.stdout) > 4 * 1024 * 1024):
            raise ValueError("Kernel inventory command failed")
        data = json.loads(result.stdout, object_pairs_hook=unique)
        if (not isinstance(data, dict) or set(data) != {"__version", "jail-information"}
                or data["__version"] != "2" or not isinstance(data["jail-information"], dict)
                or set(data["jail-information"]) != {"jail"}):
            raise ValueError("Unsupported kernel inventory")
        rows = data["jail-information"]["jail"]
        if not isinstance(rows, list):
            raise ValueError("Invalid kernel inventory rows")
        names, jids, selected = set(), set(), None
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {"jid", "name", "path", "dying"}
                    or any(not isinstance(row[key], str) or not row[key] for key in row)
                    or not re.fullmatch(r"[1-9][0-9]*", row["jid"])
                    or not row["path"].startswith("/") or row["dying"] not in ("true", "false")
                    or row["name"] in names or row["jid"] in jids):
                raise ValueError("Ambiguous kernel jail identity")
            names.add(row["name"])
            jids.add(row["jid"])
            if row["path"] == str(root) and row["name"] != name:
                raise ValueError("Kernel jail name changed for the selected root")
            if row["name"] == name:
                if row["path"] != str(root):
                    raise ValueError("Kernel jail root identity changed")
                selected = {"jid": int(row["jid"]), "dying": row["dying"] == "true"}
        return selected
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, RecursionError):
        raise RuntimeError("Cannot verify kernel jail identity/absence; removal refused, roots retained") from None


def _wait_for_jail_exit(runner, name, root, expected_jid, *, deadline=None):
    """Wait only for the same dying jail; never retry stop or accept a live jail."""
    if deadline is None:
        deadline = time.monotonic() + JAIL_TEARDOWN_SECONDS
    announced = False
    while True:
        remaining = deadline - time.monotonic()
        # Other selected stops may have consumed this jail's grace. Observe
        # current absence once even then, but never renew its waiting budget.
        current = _kernel_jail(runner, name, root, timeout=min(2, remaining) if remaining > 0 else 2)
        if remaining > 0 and time.monotonic() >= deadline:
            raise RuntimeError(f"Jail {name} teardown timed out; roots retained. Retry removal after teardown clears")
        if current is None:
            return
        if current["jid"] != expected_jid:
            raise RuntimeError("Jail identity changed during teardown; roots retained")
        if not current["dying"]:
            raise RuntimeError("Jail did not stop; nothing will be destroyed")
        if remaining <= 0:
            raise RuntimeError(f"Jail {name} teardown timed out; roots retained. Retry removal after teardown clears")
        if not announced:
            print(f"Waiting up to {JAIL_TEARDOWN_SECONDS}s for jail {name} teardown...", flush=True)
            announced = True
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(JAIL_POLL_SECONDS, remaining))


def _runtime_removed(deployment, status):
    """Removal evidence survives switching workflows and a failed data-only purge."""
    c, state = deployment.config, deployment.state
    removed = status["state"] == "removed"
    for filename in ("removal.json", "purge.json"):
        path = state / filename
        if not path.exists() and not path.is_symlink():
            continue
        data = private_json(path)
        # Removal/purge journals bind the effective configuration at removal,
        # unlike the original installation journal retained by a successor.
        if (not isinstance(data, dict) or data.get("schema_version") != c.schema_version
                or data.get("config_sha256") != config_digest(c) or not isinstance(data.get("steps"), dict)):
            raise ValueError("Removal ownership journal does not match this instance configuration")
        steps = data["steps"]
        removed |= all(isinstance(steps.get(name), dict) and steps[name].get("state") == "complete"
                       for name in RUNTIME_STEPS)
    tombstone = state / "removed.json"
    if tombstone.exists() or tombstone.is_symlink():
        value = private_json(tombstone)
        # Legacy tombstones have no config digest; the private, permanently
        # reserved instance-state directory and exact dataset bind their identity.
        if (not isinstance(value, dict) or value.get("dataset") != c.dataset_root
                or type(value.get("data_retained")) is not bool
                or value.get("credentials_retained") is not True or value.get("backups_retained") is not True):
            raise ValueError("Removal tombstone does not match this instance")
        removed = True
    return removed


def _check_network_allocations(deployment):
    c = deployment.config
    bridges = set(c.bridges)
    for other in deployment.registry.network_configs(exclude=c.instance):
        if c.network.overlaps(other.network) or bridges & set(other.bridges):
            raise ValueError("Removal network allocations are now owned by another active instance")


def _checked_jails(deployment, names=None, *, stopped=False):
    """Validate all selected targets before quiescing/destruction, including stopped roots.

    Bastille 1.4.4 common.sh:set_target prefix-completes a missing target. Never
    invoke a targeted command using dataset existence or a previous checkpoint
    alone. list.sh supports `list -j path` (Name/Path); `-a` is deprecated and
    `list -j all` omits Name. No target argument is passed to this inventory.
    """
    c, runner = deployment.config, deployment.runner
    names = names if names is not None else c.jails
    mounts = [line.split() for line in runner.output("mount", "-p").splitlines()]
    candidates = []
    for name in names:
        root = deployment.jail_root(name)
        parent = f"{c.bastille_dataset}/jails/{name}"
        points = ((parent, root.parent), (parent + "/root", root))
        present = [runner.run("zfs", "list", "-H", dataset, check=False).returncode == 0
                   for dataset, _ in points]
        if not any(present):
            if root.parent.exists() or root.parent.is_symlink():
                raise ValueError("Unexpected non-ZFS jail remnants; inspect them manually rather than deleting arbitrary paths")
            if _kernel_jail(runner, name, root) is not None:
                raise ValueError("A live/dying jail has no owned storage; removal refused")
            continue
        intent = deployment.state / (name + ".creating.json")
        if (not intent.exists() or private_json(intent) != {"name": name, "root": str(root), "release": c.release}):
            raise ValueError("Refusing removal of an unreserved jail")
        if not all(present):
            raise ValueError("Incomplete jail datasets; removal requires the owned parent and root")
        descendants = runner.output("zfs", "list", "-H", "-o", "name", "-t", "filesystem,volume", "-r", parent).splitlines()
        if set(descendants) != {parent, parent + "/root"}:
            raise ValueError("Unexpected jail dataset descendants; recursive destruction refused")
        for dataset, point in points:
            for key, expected in ((OWNER, c.instance), ("org.cloud-installer:owner", "cloud-installer"),
                                  ("type", "filesystem"), ("mountpoint", str(point)), ("mounted", "yes")):
                if runner.output("zfs", "get", "-H", "-o", "value", key, dataset) != expected:
                    raise ValueError("Refusing an unowned jail dataset or changed/unmounted jail filesystem")
            if not point.is_dir() or point.resolve() != point:
                raise ValueError("Jail mountpoint must be its real directory")
            actual = [row[:3] for row in mounts if len(row) >= 3 and row[1] == str(point)]
            rows = runner.output("df", "-P", str(point)).splitlines()
            if (actual != [[dataset, str(point), "zfs"]] or not rows or not rows[-1].split()
                    or rows[-1].split()[0] != dataset):
                raise RuntimeError("Jail dataset is not its actual uncovered ZFS mount")
        allowed = {str(point): (dataset, "zfs") for dataset, point in points}
        if not stopped:
            allowed.update({str(root) + item.target: (item.mountpoint, "nullfs")
                            for item in deployment.storage if item.jail == name})
            allowed[str(root / "dev")] = ("devfs", "devfs")
        for row in mounts:
            if len(row) >= 3 and row[1].startswith(str(root.parent) + "/"):
                if allowed.get(row[1]) != (row[0], row[2]):
                    raise RuntimeError("Foreign or persistent jail mounts remain active; removal refused")
        conf = root.parent / "jail.conf"
        try:
            info = conf.lstat()
        except FileNotFoundError:
            raise ValueError("Missing owned jail.conf; refusing Bastille target resolution") from None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or info.st_nlink != 1):
            raise ValueError("jail.conf must be an owned regular file without group/other writes")
        if stopped and _kernel_jail(runner, name, root) is not None:
            raise RuntimeError("Jail restarted or is still dying; stop it before retrying removal")
        candidates.append((name, parent))
    if not candidates:
        return candidates
    try:
        inventory = json.loads(runner.output(*BASTILLE, "list", "-j", "path"))
    except ValueError:
        raise ValueError("Bastille did not return a valid named JSON jail inventory") from None
    if (not isinstance(inventory, list) or any(not isinstance(row, dict)
            or not isinstance(row.get("Name"), str) or not isinstance(row.get("Path"), str) for row in inventory)
            or len({row["Name"] for row in inventory}) != len(inventory)):
        raise ValueError("Bastille did not return an unambiguous named JSON jail inventory")
    paths = {row["Name"]: row["Path"] for row in inventory}
    for name, _ in candidates:
        if paths.get(name) != str(deployment.jail_root(name)):
            raise ValueError("Exact Bastille jail identity changed or is missing from inventory; removal refused")
    for name, _ in candidates:
        if runner.output(*BASTILLE, "config", name, "get", "path") != str(deployment.jail_root(name)):
            raise ValueError("Jail root identity changed; removal refused")
    return candidates


def _require_jail(deployment, name, *, stopped=False):
    require_resolved(deployment)
    if not _checked_jails(deployment, (name,), stopped=stopped):
        raise ValueError("Jail disappeared before its targeted Bastille mutation; removal refused")


def remove_instance(deployment, *, purge_data=False, confirmation):
    c, runner, registry = deployment.config, deployment.runner, deployment.registry
    phrase = ("PURGE " if purge_data else "REMOVE ") + c.instance
    if confirmation != phrase:
        raise ValueError("Instance removal requires the exact typed confirmation")
    previous = registry.status(c.instance)
    from .management import installed_guard
    guard_sha256 = installed_guard(registry, c)
    if guard_sha256 is not None:
        from .service_deadlines import GUARD_DIRECTORY
        path = Path(GUARD_DIRECTORY) / (c.instance + "-storage-guard")
        if _owned_file(path, digest=guard_sha256, mode=0o700) is None and previous["state"] == "ready":
            raise ValueError("Installed storage guard is missing")
    if previous["state"] == "removed" and (not purge_data or previous.get("data_retained") is False):
        _runtime_removed(deployment, previous)
        _cleanup_owned_config(deployment, guard_sha256)
        return _removal_summary(deployment, previous.get("data_retained", True))
    journal = Journal(deployment.state / ("purge.json" if purge_data else "removal.json"), c, deployment.progress)
    retained_flag = journal.data.get("runtime_already_removed", False)
    if type(retained_flag) is not bool:
        raise ValueError("Invalid runtime removal checkpoint")
    runtime_removed = _runtime_removed(deployment, previous) or retained_flag
    if not runtime_removed:
        _check_network_allocations(deployment)
    if "runtime_already_removed" not in journal.data or runtime_removed != retained_flag:
        journal.data["runtime_already_removed"] = runtime_removed
        journal.save()
    registry.set_status(c.instance, "removing", purge_data=purge_data)

    def stop():
        candidates = _checked_jails(deployment)
        uncertain = any(private_json(path).get("database_shutdown") == "uncertain"
                        for path in (deployment.state / "removal.json", deployment.state / "purge.json")
                        if path.exists() or path.is_symlink())
        if (uncertain
                and _kernel_jail(runner, c.nextcloud_jail, deployment.jail_root(c.nextcloud_jail)) is not None):
            raise RuntimeError("Previous Nextcloud shutdown is uncertain; roots/data retained. "
                               "Inspect and establish runtime absence before retrying removal")
        journal.data.setdefault("database_shutdown", "unverified")
        journal.save()
        if c.talk:
            candidates.sort(key=lambda item: item[0] != c.talk_jail)
        marker = deployment.state / "allow-start"
        if marker.exists():
            marker.rename(deployment.state / "allow-start.disabled")
        # Fence every verified selected jail before any sequential shutdown/wait:
        # failure on the first target must not leave later targets boot-enabled.
        for name, _ in candidates:
            _require_jail(deployment, name)
            runner.run(*BASTILLE, "config", name, "set", "boot", "off")
        from .bastille import disable_boot_service
        disable_boot_service(deployment)
        if c.has_office and not c.native_office:
            from .office_vm import vm_paths, detach_native_vm_datastore, disable_vm_boot_service
            disable_vm_boot_service(deployment)
            paths = vm_paths(c)
            intent = deployment.state / (paths['name']+'.creating.json')
            if intent.exists() or intent.is_symlink():
                # Unsealed creation is intentionally refused by the ownership
                # helper. Do not destroy a partial/uncertain guest to make remove
                # proceed, and never pass VM names to Bastille.
                vm_marker = deployment.state / 'allow-vm-start'
                if vm_marker.exists() or vm_marker.is_symlink():
                    vm_marker.rename(deployment.state / 'allow-vm-start.disabled')
                detach_native_vm_datastore(deployment)
            else:
                from pathlib import Path
                if Path(paths['root']).exists() or Path(paths['root']).is_symlink():
                    raise ValueError('VM storage exists without its creation reservation; removal refused')
        pending = []
        for name, _ in candidates:
            _require_jail(deployment, name)
            current = _kernel_jail(runner, name, deployment.jail_root(name))
            if current is not None and not current["dying"]:
                _require_jail(deployment, name)
                if deployment.require_running_jail(name) != current["jid"]:
                    raise RuntimeError("Jail identity changed before stop; roots retained")
                if name == c.nextcloud_jail:
                    journal.data["database_shutdown"] = "uncertain"
                    journal.save()  # An interrupted active stop must never imply clean retention.
                    journal.data["database_shutdown"] = _shutdown_nextcloud(deployment)
                    journal.save()
                run_jail_action(runner, "stop", name, deployment=deployment, capture=False,
                                removal_guard=guard_sha256)
            expected_jid = current["jid"] if current else None
            after = _kernel_jail(runner, name, deployment.jail_root(name))
            if after is not None:
                if after["jid"] != expected_jid:
                    raise RuntimeError("Jail identity changed during stop; roots retained")
                if not after["dying"]:
                    raise RuntimeError("Jail did not stop; nothing will be destroyed")
            pending.append((name, after["jid"] if after else None, time.monotonic() + JAIL_TEARDOWN_SECONDS))
        # Stop every selected jail before waiting for lingering kernel references.
        # A failed/uncertain control or changed/live identity above still halts.
        for name, expected_jid, deadline in pending:
            _wait_for_jail_exit(runner, name, deployment.jail_root(name), expected_jid, deadline=deadline)

    def withdraw_network():
        _check_network_allocations(deployment)
        # A completed stop checkpoint is not proof that endpoints stayed stopped
        # across an interruption. Never withdraw protection from a restarted jail
        # or a VM/foreign endpoint still attached to an owned bridge.
        _checked_jails(deployment, stopped=True)
        from .host import _inet_addresses
        import ipaddress
        for endpoint in c.network_endpoints:
            current = runner.run("ifconfig", endpoint.bridge, check=False)
            if current.returncode == 0 and ("member:" in current.stdout or
                    list(_inet_addresses(current.stdout)) != [
                        (endpoint.gateway, ipaddress.IPv4Network(endpoint.gateway + "/30", strict=False))]):
                raise ValueError("Owned bridge still has an endpoint or changed addresses; "
                                 "stop/inspect it before withdrawing project protection")
        # Old PF states can outlive a rule reload. Kill only this instance's
        # endpoints, never global management or another instance's states.
        def invalidate_endpoint_states():
            _check_network_allocations(deployment)
            if (registry.root / "network/active").exists():
                for endpoint in c.network_endpoints:
                    runner.run("pfctl", "-k", endpoint.ip)
                    runner.run("pfctl", "-k", "0.0.0.0/0", "-k", endpoint.ip)

        if c.custom_egress:
            # Stopped/identity-checked endpoints cannot create new egress. PF
            # states retain child-rule references, preventing leaf retirement.
            invalidate_endpoint_states()
        if any(item.instance == c.instance for item in registry.network_configs()):
            deployment.configure_network(removing=True)
        _check_network_allocations(deployment)
        if not c.custom_egress:
            invalidate_endpoint_states()  # Preserve markerless ordering.

    def destroy_roots():
        candidates = _checked_jails(deployment, stopped=True)
        # Validate both roots before destroying either, then recheck each exact
        # target. A completed stop checkpoint does not establish current mounts.
        for name, dataset in candidates:
            _require_jail(deployment, name, stopped=True)
            runner.run(*BASTILLE, "destroy", "-y", name, capture=False)
            if runner.run("zfs", "list", "-H", dataset, check=False).returncode == 0:
                raise RuntimeError("Bastille did not destroy the requested jail root")

    def clean_bridges():
        _check_network_allocations(deployment)
        for endpoint in c.network_endpoints:
            bridge, gateway = endpoint.bridge, endpoint.gateway
            cloned = runner.run("sysrc", "-n", "cloned_interfaces", check=False).stdout.split()
            configured = runner.run("sysrc", "-n", f"ifconfig_{bridge}", check=False)
            if bridge in cloned or configured.returncode == 0:
                raise ValueError("Administrator boot configuration now reserves an owned bridge; "
                                 "correct that entry before continuing removal. It will not be erased.")
            result = runner.run("ifconfig", bridge, check=False)
            if result.returncode == 0:
                if "member:" in result.stdout or f"inet {gateway} " not in result.stdout:
                    raise ValueError("Bridge identity changed or still has members; cleanup refused")
                runner.run("ifconfig", bridge, "destroy")

    def purge():
        if runner.run("zfs", "list", "-H", c.dataset_root, check=False).returncode:
            return
        actual = set(runner.output("zfs", "list", "-H", "-o", "name", "-r", c.dataset_root).splitlines())
        expected = {item.name for item in deployment.storage}
        if not actual or not actual <= expected:
            raise ValueError("Unexpected descendants exist below the instance dataset; purge refused")
        for name in actual:
            if runner.output("zfs", "get", "-H", "-o", "value", OWNER, name) != c.instance:
                raise ValueError("Unowned dataset encountered; purge refused")
        runner.run("zfs", "destroy", "-r", c.dataset_root, capture=False)
        if runner.run("zfs", "list", "-H", c.dataset_root, check=False).returncode == 0:
            raise RuntimeError("Instance data destruction did not finish")

    # A later purge of retained data must not touch network allocations that a
    # new instance may legitimately have reused since runtime removal.
    steps = [] if journal.data["runtime_already_removed"] else list(zip(
        RUNTIME_STEPS, (stop, withdraw_network, destroy_roots, clean_bridges)))
    # Separate journal preserves the historical meaning of RUNTIME_STEPS and
    # still reconciles cleanup after legacy completed removal / data-only retry.
    cleanup = lambda: _cleanup_owned_config(deployment, guard_sha256)
    steps.append((CONFIG_CLEANUP_STEP, cleanup))
    if purge_data:
        steps.append(("permanently destroy instance data and snapshots", purge))
    journal.run(steps, checks={CONFIG_CLEANUP_STEP: cleanup})
    atomic_json(deployment.state / "removed.json", {"data_retained": not purge_data,
                "dataset": c.dataset_root, "credentials_retained": True, "backups_retained": True})
    registry.set_status(c.instance, "removed", data_retained=not purge_data)
    return _removal_summary(deployment, not purge_data)
