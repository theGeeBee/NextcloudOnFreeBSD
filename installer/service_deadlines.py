"""Fresh owned-jail controls; command completion is never jail/readiness proof.

No pipe-EOF wait and no default reaper around daemon launch. Callers retain their
ownership guards and must contain a failed launch before further resource writes.
An unclosed host control persists a refusal, not permission to race containment.
"""

import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

from .state import atomic_json, config_digest, private_json
from .network import storage_guard
from .bastille import BASTILLE, CONFIG_PATH, configuration, owned_text, ruleset

JAIL_SECONDS = {"stop": 180, "start": 120, "restart": 240}
GRACE_SECONDS = 5
REFUSAL = "service-control-unresolved.json"
GUARD_DIRECTORY = "/usr/local/libexec"


class ServiceControlError(RuntimeError):
    def __init__(self, *, host_control_closed=True):
        self.host_control_closed = host_control_closed
        super().__init__("Owned jail control failed; containment/closure required" if host_control_closed
                         else "Host control closure uncertain; conflicting mutations are blocked")


def require_resolved(deployment):
    marker = deployment.state / REFUSAL
    if marker.exists() or marker.is_symlink():
        raise ServiceControlError(host_control_closed=False)


def _owned_text(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 65536):
        raise ValueError("Unsafe owned jail control configuration")
    return path.read_text()


def qualify(deployment, name, *, prepared=True, removal_guard=None):
    """Accept only the generated 1.4.4 thick bridge topology, not legacy hooks.

    This is additional to caller ownership/JID/ZFS checks, not a replacement.
    Reject include/default blocks and unrecognized properties rather than trying
    to parse arbitrary jail.conf shell. Braces inside quoted epair hooks are data.
    """
    c = deployment.config
    number = ruleset(deployment.registry.host())
    if owned_text(CONFIG_PATH) != configuration(c, number):
        raise ValueError("Project Bastille configuration changed")
    if name not in c.jails or not re.fullmatch(r"[a-z][a-z0-9]{0,11}", name):
        raise ValueError("Not an exact selected jail")
    root = deployment.jail_root(name)
    text = _owned_text(root.parent / "jail.conf")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or lines[0] != name + " {" or lines[-1] != "}":
        raise ValueError("Unreviewed jail configuration topology")
    endpoint = next(item for item in c.jail_endpoints if item.name == name)
    host, peer = "e0a_" + name, "e0b_" + name
    hooks = {
        "exec.start = '/bin/sh /etc/rc';",
        "exec.stop = '/bin/sh /etc/rc.shutdown';",
        f'exec.prestart += "epair0=$(ifconfig epair create) && ifconfig ${{epair0}} up name {host} && ifconfig ${{epair0%a}}b up name {peer}";',
        f'exec.prestart += "ifconfig {endpoint.bridge} addm {host}";',
        f'exec.prestart += "ifconfig {host} description \\"vnet0 host interface for Bastille jail {name}\\"";',
        f'exec.poststop += "ifconfig {host} destroy";',
    }
    if prepared:
        hooks.add(f"exec.prepare = '/usr/local/libexec/{c.instance}-storage-guard {name}';")
    else:
        # Bastille create starts the jail even with --no-boot. Its initial stop
        # precedes mount/guard installation; require the exact private reservation
        # and an unfinished original provisioning phase, never infer adoption.
        if (deployment.state / 'allow-start').exists() or (deployment.state / 'allow-start').is_symlink():
            raise ValueError("Unprepared stop cannot bypass an installed start guard")
        intent = private_json(deployment.state / (name + '.creating.json'))
        journal = private_json(deployment.state / 'deployment.json')
        steps = journal.get('steps', {})
        if (intent != {'name': name, 'root': str(root), 'release': c.release}
                or journal.get('config_sha256') != config_digest(c)
                or steps.get('persistent mounts', {}).get('state') == 'complete'
                or not any(steps.get(phase, {}).get('state') in ('running', 'failed')
                           for phase in ('FreeBSD jail roots', 'persistent mounts'))):
            raise ValueError("Unprepared stop needs the original unfinished creation reservation")
    # jail.conf quoting may escape dollar signs; both mean the same literal hook.
    normalized = [line.replace('\\$', '$') for line in lines[1:-1]]
    actual = [line for line in normalized if line.startswith("exec.") and not
              line.startswith(("exec.consolelog = ", "exec.clean;"))]
    if len(actual) != len(hooks) or set(actual) != hooks:
        raise ValueError("Unreviewed jail hooks; bounded mutation refused")
    scalar = (r'(?:enforce_statfs|devfs_ruleset|securelevel) = [0-9]+;|'
              r'(?:exec.clean|mount.devfs|vnet|allow.raw_sockets);|'
              r'exec.consolelog = /[A-Za-z0-9_./-]+;|'
              r'host.hostname = [A-Za-z0-9_.-]+;|'
              r'osrelease = "[A-Za-z0-9_.-]+";|sysvsem = (?:"new"|new);|'
              r'vnet.interface = [a-zA-Z0-9_]+;|(?:mount.fstab|path) = /[A-Za-z0-9_./-]+;')
    other = [line for line in normalized if line not in hooks]
    keys = {line.split()[0].rstrip(';') for line in other}
    required = {"enforce_statfs", "devfs_ruleset", "exec.clean", "exec.consolelog",
                "host.hostname", "mount.devfs", "mount.fstab", "path", "securelevel",
                "osrelease", "vnet", "vnet.interface"}
    if (any(not re.fullmatch(scalar, line) for line in other)
            or len(keys) != len(other) or not required <= keys):
        raise ValueError("Unreviewed jail parameter/background/dependency setting")
    if (f"path = {root};" not in normalized or f"vnet.interface = {peer};" not in normalized
            or f"mount.fstab = {root.parent}/fstab;" not in normalized
            or f"devfs_ruleset = {number};" not in normalized):
        raise ValueError("Jail path/interface changed")
    if prepared:
        guard = Path(GUARD_DIRECTORY) / (c.instance + "-storage-guard")
        text = _owned_text(guard)
        if (hashlib.sha256(text.encode()).hexdigest() != removal_guard if removal_guard is not None
                else text != storage_guard(c, deployment.storage, deployment.registry.root)):
            raise ValueError("Owned synchronous storage guard changed")
    # stop.sh scans ALL settings and recursively stops reverse dependencies; it
    # also writes a missing depend key. Refuse that collateral mutation topology.
    for jail in root.parent.parent.iterdir():
        if jail.is_symlink() or not jail.is_dir():
            raise ValueError("Unreviewed Bastille jail directory")
        settings = _owned_text(jail / "settings.conf")
        if (not re.fullmatch(r'(?:\s*(?:boot="(?:on|off)"|depend=""|priority="[0-9]+")\s*)+', settings)
                or settings.count('depend=""') != 1):
            raise ValueError("Unreviewed Bastille settings/dependencies")
    for filename in ("zfs.conf", "rdr.conf", "rctl.conf", "cpuset.conf"):
        path = root.parent / filename
        if (path.exists() or path.is_symlink()) and _owned_text(path).strip():
            raise ValueError("Unreviewed Bastille auxiliary control settings")


def _control(argv, seconds, *, quiet):
    """Own a new group; keep leader unreaped until all failure signaling ends.

    Group closure covers qualified synchronous host work, NOT detached host hooks
    or daemon descendants. Those are excluded by qualify; jail processes require
    separate owned-jail containment. Output never participates in completion.
    """
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL if quiet else None,
                               stderr=subprocess.DEVNULL if quiet else None,
                               start_new_session=True, close_fds=True, umask=0o022,
                               env={"PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
                                    "LC_ALL": "C"})
    deadline = time.monotonic() + seconds
    try:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError
            found = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if found is not None:
                if found.si_code != os.CLD_EXITED or found.si_status != 0:
                    raise ServiceControlError
                break
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    except BaseException as error:
        # Do not poll()/wait() before signaling: the reserved leader PID prevents
        # a reused numeric PGID from ever being targeted by this failure path.
        try:
            for sig in (signal.SIGTERM, signal.SIGCONT):
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    pass  # The reserved leader may already be a zombie.
            time.sleep(GRACE_SECONDS)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
            # No more signals after reap. Only observe this numeric group; if it
            # remains (including an uninterruptible member), fail unresolved.
            limit = time.monotonic() + 10
            while True:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= limit:
                    raise ServiceControlError(host_control_closed=False)
                time.sleep(0.05)
        except BaseException:
            raise ServiceControlError(host_control_closed=False) from None
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise ServiceControlError from None
    # Outside the cleanup-catching region: once reaped, never signal this PGID.
    return subprocess.CompletedProcess(argv, process.wait(), "", "")


def run_jail_action(runner, action, name, *, deployment, verify_stopped=None,
                    verify_running=None, prepared=True, removal_guard=None, **kwargs):
    """Run only authorized public controls; capture=True suppresses, not captures.

    Restart callbacks accept (name, remaining_seconds), verify closure/live state,
    and must honor the remaining budget. Existing application checks still follow.
    A failed/nonzero control requires host containment, even with check=False.
    """
    if action not in JAIL_SECONDS or runner is not deployment.runner:
        raise ValueError("Unsupported jail action/runner")
    if type(prepared) is not bool or (not prepared and action != 'stop'):
        raise ValueError("Only the initial reserved stop may be unprepared")
    if removal_guard is not None and (action != "stop" or not prepared):
        raise ValueError("The installed guard digest qualifies only prepared removal stops")
    if set(kwargs) - {"capture", "check", "hide_output", "progress_label"}:
        raise ValueError("Jail controls accept no input or arbitrary deadline")
    if action == "restart" and (not callable(verify_stopped) or not callable(verify_running)):
        raise ValueError("Restart requires independent closure and live checks")
    require_resolved(deployment)
    qualify(deployment, name, prepared=prepared, removal_guard=removal_guard)
    deadline = time.monotonic() + JAIL_SECONDS[action]

    def execute(selected):
        qualify(deployment, name, prepared=prepared, removal_guard=removal_guard)
        remaining = min(JAIL_SECONDS[selected], deadline - time.monotonic())
        if remaining <= 0:
            raise ServiceControlError
        if selected == "start":
            # Read-only status ignores the rc enable flag but never loads rules.
            # Stop remains available if the live set is missing/changed.
            runner.run("/usr/local/etc/rc.d/cloud_jails_guard", "onestatus",
                       timeout=min(10, remaining), hide_output=True)
            remaining = min(JAIL_SECONDS[selected], deadline - time.monotonic())
            if remaining <= 0:
                raise ServiceControlError
        try:
            result = _control((*BASTILLE, selected, name), remaining,
                              quiet=kwargs.get("capture", True) or kwargs.get("hide_output", False))
        except ServiceControlError as error:
            if not error.host_control_closed:
                atomic_json(deployment.state / REFUSAL,
                            {"jail": name, "action": selected, "state": "unresolved"})
            raise
        if result.returncode:
            raise ServiceControlError
        return result

    if action != "restart":
        return execute(action)
    execute("stop")
    verify_stopped(name, max(0, deadline - time.monotonic()))
    result = execute("start")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ServiceControlError
    verify_running(name, remaining)
    if time.monotonic() >= deadline:
        raise ServiceControlError
    return result
