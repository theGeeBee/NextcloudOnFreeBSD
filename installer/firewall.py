"""PF transition supervisor and isolated network worker, including repeat changes.

Only the worker holds mutation/commit locks. The detached supervisor owns that
child and its separate process group, kills/reaps it before rollback, and never
depends on the interactive installer releasing a lock. No application data is
rolled back or deleted. This module is copied into the private transaction state
so recovery does not depend on the checkout remaining accessible.
"""

import fcntl
import ipaddress
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid


PF_ANCHOR = "nextcloudonfreebsd"
PF_FILE = Path("/etc/pf.cloud-installer.conf")
BOOT_SCRIPT = Path("/usr/local/etc/rc.d/cloud_network")
PARENT_FILE = Path("/etc/pf.conf")
OWNERSHIP = "coexistence-v1"
BRIDGE_SYSCTLS = frozenset(("net.link.bridge.pfil_member", "net.link.bridge.pfil_bridge",
                           "net.link.bridge.pfil_local_phys", "net.link.bridge.pfil_onlyip"))
NETWORK_SYSCTLS = {"net.inet.ip.forwarding": "1", "net.link.bridge.pfil_member": "0",
                   "net.link.bridge.pfil_bridge": "1", "net.link.bridge.pfil_local_phys": "0",
                   "net.link.bridge.pfil_onlyip": "1"}
PF_SNAPSHOTS = (("filter", ("-sr",)), ("nat", ("-sn",)),
                 ("jails", ("-t", "cloud_jails", "-T", "show")),
                 ("noninternet", ("-t", "cloud_noninternet", "-T", "show")))
CUSTOM_DIRECTORY = Path("/etc/pf.nextcloud-custom")
CUSTOM_LIMIT = 65536


def custom_instances(network):
    """Immutable hook inventory, never an identity/hash of administrator content."""
    names = network.get("custom_egress", [])
    if (not isinstance(names, list) or any(not isinstance(name, str) or
            not re.fullmatch(r"[a-z][a-z0-9]{0,7}", name) for name in names)
            or names != sorted(set(names))):
        raise ValueError("Invalid administrator PF leaf inventory")
    hooks = re.findall(r'^anchor "admin-([a-z][a-z0-9]{0,7})" ', network.get("pf_rules", ""), re.M)
    if sorted(hooks) != sorted(names * 2):
        raise ValueError("Administrator PF hook inventory differs from the managed source")
    if names and re.search(r"^\s*(?:load|include)\b", network["pf_rules"], re.M):
        raise ValueError("Managed PF must not load mutable administrator files")
    return tuple(names)


def validate_custom_rules(text):
    """A bounded subset of native PF, also accepting pfctl's canonical -sr form.

    Each line grants one numeric IPv4 destination/prefix and TCP/UDP port or
    interval. Parent hooks supply direction, interface and source. No macros,
    tables, includes, routing, tagging, nested anchors or floating states.
    """
    if (not isinstance(text, str) or len(text.encode("utf-8")) > CUSTOM_LIMIT or not text.isascii()
            or any(ord(char) < 32 and char not in "\t\r\n" for char in text) or "\x7f" in text):
        raise ValueError("Administrator PF file must be bounded ASCII text")
    expression = (r"pass(?: quick)? inet proto (tcp|udp)(?: from any)? to "
                  r"([0-9.]+(?:/[0-9]+)?) port (?:= )?([0-9]+)(?::([0-9]+))?"
                  r"( flags S/SA)? keep state \(if-bound\)")
    count = 0
    for line in text.splitlines():
        row = " ".join(line.split("#", 1)[0].split())
        if not row:
            continue
        count += 1
        match = re.fullmatch(expression, row)
        if match is None or count > 256:
            raise ValueError("Unsupported administrator PF rule; use pass inet proto tcp|udp to IPv4[/prefix] "
                             "port NUMBER[:NUMBER] keep state (if-bound)")
        protocol, address, low, high, flags = match.groups()
        try:
            destination = ipaddress.IPv4Network(address, strict=True)
            if destination.prefixlen == 0:
                raise ValueError
            if not 1 <= int(low) <= int(high or low) <= 65535:
                raise ValueError
            if flags and protocol != "tcp":
                raise ValueError
        except ValueError:
            raise ValueError("Invalid administrator PF destination, port interval or TCP flags") from None
    return text


def custom_file(instance):
    if not isinstance(instance, str) or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", instance):
        raise ValueError("Invalid administrator PF instance")
    return CUSTOM_DIRECTORY / (instance + ".conf")


def read_custom_rules(instance):
    _private_path(CUSTOM_DIRECTORY, directory=True)
    path = custom_file(instance)
    _private_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, encoding="ascii", newline="") as stream:
        _private_info(path, os.fstat(stream.fileno()))
        try:
            text = stream.read(CUSTOM_LIMIT + 1)
        except UnicodeError:
            raise ValueError("Administrator PF file must be ASCII text") from None
    return validate_custom_rules(text)


def stage_custom_files(instances):
    """Create empty opt-in files only; never replace administrator edits."""
    if not instances:
        return
    CUSTOM_DIRECTORY.mkdir(mode=0o700, exist_ok=True)
    _private_path(CUSTOM_DIRECTORY, directory=True)
    for name in instances:
        path = custom_file(name)
        if not _private_path(path, optional=True):
            exclusive_file(path, "# Administrator Nextcloud egress; one native PF rule per line.\n"
                           "# Example: pass inet proto tcp to 192.168.50.10 port 445 keep state (if-bound)\n")
        read_custom_rules(name)


def _custom_namespace(runner, instances, *, exact=True):
    # FreeBSD 15.1 pfctl_walk_anchors recursively prints FULL anchor paths,
    # even without a wildcard. Do not silently normalize foreign/nested names.
    rows = runner.run("pfctl", "-a", PF_ANCHOR, "-s", "Anchors").stdout.split()
    expected = {f"{PF_ANCHOR}/admin-{name}" for name in instances}
    if len(rows) != len(set(rows)) or not set(rows).issubset(expected) or (exact and set(rows) != expected):
        raise ValueError("Unexpected child anchor inventory inside the owned project anchor")
    return set(rows)


def _empty_custom_leaf(runner, name):
    anchor = f"{PF_ANCHOR}/admin-{name}"
    for args in (("-P", "-sr"), ("-sn",), ("-s", "Tables"), ("-s", "ethernet"), ("-s", "Anchors")):
        if runner.run("pfctl", "-a", anchor, *args).stdout.strip():
            raise ValueError("Retired administrator PF leaf is not empty")


def _wait_custom_retirement(network, retired, runner):
    """Bounded kernel rule-reference reclamation, never a wildcard allowance.

    FreeBSD unlinks old rules before asynchronously freeing anchor references.
    Removal must invalidate its own endpoint states before this transaction;
    this wait does not kill states. Any nonempty/foreign child fails immediately.
    """
    current = set(custom_instances(network))
    retired = set(retired) - current
    if not retired:
        return
    deadline = time.monotonic() + 30
    while True:
        actual = _custom_namespace(runner, current | retired, exact=False)
        if not {f"{PF_ANCHOR}/admin-{name}" for name in current}.issubset(actual):
            raise ValueError("Required administrator PF child is missing")
        lingering = {name for name in retired if f"{PF_ANCHOR}/admin-{name}" in actual}
        if not lingering:
            return
        for name in sorted(lingering):
            _empty_custom_leaf(runner, name)
        if time.monotonic() >= deadline:
            raise RuntimeError("Empty retired PF anchor references remain; inspect endpoint states before retrying recovery")
        time.sleep(1)


def verify_custom_children(network, runner, *, files=False):
    """Read-only checks; mutable leaves are deliberately NOT commit snapshots."""
    names = custom_instances(network)
    _custom_namespace(runner, names)
    rules = {}
    for name in names:
        anchor = f"{PF_ANCHOR}/admin-{name}"
        for args in (("-sn",), ("-s", "Tables"), ("-s", "ethernet"), ("-s", "Anchors")):
            if runner.run("pfctl", "-a", anchor, *args).stdout.strip():
                raise ValueError("Administrator PF leaf contains translation, tables, Ethernet or nested anchors")
        # -P preserves numeric ports instead of FreeBSD /etc/services names.
        rules[name] = validate_custom_rules(runner.run("pfctl", "-a", anchor, "-P", "-sr").stdout)
        if files:
            read_custom_rules(name)
    return rules


def _load_custom_rules(name, text, runner, directory):
    """Load validated bytes through a private candidate, not a mutable pathname."""
    validate_custom_rules(text)
    descriptor, filename = tempfile.mkstemp(prefix=".admin-pf-", dir=directory)
    path = Path(filename)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        anchor = f"{PF_ANCHOR}/admin-{name}"
        runner.run("pfctl", "-a", anchor, "-o", "none", "-nf", str(path))
        runner.run("pfctl", "-a", anchor, "-o", "none", "-f", str(path))
    finally:
        path.unlink(missing_ok=True)


def _previous_network(transaction):
    previous = transaction.get("previous_active")
    return json.loads(_private_text(Path(previous) / "firewall-transition.json"))["network"] if previous else {}


def _save_custom_rules(state, transaction, runner):
    previous = _previous_network(transaction)
    rules = verify_custom_children(previous, runner)
    if not (custom_instances(previous) or custom_instances(transaction["network"])):
        return
    # Complete the live rollback capture before the first leaf mutation. This
    # temporary input is NOT a persistent content pin for administrator files.
    for name, text in rules.items():
        exclusive_file(state / f"pf-admin-{name}.before", text)
    exclusive_file(state / "custom-egress-saved", "Captured previous live administrator rules.\n")


def _retire_custom_rules(names, runner):
    for name in sorted(names):
        runner.run("pfctl", "-a", f"{PF_ANCHOR}/admin-{name}", "-F", "rules")


def _restore_custom_rules(state, transaction, runner):
    """Restore only transaction-local live bytes; never consult mutable files."""
    previous = _previous_network(transaction)
    before = set(custom_instances(previous))
    after = set(custom_instances(transaction["network"]))
    if not before and not after:
        return
    _custom_namespace(runner, before | after, exact=False)
    if _private_path(state / "custom-egress-saved", optional=True):
        # Validate ALL captures before any reload. Missing captures refuse rather
        # than reaching for mutable files or old committed custom contents.
        saved = {name: validate_custom_rules(_private_text(state / f"pf-admin-{name}.before"))
                 for name in before}
        for name, text in saved.items():
            _load_custom_rules(name, text, runner, state)
        _retire_custom_rules(after - before, runner)
        _wait_custom_retirement(previous, after - before, runner)
    verify_custom_children(previous, runner)


def starter_parent():
    """Preparation text ONLY: caller must establish emptiness and obtain consent.

    Create PF_FILE (empty) before loading this parent. Only preparation may load
    the root policy; normal installation/recovery never does. Stateless fallback
    preserves existing management connections when PF is first enabled.
    """
    return (f'nat-anchor "{PF_ANCHOR}"\nrdr-anchor "{PF_ANCHOR}"\n'
            f'anchor "{PF_ANCHOR}" quick\n'
            f'load anchor "{PF_ANCHOR}" from "{PF_FILE}"\n'
            'pass all no state\n')


class StarterRequired(ValueError):
    """An empty host is eligible for separately consented parent preparation."""


def _empty_live_parent(runner):
    for args in (("-sr",), ("-sn",), ("-s", "ethernet"), ("-s", "Anchors"),
                 ("-s", "Tables"), ("-ss",)):
        result = runner.run("pfctl", *args, check=False)
        if result.returncode or result.stdout.strip():
            return False
    interfaces = runner.run("pfctl", "-v", "-s", "Interfaces", check=False)
    return not interfaces.returncode and bool(interfaces.stdout.strip()) and "skip" not in interfaces.stdout


def _starter_firewalls_clear(runner):
    """No alternative firewall, including service-specific boot overrides.

    Loaded IPFW/IPFilter modules are conservatively unsupported even when their
    current enable flag is off. Do not invoke ipfw/ipf: inspection commands may
    autoload these modules and thereby activate a foreign firewall.
    """
    for service, variable in (("ipfw", "firewall_enable"), ("ipfilter", "ipfilter_enable"),
                              ("ipnat", "ipnat_enable")):
        result = runner.run("sysrc", "-s", service, "-n", variable, check=False)
        if result.returncode or result.stdout.strip().upper() != "NO":
            return False
    for module in ("ipfw", "ipfilter"):
        if runner.run("kldstat", "-q", "-m", module, check=False).returncode != 1:
            return False
    for name in ("net.inet.ip.fw.enable", "net.inet6.ip6.fw.enable"):
        result = runner.run("sysctl", "-n", name, check=False)
        if result.returncode != 1 or result.stdout.strip():
            return False  # A present IPFW sysctl also covers compiled-in support.
    return True


def starter_available(runner):
    """Read-only empty-host check; disabled PF alone never establishes this."""
    enabled = runner.run("sysrc", "-s", "pf", "-n", "pf_enable", check=False)
    if enabled.returncode or enabled.stdout.strip().upper() != "NO":
        return False
    if not _starter_firewalls_clear(runner):
        return False
    configured = runner.run("sysrc", "-s", "pf", "-n", "pf_rules", check=False)
    if configured.returncode or configured.stdout.strip() != str(PARENT_FILE):
        return False
    flags = runner.run("sysrc", "-s", "pf", "-n", "pf_flags", check=False)
    if flags.returncode or flags.stdout.strip():
        return False
    program = runner.run("sysrc", "-s", "pf", "-n", "pf_program", check=False)
    if program.returncode or program.stdout.strip() != "/sbin/pfctl":
        return False
    for path in (PARENT_FILE, PF_FILE):
        if path.is_symlink():
            return False
        result = runner.run("cat", str(path), check=False)
        if result.returncode:
            if runner.run("test", "-e", str(path), check=False).returncode == 0:
                return False
        elif any(line.split("#", 1)[0].strip() for line in result.stdout.splitlines()):
            return False
    if runner.run("kldstat", "-q", "-m", "pf", check=False).returncode:
        return True  # An unloaded PF module cannot retain a live PF policy.
    return _empty_live_parent(runner)


def prepare_parent(runner, ssh_connection=None):
    """Explicit PREPARE-only empty-host operation, before deployment transactions.

    Caller owns the host operation lock and records explicit operator consent.
    No existing administrator policy is merged, replaced or reloaded. Network
    prerequisites must already be corrected by the administrator. This starter
    is deliberately retained on later cancellation/removal.
    """
    if not starter_available(runner):
        raise ValueError("Parent preparation refused: configured or live foreign PF policy or IPFW/IPFilter exists")
    _verify_network_prerequisites(runner)
    runner.run("kldload", "-n", "pf")
    if not starter_available(runner) or not _empty_live_parent(runner):
        raise ValueError("PF changed during preparation; administrator must integrate the hooks")
    for path in (PF_FILE, PARENT_FILE):
        if path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError(f"Unsafe empty PF preparation file: {path}")
    # Anchor must exist before the parent syntax check recursively loads it.
    replace_file(PF_FILE, "# nextcloudonfreebsd: empty owned anchor\n")
    replace_file(PARENT_FILE, starter_parent(),
                 validate=lambda candidate: runner.run("pfctl", "-nf", str(candidate)))
    if not _starter_firewalls_clear(runner) or not _empty_live_parent(runner):
        raise ValueError("Live PF changed; prepared files retained, no root policy was loaded")
    runner.run("pfctl", "-f", str(PARENT_FILE))
    if runner.run("pfctl", "-s", "Running", check=False).returncode:
        runner.run("pfctl", "-e")
    runner.run("sysrc", "-s", "pf", "pf_enable=YES")
    verify_parent(runner)


def _parent_rows(text):
    """One deliberately bounded parent format, not an arbitrary PF parser."""
    rows = []
    for line in text.splitlines():
        try:
            row = shlex.split(line, comments=True)
        except ValueError:
            raise ValueError("Unsupported multiline/quoted PF parent syntax") from None
        if not row:
            continue
        if "\\" in line or ";" in line or row[0] in ("include", "ether", "ethernet", "scrub"):
            raise ValueError("Unsupported PF parent include, continuation, Ethernet or scrub rule")
        if row[0] in ("binat", "binat-anchor") or row[:2] in (["no", "binat"], ["no", "scrub"]):
            raise ValueError("Parent binat/scrub policy is outside the supported integration contract")
        if row[0].endswith("anchor") and ("{" in row or "}" in row):
            raise ValueError("Inline PF anchors are unsupported; use named external anchors")
        if row[:2] == ["set", "skip"] and row != ["set", "skip", "on", "lo0"]:
            raise ValueError("PF parent may skip only lo0; project traffic must be filtered")
        if row[:2] == ["set", "require-order"] and row != ["set", "require-order", "yes"]:
            raise ValueError("PF parent must retain normal rule ordering")
        rows.append(row)
    return rows


def validate_parent_policy(text, *, live=False, translation=False):
    """Require first unconditional translation hooks and first quick filter hook.

    FreeBSD 15.1 pf.conf(5): first matching NAT/RDR wins; a quick anchor
    terminates parent evaluation when ANY rule in it matches. No preceding
    match/pass/block/anchor is admitted, even a seemingly harmless one.
    """
    rows = _parent_rows(text)
    for row in rows:
        anchor_name = (row[2] if row[:2] == ["load", "anchor"] and len(row) > 2 else
                       row[1] if row[0].endswith("anchor") and len(row) > 1 else "")
        if anchor_name.lstrip("/").startswith(PF_ANCHOR + "/"):
            raise ValueError("PF parent must not invoke or load project child anchors directly")
    kinds = ("nat", "rdr") if translation else (("filter",) if live else ("nat", "rdr", "filter"))
    for kind in kinds:
        if kind == "filter":
            selected = [row for row in rows if row[0] in ("anchor", "pass", "block", "match")]
            expected = ["anchor", PF_ANCHOR, "quick"]
        else:
            selected = [row for row in rows if row[0] in (kind, kind + "-anchor")
                        or row[:2] == ["no", kind]]
            expected = [kind + "-anchor", PF_ANCHOR]
        if live:
            expected.append("all")
        if not selected or selected[0] != expected:
            raise ValueError(f"PF parent requires first unconditional {kind} hook: {' '.join(expected)}")
        if sum(PF_ANCHOR in row for row in selected) != 1:
            raise ValueError("Duplicate project PF parent hook")
    if not live:
        loads = [row for row in rows if row[:2] == ["load", "anchor"] and PF_ANCHOR in row]
        if loads != [["load", "anchor", PF_ANCHOR, "from", str(PF_FILE)]]:
            raise ValueError(f'PF parent requires load anchor "{PF_ANCHOR}" from "{PF_FILE}"')
        # Macros and single-line tables are allowed, but unknown directives are
        # refused rather than silently interpreted as harmless declarations.
        for row in rows:
            if row[0] not in ("set", "table", "nat", "nat-anchor", "rdr", "rdr-anchor",
                               "no", "anchor", "pass", "block", "match", "load") and not (
                    len(row) >= 3 and row[1] == "=" and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", row[0])):
                raise ValueError("Unsupported PF parent directive")


def _verify_parent(runner):
    """Read-only live AND boot integration/prerequisites; never prepare the host.

    Foreign ingress reservations are checked separately by host admission.
    Parent rules are inspected only to establish hook order, never snapshotted
    as project ownership. Return the administrator's persistent parent path.
    """
    def output(*args, **kwargs):
        return (runner.run(*args, **kwargs).stdout or "").strip()
    if runner.run("pfctl", "-s", "Running", check=False).returncode:
        raise ValueError("Enable the prepared administrator PF parent, then Recheck host")
    validate_parent_policy(output("pfctl", "-sr"), live=True)
    validate_parent_policy(output("pfctl", "-sn"), live=True, translation=True)
    if output("pfctl", "-s", "ethernet"):
        raise ValueError("PF Ethernet policy is outside the supported parent contract")
    interfaces = output("pfctl", "-v", "-s", "Interfaces")
    if not interfaces:
        raise ValueError("Cannot establish PF interface skip policy")
    for line in interfaces.splitlines():
        if "skip" in line and line.split() != ["lo0", "(skip)"]:
            raise ValueError("PF skip is permitted only on lo0; correct the parent and reload it")
    parent = verify_persistent_parent(runner)
    runner.run("pfctl", "-nf", parent)
    _verify_network_prerequisites(runner)
    return parent


def verify_persistent_parent(runner):
    """The boot-safe portion of the parent contract, before bridges/PF exist.

    A syntax check loads anchor sources and can require their bridge interfaces;
    leave that and live-policy/prerequisite checks to the post-PF jail guard.
    """
    def output(*args):
        return (runner.run(*args).stdout or "").strip()
    if output("sysrc", "-s", "pf", "-n", "pf_enable").upper() != "YES":
        raise ValueError("Administrator must persist pf_enable=YES")
    if output("sysrc", "-s", "pf", "-n", "pf_program") != "/sbin/pfctl":
        raise ValueError("Custom pf_program is outside the supported parent contract")
    if output("sysrc", "-s", "pf", "-n", "pf_flags"):
        raise ValueError("Custom pf_flags are outside the supported parent contract")
    parent = output("sysrc", "-s", "pf", "-n", "pf_rules")
    if not parent.startswith("/") or parent == str(PF_FILE) or "\n" in parent:
        raise ValueError("pf_rules must name an administrator parent, not the project anchor file")
    validate_parent_policy(output("cat", parent))
    return parent


def _verify_network_prerequisites(runner):
    def output(*args):
        return (runner.run(*args).stdout or "").strip()
    if output("sysrc", "-s", "routing", "-n", "gateway_enable").upper() != "YES":
        raise ValueError("Administrator must persist gateway_enable=YES")
    bridge_boot = runner.run("sysrc", "-f", "/boot/loader.conf", "-f", "/boot/loader.conf.local",
                             "-n", "if_bridge_load", check=False)
    if bridge_boot.returncode or bridge_boot.stdout.strip().upper() != "YES":
        raise ValueError("Administrator must persist if_bridge_load=YES in /boot/loader.conf "
                         "without a conflicting loader.conf.local override, so bridge sysctls exist at boot")
    persistent = {}
    for path in ("/etc/sysctl.conf", "/etc/sysctl.conf.local"):
        result = runner.run("cat", path, check=False)
        if result.returncode:
            if runner.run("test", "-e", path, check=False).returncode == 0:
                raise ValueError(f"Cannot read shared networking prerequisites in {path}")
            continue
        for line in result.stdout.splitlines():
            name, separator, value = line.split("#", 1)[0].strip().partition("=")
            if separator and name.strip() in NETWORK_SYSCTLS:
                persistent[name.strip()] = value.strip()
    for name, value in NETWORK_SYSCTLS.items():
        if output("sysctl", "-n", name) != value:
            raise ValueError(f"Administrator must set live {name}={value}; then Recheck host")
        if (name in BRIDGE_SYSCTLS and persistent.get(name) != value) or (
                name in persistent and persistent[name] != value):
            raise ValueError(f"Administrator must persist {name}={value} in /etc/sysctl.conf; then Recheck host")


def verify_parent(runner):
    """Validate the supported live/persistent parent and shared prerequisites.

    StarterRequired offers a separately approved empty-host preparation; other
    failures require administrator changes and Recheck. Always read-only.
    """
    try:
        return _verify_parent(runner)
    except ValueError as error:
        if starter_available(runner):
            raise StarterRequired("Empty PF host: explicit PREPARE can install the minimal parent; "
                                  "forwarding and bridge sysctls must first be prepared by the administrator.\n"
                                  "Load if_bridge if its sysctls are absent, persist if_bridge_load=YES "
                                  "in /boot/loader.conf and gateway_enable=YES, "
                                  "and set these live values (persist bridge values in /etc/sysctl.conf):\n" +
                                  "\n".join(f"{name}={value}" for name, value in NETWORK_SYSCTLS.items())) from error
        raise ValueError(str(error) + "\n\nAdministrator PF integration (edit/load yourself, then Recheck):\n"
                         f'nat-anchor "{PF_ANCHOR}"\n# Existing NAT rules follow here\n'
                         f'rdr-anchor "{PF_ANCHOR}"\n# Existing RDR rules follow here\n'
                         f'anchor "{PF_ANCHOR}" quick\n'
                         f'load anchor "{PF_ANCHOR}" from "{PF_FILE}"\n'
                         "The translation hooks must be first in their sections and the unconditional quick "
                         "filter hook must be the FIRST filtering rule. Create the empty root-owned mode0600 "
                         "anchor file before loading. Keep existing NAT/RDR rules in their respective "
                         "translation sections and existing filter rules after the quick filter hook. "
                         "Only lo0 may be skipped; includes, inline anchors, scrub/Ethernet and binat "
                         "are outside this bounded parent contract.") from error


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def exclusive_file(path, contents):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(Path(path).parent)
    except BaseException:
        # A failed write/fsync must not leave a success marker for the supervisor.
        Path(path).unlink()
        fsync_directory(Path(path).parent)
        raise


def replace_file(path, contents, *, validate=None, mode=0o600):
    """Validate a private same-filesystem candidate before an atomic replacement."""
    path = Path(path)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    candidate = Path(name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        if validate is not None:
            validate(candidate)
        os.replace(candidate, path)
        fsync_directory(path.parent)
    finally:
        candidate.unlink(missing_ok=True)


def replace_link(path, destination):
    path = Path(path)
    candidate = path.with_name(f".{path.name}.{uuid.uuid4().hex}")
    os.symlink(str(destination), candidate)
    try:
        os.replace(candidate, path)
        fsync_directory(path.parent)
    finally:
        candidate.unlink(missing_ok=True)


def active_pointer(state, settings, *, restore=False):
    """Change only the expected shared pointer; never unlink a foreign target."""
    if "active_link" not in settings:
        return  # Fresh-host transactions written by the original installer.
    path = Path(settings["active_link"])
    previous = settings.get("previous_active")
    own = str(Path(state).absolute())
    if not path.is_absolute() or (previous is not None and
            (not Path(previous).is_absolute() or previous == own
             or not (Path(previous) / "firewall-confirmed").is_file())):
        raise RuntimeError("Invalid active network pointer or previous committed transaction")
    try:
        current = os.readlink(path)
    except FileNotFoundError:
        current = None
    except OSError as error:
        raise RuntimeError("The active network pointer is not a symbolic link") from error
    if current is not None and not Path(current).is_absolute():
        raise RuntimeError("The active network pointer must have an absolute destination")
    if restore:
        if current == previous:
            fsync_directory(path.parent)
            return
        if current != own:
            raise RuntimeError("The active network pointer changed outside this transaction")
        if previous is None:
            path.unlink()
            fsync_directory(path.parent)
        else:
            replace_link(path, previous)
    else:
        if current != previous:
            raise RuntimeError("The active network pointer changed outside this transaction")
        replace_link(path, own)


def require_pending(state):
    settings = json.loads((state / "firewall-transition.json").read_text())
    if settings.get("architecture") != OWNERSHIP:
        raise ValueError("Legacy network transaction requires its original retained installer")
    if ((state / "firewall-rolled-back").exists() or (state / "firewall-confirmed").exists()
            or time.monotonic() >= settings["deadline"]):
        raise RuntimeError("The firewall transition is no longer pending; no further network mutations are allowed")


def _private_info(path, info, *, directory=False):
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected_type(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or (not directory and info.st_nlink != 1)):
        raise ValueError(f"Unsafe private network state: {path}")


def _private_path(path, *, directory=False, optional=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return False
        raise
    _private_info(path, info, directory=directory)
    return True


def _transaction_files(state):
    _private_path(state, directory=True)
    names = set()
    for path in state.iterdir():
        _private_path(path)
        names.add(path.name)
    return names


def _private_text(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, encoding="utf-8", newline="") as stream:
        _private_info(path, os.fstat(stream.fileno()))
        return stream.read()


def _previous_policy(state, settings):
    """Bind recovery input and expected live policy to the previous commit."""
    previous = settings.get("previous_active")
    state = Path(state).absolute()
    if not isinstance(previous, str) or not Path(previous).is_absolute():
        raise ValueError("Previous managed PF requires its committed transaction; manual recovery is required")
    previous = Path(previous)
    if state.parent.name != "transactions" or previous.parent != state.parent or previous == state:
        raise ValueError("Previous PF transaction is outside this registry")
    for directory in (state.parent.parent, state.parent, state, previous):
        _private_path(directory, directory=True)
    _private_path(previous / "firewall-confirmed")
    if _private_path(previous / "firewall-rolled-back", optional=True):
        raise ValueError("Previous PF transaction was rolled back")
    committed = json.loads(_private_text(previous / "firewall-transition.json"))
    if not isinstance(committed, dict) or committed.get("architecture") != OWNERSHIP:
        raise ValueError("Previous transaction is not a coexistence-v1 anchor policy")
    network = committed.get("network") if isinstance(committed, dict) else None
    rules = network.get("pf_rules") if isinstance(network, dict) else None
    if not isinstance(rules, str) or not rules.strip():
        raise ValueError("Previous committed PF policy is missing or empty")
    custom_instances(network)
    source = settings.get("previous_pf_file")
    if not isinstance(source, str) or not Path(source).is_absolute():
        raise ValueError("Missing private copy of the previous PF policy")
    if _private_text(Path(source)) != rules:
        raise ValueError("Previous PF copy differs from the committed policy; manual recovery is required")
    expected = {name: _private_text(previous / f"pf-{name}.expected") for name, _ in PF_SNAPSHOTS}
    return rules, expected


def pending_transactions(root):
    """Return name-sorted unresolved transaction Paths without creating state.

    All existing registry/transaction directories and their direct files must
    be private and owned by the caller (root on the host). Pre-arm diagnostic
    directories without a transition JSON are retained but do not block work.
    Call while holding the host operation lock before allowing a new operation.
    """
    root = Path(root).absolute()
    if not _private_path(root, directory=True, optional=True):
        return ()
    directory = root / "transactions"
    if not _private_path(directory, directory=True, optional=True):
        return ()
    pending = []
    for state in sorted(directory.iterdir()):
        files = _transaction_files(state)
        if ("firewall-transition.json" in files
                and not files.intersection(("firewall-confirmed", "firewall-rolled-back"))):
            pending.append(state)
    return tuple(pending)


def _boot_inventory(network):
    bridges = network.get("boot_bridge_addresses")
    if not isinstance(bridges, dict) or any(
            not isinstance(name, str) or not re.fullmatch(r"bridge[0-9]{1,4}", name)
            for name in bridges):
        raise ValueError("Invalid committed boot bridge inventory")
    try:
        if any(not isinstance(value, str) or str(ipaddress.IPv4Address(value)) != value
               or int(ipaddress.IPv4Address(value)) % 4 != 1 for value in bridges.values()):
            raise ValueError
        if len(set(bridges.values())) != len(bridges):
            raise ValueError
    except ValueError:
        raise ValueError("Invalid committed boot bridge /30 gateways") from None
    return bridges


def _committed_boot_network(active):
    """Validate only the current commit, never depend on a previous transaction."""
    active = Path(active)
    root = active.parent.parent
    if (not active.is_absolute() or active.name != "active" or active.parent.name != "network"
            or root.resolve(strict=True) != root):
        raise ValueError("Expected the private registry network/active pointer")
    for directory in (root, active.parent, root / "transactions"):
        _private_path(directory, directory=True)
    info = active.lstat()
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise ValueError("Unsafe active network pointer")
    destination = os.readlink(active)
    state = Path(destination)
    if (not state.is_absolute() or str(state) != destination
            or state.parent != root / "transactions" or state.resolve(strict=True) != state):
        raise ValueError("Active network transaction is outside this registry")
    _private_path(state, directory=True)
    _private_path(state / "firewall-confirmed")
    if _private_path(state / "firewall-rolled-back", optional=True):
        raise ValueError("Active network transaction was rolled back")
    settings = json.loads(_private_text(state / "firewall-transition.json"))
    if (not isinstance(settings, dict) or settings.get("architecture") != OWNERSHIP
            or settings.get("active_link") != str(active)):
        raise ValueError("Active network transaction is not a committed coexistence-v1 policy")
    network = settings.get("network")
    if (not isinstance(network, dict) or network.get("pf_file") != str(PF_FILE)
            or not isinstance(network.get("pf_rules"), str) or not network["pf_rules"].strip()
            or _private_text(PF_FILE) != network["pf_rules"]):
        raise ValueError("Project PF source differs from its committed transaction")
    bridges = _boot_inventory(network)
    custom_instances(network)
    for name, _ in PF_SNAPSHOTS:
        _private_path(state / f"pf-{name}.expected")
    if pending_transactions(root):
        raise ValueError("Unconfirmed network transaction remains; use recover-network before boot networking")
    return bridges


def boot_bridges(active, runner):
    """Restore committed empty bridges before parent PF loads, never start guests.

    This is a cold-boot action, not a live restart/adoption path. Any occupied
    name refuses the entire inventory before creation, even if addresses match.
    A partial command failure leaves empty bridges for explicit inspection.
    """
    active = Path(active)
    bridges = _committed_boot_network(active)
    path = active.parent.parent / "operation.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r+") as lock:
        _private_info(path, os.fstat(lock.fileno()))
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Host operation is active; boot bridge creation refused") from None
        bridges = _committed_boot_network(active)
        verify_persistent_parent(runner)
        interfaces = runner.run("ifconfig", "-l").stdout.split()
        if not interfaces or len(interfaces) != len(set(interfaces)):
            raise ValueError("Cannot establish host interface inventory for boot networking")
        if set(bridges).intersection(interfaces):
            raise ValueError("Committed bridge name already exists; refusing boot adoption or member changes")
        network = json.loads(_private_text(active / "firewall-transition.json"))["network"]
        custom = {name: read_custom_rules(name) for name in custom_instances(network)}
        if bridges:
            runner.run("kldload", "-n", "if_bridge")
        for bridge, gateway in bridges.items():
            runner.run("ifconfig", bridge, "create")
            runner.run("ifconfig", bridge, "inet", gateway + "/30", "up")
        if custom:
            # Independent children survive the subsequent parent PF load:
            # no child load/inline rules exist in the managed parent source.
            runner.run("kldload", "-n", "pf")
            _custom_namespace(runner, custom, exact=False)
            for name, text in custom.items():
                _load_custom_rules(name, text, runner, active)


def reload_custom(active, runner):
    """Explicit administrator leaf reload; serialize with every host mutation."""
    active = Path(active)
    _committed_boot_network(active)
    path = active.parent.parent / "operation.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r+") as lock:
        _private_info(path, os.fstat(lock.fileno()))
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Host operation is active; administrator PF reload refused") from None
        _committed_boot_network(active)
        network = json.loads(_private_text(active / "firewall-transition.json"))["network"]
        verify_parent(runner)
        for name, args in PF_SNAPSHOTS:
            actual = runner.run("pfctl", "-a", PF_ANCHOR, *args).stdout
            if actual.rstrip("\n") != _private_text(active / f"pf-{name}.expected").rstrip("\n"):
                raise ValueError("Managed PF differs from its committed snapshot")
        verify_custom_children(network, runner)
        # Read and validate every candidate before any leaf mutation. Native
        # failures propagate; no host-wide reload or state flush is performed.
        custom = {name: read_custom_rules(name) for name in custom_instances(network)}
        for name, text in custom.items():
            _load_custom_rules(name, text, runner, active)
        verify_custom_children(network, runner)


def _recovery_settings(state):
    path = state / "firewall-transition.json"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        _private_info(path, os.fstat(stream.fileno()))
        settings = json.load(stream)
    required = {"deadline", "boot_identity", "bridges", "backups",
                 "previous_pf_file", "active_link", "previous_active", "network"}
    if (not isinstance(settings, dict) or settings.get("architecture") != OWNERSHIP
            or not required.issubset(settings)):
        raise ValueError("Incomplete or legacy network transaction; manual recovery is required")
    deadline = settings["deadline"]
    if (type(deadline) not in (int, float) or deadline < 0
            or (type(deadline) is float and not math.isfinite(deadline))):
        raise ValueError("Invalid network recovery deadline; manual recovery is required")
    network = settings["network"]
    if (not isinstance(network, dict)
            or not {"bridge_addresses", "boot_bridge_addresses", "pf_file", "pf_rules"}.issubset(network)):
        raise ValueError("Incomplete network recovery policy; manual recovery is required")
    def absolute(value):
        return isinstance(value, str) and Path(value).is_absolute()
    if (network["pf_file"] != str(PF_FILE) or not absolute(settings["active_link"])
            or (settings["previous_active"] is not None and not absolute(settings["previous_active"]))
            or not isinstance(network["pf_rules"], str)):
        raise ValueError("Invalid previous network policy or active pointer; manual recovery is required")
    custom_instances(network)
    bridges = settings["bridges"]
    if (not isinstance(bridges, list)
            or any(not isinstance(name, str) or not name.startswith("bridge") or not name[6:].isdigit() for name in bridges)
            or not isinstance(network["bridge_addresses"], dict)
            or len(bridges) != len(set(bridges))
            or set(bridges) != set(network["bridge_addresses"])):
        raise ValueError("Invalid owned bridge recovery list")
    try:
        if any(not isinstance(value, str) or str(ipaddress.IPv4Address(value)) != value
               for value in network["bridge_addresses"].values()):
            raise ValueError
    except ValueError:
        raise ValueError("Invalid owned bridge IPv4 recovery addresses") from None
    boot_bridges = _boot_inventory(network)
    if any(boot_bridges.get(name) != address for name, address in network["bridge_addresses"].items()):
        raise ValueError("New bridges differ from the committed boot inventory")
    backups = settings["backups"]
    if not isinstance(backups, dict) or set(backups) != {str(PF_FILE)}:
        raise ValueError("Only the owned PF anchor may have a network recovery backup")
    for target, backup in backups.items():
        if not absolute(target) or (backup is not None and
                (not isinstance(backup, str) or not backup or Path(backup).name != backup or backup in (".", ".."))):
            raise ValueError("Invalid network recovery backup path")
        if backup is not None:
            _private_path(state / backup)
    previous_pf = settings["previous_pf_file"]
    backup = backups[network["pf_file"]]
    if not backup or not absolute(previous_pf) or Path(previous_pf) != state / backup:
        raise ValueError("Missing private copy of the previous PF anchor; manual recovery is required")
    if settings["previous_active"]:
        _previous_policy(state, settings)
    elif _parent_rows(_private_text(Path(previous_pf))):
        raise ValueError("First transaction requires an empty previous project anchor")
    active = Path(settings["active_link"])
    _private_path(active.parent, directory=True)
    previous_active = settings["previous_active"]
    if previous_active is not None:
        _private_path(Path(previous_active), directory=True)
        _private_path(Path(previous_active) / "firewall-confirmed")
    try:
        current = os.readlink(active)
    except FileNotFoundError:
        current = None
    if current not in (previous_active, str(state)):
        # Refuse stale/out-of-order recovery before changing live PF, not only
        # when trying to restore the shared readiness pointer afterwards.
        raise ValueError("Active network pointer changed outside this transaction; manual recovery is required")
    return settings


def _require_recoverable(settings, current_boot):
    saved_boot = settings["boot_identity"]
    if (not isinstance(saved_boot, str) or not saved_boot.strip()
            or not isinstance(current_boot, str) or not current_boot.strip()):
        raise ValueError("Saved and current boot identities are required; manual recovery is required")
    if saved_boot.strip() == current_boot.strip() and time.monotonic() < settings["deadline"]:
        raise RuntimeError("Network transaction is still pending on this boot; recovery requires its deadline to expire")


def _load_recovery_modules():
    for module in ("pf", "if_bridge"):
        try:
            present = subprocess.run(["/sbin/kldstat", "-q", "-m", module], check=False,
                                     text=True, capture_output=True, timeout=30)
            if present.returncode:
                subprocess.run(["/sbin/kldload", module], check=True,
                               text=True, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError(f"Network recovery could not prepare module {module}; no policy rollback was attempted: {error}") from None


def recover_pending(state, current_boot):
    """Explicit RECOVER-only rollback; the caller must hold the host operation lock.

    A different boot permits immediate recovery. On the same boot the saved
    monotonic deadline must have expired. Never wait for a lock, poll liveness,
    or signal a process: a surviving supervisor alone owns its worker group.
    Return None on recovery or an already-resolved transaction; errors leave
    pending state blocking subsequent operations.
    """
    state = Path(state).absolute()
    if state.parent.name != "transactions":
        raise ValueError("Expected a private registry transactions/<id> directory")
    _private_path(state.parent.parent, directory=True)
    _private_path(state.parent, directory=True)
    files = _transaction_files(state)
    if files.intersection(("firewall-confirmed", "firewall-rolled-back")):
        return
    _require_recoverable(_recovery_settings(state), current_boot)
    path = state / "firewall.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, "r+") as lock:
        _private_info(path, os.fstat(lock.fileno()))
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Network transaction is still active or recovering; recovery lock is busy") from None
        # Recheck after obtaining the lock: the detached supervisor may have
        # completed between discovery and our nonblocking acquisition.
        files = _transaction_files(state)
        if files.intersection(("firewall-confirmed", "firewall-rolled-back")):
            return
        settings = _recovery_settings(state)
        _require_recoverable(settings, current_boot)
        _load_recovery_modules()
        _rollback_locked(state, settings)


@contextmanager
def mutation(state):
    """Serialize *all* applying mutations with rollback, not merely commit.

    Only the supervised worker may hold this lock in production. It releases the
    lock before waiting for confirmation. Its supervisor can kill even a stopped
    worker and its command descendants before acquiring this lock for rollback.
    """
    state = Path(state)
    with (state / "firewall.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        require_pending(state)
        yield lambda: require_pending(state)


def rollback(state):
    state = Path(state)
    with (state / "firewall.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _rollback_locked(state)


def _withdraw_new_bridge_addresses(settings):
    """Establish closure before withdrawing an unconfirmed bridge's protection.

    Inspect ALL newly-created bridges first, then withdraw only their recorded
    IPv4 addresses. Foreign addresses/members refuse recovery; existing bridges
    never occur in this transaction-owned list. Empty/absent bridges permit retry.
    Anchor rules use dynamic (self), not a snapshot of unrelated host addresses.
    """
    bridges = settings["bridges"]
    if not bridges:
        return
    addresses = settings["network"]["bridge_addresses"]
    if set(bridges) != set(addresses):
        raise RuntimeError("New bridge address inventory changed")
    for bridge in bridges:
        address = addresses[bridge]
        if (not isinstance(bridge, str) or not bridge.startswith("bridge") or not bridge[6:].isdigit()
                or not isinstance(address, str) or str(ipaddress.IPv4Address(address)) != address):
            raise RuntimeError("Invalid new bridge address identity")
    interfaces = subprocess.run(("/sbin/ifconfig", "-l"), check=True, timeout=30,
                               text=True, capture_output=True).stdout.split()
    if not interfaces or len(interfaces) != len(set(interfaces)):
        raise RuntimeError("Cannot establish host interface inventory for network recovery")
    withdraw = []
    for bridge in bridges:
        if bridge not in interfaces:
            continue
        result = subprocess.run(("/sbin/ifconfig", bridge), check=True, timeout=30,
                                text=True, capture_output=True)
        rows = [line.split() for line in result.stdout.splitlines()]
        if not rows or not rows[0] or rows[0][0] != bridge + ":":
            raise RuntimeError("Cannot establish new bridge identity")
        actual = [row[1] for row in rows if len(row) > 1 and row[0] == "inet"]
        if (any(row[0] == "member:" for row in rows if row)
                or actual not in ([], [addresses[bridge]])):
            raise RuntimeError("New bridge has foreign members or IPv4 addresses; recovery refused")
        if actual:
            withdraw.append((bridge, actual[0]))
    for bridge, address in withdraw:
        subprocess.run(("/sbin/ifconfig", bridge, "inet", address, "-alias"), check=True,
                       timeout=30, stdout=sys.stderr)


def _rollback_locked(state, settings=None):
    """Caller owns firewall.lock, including throughout the final durable marker."""
    if (state / "firewall-confirmed").exists() or (state / "firewall-rolled-back").exists():
        return
    if settings is None:
        settings = _recovery_settings(state)
    if settings.get("architecture") != OWNERSHIP:
        raise ValueError("Legacy network rollback requires its original retained installer")
    errors = []
    def run(*args):
        try:
            # Supervisor stdout is the caller's IPC pipe, which can be closed
            # during rollback. Send command output to its private diagnostic
            # stream, not a disconnected terminal/control channel (SIGPIPE).
            subprocess.run(args, check=True, timeout=30, stdout=sys.stderr)
            return True
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(str(error))
            return False
    def exists(*args):
        try:
            return subprocess.run(list(args), stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=30, check=False).returncode == 0
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(str(error))
            return False
    pf_file = settings["network"]["pf_file"]
    previous_pf = settings["previous_pf_file"]
    try:
        verify_parent(NativeRunner(time.monotonic() + 120))
        if settings["previous_active"]:
            rules, expected = _previous_policy(state, settings)
        else:
            rules, expected = _private_text(Path(previous_pf)), None
            if _parent_rows(rules):
                raise RuntimeError("Uncommitted first anchor was not empty")
        if _private_text(Path(pf_file)) not in (rules, settings["network"]["pf_rules"]):
            raise RuntimeError("Owned PF file changed outside this transaction")
        if not run("/sbin/pfctl", "-a", PF_ANCHOR, "-o", "none", "-nf", previous_pf):
            raise RuntimeError("Previous PF anchor validation failed")
        # No newly created endpoint may still be attached when its protection
        # is withdrawn. Never disconnect unknown bridge members to force this.
        _withdraw_new_bridge_addresses(settings)
        replace_file(pf_file, rules)
        if not run("/sbin/pfctl", "-a", PF_ANCHOR, "-o", "none", "-f", previous_pf):
            raise RuntimeError("Previous PF anchor reload failed")
        _restore_custom_rules(state, settings, NativeRunner(time.monotonic() + 120))
        if expected is not None:
            for name, args in PF_SNAPSHOTS:
                actual = subprocess.run(("/sbin/pfctl", "-a", PF_ANCHOR, *args), check=True, timeout=30,
                                        text=True, capture_output=True).stdout
                if actual.rstrip("\n") != expected[name].rstrip("\n"):
                    raise RuntimeError(f"Restored PF {name} snapshot differs from the previous committed policy")
        else:
            if not run("/sbin/pfctl", "-a", PF_ANCHOR, "-F", "Tables"):
                raise RuntimeError("Could not clear uncommitted project tables")
            for args in (("-sr",), ("-sn",), ("-s", "Tables"), ("-s", "Anchors")):
                result = subprocess.run(("/sbin/pfctl", "-a", PF_ANCHOR, *args),
                                        check=True, timeout=30, text=True, capture_output=True)
                if result.stdout.strip():
                    raise RuntimeError("Uncommitted project anchor is not empty after rollback")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"Network rollback needs manual attention: {error}; parent PF remains untouched") from None
    for bridge in settings["bridges"]:
        if exists("/sbin/ifconfig", bridge):
            run("/sbin/ifconfig", bridge, "destroy")
    try:
        active_pointer(state, settings, restore=True)
    except (OSError, RuntimeError) as error:
        errors.append(str(error))
    if errors:
        raise RuntimeError("Network rollback needs manual attention: " + "; ".join(errors))
    exclusive_file(state / "firewall-rolled-back", "Unconfirmed PF/network configuration rolled back.\n")


def arm(state):
    state = Path(state)
    exclusive_file(state / "firewall.lock", "")
    script = state / "firewall-watchdog.py"
    exclusive_file(script, Path(__file__).read_text())
    descriptor = os.open(state / "firewall-rollback.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as log:
        process = subprocess.Popen([sys.executable, str(script), "supervise", str(state)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=log, text=True, start_new_session=True)
    return Controller(state, process)


def read_message(stream, deadline, *, abort=None):
    """Read a tiny private IPC line without an unbounded readline on partial input."""
    message = bytearray()
    while len(message) < 64:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Firewall transition confirmation deadline expired")
        descriptors = [stream] if abort is None else [stream, abort]
        ready, _, _ = select.select(descriptors, [], [], remaining)
        if not ready:
            raise TimeoutError("Firewall transition confirmation deadline expired")
        if abort is not None and abort in ready:
            raise RuntimeError("The installer disconnected or cancelled during network mutation")
        char = os.read(stream.fileno(), 1)
        if not char:
            raise RuntimeError("Firewall transaction channel closed before completion")
        if char == b"\n":
            return message.decode("ascii")
        message.extend(char)
    raise RuntimeError("Invalid firewall transaction message")


def send_message(stream, message):
    stream.write(message + "\n")
    stream.flush()


def close_pipe(stream):
    # Buffered stdin may still contain KEEP after a failed flush. Closing it
    # can raise EPIPE again; a cleanup error must never bypass network rollback.
    try:
        stream.close()
    except OSError:
        pass


def notify_final(stream, message):
    """Best-effort notification only after a durable commit/rollback marker.

    Losing the caller must not turn a completed recovery into a noisy secondary
    failure; close the buffered pipe too so interpreter shutdown cannot reflush.
    Application/confirmation messages still use strict send_message semantics.
    """
    try:
        send_message(stream, message)
    except (BrokenPipeError, ConnectionResetError):
        close_pipe(stream)


class Controller:
    """Interactive caller handle. It never mutates PF or acquires its lock."""

    def __init__(self, state, process):
        self.state = Path(state)
        self.process = process
        self.deadline = json.loads((self.state / "firewall-transition.json").read_text())["deadline"]

    def wait_applied(self):
        if read_message(self.process.stdout, self.deadline) != "APPLIED":
            raise RuntimeError("Network application failed; inspect the private firewall-rollback.log")

    def confirm(self):
        send_message(self.process.stdin, "KEEP")
        if read_message(self.process.stdout, self.deadline) != "COMMITTED":
            raise RuntimeError("Network confirmation failed; inspect the private firewall-rollback.log")
        if self.process.wait(timeout=15) != 0:
            raise RuntimeError("The network supervisor did not exit successfully")
        close_pipe(self.process.stdin)
        close_pipe(self.process.stdout)

    def cancel(self):
        # EOF also works if the interactive caller dies without calling cancel.
        # Never kill the supervisor: it must remain able to restore networking.
        if not self.process.stdin.closed:
            close_pipe(self.process.stdin)
        try:
            self.process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Network recovery is still running; inspect the private firewall-rollback.log and use the console if needed") from None
        finally:
            close_pipe(self.process.stdout)


class NativeRunner:
    """Bounded network-only commands in the private helper, with no shell eval."""

    def __init__(self, deadline):
        self.deadline = deadline

    def run(self, *args, check=True, timeout=15):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Firewall mutation deadline expired")
        result = subprocess.run([str(arg) for arg in args], text=True, capture_output=True,
                                check=False, timeout=min(timeout, remaining), umask=0o022)
        if check and result.returncode:
            raise RuntimeError(f"Network command failed: {' '.join(map(str, args))}\n{result.stderr.strip()}")
        return result


def apply_network(state, runner):
    state = Path(state)
    transaction = _recovery_settings(state)
    settings = transaction["network"]
    require_pending(state)
    verify_parent(runner)
    previous = _private_text(Path(transaction["previous_pf_file"]))
    if _private_text(Path(settings["pf_file"])) != previous:
        raise ValueError("Project anchor file changed after network review")
    _save_custom_rules(state, transaction, runner)
    if transaction["previous_active"]:
        _, expected = _previous_policy(state, transaction)
        for name, args in PF_SNAPSHOTS:
            actual = runner.run("pfctl", "-a", PF_ANCHOR, *args).stdout
            if actual.rstrip("\n") != expected[name].rstrip("\n"):
                raise ValueError("Project anchor changed after network review")
    else:
        for args in (("-sr",), ("-sn",), ("-s", "Tables")):
            if runner.run("pfctl", "-a", PF_ANCHOR, *args).stdout.strip():
                raise ValueError("Unregistered project anchor changed after network review")
    bridges = settings["bridge_addresses"]
    # Only add private bridges; the physical uplink is NEVER a bridge member.
    for bridge, gateway in bridges.items():
        runner.run("ifconfig", bridge, "create")
        runner.run("ifconfig", bridge, "inet", gateway + "/30", "up")
    before = set(custom_instances(_previous_network(transaction)))
    after = set(custom_instances(settings))
    custom = {name: read_custom_rules(name) for name in sorted(after - before)}
    for name, text in custom.items():
        require_pending(state)
        _load_custom_rules(name, text, runner, state)
    require_pending(state)
    def validate(candidate):
        runner.run("pfctl", "-a", PF_ANCHOR, "-o", "none", "-nf", str(candidate))
        require_pending(state)
    replace_file(settings["pf_file"], settings["pf_rules"], validate=validate)
    runner.run("pfctl", "-a", PF_ANCHOR, "-o", "none", "-f", settings["pf_file"])
    _retire_custom_rules(before - after, runner)
    _wait_custom_retirement(settings, before - after, runner)
    verify_custom_children(settings, runner)
    for name, args in PF_SNAPSHOTS:
        exclusive_file(state / f"pf-{name}.applied", runner.run("pfctl", "-a", PF_ANCHOR, *args).stdout)


def worker(state):
    transaction = json.loads((Path(state) / "firewall-transition.json").read_text())
    runner = NativeRunner(transaction["deadline"])
    try:
        with mutation(state):
            apply_network(state, runner)
        send_message(sys.stdout, "APPLIED")
        if read_message(sys.stdin, transaction["deadline"]) != "KEEP":
            raise RuntimeError("Network confirmation was not received")
        commit(state, runner, transaction["network"]["pf_file"])
        send_message(sys.stdout, "COMMITTED")
    except BaseException as error:
        print(f"Network worker failed: {error}", file=sys.stderr, flush=True)
        send_message(sys.stdout, "FAILED")
    finally:
        # Stay the process-group leader until the supervisor terminates/reaps us.
        # This prevents PID reuse while it terminates command descendants too.
        sys.stdin.read()


def terminate_worker(process):
    """Only use with our unreaped direct child, created with start_new_session."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # The direct child can already be an unreaped zombie, never a reused PID.
    process.wait(timeout=15)
    close_pipe(process.stdin)
    close_pipe(process.stdout)


def supervise(state, request, response, *, worker_command=None):
    """Own the mutator lifecycle; tests may inject a harmless Python child."""
    state = Path(state)
    transaction = json.loads((state / "firewall-transition.json").read_text())
    command = worker_command or [sys.executable, str(Path(__file__).resolve()), "mutate", str(state)]
    process = None
    try:
        require_pending(state)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=sys.stderr, text=True, start_new_session=True)
        if read_message(process.stdout, transaction["deadline"], abort=request) != "APPLIED":
            raise RuntimeError("Network worker did not apply the reviewed policy")
        send_message(response, "APPLIED")
        if read_message(request, transaction["deadline"]) != "KEEP":
            raise RuntimeError("Network confirmation declined")
        send_message(process.stdin, "KEEP")
        if read_message(process.stdout, transaction["deadline"], abort=request) != "COMMITTED":
            raise RuntimeError("Network worker did not commit the confirmed policy")
    except BaseException as error:
        print(f"Network supervisor: {error}", file=sys.stderr, flush=True)
    finally:
        # Critically, kill/reap BEFORE trying the rollback lock. SIGKILL releases
        # it even if the worker was suspended with SIGSTOP while holding flock.
        if process is not None:
            terminate_worker(process)
    # A worker paused just after its final durable commit marker is still a
    # committed transaction. Never undo an explicitly confirmed policy then.
    if (state / "firewall-confirmed").exists():
        notify_final(response, "COMMITTED")
        return 0
    rollback(state)
    notify_final(response, "ROLLED_BACK")
    return 1


def commit(state, runner, pf_file):
    state = Path(state)
    with (state / "firewall.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        settings = json.loads((state / "firewall-transition.json").read_text())
        require_pending(state)
        verify_parent(runner)
        if _private_text(Path(pf_file)) != settings["network"]["pf_rules"]:
            raise ValueError("Project anchor file changed before KEEP")
        verify_custom_children(settings["network"], runner)
        for name, args in PF_SNAPSHOTS:
            # Preserve leading table indentation: shell command substitution in
            # the startup guard strips trailing newlines, not leading spaces.
            actual = runner.run("pfctl", "-a", PF_ANCHOR, *args, timeout=15).stdout
            if actual.rstrip("\n") != _private_text(state / f"pf-{name}.applied").rstrip("\n"):
                raise ValueError("Project anchor changed before KEEP")
            exclusive_file(state / f"pf-{name}.expected", actual)
        require_pending(state)
        # Publish the pending transaction first. Startup guards fail closed until
        # its final marker exists, and rollback can restore the previous pointer
        # if the worker is stopped/killed between these two durable operations.
        active_pointer(state, settings)
        require_pending(state)
        # Last operation: the watchdog cannot race with this write under flock.
        exclusive_file(state / "firewall-confirmed", "Administrator confirmed management connectivity.\n")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("supervise", "mutate", "check-parent", "boot-bridges", "reload-custom"):
        raise SystemExit("Internal helper: expected supervise|mutate|check-parent|boot-bridges|reload-custom and private state")
    if os.geteuid() != 0 or not sys.platform.startswith("freebsd"):
        raise SystemExit("This internal network helper requires the target FreeBSD root context")
    os.environ["PATH"] = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"
    directory = Path(sys.argv[2])
    if sys.argv[1] == "boot-bridges":
        boot_bridges(directory, NativeRunner(time.monotonic() + 120))
        raise SystemExit(0)
    if sys.argv[1] == "reload-custom":
        reload_custom(directory, NativeRunner(time.monotonic() + 120))
        raise SystemExit(0)
    if sys.argv[1] == "check-parent":
        settings = json.loads(_private_text(directory / "firewall-transition.json"))
        if (settings.get("architecture") != OWNERSHIP
                or settings.get("network", {}).get("pf_file") != str(PF_FILE)
                or _private_text(PF_FILE) != settings["network"].get("pf_rules")):
            raise SystemExit("Project PF source/architecture differs from its committed transaction")
        runner = NativeRunner(time.monotonic() + 120)
        verify_parent(runner)
        verify_custom_children(settings["network"], runner, files=True)
        raise SystemExit(0)
    if sys.argv[1] == "supervise":
        raise SystemExit(supervise(directory, sys.stdin, sys.stdout))
    worker(directory)
