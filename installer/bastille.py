"""One explicit Bastille namespace; never load the administrator's configuration."""

import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shlex
import stat

CONFIG_NAME = "nextcloudonfreebsd.conf"
CONFIG_PATH = "/usr/local/etc/bastille/" + CONFIG_NAME
SAMPLE_PATH = "/usr/local/etc/bastille/bastille.conf.sample"
DEVFS_PATH = "/usr/local/etc/cloud-jails/devfs.rules"
DEVFS_KEY = "devfs_ruleset"
RC_DIRECTORY = Path("/usr/local/etc/rc.d")
PATH = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"


def command(*args, creating=None):
    # 1.4.4 sources common.sh BEFORE parsing --config. Set the explicit initial
    # config too; env -i also prevents inherited shell/PATH/Bastille overrides.
    env = ("/usr/bin/env", "-i", "PATH=" + PATH, "LC_ALL=C", "BASTILLE_CONFIG=" + CONFIG_PATH)
    if creating is not None:
        if not re.fullmatch(r"[a-z][a-z0-9]{0,11}", creating) or not args or args[0] != "create":
            raise ValueError("Invalid reserved Bastille creation target")
        env += ("CLOUD_BASTILLE_CREATING=" + creating,)
    return (*env, "/usr/local/bin/bastille", "--config", CONFIG_NAME, *args)


BASTILLE = command()


def owned_text(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Project Bastille paths must be absolute without traversal")
    for parent in path.parents:
        info = parent.lstat()
        sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not sticky)):
            raise ValueError(f"Unsafe project Bastille parent: {parent}")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 1048576):
        raise ValueError(f"Unsafe project Bastille file: {path}")
    return path.read_text()


def static_settings(path, *, bastille=False):
    """Accept literal rc assignments (and simple Bastille path references).

    This is a bounded input check, not a shell interpreter. In particular sysrc
    sources its inputs: validate before asking it to expand Bastille paths.
    """
    values = {}
    for line in owned_text(path).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # No commands, substitutions, continuations, functions or conditionals.
        if not re.fullmatch(r'''\s*[A-Za-z_][A-Za-z0-9_]*=(?:"[^"`\\\n]*"|'[^'\n]*'|[A-Za-z0-9_./:+${}-]*)(?:\s+#.*)?\s*''', line):
            raise ValueError(f"Dynamic configuration requires administrator review: {path}")
        tokens = shlex.split(line, comments=True)
        if len(tokens) != 1:
            raise ValueError(f"Ambiguous configuration assignment: {path}")
        key, _, value = tokens[0].partition("=")
        if bastille and not re.fullmatch(r"bastille_[a-z0-9_]+", key):
            raise ValueError(f"External Bastille config may contain only static bastille_ settings: {path}")
        remainder = re.sub(r"\$\{bastille_[a-z_]+\}", "", value) if bastille else value
        if "$" in remainder or "`" in remainder:
            raise ValueError(f"Dynamic configuration value requires administrator review: {path}")
        values[key] = value
    return values


def inspect_vnet(parameters, configs):
    """Recognize Bastille1.4.4 if_bridge -B/-V hooks and literal rc IPv4 only."""
    name, peer = parameters.get("name", ""), parameters.get("vnet.interface", "")
    if (not re.fullmatch(r"[A-Za-z0-9_-]+", name)
            or not re.fullmatch(r"e0b_[A-Za-z0-9_]{1,11}", peer)
            or parameters.get("exec.start") != "/bin/sh /etc/rc"
            or parameters.get("exec.stop") not in ("/bin/sh /etc/rc.shutdown", "/bin/sh /etc/rc.shutdown jail")):
        raise ValueError("External VNET interface topology is not a reviewed Bastille if_bridge declaration")
    host, suffix = "e0a_" + peer[4:], peer[4:]
    pre = parameters.get("exec.prestart", "").split(",")
    description = f'ifconfig {host} description "vnet0 host interface for Bastille jail {name}"'
    epair = f"epair0=$(ifconfig epair create) && ifconfig ${{epair0}} up name {host} && ifconfig ${{epair0%a}}b up name {peer}"
    if pre and pre[0] == epair and len(pre) >= 3:
        match = re.fullmatch(r"ifconfig ([A-Za-z][A-Za-z0-9_]{0,14}) addm " + re.escape(host), pre[1])
        if not match:
            raise ValueError("Unreviewed external VNET bridge attachment")
        interfaces, rest = {match[1], host, peer}, pre[2:]
    else:
        match = re.fullmatch(r"jib addm " + re.escape(suffix) + r" ([A-Za-z][A-Za-z0-9_]{0,14})", pre[0])
        if not match:
            raise ValueError("Unreviewed external VNET creation hook")
        # FreeBSD share/examples/jails/jib defaults to <interface>bridge.
        interfaces, rest = {match[1], match[1] + "bridge", host, peer}, pre[1:]
    if (rest != [description] and not (len(rest) == 3 and rest[-1] == description
            and all(re.fullmatch(r"ifconfig " + re.escape(interface) + r" ether (?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", hook)
                    for interface, hook in zip((host, peer), rest[:2])))):
        raise ValueError("Unreviewed external VNET prestart hook")
    hooks = {key: value for key, value in parameters.items() if key in HOST_HOOKS and value}
    if (set(hooks) != {"exec.prestart", "exec.poststop"}
            or hooks["exec.poststop"] != f"ifconfig {host} destroy"):
        raise ValueError("Unreviewed external VNET host hook")
    reserved = {endpoint.bridge for c in configs for endpoint in c.network_endpoints}
    reserved.update(prefix + jail for c in configs for jail in c.jails for prefix in ("e0a_", "e0b_"))
    if interfaces & reserved:
        raise ValueError("Configured external VNET bridge/interface conflicts with a project reservation")
    root = Path(parameters.get("path", ""))
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("External VNET root must have an exact absolute path")
    settings = {}
    for leaf in ("etc/rc.conf", "etc/rc.conf.local"):
        path = root / leaf
        if path.exists() or path.is_symlink():
            settings.update(static_settings(path))
    for service in ("netif", "routing", "network"):
        path = root / "etc/rc.conf.d" / service
        if path.exists() or path.is_symlink():
            raise ValueError("External VNET network service override requires administrator review")
    if (settings.get("ifconfig_" + peer + "_name") != "vnet0"
            or not settings.get("ifconfig_vnet0")
            or settings.get("rc_conf_files", "/etc/rc.conf /etc/rc.conf.local") != "/etc/rc.conf /etc/rc.conf.local"
            or settings.get("static_routes") or settings.get("cloned_interfaces")):
        raise ValueError("External VNET address/route sources are not the reviewed static rc layout")
    for key, value in settings.items():
        if not key.startswith("ifconfig_") or key.endswith("_descr") or not value:
            continue
        if key.endswith("_name"):
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,14}", value):
                raise ValueError("Unreviewed external VNET interface rename")
            continue
        if key.endswith("_ipv6"):
            if not re.fullmatch(r"inet6 -ifdisabled (?:accept_rtadv|[0-9a-fA-F:]+/[0-9]{1,3})", value):
                raise ValueError("Unreviewed external VNET IPv6 declaration")
            continue
        match = re.fullmatch(r"inet ([0-9.]+)(?:/([0-9]+)| netmask ([0-9.]+))(?: (?:alias|up))*", value)
        if not match:
            raise ValueError("External VNET requires static, inspectable IPv4 addresses; DHCP/custom ifconfig needs review")
        network = ipaddress.IPv4Network(match[1] + "/" + (match[2] or match[3]), strict=False)
        if any(c.network.overlaps(network) for c in configs):
            raise ValueError("Configured external VNET address overlaps a project private network")
    gateway = settings.get("defaultrouter", "NO")
    if gateway not in ("", "NO") and any(ipaddress.IPv4Address(gateway) in c.network for c in configs):
        raise ValueError("Configured external VNET gateway uses a project private network")


HOST_HOOKS = {"exec.prepare", "exec.prestart", "exec.created", "exec.poststart",
              "exec.prestop", "exec.poststop", "exec.release"}


def ruleset(host):
    value = (host or {}).get(DEVFS_KEY)
    if type(value) is not int or not 1000 <= value <= 65535:
        raise ValueError("Missing/invalid reserved project devfs ruleset; inspect host.json")
    return value


def configuration(config, number, *, sample=None):
    ruleset({DEVFS_KEY: number})
    sample = owned_text(SAMPLE_PATH) if sample is None else sample
    sample_hash = hashlib.sha256(sample.encode()).hexdigest()
    # Source the package SAMPLE, never bastille.conf. It supplies upstream
    # defaults; reset every derived path after changing the project prefix.
    settings = {"bastille_prefix": config.bastille_root,
                **{"bastille_" + name + "dir": config.bastille_root + "/" + name
                   for name in ("backups", "cache", "jails", "releases", "templates", "logs")},
                "bastille_zfs_enable": "YES", "bastille_zfs_zpool": config.pool,
                "bastille_zfs_prefix": "cloud-installer/bastille",
                "bastille_network_vnet_type": "if_bridge",
                "bastille_pf_conf": "/etc/pf.cloud-installer.conf"}
    text = ("# NextcloudOnFreeBSD private Bastille configuration\n"
            f'[ "$(/sbin/sha256 -q {SAMPLE_PATH})" = {sample_hash} ] || exit 1\n'
            ". " + SAMPLE_PATH + "\n")
    text += "".join(key + "=" + shlex.quote(value) + "\n" for key, value in settings.items())
    text += devfs_check(number)
    # Native create starts before applying templates, with hardcoded ruleset13.
    # Intercept ONLY that explicitly reserved creation's internal start. Native
    # config performs the edit before jail(8) mounts devfs; no package patch.
    text += f'''\n# Scope recursive upstream calls and prepare the reserved first devfs mount.
bastille() {{
    if [ "$1" = start ] && [ -n "${{CLOUD_BASTILLE_CREATING:-}}" ]; then
        [ "$#" = 2 ] && [ "$2" = "$CLOUD_BASTILLE_CREATING" ] || return 1
        check_project_devfs || return 1
        case "$(/usr/local/bin/bastille --config {CONFIG_NAME} config "$2" get devfs_ruleset)" in
            13|{number}) ;;
            *) return 1 ;;
        esac
        /usr/local/bin/bastille --config {CONFIG_NAME} config "$2" set devfs_ruleset {number} || return 1
    fi
    /usr/local/bin/bastille --config {CONFIG_NAME} "$@"
}}
'''
    return text


def devfs_lines():
    # FreeBSD15.1 defaults/devfs.rules sets1..5, flattened: no dependency on
    # administrator-modified shared rules, and no global devfs restart/delset.
    paths = ["null", "zero", "crypto", "random", "urandom"]
    paths += [prefix + letter + "*" for prefix in ("pty", "tty") for letter in "pqrsPQRSlmnoLMNO"]
    paths += ["ptmx", "pts", "pts/*", "fd", "fd/*", "stdin", "stdout", "stderr", "fuse", "zfs", "pf", "bpf*"]
    return ["100 hide", *(f"{(index + 2) * 100} path {path} unhide" for index, path in enumerate(paths))]


def devfs_text(number):
    ruleset({DEVFS_KEY: number})
    return f"[nextcloudonfreebsd={number}]\n" + "".join("add " + line + "\n" for line in devfs_lines())


def devfs_used(runner):
    text = runner.output("devfs", "rule", "showsets")
    if any(not value.isdigit() or not 0 <= int(value) <= 65535 for value in text.split()):
        raise ValueError("Cannot interpret native devfs ruleset inventory")
    used = {int(value) for value in text.split()}
    paths = runner.run("sysrc", "-n", "-s", "devfs", "devfs_rulesets", check=False).stdout.split()
    for name in set(paths + ["/etc/defaults/devfs.rules", "/etc/devfs.rules"]):
        path = Path(name)
        if path.exists() or path.is_symlink():
            text = owned_text(path)
            used.update(int(value) for value in re.findall(r"(?m)^\s*\[[^\]\n]*=\s*([0-9]+)\s*\]", text))
    return used


def check_devfs(runner, host=None):
    used = devfs_used(runner)
    path = Path(DEVFS_PATH)
    if host and DEVFS_KEY in host:
        number = ruleset(host)
        expected = devfs_text(number)
        if path.exists() or path.is_symlink():
            if owned_text(path) != expected:
                raise ValueError("Project devfs definition changed; inspect before continuing")
        elif number in used:
            raise ValueError("Reserved project devfs identity is occupied without its owned definition")
        live = runner.output("devfs", "rule", "-s", str(number), "show")
        if live and live.splitlines() != devfs_lines():
            raise ValueError("Reserved project devfs rules differ; never overwrite an existing ruleset")
        # Any persistent declaration elsewhere is a collision, even if identical.
        paths = runner.run("sysrc", "-n", "-s", "devfs", "devfs_rulesets", check=False).stdout.split()
        for name in set(paths + ["/etc/defaults/devfs.rules", "/etc/devfs.rules"]):
            other = Path(name)
            if other != path and (other.exists() or other.is_symlink()):
                if re.search(r"(?m)^\s*\[[^\]\n]*=\s*" + str(number) + r"\s*\]", owned_text(other)):
                    raise ValueError("Reserved project devfs number is also configured elsewhere")
        return number
    if path.exists() or path.is_symlink():
        raise ValueError("Project devfs file has no reserved host identity; refusing adoption")
    for number in range(1000, 65536):
        if number not in used:
            return number
    raise ValueError("No unoccupied project devfs ruleset is available")


def reserve_devfs(registry, runner):
    from .state import atomic_json
    registry._require_lock()
    host = registry.host()
    if not isinstance(host, dict):
        raise ValueError("Project devfs reservation requires the saved host registry")
    number = check_devfs(runner, host)
    if DEVFS_KEY not in host:
        atomic_json(registry.root / "host.json", {**host, DEVFS_KEY: number})
    return number


def devfs_check(number):
    """Read-only gate: FreeBSD can mount an absent ruleset as an empty set."""
    ruleset({DEVFS_KEY: number})
    expected = "\n".join(devfs_lines())
    return f'''check_project_devfs() {{
    current=$(/sbin/devfs rule -s {number} show) || return 1
    [ "$current" = {shlex.quote(expected)} ]
}}
'''


def devfs_loader(number):
    """Idempotent own-set load; partial or changed sets are never overwritten."""
    ruleset({DEVFS_KEY: number})
    additions = "\n".join(f"        /sbin/devfs rule -s {number} add {shlex.join(line.split())} || return 1"
                          for line in devfs_lines())
    return devfs_check(number) + f'''load_project_devfs() {{
    current=$(/sbin/devfs rule -s {number} show) || return 1
    if [ -z "$current" ]; then
{additions}
    fi
    check_project_devfs
}}
'''


def _boot_record(deployment):
    from .state import config_digest, private_json
    path = deployment.state / "jail-boot-service.json"
    service = RC_DIRECTORY / ("cloud_" + deployment.config.instance + "_jails")
    if not path.exists() and not path.is_symlink():
        if service.exists() or service.is_symlink():
            raise ValueError("Unreceipted project jail boot service; cleanup refused")
        return None
    value = private_json(path)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "config_sha256", "service_path", "service_sha256"}
            or value["schema_version"] != 1 or value["config_sha256"] != config_digest(deployment.config)
            or value["service_path"] != str(service)
            or not re.fullmatch(r"[a-f0-9]{64}", str(value["service_sha256"]))):
        raise ValueError("Project jail boot receipt changed; cleanup refused")
    return value


def disable_boot_service(deployment):
    from .lifecycle import _owned_file
    from .state import private_json
    deployment.registry._require_lock()
    value = _boot_record(deployment)
    if value is None:
        return
    current = _owned_file(value["service_path"], digest=value["service_sha256"], mode=0o700)
    if current is None:
        return  # No executable exists; retained receipt still governs cleanup.
    cleanup = deployment.state / "removal-config.json"
    if cleanup.exists() or cleanup.is_symlink():
        prior = private_json(cleanup).get("files", {}).get("jail_service")
        if prior is not None and (prior.get("state") != "authorized" or prior.get("identity") != current[1]):
            raise ValueError("Project jail boot service reappeared; withdrawal refused")
    key = "cloud_" + deployment.config.instance + "_jails_enable"
    flag = deployment.runner.run("sysrc", "-n", key, check=False).stdout.strip()
    if flag not in ("", "YES", "NO"):
        raise ValueError("Project jail boot enable entry changed; withdrawal refused")
    if flag == "YES":
        deployment.runner.run("sysrc", key + "=NO")


def cleanup_boot_service(deployment, journal):
    """Reuse owner-qualified, interruption-safe removal for this exact rc file."""
    from .lifecycle import _owned_file, _remove_owned_file
    deployment.registry._require_lock()
    value = _boot_record(deployment)
    if value is None:
        return
    current = _owned_file(value["service_path"], digest=value["service_sha256"], mode=0o700)
    prior_file = journal.data.get("files", {}).get("jail_service")
    if current is not None and prior_file is not None and (
            prior_file.get("state") != "authorized" or prior_file.get("identity") != current[1]):
        raise ValueError("Project jail boot service reappeared; cleanup refused")
    key = "cloud_" + deployment.config.instance + "_jails_enable"
    result = deployment.runner.run("sysrc", "-a", hide_output=True)
    entries = [line.partition(": ")[2] for line in result.stdout.splitlines() if line.startswith(key + ": ")]
    prior = journal.data.get("jail_enable")
    if (len(entries) > 1 or (entries and entries[0] not in ("YES", "NO"))
            or (prior is not None and (not isinstance(prior, dict) or prior.get("key") != key
                                      or prior.get("state") not in ("authorized", "removed", "absent")))):
        raise ValueError("Project jail boot enable cleanup identity changed")
    if entries:
        if prior is not None and (prior.get("state") != "authorized" or prior.get("value") != entries[0]):
            raise ValueError("Project jail boot enable entry reappeared/changed; cleanup refused")
        if prior is None:
            journal.data["jail_enable"] = dict(key=key, value=entries[0], state="authorized")
            journal.save()
        deployment.runner.run("sysrc", "-x", key, hide_output=True)
        result = deployment.runner.run("sysrc", "-a", hide_output=True)
        if any(line.startswith(key + ": ") for line in result.stdout.splitlines()):
            raise RuntimeError("Project jail boot enable removal did not finish")
    journal.data["jail_enable"] = dict(key=key, state="removed" if entries or prior else "absent")
    journal.save()
    _remove_owned_file(journal, "jail_service", value["service_path"], value["service_sha256"], mode=0o700)


def boot_service(config, number, *, config_sha256, guard_sha256, jail_files):
    """Per-instance rc service; removed roots are skipped, never target 'all'."""
    if any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in (config_sha256, guard_sha256)):
        raise ValueError("Project boot helper requires exact configuration/guard identities")
    if (set(jail_files) != set(config.jails)
            or any(set(value) != {"jail.conf", "fstab"} for value in jail_files.values())
            or any(not re.fullmatch(r"[a-f0-9]{64}", digest)
                   for value in jail_files.values() for digest in value.values())):
        raise ValueError("Project boot helper requires exact selected jail configuration identities")
    cases = "\n".join(f'        {jail}) check_file "${{root%/root}}/jail.conf" {value["jail.conf"]} && '
                      f'check_file "${{root%/root}}/fstab" {value["fstab"]} || return 1 ;;'
                      for jail, value in jail_files.items())
    name = "cloud_" + config.instance + "_jails"
    cmd = shlex.join(command())
    guard = "/usr/local/libexec/" + config.instance + "-storage-guard"
    return f'''#!/bin/sh
# PROVIDE: {name}
# REQUIRE: NETWORKING pf zfs devfs cloud_jails_guard
# KEYWORD: shutdown nojail
. /etc/rc.subr
name={name}
rcvar={name}_enable
start_cmd={name}_start
stop_cmd={name}_stop
check_file() {{
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    parent=${{1%/*}}
    while :; do
        [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
        metadata=$(/usr/bin/stat -f '%u:%Lp' "$parent") || return 1
        [ "${{metadata%%:*}}" = 0 ] || return 1
        mode=${{metadata#*:}}
        case "$mode" in ''|*[!0-7]*) return 1 ;; esac
        [ "$((0$mode & 022))" = 0 ] || return 1
        [ "$parent" != / ] || break
        parent=${{parent%/*}}; [ -n "$parent" ] || parent=/
    done
    metadata=$(/usr/bin/stat -f '%u:%Lp:%l' "$1") || return 1
    case "$metadata" in 0:600:1|0:700:1|0:644:1|0:755:1) ;; *) return 1 ;; esac
    [ "$(/sbin/sha256 -q "$1")" = "$2" ]
}}
project_jail() {{
    action=$1; jail=$2
    check_file {CONFIG_PATH} {config_sha256} || return 1
    root={shlex.quote(config.bastille_root)}/jails/$jail/root
    [ ! -L "$root" ] && [ ! -L "${{root%/root}}" ] || return 1
    [ -d "$root" ] || {{ [ ! -e "${{root%/root}}" ] && [ ! -L "${{root%/root}}" ]; return $?; }}
    case "$jail" in
{cases}
        *) return 1 ;;
    esac
    [ "$({cmd} config "$jail" get path)" = "$root" ] || return 1
    [ "$(/sbin/zfs get -H -o value org.cloud-installer:instance {config.bastille_dataset}/jails/$jail)" = {config.instance} ] || return 1
    [ "$(/sbin/zfs get -H -o value org.cloud-installer:instance {config.bastille_dataset}/jails/$jail/root)" = {config.instance} ] || return 1
    [ "$(/sbin/zfs get -H -o value mountpoint {config.bastille_dataset}/jails/$jail/root)" = "$root" ] || return 1
    [ "$(/sbin/zfs get -H -o value mounted {config.bastille_dataset}/jails/$jail/root)" = yes ] || return 1
    if current=$(/usr/sbin/jls -j "$jail" -n name path 2>/dev/null); then
        [ "$current" = "name=$jail path=$root" ] || return 1
    elif [ "$action" = stop ]; then
        return 0
    fi
    [ "$({cmd} config "$jail" get devfs_ruleset)" = {number} ] || return 1
    for settings in {shlex.quote(config.bastille_root)}/jails/*/settings.conf; do
        [ -f "$settings" ] && [ ! -L "$settings" ] || return 1
        /usr/bin/awk '
            /^[[:space:]]*$/ {{ next }}
            /^[[:space:]]*(boot="(on|off)"|depend=""|priority="[0-9]+")[[:space:]]*$/ {{ next }}
            {{ exit 1 }}' "$settings" || return 1
        dependency=$(/usr/sbin/sysrc -f "$settings" -n depend) || return 1
        [ "$dependency" = "" ] || return 1
    done
    if [ "$action" = start ]; then
        [ "$({cmd} config "$jail" get boot)" = on ] || return 0
        check_file {guard} {guard_sha256} || return 1
        {guard} "$jail" || return 1
        {cmd} start --boot "$jail"
    else
        {cmd} stop "$jail"
    fi
}}
{name}_start() {{
    result=0
    for jail in {' '.join(config.jails)}; do project_jail start "$jail" || result=1; done
    return "$result"
}}
{name}_stop() {{
    result=0
    for jail in {' '.join(reversed(config.jails))}; do project_jail stop "$jail" || result=1; done
    return "$result"
}}
load_rc_config "$name"
: ${{{name}_enable:=NO}}
run_rc_command "$1"
'''
