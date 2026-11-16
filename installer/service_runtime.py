"""Native-service seams and post-occ Push artifact handoff; no implicit repair."""

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

from .state import atomic_write, atomic_json, private_directory, private_json


_PACKAGE_RECORD_VERSION = r"[A-Za-z0-9._+][A-Za-z0-9.+_,~:\-]{0,255}"


def require_host_controls_resolved(registry):
    """No shared-host mutation beneath a retained uncertain control group."""
    from .service_deadlines import REFUSAL, ServiceControlError
    directory = registry.root / "instances"
    if directory.is_symlink():
        raise ValueError("Unsafe instance registry; manual control assessment required")
    if not directory.exists():
        return
    for path in directory.iterdir():
        if path.is_symlink():
            raise ValueError("Unsafe instance registry; manual control assessment required")
        marker = path / REFUSAL
        if marker.exists() or marker.is_symlink():
            raise ServiceControlError(host_control_closed=False)


TALK_SERVICE_ADAPTER = r'''code = 70
try:
    import hashlib, os, stat, sys
    if len(sys.argv) != 4 or sys.argv[1] not in ('nats', 'janus', 'turnserver', 'ncs_signaling') or sys.argv[2] not in ('onestart', 'onestop', 'onestatus'):
        raise ValueError('Unsupported service action')
    path = '/root/cloud-installer/resources/jails/talk-runtime.py'
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in ('root', 'cloud-installer', 'resources', 'jails'):
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Unprotected helper parent')
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unprotected helper parent')
        fd = os.open('talk-runtime.py', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 1048576:
                raise ValueError('Unprotected helper')
            source = stream.read(1048577)
    finally:
        os.close(directory)
    if len(source) > 1048576 or hashlib.sha256(source).hexdigest() != sys.argv[3]:
        raise ValueError('Helper differs from original artifact')
    runtime = {'__name__': '_cloud_talk_service_adapter', '__file__': path}
    exec(compile(source, path, 'exec'), runtime)
    result = runtime['service_command'](sys.argv[1], sys.argv[2])
    if type(result) is int and 0 <= result <= 255:
        frame = 'CLOUD_TALK_SERVICE_V1 ' + sys.argv[1] + ' ' + sys.argv[2] + ' ' + str(result) + '\n'
        sys.stdout.write(frame)
        sys.stdout.flush()
        code = 0
except BaseException:
    # Validation, timeout, signal/cancellation and import failures must NEVER
    # alias native onestatus=1 (positively stopped). No raw exception output.
    code = 70
raise SystemExit(code)
'''


def talk_service_command(deployment, service, action):
    """Public scalar argv only; interpret status AFTER the numeric-JID guard."""
    from .paths import RESOURCES
    from .talk import SERVICES
    digest = hashlib.sha256((RESOURCES / "jails/talk-runtime.py").read_bytes()).hexdigest()
    name = deployment.config.talk_jail
    result = deployment.jail(name, "python3", "-I", "-B", "-c",
                             TALK_SERVICE_ADAPTER, service, action, digest,
                             check=False, hide_output=True, input="", timeout=30)
    # An outer jexec/interpreter exit1 is NOT evidence of native stopped state.
    # Accept one canonical bounded PUBLIC completion frame, only after all
    # identity checks, with the launcher and primitive outcomes kept separate.
    if (service not in SERVICES or action not in ("onestart", "onestop", "onestatus")
            or result.returncode != 0 or result.stderr != "" or not isinstance(result.stdout, str)
            or len(result.stdout) > 128):
        return 70
    frame = re.fullmatch(r"CLOUD_TALK_SERVICE_V1 ([a-z_]+) (onestart|onestop|onestatus) (0|[1-9][0-9]{0,2})\n", result.stdout)
    if (frame is None or frame[1] != service or frame[2] != action or int(frame[3]) > 255):
        return 70
    return int(frame[3])


class _HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        if not url.startswith("https://"):
            raise ValueError("Native-service artifact redirect must retain HTTPS")
        return super().redirect_request(request, response, code, message, headers, url)


class _PushHTTPSRedirect(_HTTPSRedirect):
    def redirect_request(self, request, response, code, message, headers, url):
        if urlsplit(url).hostname not in ("github.com", "release-assets.githubusercontent.com"):
            raise ValueError("Official Push asset redirected outside GitHub release storage")
        return super().redirect_request(request, response, code, message, headers, url)


def require_supported_maintenance_profile(config, operation):
    if getattr(config, "service_profile", ""):
        raise ValueError(f"{operation} is unavailable for native-v1: Push/Talk coherent maintenance participants are not reviewed")


def package_group(endpoint):
    try:
        return {"nc": "nextcloud", "nativeoo": "onlyoffice", "talk": "talk"}[endpoint.role]
    except KeyError:
        raise ValueError("Unexpected jail endpoint role; VM identities must not enter Bastille") from None


def package_runtime_versions(deployment, group):
    from .package_policy import repository_current
    from .version_runtime import dependency_text, package_text, runtime_versions
    plan = deployment.versions
    if repository_current(plan):
        return runtime_versions(plan, "", "", group=group)
    return runtime_versions(plan, package_text(plan, group), dependency_text(plan, group))


def stage_package_inputs(deployment, target, group):
    """Never retrofit requirements onto retained lock files or erase evidence."""
    from .package_policy import repository_current, requirements_text
    from .version_runtime import dependency_text, package_text
    plan = deployment.versions
    if repository_current(plan):
        if any((target / name).exists() or (target / name).is_symlink()
               for name in ("packages.lock", "packages.dependencies")):
            raise ValueError("Unexpected retained package locks in repository-current payload; explicit inspection required")
        atomic_write(target / "packages.requirements.json", requirements_text(plan, group))
    else:
        atomic_write(target / "packages.lock", package_text(plan, group))
        atomic_write(target / "packages.dependencies", dependency_text(plan, group))
    return package_runtime_versions(deployment, group)


def _package_command(deployment, group, *args, **kwargs):
    if group == "host":
        return deployment.pkg(*args, **kwargs)
    endpoint = next(endpoint for endpoint in deployment.config.jail_endpoints if package_group(endpoint) == group)
    # Use the same clean native pkg configuration as versions.sh; jail() retains
    # the numeric-JID/name/root checks on both sides of every command.
    return deployment.jail(endpoint.name, "/usr/bin/env", "-i",
                           "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C",
                           "/usr/local/sbin/pkg", "-C", "/dev/null", *args, **kwargs)


def inspect_package_requirements(deployment, group, *, names=None, allow_missing=False, repository=False, deadline=None):
    """Observe selected root names/origins/ABI, without package version locks."""
    from .package_policy import requirements
    from .versions import NAME, ORIGIN
    value = requirements(deployment.versions, group)
    roots = value["roots"]
    selected = sorted(roots if names is None else names)
    if not selected or any(name not in roots for name in selected):
        raise ValueError("Unselected package requirement")
    def timeout():
        remaining = 30 if deadline is None else min(30, deadline - time.monotonic())
        if remaining <= 0:
            raise RuntimeError("Package requirement inspection deadline expired")
        return remaining
    observed, missing = {}, []
    for name in selected:
        args = ("rquery", "-U", "-r", "FreeBSD-ports") if repository else ("query",)
        result = _package_command(deployment, group, *args, "%n|%v|%o|%q", name,
                                  check=False, hide_output=True, input="", timeout=timeout())
        if (allow_missing and result.returncode == 1
                and not result.stdout.strip() and not result.stderr.strip()):
            missing.append(name)
            continue
        row = result.stdout.strip().split("|")
        if (result.returncode or len(row) != 4 or (row[0] != name and "/" not in name)
                or not re.fullmatch(NAME, row[0]) or not re.fullmatch(_PACKAGE_RECORD_VERSION, row[1])
                or not re.fullmatch(ORIGIN, row[2]) or (roots[name] and row[2] != roots[name])
                or row[3] not in (value["abi"], value["abi"].rsplit(":", 1)[0] + ":*")):
            raise ValueError("Required package name/origin/ABI is missing or invalid: " + name)
        observed[name] = (row[1], row[2])
    if group == "host" and not repository:
        python = deployment.runner.run("/usr/local/bin/python3", "-I", "-B", "-c",
                                       "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)",
                                        check=False, hide_output=True, input="", timeout=timeout())
        if python.returncode:
            raise ValueError("Host Python must be functional Python 3.11 or newer; explicit host maintenance required")
    return observed, missing


def _package_inventory(deployment, group):
    from .versions import NAME, ORIGIN
    result = _package_command(deployment, group, "query", "-a", "%n %v %o", hide_output=True, input="", timeout=30)
    lines = result.stdout.splitlines()
    rows = [line.split() for line in lines]
    if (result.returncode or not rows or any(len(row) != 3 or not re.fullmatch(NAME, row[0])
                        or not re.fullmatch(_PACKAGE_RECORD_VERSION, row[1]) or not re.fullmatch(ORIGIN, row[2]) for row in rows)
            or len({row[0] for row in rows}) != len(rows)):
        raise ValueError("Invalid or empty observed package inventory")
    return lines


def verify_package_requirements(deployment, group):
    """Check selected roots, not every installed compiler/base package capability.

    Completed phases never contact a repository or perform package repair. This
    is not a recursive dependency audit; application readiness is checked apart.
    """
    observed, _ = inspect_package_requirements(deployment, group)
    selected = sorted(observed)
    # With no names pkg defaults to all packages. Never broaden an empty plan.
    if not selected:
        raise ValueError("Native pkg consistency check requires selected package roots")
    command = ("check", "-d", "-n", "-q", *selected)
    parent = private_directory(private_directory(deployment.state) / "package-diagnostics")
    evidence = private_directory(tempfile.mkdtemp(prefix="pkg-check-", dir=parent))
    record = {"group": group, "command": ["pkg", *command], "outcome": "incomplete",
              "exit_status": None, "stream_limit_bytes": 65536}
    atomic_json(evidence / "result.json", record)
    try:
        result = _package_command(deployment, group, *command,
                                  check=False, hide_output=True, input="", timeout=60)
    except Exception as error:
        # Runner deliberately discards private timeout output. Do not invent an
        # exit status/empty-stream success or serialize a raw exception/argv.
        record["outcome"] = ("timeout" if isinstance(error, subprocess.TimeoutExpired)
                             or str(error) == "Private command timed out" else "command-incomplete")
        atomic_json(evidence / "result.json", record)
        raise ValueError(f"Native pkg consistency check did not complete; inspect private evidence: {evidence}") from None
    record["exit_status"] = result.returncode
    for stream in ("stdout", "stderr"):
        data = getattr(result, stream).encode("utf-8")
        retained = data[:record["stream_limit_bytes"]]
        atomic_write(evidence / stream, retained)
        record[stream] = {"captured_bytes": len(data), "retained_bytes": len(retained),
                          "truncated": len(data) > len(retained)}
    findings = result.returncode != 0 or result.stdout != "" or result.stderr != ""
    record["outcome"] = "findings-or-diagnostics" if findings else "success"
    atomic_json(evidence / "result.json", record)
    if findings:
        raise ValueError(f"Native pkg consistency check produced findings or diagnostics; inspect private evidence: {evidence}")
    key = "host" if group == "host" else next(endpoint.name for endpoint in deployment.config.jail_endpoints
                                               if package_group(endpoint) == group)
    deployment.manifest.setdefault("package_versions", {})[key] = _package_inventory(deployment, group)


def _host_install_proposal(text, installed, missing):
    """Inspect native pkg's disclosed actions, not its dependency solution."""
    if not isinstance(text, str) or not text or len(text) > 1048576:
        raise ValueError("Invalid native host pkg dry-run output")
    proposed, action = set(), False
    for line in text.splitlines():
        header = re.search(r"(?:packages|groups) to be ([A-Z]+):$", line)
        if header:
            if line != "New packages to be INSTALLED:":
                raise ValueError("Host pkg proposed upgrades/removals/downgrades/reinstallation; explicit host maintenance required")
            action = True
            continue
        if action:
            row = re.fullmatch(r"\s+([A-Za-z0-9][A-Za-z0-9_+.-]*):\s+\S+(?:\s+.*)?", line)
            if row:
                if row[1] in installed or row[1] in proposed or row[1].startswith("FreeBSD-"):
                    raise ValueError("Host pkg proposed changing an existing/base package; explicit host maintenance required")
                proposed.add(row[1])
            elif line.strip():
                if line[0].isspace():
                    raise ValueError("Unrecognized native host pkg dry-run action")
                action = False
    if not set(missing) <= proposed:
        raise ValueError("Native host pkg dry-run did not disclose all missing roots")
    return proposed


def install_missing_host_packages(deployment, missing, *, arguments=None):
    """Permit additions only, including when a missing root needs dependencies."""
    before = {line.split()[0]: line for line in _package_inventory(deployment, "host")}
    args = missing if arguments is None else arguments
    if not missing or set(missing) & before.keys():
        raise ValueError("Host package addition requires exclusively missing roots")
    managers = before.keys() & {"pkg", "pkg-devel"}
    if len(managers) != 1:
        raise ValueError("Cannot establish the installed host package-manager identity; inspect pkg before continuing")
    # pkg skips its special self-version check during dry-run. Explicitly name
    # the installed manager for review only, so its proposed upgrade is visible.
    proposal = deployment.pkg("install", "-n", "-y", "-U", "-r", "FreeBSD-ports", *args, *sorted(managers),
                               input="", timeout=120)
    if isinstance(proposal.stdout, str) and len(proposal.stdout) <= 1048576:
        print(proposal.stdout, end="" if proposal.stdout.endswith("\n") else "\n", flush=True)
    additions = _host_install_proposal(proposal.stdout, before, missing)
    current = {line.split()[0]: line for line in _package_inventory(deployment, "host")}
    if current != before:
        raise ValueError("Host package inventory changed during review; recheck before installing")
    # -U retains the reviewed signed catalog. The dry-run rejects ALL existing
    # package changes, including dependencies and the manager's self-upgrade.
    # Only missing roots enter the real install; do not change manager flags.
    deployment.pkg("install", "-y", "-U", "-r", "FreeBSD-ports", *args, capture=False)
    after = {line.split()[0]: line for line in _package_inventory(deployment, "host")}
    if (any(after.get(name) != row for name, row in before.items())
            or after.keys() - before.keys() != additions):
        raise ValueError("Host package outcome differs from additions-only review; inspect native pkg state")


def install_host_requirements(deployment):
    """Reuse installed roots; native pkg owns required package/dependency updates."""
    _, missing = inspect_package_requirements(deployment, "host", allow_missing=True)
    if missing:
        deployment.pkg("update", "-r", "FreeBSD-ports", capture=False)
        inspect_package_requirements(deployment, "host", names=missing, repository=True, allow_missing=True)
        deployment.pkg("install", "-y", "-U", "-r", "FreeBSD-ports", *missing, capture=False)
    verify_package_requirements(deployment, "host")


TALK_ADDRESS_PHASE = "Talk installation address"


def resolve_talk_address(config, runner):
    """Resolve media identity once on the host, never through jail hosts overrides."""
    script = """import json,socket,sys
addresses = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(
    sys.argv[1], None, socket.AF_INET, socket.SOCK_DGRAM)))
print(json.dumps(addresses))
"""
    result = runner.run("/usr/local/bin/python3", "-I", "-B", "-c", script,
                        config.talk_media_hostname, hide_output=True, input="", timeout=30)
    try:
        if result.returncode or len(result.stdout) > 65536:
            raise ValueError
        addresses = json.loads(result.stdout)
        if (not isinstance(addresses, list) or not addresses or len(addresses) > 1024
                or any(not isinstance(address, str) for address in addresses)):
            raise ValueError
        from .config import validate_talk_public_ip
        for address in addresses:
            try:
                return validate_talk_public_ip(address, live=True)
            except (ValueError, TypeError):
                continue
    except (ValueError, TypeError):
        pass
    raise ValueError("Talk media hostname has no usable IPv4 for Janus/coturn installation settings")


def _talk_address_identity(registry, config):
    from .host import read_private
    from .state import config_digest
    source = read_private(registry.evidence_path(config.instance, "source.sha256")).strip()
    if not re.fullmatch(r"[a-f0-9]{64}", source):
        raise ValueError("Talk installation address requires its recorded installer identity")
    return {"schema_version": 1, "instance": config.instance,
            "config_sha256": config_digest(config), "source_sha256": source,
            "media_hostname": config.talk_media_hostname}


def _talk_address_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _read_talk_address(registry, config):
    from .config import validate_talk_public_ip
    path = registry.instance_path(config.instance) / "talk-address.json"
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise ValueError("Unsafe Talk installation address input")
    value = private_json(path)
    expected = _talk_address_identity(registry, config)
    if (not isinstance(value, dict) or set(value) != set(expected) | {"address"}
            or type(value.get("schema_version")) is not int
            or not isinstance(value.get("address"), str)
            or any(value.get(key) != item for key, item in expected.items())):
        raise ValueError("Talk installation address identity differs from the selected instance")
    validate_talk_public_ip(value["address"], live=True)
    return value


def load_talk_address(registry, config):
    """Authenticate the installation input; DNS changes are not eligibility checks."""
    if not config.talk or not config.talk_media_hostname:
        raise ValueError("A hostname-selected Talk instance is required")
    value = _read_talk_address(registry, config)
    journal = private_json(registry.instance_path(config.instance) / "deployment.json")
    if (journal.get("config_sha256") != value["config_sha256"]
            or journal.get("talk_address_sha256") != _talk_address_digest(value)
            or journal.get("steps", {}).get(TALK_ADDRESS_PHASE, {}).get("state") != "complete"):
        raise ValueError("Talk installation address is not a completed authenticated input; inspect retained state")
    return value["address"]


def prepare_talk_address(deployment, journal):
    """Write once before dependent phases; an interrupted preparation reuses its bytes."""
    config = deployment.config
    if not deployment.registry._locked:
        raise ValueError("Talk installation address preparation requires the host operation lock")
    deployment.require_original_artifact()
    phase = journal.data["steps"].get(TALK_ADDRESS_PHASE, {})
    if phase.get("state") != "running":
        raise ValueError("Talk installation address must be prepared by its journal phase")
    path = deployment.state / "talk-address.json"
    digest = journal.data.get("talk_address_sha256")
    if digest:
        value = _read_talk_address(deployment.registry, config)
        if digest != _talk_address_digest(value):
            raise ValueError("Talk installation address differs from its journaled input")
        return
    if any(name != TALK_ADDRESS_PHASE for name in journal.data["steps"]):
        raise ValueError("Dependent deployment phases exist without an authenticated Talk address")
    if path.exists() or path.is_symlink():
        value = _read_talk_address(deployment.registry, config)
    else:
        value = {**_talk_address_identity(deployment.registry, config),
                 "address": resolve_talk_address(config, deployment.runner)}
        atomic_json(path, value)
    journal.data["talk_address_sha256"] = _talk_address_digest(value)
    journal.save()


def deployment_talk_public(deployment):
    config = deployment.config
    address = (load_talk_address(deployment.registry, config)
               if config.talk_media_hostname else None)
    return talk_public(config, resolved_address=address)


def talk_public(config, *, resolved_address=None):
    from .talk import public_from_config
    return public_from_config(config, no_other_sensitive_udp_services=True,
                              resolved_address=resolved_address,
                              forbidden_peer_ips=(config.nextcloud_gateway, config.talk_gateway,
                                                  *((resolved_address or config.talk_public_ip,)
                                                    if resolved_address or config.talk_public_ip else ())))


def integration_input(config, secrets, connector):
    """Only app-native connector and Talk HMAC secrets enter NC finishing stdin."""
    if not config.has_native_services:
        return connector
    value = {"connector": ({"jwt_secret": secrets["jwt_secret"]}
                            if config.backend in ("onlyoffice", "eurooffice") else {})}
    if config.talk:
        value["talk"] = {key: secrets["talk_" + key] for key in ("signaling_secret", "turn_secret")}
    return value


def prepare_assets(deployment, selection=None):
    """Authenticate locked bytes before any provisioning; never substitute latest.

    A preexisting partial, symlink or mismatching cache requires inspection. The
    app's vendor signature is separately verified by the NC installation worker.
    """
    from .service_deadlines import require_resolved
    require_resolved(deployment)
    from .client_push import ArtifactLock, validate_artifact
    from .services import validate_extension
    identity = deployment.state / "source.sha256"
    if identity.exists() or identity.is_symlink():
        deployment.require_original_artifact()
    extension = validate_extension(deployment.versions["services"], config=deployment.config)
    fresh = "app_installation" in deployment.versions
    if fresh and selection is None:
        return None  # No binary identity exists until real occ installs the app.
    cache = private_directory(deployment.state / "service-artifacts")
    if any(path.name not in ("notify_push", "notify_push.tar.gz") for path in cache.iterdir()):
        raise ValueError("Uncertain native-service artifact cache requires explicit inspection")
    artifacts = (("notify_push", selection["native"]),) if fresh else (("notify_push", extension["push"]["native"]),
                         ("notify_push.tar.gz", extension["push"]["app"]))
    for name, record in artifacts:
        path = cache / name
        partial = cache / (name + ".partial")
        if partial.exists() or partial.is_symlink() or path.is_symlink():
            raise ValueError("Uncertain native-service artifact cache requires explicit inspection")
        if path.exists():
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o777 != 0o600 or info.st_nlink != 1 or info.st_size != record["size"]):
                raise ValueError("Native-service cached artifact identity differs")
            data = path.read_bytes()
        else:
            url = record.get("url") or record["release"]["download"]
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _PushHTTPSRedirect() if fresh else _HTTPSRedirect())
            with opener.open(url, timeout=60) as response:
                if not response.geturl().startswith("https://"):
                    raise ValueError("Native-service artifact redirect must retain HTTPS")
                data = response.read(record["size"] + 1)
        if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError("Native-service artifact size/checksum differs from immutable lock")
        if name == "notify_push":
            validate_artifact(data, ArtifactLock(**record))
        if not path.exists():
            atomic_write(path, data)
    return cache


def observe_apps(deployment):
    """Read actual native completed app state, without selecting/updating releases."""
    selected = deployment.versions["app_installation"]["apps"]
    def occ(*args):
        return deployment.jail(deployment.config.nextcloud_jail, "mdo", "-u", "www", "/usr/local/bin/php",
                               "/usr/local/www/nextcloud/occ", "--no-interaction", *args,
                               hide_output=True, input="", timeout=60).stdout
    try:
        inventory = json.loads(occ("app:list", "--output=json"))
        enabled = inventory["enabled"]
        if enabled == []:
            enabled = {}
        if not isinstance(enabled, dict):
            raise ValueError
        observed = {}
        for app in selected:
            version = enabled.get(app)
            if (not isinstance(version, str) or not version or len(version) > 128
                    or any(ord(char) < 32 or ord(char) == 127 for char in version)
                    or occ("config:app:get", app, "installed_version").rstrip("\r\n") != version):
                raise ValueError
            observed[app] = version
        for app, action in (("snappymail", "snappymail-check"),
                            ("files_external", "external-storage-check")):
            if app not in selected:
                continue
            deployment.jail(deployment.config.nextcloud_jail, "/bin/sh", "-c",
                "exec mdo -u www /usr/local/bin/php "
                "-d log_errors=0 -d error_log=/dev/null -d display_errors=0 -d zend.exception_ignore_args=1 "
                f"/usr/local/libexec/cloud-nextcloud-bootstrap.php {action} "
                "3< /root/cloud-installer/runtime.json < /dev/null",
                hide_output=True, input="", timeout=60)
        return observed
    except (ValueError, TypeError, KeyError):
        raise ValueError("Selected apps do not report completed native enabled/installed state; explicit recovery required") from None


def install_apps(deployment):
    deployment.nextcloud_phase("apps")
    atomic_json(deployment.state / "app-observations.json", observe_apps(deployment))


def prepare_push(deployment, journal, *, select=None):
    """One write-once initialization output, reused on Resume before any install."""
    from dataclasses import asdict
    from .client_push import validate_selection
    from .discovery import push_native_artifact
    from .host import read_private
    if not deployment.registry._locked or "app_installation" not in deployment.versions:
        raise ValueError("Deferred Push requires the fresh occ contract and host operation lock")
    deployment.require_original_artifact()
    observed = observe_apps(deployment)
    plan_hash = hashlib.sha256(json.dumps(deployment.versions, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    source = read_private(deployment.registry.evidence_path(deployment.config.instance, "source.sha256")).strip()
    identity = dict(instance=deployment.config.instance, source_sha256=source, plan_sha256=plan_hash,
                    app_version=observed["notify_push"])
    path = deployment.state / "push-native.json"
    recorded = journal.data.get("push_selection_sha256")
    complete = journal.data.get("steps", {}).get("Client Push native artifact", {}).get("state") == "complete"
    if complete and recorded is None:
        raise ValueError("Completed Push phase has no journaled selection identity; explicit recovery required")
    if path.exists() or path.is_symlink():
        selection = validate_selection(private_json(path), **identity)
    else:
        if recorded is not None or complete:
            raise ValueError("Saved Push phase input is missing; explicit recovery required, no reselection")
        native = (push_native_artifact if select is None else select)(observed["notify_push"])
        selection = validate_selection({"schema_version": 1, **identity, "native": asdict(native)}, **identity)
        atomic_json(path, selection)  # Persist exact identity BEFORE download/stage/install.
    digest = hashlib.sha256(json.dumps(selection, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if recorded is not None and recorded != digest:
        raise ValueError("Push phase input differs from its journaled identity; explicit recovery required")
    if recorded is None:
        journal.data["push_selection_sha256"] = digest
        journal.save()  # Survives failed attempts; Journal.run preserves top-level outputs.
    cache = prepare_assets(deployment, selection)
    target = deployment.jail_root(deployment.config.nextcloud_jail) / "root/cloud-installer"
    jid = deployment.require_running_jail(deployment.config.nextcloud_jail)
    try:
        private_directory(target)
        for name, data in (("push-native.json", json.dumps(selection, sort_keys=True, separators=(",", ":")).encode() + b"\n"),
                           ("notify-push.bin", (cache / "notify_push").read_bytes())):
            destination = target / name
            if destination.exists() or destination.is_symlink():
                info = destination.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o600
                        or info.st_nlink != 1 or destination.read_bytes() != data):
                    raise ValueError("Staged Push phase input changed; explicit recovery required")
            else:
                atomic_write(destination, data)
    finally:
        if deployment.require_running_jail(deployment.config.nextcloud_jail) != jid:
            raise RuntimeError("Nextcloud jail identity changed during Push staging")
    return selection


def talk_phase(deployment, phase):
    """Worker owns local config/service validation; stdin never gets NC secrets."""
    from .talk import SECRET_KEYS, configure_stdin, normalize_secrets
    if phase not in ("prepare", "configure", "verify"):
        raise ValueError("Unknown Talk worker phase")
    kwargs = {"hide_output": True}
    if phase == "configure":
        selected = normalize_secrets({key: deployment.secrets[key] for key in SECRET_KEYS})
        kwargs["input"] = configure_stdin(deployment_talk_public(deployment), selected).decode("utf-8")
    result = deployment.jail(deployment.config.talk_jail, "/bin/sh",
                            "/root/cloud-installer/resources/jails/talk.sh", phase, **kwargs)
    advisory = "Optional signaling feature changed-users is absent."
    if advisory in result.stdout.splitlines():
        print("WARNING: " + advisory)
    return result


def stop_talk(deployment):
    from .talk import SERVICES
    failed = False
    for service in reversed(SERVICES):
        try:
            talk_service_command(deployment, service, "onestop")
        except (ValueError, RuntimeError, OSError):
            # A failed launcher/transport does not prove either running or
            # stopped. Still attempt the independently guarded status check.
            pass
        try:
            status = talk_service_command(deployment, service, "onestatus")
            if status != 1:
                failed = True
        except (ValueError, RuntimeError, OSError):
            failed = True
    if failed:
        raise RuntimeError("Talk shutdown is unconfirmed; keep the owned jail stopped and inspect retained state")


def start_talk(deployment):
    """Restart the disabled-boot stack in dependency order, then observe it."""
    from .talk import SERVICES
    # C's read-only identity/config primitives do not require running listeners.
    # Authenticate them BEFORE starting a daemon, not after a changed secret or
    # config may already have been consumed. Output stays private on failure.
    deployment.jail(deployment.config.talk_jail, "python3", "-I", "-B", "-c", '''import runpy
r = runpy.run_path('/root/cloud-installer/resources/jails/talk-runtime.py')
p = r['load_public']()
r['native_guard'](p)
s = r['read_state'](r['payload_identity'](), p.instance)
if s is None or s['phase'] != 'configured':
    raise SystemExit('Talk has no confirmed configured identity')
r['read_configured'](p, s)
r['check_ca_trust'](s['payload'])
r['check_rc_settings'](require_disabled=False)
r['boot_runtime']()
r['check_directories'](r['service_accounts']())
''', hide_output=True, timeout=30)
    try:
        for service in SERVICES:
            status = talk_service_command(deployment, service, "onestatus")
            if status == 1:
                if talk_service_command(deployment, service, "onestart") != 0:
                    raise RuntimeError("Talk service launch failed; readiness remains unconfirmed")
            elif status != 0:
                raise RuntimeError("Talk startup status is uncertain; refusal requires inspection")
        for attempt in range(3):
            try:
                talk_phase(deployment, "verify")
                break
            except RuntimeError:
                if attempt == 2:
                    raise
                time.sleep(2)
    except BaseException:
        stop_talk(deployment)
        raise


def stage_nextcloud_services(deployment, target, runtime):
    """Stage authenticated copies, never modify an app's vendor binary tree."""
    fragment = None
    if deployment.config.talk:
        from .talk_proxy import render_proxy
        fragment = render_proxy(deployment.config, deployment_talk_public(deployment))
    elif (target / "apache-talk.conf").exists() or (target / "apache-talk.conf").is_symlink():
        raise ValueError("Unselected Talk proxy payload exists; explicit inspection required")
    fresh = "app_installation" in deployment.versions
    cache = prepare_assets(deployment)
    for name, staged in (() if fresh else (("notify_push", "notify-push.bin"), ("notify_push.tar.gz", "notify-push.tar.gz"))):
        path = target / staged
        data = (cache / name).read_bytes()
        if path.is_symlink() or (path.exists() and (not path.is_file() or path.read_bytes() != data)):
            raise ValueError("Staged native-service artifact changed; inspection required")
        if path.exists():
            info = path.lstat()
            if info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o600 or info.st_nlink != 1:
                raise ValueError("Staged native-service artifact protection changed")
        if not path.exists():
            atomic_write(path, data)
    from .client_push import native_runtime
    runtime["native_services"] = native_runtime(
        deployment.config, deployment.versions,
        talk_public=deployment_talk_public(deployment) if deployment.config.talk else None)
    if fragment is not None:
        atomic_write(target / "apache-talk.conf", fragment)


def verify_services(deployment):
    """Observational local evidence only, never a public media/TURN assertion."""
    nc = deployment.config.nextcloud_jail
    if deployment.config.talk and deployment.config.talk_media_hostname:
        from .talk import normalize_public
        expected = deployment_talk_public(deployment)
        staged = private_json(deployment.jail_root(deployment.config.talk_jail)
                              / "root/cloud-installer/runtime.json")
        if normalize_public(staged.get("talk")) != expected:
            raise ValueError("Staged Talk settings differ from the prepared installation input")
    if "app_installation" in deployment.versions:
        from .client_push import validate_selection
        from .host import read_private
        deployment.require_original_artifact()
        observed = observe_apps(deployment)
        selection = validate_selection(private_json(deployment.state / "push-native.json"),
            instance=deployment.config.instance,
            source_sha256=read_private(deployment.registry.evidence_path(deployment.config.instance, "source.sha256")).strip(),
            plan_sha256=hashlib.sha256(json.dumps(deployment.versions, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
            app_version=observed["notify_push"])
        expected = private_json(deployment.state / "deployment.json").get("push_selection_sha256")
        if expected != hashlib.sha256(json.dumps(selection, sort_keys=True, separators=(",", ":")).encode()).hexdigest():
            raise ValueError("Push selection differs from its journaled initialization output")
        if private_json(deployment.jail_root(nc) / "root/cloud-installer/push-native.json") != selection:
            raise ValueError("Staged Push selection differs from the saved initialization output")
        version = deployment.jail(nc, "mdo", "-u", "www", "/usr/local/libexec/cloud-installer/notify_push", "--version",
                                  hide_output=True, input="", timeout=30).stdout.strip()
        if version != "notify_push " + selection["native"]["version"]:
            raise ValueError("Native Push version differs from its exact saved artifact")
    deployment.jail(nc, "service", "cloud_notify_push", "onestatus", hide_output=True)
    # Root opens the private PUBLIC runtime descriptor before dropping identity.
    # No dynamic shell input, secret argv, setup/self-test, config import or repair.
    deployment.jail(nc, "/bin/sh", "-c", "exec mdo -u www /usr/local/bin/php "
                    "-d log_errors=0 -d error_log=/dev/null -d display_errors=0 -d zend.exception_ignore_args=1 "
                    "/usr/local/libexec/cloud-nextcloud-bootstrap.php push-observe "
                     "3< /root/cloud-installer/runtime.json "
                     + ("4< /root/cloud-installer/push-native.json " if "app_installation" in deployment.versions else "")
                     + "< /dev/null", hide_output=True)
    sockets = deployment.jail(nc, "sockstat", "-46l", "-P", "tcp", "-p", "7867", hide_output=True)
    rows = [line.split() for line in sockets.stdout.splitlines() if line.strip()]
    if (not rows or rows[0] != ["USER", "COMMAND", "PID", "FD", "PROTO", "LOCAL", "ADDRESS", "FOREIGN", "ADDRESS"]
            or len(rows) < 2 or any(len(row) != 7 or row[0] != "www" or row[4] != "tcp4"
                                    or row[5] != "127.0.0.1:7867" for row in rows[1:])):
        raise RuntimeError("Client Push must have only the owned www IPv4 loopback listener")
    if deployment.config.talk:
        talk_phase(deployment, "verify")
    deployment.manifest["native_services"] = {
        "profile": deployment.config.service_profile,
        "push": deployment.versions["services"]["push"],
        "talk": deployment.config.talk,
        "scope": "local runtime/control-plane observations; external media/TURN acceptance not established"}
