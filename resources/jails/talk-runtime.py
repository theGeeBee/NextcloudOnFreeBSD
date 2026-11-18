#!/usr/local/bin/python3
"""Native Talk jail phase adapter. Host admission/publication remain separate.

CLI is only called by guarded talk.sh after native package requirement validation
(or the retained artifact's exact-lock checks).
Local readiness is not authenticated/public TURN, TLS or browser media acceptance.
"""
from __future__ import annotations

import grp
import base64
import configparser
import hashlib
import http.client
import json
import os
import platform
import pwd
import re
import secrets
import socket
import signal
import ssl
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True  # Verify never creates payload __pycache__ files.


class InputError(ValueError):
    pass


# Kept local so a tiny staged writer does not import unrelated installer code.
DESTINATIONS = {
    "/usr/local/etc/ncs/server.conf": "signaling",
    "/usr/local/etc/nats.conf": "nats",
    "/usr/local/etc/janus/janus.jcfg": "cloudjanus",
    "/usr/local/etc/janus/janus.transport.websockets.jcfg": "cloudjanus",
    "/usr/local/etc/janus/janus.eventhandler.wsevh.jcfg": "cloudjanus",
    "/usr/local/etc/janus/janus.plugin.videoroom.jcfg": "cloudjanus",
    "/usr/local/etc/turnserver.conf": "_turnserver",
}
SERVICE_ORDER = ("nats", "janus", "turnserver", "ncs_signaling")
PAYLOAD = "/root/cloud-installer"
STATE = "/var/db/cloud-installer-talk"
CA_PAYLOAD_KEY = "tls/ca.pem"
CA_ANCHOR = "/usr/local/share/certs/cloud-installer-talk/ca.pem"
CA_STORE = "/etc/ssl/certs"
CA_LIMIT = 1048576
ENV = {"PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL": "C"}


def native_command(argv, *, capture=False, timeout=15, umask=-1):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=ENV, timeout=timeout, check=False, umask=umask)
    except (OSError, subprocess.TimeoutExpired):
        raise InputError("A native Talk command failed or timed out.") from None
    if result.returncode != 0:
        raise InputError("A native Talk command did not succeed.")
    if capture:
        if len(result.stdout) > 1048576:
            raise InputError("Native Talk observation exceeds its bound.")
        return result.stdout.decode("utf-8", errors="strict")
    return None


def service_command(service: str, action: str) -> int:
    """Narrow, bounded native service action; output cannot become a secret log.

    Only parent-guarded callers may use these primitives. In particular no
    shell, inherited secret environment, stdin consumption or automatic enable.
    """
    if service not in SERVICE_ORDER or action not in ("onestart", "onestop", "onestatus"):
        raise InputError("Unsupported Talk service action.")
    try:
        path = "/usr/local/etc/rc.d/" + service
        protected_read(path)  # Missing script exit1 must NOT mean "stopped".
        if not os.stat(path, follow_symlinks=False).st_mode & stat.S_IXUSR:
            raise InputError("Required native Talk rc script is not executable.")
        binary = {"nats": "nats-server", "janus": "janus", "turnserver": "turnserver",
                  "ncs_signaling": "ncs-signaling"}[service]
        info = os.stat("/usr/local/bin/" + binary, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not info.st_mode & stat.S_IXUSR):
            raise InputError("Required native Talk executable protection changed.")
        result = subprocess.run(
            ["/usr/sbin/service", service, action],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"},
            timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise InputError("Talk service command failed or exceeded its deadline.") from None
    return result.returncode


def stop_services(command=service_command) -> None:
    """Attempt every stop in reverse order; positively check each stopped state.

    Failure means caller must keep ingress unpublished and stop the owned jail;
    neither this primitive nor a readiness failure grants permission to proceed.
    """
    failed = False
    for service in reversed(SERVICE_ORDER):
        try:
            command(service, "onestop")
            # rc.subr onestatus: 0 running, 1 not running. Any other status is
            # an uncertain check, not stopped. Stop exit alone is not proof.
            if command(service, "onestatus") != 1:
                failed = True
        except InputError:
            failed = True
    if failed:
        raise InputError("Talk shutdown is unconfirmed; keep ingress closed and stop the owned jail.")


def start_for_probe(probe, command=service_command) -> None:
    """Start in dependency order for a bounded integration-owned probe only.

    This is NOT publication/readiness and writes NO receipt. probe must perform
    reviewed socket/account/SFU/TURN observations; no default welcome fallback.
    Caller must fence ingress, ensure enable=NO and remove any old readiness
    marker before entering. These requirements remain unavailable at the CLI.
    """
    if not callable(probe):
        raise InputError("A native Talk observation probe is required.")
    try:
        for service in SERVICE_ORDER:
            if command(service, "onestart") != 0:
                raise InputError("Talk service startup failed.")
            deadline = time.monotonic() + 15
            while command(service, "onestatus") != 0:
                if time.monotonic() >= deadline:
                    raise InputError("Talk service did not become running before its deadline.")
                time.sleep(0.2)
        if probe() is not True:
            raise InputError("Talk native observations are not ready.")
    except BaseException:
        # Even cancellation must attempt every owned service stop. Never emit
        # the probe's exception: it may contain a response/config/credential.
        try:
            stop_services(command)
        except InputError:
            raise InputError("Talk startup/probe failed and shutdown is unconfirmed; stop the owned jail.") from None
        raise InputError("Talk startup/probe failed; services stopped, publication remains forbidden.") from None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate Talk configure key.")
        result[key] = value
    return result


def read_configs(stream) -> dict[str, str]:
    raw = stream.read(65537)
    if len(raw) > 65536:
        raise InputError("Talk configure input exceeds its bound.")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError):
        raise InputError("Invalid Talk configure input.") from None
    if (not isinstance(value, dict) or set(value) != {"schema", "configs"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or not isinstance(value["configs"], dict)
            or set(value["configs"]) != set(DESTINATIONS)):
        raise InputError("Talk configure requires the exact fixed-path config set.")
    for content in value["configs"].values():
        if not isinstance(content, str) or not content or "\0" in content:
            raise InputError("Invalid Talk config content.")
        try:
            length = len(content.encode("utf-8"))
        except UnicodeError:
            raise InputError("Invalid Talk config encoding.") from None
        if length > 16384:
            raise InputError("Talk config content exceeds its bound.")
    return value["configs"]


def _protected_directory(path: str) -> int:
    """Walk from / using descriptors; no symlink or service-writable parent."""
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.strip("/").split("/"):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise InputError("Talk config parent must be root-owned and protected.")
        return directory
    except BaseException:
        os.close(directory)
        raise


def _atomic_config(directory: int, name: str, content: str, gid: int, mode=0o640) -> None:
    """Per-file atomic, fsynced root:service 0640; NOT a multi-file transaction.

    Caller must stop all four services before replacing any configs and retain
    their disabled/unpublished state on partial failure. No input/exception is
    printed. Reject existing symlinks/special files rather than replacing them.
    """
    try:
        previous = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        previous = None
    if previous is not None and (not stat.S_ISREG(previous.st_mode)
                                 or previous.st_uid != 0 or previous.st_mode & 0o022):
        raise InputError("Unsafe existing Talk configuration file.")
    temporary = ".talk-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), 0, gid)
            stream.write(content.encode("utf-8"))
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def write_configs(configs: dict[str, str]) -> None:
    """Internal primitive only; not a substitute for stopped-service guards."""
    if os.geteuid() != 0 or set(configs) != set(DESTINATIONS):
        raise InputError("Talk config writer requires root and its fixed config set.")
    # Resolve every required service group before the first config mutation.
    groups = {group: grp.getgrnam(group).gr_gid for group in set(DESTINATIONS.values())}
    descriptors = {}
    try:
        for path in DESTINATIONS:
            parent, _ = path.rsplit("/", 1)
            if parent not in descriptors:
                descriptors[parent] = _protected_directory(parent)
        for path, group in DESTINATIONS.items():
            parent, name = path.rsplit("/", 1)
            _atomic_config(descriptors[parent], name, configs[path], groups[group])
    finally:
        for directory in descriptors.values():
            os.close(directory)


def protected_read(path, limit=65536, *, private=False, private_mode=None):
    parent, name = path.rsplit("/", 1)
    directory = _protected_directory(parent)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or info.st_size > limit
                    or (private and stat.S_IMODE(info.st_mode) not in (0o400, 0o600))
                    or (private_mode is not None and stat.S_IMODE(info.st_mode) != private_mode)):
                raise InputError("Required Talk input protection changed.")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise InputError("Required Talk input exceeds its bound.")
            return data
    finally:
        os.close(directory)


def atomic_public(path, content, *, gid=0, mode=0o640):
    parent, name = path.rsplit("/", 1)
    directory = _protected_directory(parent)
    try:
        _atomic_config(directory, name, content, gid, mode)
    finally:
        os.close(directory)


def _talk_module():
    # Fixed root-private payload, not PYTHONPATH or the invoking cwd. -I is used
    # by the shell. Every staged parent/file is protected before import.
    protected_read(PAYLOAD + "/installer/__init__.py")
    protected_read(PAYLOAD + "/installer/talk.py", 131072)
    if PAYLOAD not in sys.path:
        sys.path.insert(0, PAYLOAD)
    from installer import talk
    return talk


def load_public():
    raw = protected_read(PAYLOAD + "/runtime.json", private=True)
    value = json.loads(raw, object_pairs_hook=_unique)
    if (not isinstance(value, dict) or set(value) != {"repository", "versions", "talk"}
            or value["repository"] not in ("latest", "quarterly")
            or not isinstance(value["versions"], dict)
            or value["versions"].get("service_profile") != "native-v1"
            or value["versions"].get("talk_selected") != "yes"):
        raise InputError("Talk runtime requires its exact selected public schema.")
    public = _talk_module().normalize_public(value["talk"])
    validate_locked_payload(value)
    return public


def repository_current(versions):
    """Worker discriminator only; never infer the policy from app installation."""
    if "package_installation" not in versions:
        if "requirements_sha256" in versions:
            raise InputError("Talk package requirements need the explicit native pkg contract.")
        return False
    if (versions["package_installation"] != "pkg"
            or "packages_sha256" in versions or "dependencies_sha256" in versions
            or not isinstance(versions.get("requirements_sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", versions["requirements_sha256"])):
        raise InputError("Invalid Talk native pkg requirement contract.")
    return True


def current_requirements(runtime):
    """Authenticate public root requirements, never a transitive package lock."""
    versions = runtime["versions"]
    if not repository_current(versions):
        raise InputError("Talk package requirements require the explicit native pkg contract.")
    _talk_module()  # Establish the fixed protected import root, never caller cwd.
    for name in ("version_runtime.py", "package_policy.py", "versions.py"):
        protected_read(PAYLOAD + "/installer/" + name, 131072)
    from installer.package_policy import validate_requirements
    from installer.version_runtime import validate_runtime_versions
    from installer.versions import target
    try:
        validate_runtime_versions(versions)
        policy = json.loads(protected_read(PAYLOAD + "/resources/versions.json", 131072), object_pairs_hook=_unique)
        generic = current_platform(policy, versions)
        if generic:
            selected = {"release": versions["freebsd_release"], "architecture": "amd64",
                        "abi": "FreeBSD:" + versions["freebsd_release"].split(".")[0] + ":amd64"}
        else:
            selected = target(policy, versions["freebsd_release"], versions["architecture"])
        data = protected_read(PAYLOAD + "/packages.requirements.json", 1048576,
                              private=True, private_mode=0o600)
        if hashlib.sha256(data).hexdigest() != versions["requirements_sha256"]:
            raise InputError("Talk package requirements differ from the immutable runtime digest.")
        value = validate_requirements(json.loads(data, object_pairs_hook=_unique), target=selected)
        if (value["group"] != "talk" or value["repository"] != runtime.get("repository")
                or (not generic and versions["freebsd_release"] not in ("15.1-RELEASE", "15.2-STABLE", "16.0-CURRENT"))
                or versions["architecture"] != "amd64"):
            raise InputError("Talk package requirements differ from the selected group, repository or target.")
        return value
    except ValueError:
        raise InputError("Invalid authenticated Talk package requirements.") from None


def current_platform(policy, versions):
    """Optional fresh-only admission; absence preserves exact target policy."""
    if versions.get("app_installation") != "occ" or "repository_current_platform" not in policy:
        return False
    from installer.versions import repository_current_platform, repository_current_release
    try:
        rule = repository_current_platform(policy)
    except ValueError:
        raise InputError("Invalid Talk repository-current platform policy.") from None
    try:
        repository_current_release(rule, versions.get("freebsd_release"), versions.get("architecture"), normalized=True)
    except ValueError:
        raise InputError("Talk runtime differs from the fresh native platform policy.") from None
    return True


def validate_locked_payload(runtime):
    versions = runtime["versions"]
    if repository_current(versions):
        current_requirements(runtime)
        inputs = (("services.json", "services_sha256"),)
    else:
        inputs = (("packages.lock", "packages_sha256"), ("packages.dependencies", "dependencies_sha256"),
                  ("services.json", "services_sha256"))
    for name, key in inputs:
        data = protected_read(PAYLOAD + "/" + name, 1048576, private=True)
        if hashlib.sha256(data).hexdigest() != versions.get(key):
            raise InputError("Talk staged payload digest differs from its immutable runtime lock.")
    services = json.loads(protected_read(PAYLOAD + "/services.json", 196608, private=True), object_pairs_hook=_unique)
    policy = json.loads(protected_read(PAYLOAD + "/resources/native-services.json", 196608), object_pairs_hook=_unique)
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if (services.get("profile") != "native-v1" or services.get("talk") is not True
            or services.get("policy_sha256") != hashlib.sha256(canonical).hexdigest()):
        raise InputError("Talk service policy identity differs from the selected locked policy.")
    if repository_current(versions) and not current_platform(policy, versions):
        targets = [policy["target"], *policy.get("repository_current_targets", [])]
        if not any(item["release"] == versions["freebsd_release"] and item["architecture"] == versions["architecture"]
                   for item in targets):
            raise InputError("Talk runtime differs from the exact native service targets.")


def native_guard(public):
    if sys.version_info < (3, 11):
        raise InputError("Talk worker requires Python 3.11 or newer for its code ABI.")
    if os.geteuid() != 0 or platform.system() != "FreeBSD" or platform.machine() != "amd64":
        raise InputError("Talk worker requires FreeBSD amd64 jail root.")
    if native_command(["/sbin/sysctl", "-n", "security.jail.jailed"], capture=True).strip() != "1":
        raise InputError("Talk worker refuses execution outside a jail.")
    if native_command(["/sbin/sysctl", "-n", "security.jail.vnet"], capture=True).strip() != "1":
        raise InputError("Talk worker requires its dedicated VNET namespace.")
    if native_command(["/bin/hostname"], capture=True).strip() != public.instance + "tk":
        raise InputError("Talk jail hostname differs from the owned runtime identity.")
    for path in (STATE, PAYLOAD):
        directory = _protected_directory(path)
        try:
            if stat.S_IMODE(os.fstat(directory).st_mode) != 0o700:
                raise InputError("Talk private runtime/payload mode changed.")
        finally:
            os.close(directory)
    # Direct helper invocation does not bypass the shell's immutable group,
    # target-release, digest, services-policy or installed-inventory checks.
    native_command(["/bin/sh", "-c", '''
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
PAYLOAD=/root/cloud-installer
STATE=/var/db/cloud-installer-talk
RUNTIME=$PAYLOAD/runtime.json
fail() { exit 1; }
. "$PAYLOAD/resources/jails/versions.sh"
version_load talk
version_environment
[ "$version_architecture" = amd64 ]
version_packages_check
'''], timeout=60)


def payload_identity():
    result = {}
    data = protected_read(PAYLOAD + "/runtime.json", 1048576, private=True)
    value = json.loads(data, object_pairs_hook=_unique)
    current = repository_current(value["versions"])
    if current:
        current_requirements(value)
    result["runtime.json"] = hashlib.sha256(data).hexdigest()
    package_inputs = ("packages.requirements.json",) if current else ("packages.lock", "packages.dependencies")
    module_inputs = ("installer/version_runtime.py", "installer/package_policy.py", "installer/versions.py", "resources/versions.json") if current else ()
    for name in (*package_inputs, *module_inputs, "services.json",
                 "resources/native-services.json", "resources/jails/versions.sh",
                 "resources/jails/talk.sh", "resources/jails/talk-runtime.py", "installer/talk.py"):
        data = protected_read(PAYLOAD + "/" + name, 1048576,
                              private=name in (*package_inputs, "services.json"),
                              **({"private_mode": 0o600} if name == "packages.requirements.json" else {}))
        result[name] = hashlib.sha256(data).hexdigest()
    for template, _ in _talk_module().CONFIG_FILES.values():
        name = "resources/templates/talk/" + template
        result[name] = hashlib.sha256(protected_read(PAYLOAD + "/" + name)).hexdigest()
    for template in ("cloud-talk-log-reopen.sh", "cloud_talk_runtime.rc"):
        name = "resources/templates/talk/" + template
        result[name] = hashlib.sha256(protected_read(PAYLOAD + "/" + name)).hexdigest()
    ca = read_ca_payload()
    # Explicit absence is immutable too; old unsealed state is not migrated.
    result[CA_PAYLOAD_KEY] = None if ca is None else hashlib.sha256(ca).hexdigest()
    return result


def certificate_fingerprints(data, *, validate=False):
    """Public CERTIFICATE-only PEM bundle; never accept/print private material."""
    import re
    pattern = rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----"
    result, offset = set(), 0
    for match in re.finditer(pattern, data):
        if data[offset:match.start()].strip():
            raise InputError("Talk CA input must contain only public PEM certificates.")
        try:
            der = base64.b64decode(b"".join(match[1].split()), validate=True)
        except ValueError:
            raise InputError("Invalid public Talk CA certificate encoding.") from None
        if not der:
            raise InputError("Empty public Talk CA certificate.")
        result.add(hashlib.sha256(der).hexdigest())
        offset = match.end()
    if not result or data[offset:].strip():
        raise InputError("Talk CA input must contain only public PEM certificates.")
    if validate:
        try:
            # Isolated parse only: no default roots loaded, no global/system
            # import and no TLS verification bypass or environment override.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=data.decode("ascii"))
        except (ValueError, UnicodeError, ssl.SSLError):
            raise InputError("Invalid public Talk CA X.509 certificate bundle.") from None
    return result


def read_ca_payload():
    path = PAYLOAD + "/" + CA_PAYLOAD_KEY
    try:
        data = protected_read(path, CA_LIMIT, private=True)
    except FileNotFoundError:
        return None
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise InputError("Staged public Talk CA must be a regular root-owned mode0600 file.")
    certificate_fingerprints(data, validate=True)
    return data


def sealed_ca_payload(identity):
    if CA_PAYLOAD_KEY not in identity:
        raise InputError("Talk state has no sealed CA presence identity; assess original payload recovery.")
    data = read_ca_payload()
    digest = None if data is None else hashlib.sha256(data).hexdigest()
    if digest != identity[CA_PAYLOAD_KEY]:
        raise InputError("Talk CA presence/bytes differ from the sealed prepared identity.")
    return data


def public_ca_directory(path):
    directory = _protected_directory(path)
    try:
        if stat.S_IMODE(os.fstat(directory).st_mode) & 0o005 != 0o005:
            raise InputError("Talk public CA directory is not service-readable/traversable.")
    finally:
        os.close(directory)


def installed_ca_fingerprints(*, allow_missing=False, require_public=True):
    """Read native15.1 certctl's flat hashed public certificate copies only."""
    import re
    try:
        public_ca_directory(CA_STORE)
    except FileNotFoundError:
        if allow_missing:
            return set()
        raise InputError("Native Talk OS certificate store is missing.") from None
    result, total, count = set(), 0, 0
    with os.scandir(CA_STORE) as entries:
        for entry in entries:
            count += 1
            if count > 4096:
                raise InputError("Native Talk certificate store exceeds its scan bound.")
            if not re.fullmatch(r"[0-9a-f]{8}\.[0-9]+", entry.name):
                continue
            path = CA_STORE + "/" + entry.name
            data = protected_read(path, CA_LIMIT)
            info = os.stat(path, follow_symlinks=False)
            if require_public and stat.S_IMODE(info.st_mode) not in (0o444, 0o644):
                raise InputError("Native Talk OS certificate copy is not publicly readable/protected.")
            total += len(data)
            if total > 8 * CA_LIMIT:
                raise InputError("Native Talk certificate store exceeds its byte bound.")
            result.update(certificate_fingerprints(data))
    return result


def check_ca_trust(identity):
    """Read-only seal/source/anchor/native-store check, including absence."""
    data = sealed_ca_payload(identity)
    try:
        anchor = protected_read(CA_ANCHOR, CA_LIMIT)
    except FileNotFoundError:
        if data is None:
            return
        raise InputError("Sealed public Talk CA anchor is missing.") from None
    if data is None or anchor != data:
        raise InputError("Installed public Talk CA anchor differs from the sealed input.")
    info = os.stat(CA_ANCHOR, follow_symlinks=False)
    if info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o644:
        raise InputError("Installed public Talk CA anchor ownership/mode changed.")
    for path in ("/usr", "/usr/local", "/usr/local/share", "/usr/local/share/certs",
                 "/usr/local/share/certs/cloud-installer-talk", "/etc", "/etc/ssl"):
        public_ca_directory(path)
    if not certificate_fingerprints(data) <= installed_ca_fingerprints():
        raise InputError("Sealed Talk CA certificates are absent from the actual native OS trusted store.")


def install_ca_trust(identity):
    """Prepare only, after disabled boot/checked stop. No host-store operation."""
    data = sealed_ca_payload(identity)
    if data is None:
        check_ca_trust(identity)  # Never adopt an unexpected existing anchor.
        return
    try:
        anchor = protected_read(CA_ANCHOR, CA_LIMIT)
    except FileNotFoundError:
        anchor = None
    else:
        if anchor != data:
            raise InputError("Refusing replacement of a changed public Talk CA anchor.")
        info = os.stat(CA_ANCHOR, follow_symlinks=False)
        if info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o644:
            raise InputError("Existing public Talk CA anchor protection changed.")
    for path in ("/usr/local/share/certs", "/usr/local/share/certs/cloud-installer-talk",
                 "/etc/ssl", "/etc/ssl/certs"):
        secure_directory(path, 0, 0, 0o755)
    # Earlier bootstrap under umask077 may have left root-only cached copies.
    # The default rehash fixes their public mode; preserve their DER identities.
    existing = installed_ca_fingerprints(allow_missing=True, require_public=False)
    if anchor is None:
        atomic_public(CA_ANCHOR, data.decode("ascii"), mode=0o644)
    # Base15.1 certctl is a C utility. Use all default trusted/untrusted input
    # paths, clean env, and public umask: no custom bundle replacing base roots,
    # trust-path override, untrust command or installer cleanup of certificates.
    native_command(["/usr/sbin/certctl", "rehash"], timeout=60, umask=0o022)
    check_ca_trust(identity)
    if not existing <= installed_ca_fingerprints():
        raise InputError("Native CA rehash changed pre-existing trusted roots; keep services stopped and assess jail trust recovery.")


def read_state(identity, instance):
    if CA_PAYLOAD_KEY not in identity:
        raise InputError("Talk prepared identity must explicitly seal CA presence or absence.")
    try:
        raw = protected_read(STATE + "/state.json", private=True)
    except FileNotFoundError:
        return None
    value = json.loads(raw, object_pairs_hook=_unique)
    if (not isinstance(value, dict) or set(value) != {"schema", "instance", "payload", "phase", "configs", "baseline"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["instance"] != instance or value["payload"] != identity
            or value["phase"] not in ("prepared", "configuring", "configured")
            or not isinstance(value["configs"], dict) or not isinstance(value["baseline"], dict)
            or set(value["baseline"]) != set(DESTINATIONS)):
        raise InputError("Talk saved identity changed; retain original payload and assess recovery.")
    import re
    for path, digest in value["baseline"].items():
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
            raise InputError("Invalid saved Talk baseline identity.")
    if value["phase"] == "prepared":
        if value["configs"]:
            raise InputError("Prepared Talk state has an unexpected configure identity.")
    elif (set(value["configs"]) != set(DESTINATIONS) or any(
        not isinstance(d, str) or not re.fullmatch(r"[a-f0-9]{64}", d) for d in value["configs"].values()
    )):
        raise InputError("Invalid saved Talk configure identity.")
    return value


def save_state(identity, instance, phase, configs, baseline):
    if CA_PAYLOAD_KEY not in identity:
        raise InputError("Talk checkpoint requires explicit sealed CA presence or absence.")
    content = json.dumps({"schema": 1, "instance": instance, "payload": identity,
                          "phase": phase, "configs": configs, "baseline": baseline}, sort_keys=True) + "\n"
    atomic_public(STATE + "/state.json", content, mode=0o600)


def secure_directory(path, uid, gid, mode):
    parent, name = path.rsplit("/", 1)
    descriptor = _protected_directory(parent)
    try:
        try:
            os.mkdir(name, mode, dir_fd=descriptor)
        except FileExistsError:
            pass
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            info = os.fstat(child)
            if info.st_uid not in (0, uid) or info.st_mode & 0o022:
                raise InputError("Talk directory ownership changed.")
            os.fchown(child, uid, gid)
            os.fchmod(child, mode)
        finally:
            os.close(child)
    finally:
        os.close(descriptor)


def service_accounts(*, create=False):
    try:
        pwd.getpwnam("cloudjanus")
    except KeyError:
        if not create:
            raise InputError("Dedicated unprivileged Janus account is missing.") from None
        try:
            grp.getgrnam("cloudjanus")
        except KeyError:
            native_command(["/usr/sbin/pw", "groupadd", "-n", "cloudjanus"])
        native_command(["/usr/sbin/pw", "useradd", "-n", "cloudjanus", "-g", "cloudjanus",
                        "-d", "/var/db/cloud-janus", "-s", "/usr/sbin/nologin", "-w", "no"])
    result = {}
    for name in ("nats", "signaling", "_turnserver", "cloudjanus"):
        try:
            account, group = pwd.getpwnam(name), grp.getgrnam(name)
        except KeyError:
            raise InputError("A required native package account/group is missing.") from None
        if (account.pw_uid == 0 or group.gr_gid == 0 or account.pw_gid != group.gr_gid
                or account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/false")
                or not account.pw_passwd.startswith(("*", "!"))
                or set(os.getgrouplist(name, group.gr_gid)) != {group.gr_gid}):
            raise InputError("A Talk account has unexpected privileges or login access.")
        result[name] = (account.pw_uid, group.gr_gid)
        if name == "cloudjanus" and account.pw_dir != "/var/db/cloud-janus":
            raise InputError("Dedicated Janus home identity changed.")
    if len({uid for uid, _ in result.values()}) != 4 or len({gid for _, gid in result.values()}) != 4:
        raise InputError("Talk service account UIDs/groups must be distinct.")
    return result


def install_rc_settings():
    secure_directory("/etc/rc.conf.d", 0, 0, 0o755)
    for service, settings in _talk_module().rc_settings().items():
        install_owned("/etc/rc.conf.d/" + service,
                      "".join(f'{key}="{value}"\n' for key, value in settings.items()))


def install_owned(path, content, *, mode=0o640):
    """Never overwrite an unrelated/changed owned hook during a partial retry."""
    try:
        current = protected_read(path, 131072)
    except FileNotFoundError:
        atomic_public(path, content, mode=mode)
        return
    info = os.stat(path, follow_symlinks=False)
    if current != content.encode("utf-8") or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode:
        raise InputError("An owned Talk native hook/settings file changed; assess recovery.")


def check_rc_settings(*, require_disabled=True, services=None):
    # No root evaluation of service-writable rc inputs. An owned fragment has
    # only our literal scalar assignments (plus optional comments/blank lines).
    import re
    for path in ("/etc/defaults/rc.conf", "/etc/rc.conf", "/etc/rc.conf.local"):
        try:
            protected_read(path, 131072)
        except FileNotFoundError:
            if path != "/etc/rc.conf.local":
                raise InputError("Required native rc configuration is missing.") from None
    for service, settings in _talk_module().rc_settings().items():
        if services is not None and service not in services:
            continue
        fragment = protected_read("/etc/rc.conf.d/" + service).decode("utf-8")
        parsed = {}
        for line in fragment.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r'([a-z_]+)="([^"\n]*)"', line)
            if match is None or match[1] in parsed:
                raise InputError("Owned Talk rc fragment contains unreviewed shell content.")
            parsed[match[1]] = match[2]
        if set(parsed) != set(settings):
            raise InputError("Owned Talk rc fragment keys changed.")
        native_rc = "/etc/rc.d/syslogd" if service == "syslogd" else "/usr/local/etc/rc.d/" + service
        protected_read(native_rc)
        for key, expected in settings.items():
            if parsed[key] != expected and not (not require_disabled and key.endswith("_enable") and parsed[key] == "YES"):
                raise InputError("Owned Talk rc fragment values changed.")
            actual = native_command(["/usr/sbin/sysrc", "-n", "-s", service, key], capture=True).strip()
            if actual != expected and not (not require_disabled and key.endswith("_enable") and actual == "YES"):
                raise InputError("Native Talk rc settings differ from the owned disabled-boot contract.")


def log_rotation_text():
    return ("# Native FreeBSD newsyslog: KiB thresholds; bounded retained archives.\n"
            "/var/log/janus.log cloudjanus:cloudjanus 640 5 10240 * JCR /usr/local/libexec/cloud-talk-log-reopen\n"
            "/var/log/turnserver/turnserver.log _turnserver:_turnserver 640 5 10240 * JCR /usr/local/libexec/cloud-talk-log-reopen\n")


def check_rotation():
    if protected_read("/usr/local/etc/newsyslog.conf.d/cloud-talk.conf").decode() != log_rotation_text():
        raise InputError("Native Talk log rotation policy changed.")
    if b"<include> /usr/local/etc/newsyslog.conf.d/[!.]*.conf" not in protected_read("/etc/newsyslog.conf"):
        raise InputError("Native newsyslog does not include the Talk rotation policy.")
    if b"newsyslog" not in protected_read("/etc/crontab"):
        raise InputError("Native newsyslog scheduling is absent.")
    native_command(["/usr/sbin/service", "cron", "onestatus"])
    native_command(["/usr/sbin/service", "syslogd", "onestatus"])
    if protected_read("/usr/local/libexec/cloud-talk-log-reopen") != protected_read(PAYLOAD + "/resources/templates/talk/cloud-talk-log-reopen.sh"):
        raise InputError("Native Talk log reopen hook changed.")
    if protected_read("/usr/local/libexec/cloud-talk-runtime.py", 131072) != protected_read(PAYLOAD + "/resources/jails/talk-runtime.py", 131072):
        raise InputError("Native Talk log reopen adapter changed.")
    if protected_read("/usr/local/etc/rc.d/cloud_talk_runtime") != protected_read(PAYLOAD + "/resources/templates/talk/cloud_talk_runtime.rc"):
        raise InputError("Native Talk volatile-directory rc hook changed.")


def prepare(public, identity, saved):
    if saved and saved["phase"] != "prepared":
        raise InputError("Talk prepare refuses to replay after configuration began.")
    if saved:
        check_ca_trust(identity)
        service_accounts()
        check_rc_settings()
        check_rotation()
        module_inventory()
        check_directories(service_accounts())
        if config_hashes(allow_missing=True) != saved["baseline"]:
            raise InputError("Prepared Talk config baseline changed; assess recovery.")
        for service in SERVICE_ORDER:
            if service_command(service, "onestatus") != 1:
                raise InputError("Prepared Talk services are not confirmed stopped.")
        return
    install_rc_settings()
    check_rc_settings(services=SERVICE_ORDER)
    stop_services()
    install_ca_trust(identity)
    # FreeBSD15.1 default -s still opens a UDP socket. This dedicated jail has
    # no remote syslog contract; retain UNIX logging, explicitly remove UDP.
    native_command(["/usr/sbin/service", "syslogd", "onerestart"])
    accounts = service_accounts(create=True)
    for path, group in (("/usr/local/etc/ncs", "signaling"), ("/usr/local/etc/janus", "cloudjanus")):
        secure_directory(path, 0, accounts[group][1], 0o750)
    for path, user in (("/var/run/cloud-janus", "cloudjanus"), ("/var/run/turnserver", "_turnserver"),
                       ("/var/log/nats", "nats"),
                       ("/var/db/cloud-janus", "cloudjanus")):
        secure_directory(path, *accounts[user], 0o750)
    secure_directory("/var/log/turnserver", 0, accounts["_turnserver"][1], 0o750)
    # Native Janus rc has a fixed file log path. Precreate without truncation.
    for path, user in (("/var/log/janus.log", "cloudjanus"), ("/var/log/turnserver/turnserver.log", "_turnserver")):
        parent, name = path.rsplit("/", 1)
        directory = _protected_directory(parent)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o640, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, accounts[user][0]):
                    raise InputError("Unsafe native Talk log file.")
                os.fchown(fd, *accounts[user])
                os.fchmod(fd, 0o640)
            finally:
                os.close(fd)
        finally:
            os.close(directory)
    secure_directory("/usr/local/libexec", 0, 0, 0o755)
    install_owned("/usr/local/libexec/cloud-talk-runtime.py", protected_read(PAYLOAD + "/resources/jails/talk-runtime.py", 131072).decode(), mode=0o444)
    install_owned("/usr/local/libexec/cloud-talk-log-reopen", protected_read(PAYLOAD + "/resources/templates/talk/cloud-talk-log-reopen.sh").decode(), mode=0o555)
    secure_directory("/usr/local/etc/rc.d", 0, 0, 0o755)
    install_owned("/usr/local/etc/rc.d/cloud_talk_runtime", protected_read(PAYLOAD + "/resources/templates/talk/cloud_talk_runtime.rc").decode(), mode=0o555)
    secure_directory("/usr/local/etc/newsyslog.conf.d", 0, 0, 0o755)
    install_owned("/usr/local/etc/newsyslog.conf.d/cloud-talk.conf", log_rotation_text())
    check_rc_settings()
    check_rotation()
    module_inventory()
    check_directories(accounts)
    baseline = config_hashes(allow_missing=True)
    if saved and baseline != saved["baseline"]:
        raise InputError("Prepared Talk config baseline changed; assess recovery.")
    save_state(identity, public.instance, "prepared", {}, baseline)


def check_directories(accounts):
    for path, user, root_owned in (("/var/run/cloud-janus", "cloudjanus", False),
                                 ("/var/run/turnserver", "_turnserver", False),
                                 ("/var/log/nats", "nats", False),
                                 ("/var/log/turnserver", "_turnserver", True),
                                 ("/var/db/cloud-janus", "cloudjanus", False),
                                 ("/usr/local/etc/ncs", "signaling", True),
                                 ("/usr/local/etc/janus", "cloudjanus", True)):
        parent, name = path.rsplit("/", 1)
        directory = _protected_directory(parent)
        try:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                info = os.fstat(child)
                if (info.st_uid != (0 if root_owned else accounts[user][0])
                        or info.st_gid != accounts[user][1] or stat.S_IMODE(info.st_mode) != 0o750):
                    raise InputError("Talk config/runtime/log/home directory protection changed.")
            finally:
                os.close(child)
        finally:
            os.close(directory)


def reopen_log(role):
    """newsyslog hook after privilege drop; no root signal of writable PID data."""
    user, path, binary = {
        "reopen-janus": ("cloudjanus", "/var/run/cloud-janus/janus.pid", "janus"),
        "reopen-turnserver": ("_turnserver", "/var/run/turnserver/turnserver.pid", "turnserver"),
    }[role]
    account = pwd.getpwnam(user)
    if os.geteuid() == 0 or os.geteuid() != account.pw_uid:
        raise InputError("Log reopening must run as the dedicated service user.")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return  # Service is stopped; no readiness implication.
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read(65)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != account.pw_uid
                or info.st_mode & 0o022 or len(raw) > 64 or not raw.strip().isdigit()):
            raise InputError("Unsafe service log-reopen PID file.")
    pid = int(raw.strip())
    if pid <= 1:
        raise InputError("Invalid service log-reopen PID.")
    try:
        if process_identity(pid) != (account.pw_uid, "/usr/local/bin/" + binary):
            raise InputError("Log reopening process identity changed.")
        os.kill(pid, signal.SIGHUP)  # Kernel also enforces same-user signalling.
    except ProcessLookupError:
        return


def boot_runtime():
    """Native one-shot rc hook: only volatile dirs, never start/enable services."""
    if os.geteuid() != 0 or platform.system() != "FreeBSD" or platform.machine() != "amd64":
        raise InputError("Talk volatile runtime hook requires native jail root.")
    if native_command(["/sbin/sysctl", "-n", "security.jail.jailed"], capture=True).strip() != "1":
        raise InputError("Talk volatile runtime hook refuses the host.")
    if native_command(["/sbin/sysctl", "-n", "security.jail.vnet"], capture=True).strip() != "1":
        raise InputError("Talk volatile runtime hook requires VNET.")
    release = native_command(["/bin/freebsd-version", "-u"], capture=True).strip()
    import re
    if re.fullmatch(r"15\.1-RELEASE(?:-p[0-9]+)?", release):
        pass  # Retained strict15.1 boot contract does not require native pkg.
    else:
        match = re.fullmatch(r"([1-9][0-9]*)\.(0|[1-9][0-9]*)-(RELEASE(?:-p[0-9]+)?|STABLE|CURRENT)", release)
        if not match or int(match[1]) < 15:
            raise InputError("Unreviewed native runtime hook userland release.")
        # Authenticate requirements and service policy before volatile writes.
        runtime = json.loads(protected_read(PAYLOAD + "/runtime.json", private=True), object_pairs_hook=_unique)
        if not repository_current(runtime["versions"]):
            raise InputError("Native runtime hook requires authenticated repository-current requirements.")
        validate_locked_payload(runtime)
        if runtime["versions"]["freebsd_release"] != release.split("-p", 1)[0]:
            raise InputError("Native runtime hook userland differs from its selected target.")
    accounts = service_accounts()
    for path, user in (("/var/run/cloud-janus", "cloudjanus"), ("/var/run/turnserver", "_turnserver")):
        secure_directory(path, *accounts[user], 0o750)


MODULES = {
    "plugins": ({"libjanus_videoroom.so"}, {
        "libjanus_audiobridge.so", "libjanus_duktape.so", "libjanus_echotest.so",
        "libjanus_lua.so", "libjanus_nosip.so", "libjanus_recordplay.so", "libjanus_sip.so",
        "libjanus_streaming.so", "libjanus_textroom.so", "libjanus_videocall.so"}),
    "transports": ({"libjanus_websockets.so"}, {"libjanus_http.so", "libjanus_mqtt.so",
                    "libjanus_nanomsg.so", "libjanus_pfunix.so", "libjanus_rabbitmq.so"}),
    "events": ({"libjanus_wsevh.so"}, {"libjanus_gelfevh.so", "libjanus_mqttevh.so",
               "libjanus_nanomsgevh.so", "libjanus_rabbitmqevh.so", "libjanus_sampleevh.so"}),
    "loggers": (set(), {"libjanus_jsonlog.so"}),
}


def module_inventory():
    for directory, (required, disabled) in MODULES.items():
        path = "/usr/local/libexec/janus/" + directory
        descriptor = _protected_directory(path)
        os.close(descriptor)
        present = {entry.name for entry in os.scandir(path) if entry.name.endswith(".so")}
        if not required <= present or present - required - disabled:
            raise InputError("Required Janus modules missing or unknown modules installed.")
        for name in present:
            target = os.path.realpath(path + "/" + name)
            if os.path.dirname(target) != path:
                raise InputError("Janus module link escapes its native module directory.")
            info = os.stat(target, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise InputError("Janus module protection changed.")


def config_hashes(*, allow_missing=False):
    result = {}
    for path in DESTINATIONS:
        try:
            # Initial package samples (not our minimal generated files) may be
            # substantially larger; hash them before any overwrite as baseline.
            result[path] = hashlib.sha256(protected_read(path, 131072)).hexdigest()
        except FileNotFoundError:
            if not allow_missing:
                raise InputError("A configured Talk file is missing.") from None
            result[path] = None
    return result


def validate_configs(public, configs):
    """Extract only the narrow secrets in memory and require exact pure rendering."""
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(configs["/usr/local/etc/ncs/server.conf"])
    turn = [line.removeprefix("static-auth-secret=")
            for line in configs["/usr/local/etc/turnserver.conf"].splitlines()
            if line.startswith("static-auth-secret=")]
    if len(turn) != 1:
        raise InputError("Invalid private Talk configuration identity.")
    talk = _talk_module()
    subset = talk.normalize_secrets({
        "talk_signaling_secret": parser.get("nextcloud", "secret"),
        "talk_turn_secret": turn[0], "talk_session_hashkey": parser.get("sessions", "hashkey"),
        "talk_session_blockkey": parser.get("sessions", "blockkey"),
    })
    if configs != talk.render_configs(public, subset):
        raise InputError("Talk configure contents differ from the reviewed renderer.")
    return {path: hashlib.sha256(content.encode()).hexdigest() for path, content in configs.items()}


def read_configured(public, saved):
    configs = {path: protected_read(path, 16384).decode("utf-8") for path in DESTINATIONS}
    for path, group in DESTINATIONS.items():
        info = os.stat(path, follow_symlinks=False)
        if info.st_uid != 0 or info.st_gid != grp.getgrnam(group).gr_gid or stat.S_IMODE(info.st_mode) != 0o640:
            raise InputError("Talk private config ownership/mode changed.")
    if validate_configs(public, configs) != saved["configs"]:
        raise InputError("Talk private config identity changed; do not regenerate secrets.")


def recv_exact(stream, length, deadline=None):
    if not 0 <= length <= 65536:
        raise InputError("Local Talk protocol response exceeds its bound.")
    result = bytearray()
    deadline = time.monotonic() + 3 if deadline is None else deadline
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InputError("Local Talk protocol deadline expired.")
        stream.settimeout(remaining)
        part = stream.recv(length - len(result))
        if not part:
            raise InputError("Local Talk protocol connection closed early.")
        result.extend(part)
    return bytes(result)


def probe_versions():
    """Legacy expected versions; current pkg uses functional protocol evidence."""
    value = json.loads(protected_read(PAYLOAD + "/runtime.json", private=True), object_pairs_hook=_unique)
    versions = value["versions"]
    if repository_current(versions):
        current_requirements(value)
        # native_guard already checked installed root names/origins/ABI and pkg
        # consistency. Package labels need not equal protocol version strings.
        return dict.fromkeys(("nats", "janus", "signaling"))
    expected = {"nats": "2.15.1", "janus": "1.4.3", "signaling": "2.1.1"}
    if "app_installation" not in versions:
        return expected  # Retained artifact semantics.
    if versions["app_installation"] != "occ":
        raise InputError("Unknown Talk app installation contract.")
    data = protected_read(PAYLOAD + "/packages.lock", 1048576, private=True)
    if hashlib.sha256(data).hexdigest() != versions.get("packages_sha256"):
        raise InputError("Talk staged payload digest differs from its immutable runtime lock.")
    packages = {}
    for line in data.decode("utf-8").splitlines():
        fields = line.split("|")
        if len(fields) != 4 or fields[0] in packages:
            raise InputError("Invalid selected Talk package identity.")
        packages[fields[0]] = fields
    for role, name, origin in (("nats", "nats-server", "net/nats-server"),
                               ("janus", "janus", "www/janus"),
                               ("signaling", "nextcloud-spreed-signaling", "net-im/nextcloud-spreed-signaling")):
        package = packages.get(name)
        if (package is None or package[2] != origin
                or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*(?:_[0-9]+)?(?:,[0-9]+)?", package[1])):
            raise InputError("Missing or invalid selected Talk probe package.")
        # Same pkg upstream convention as versions.sh / versions.package_upstream:
        # strip PORTEPOCH, then PORTREVISION; neither is a protocol version.
        expected[role] = package[1].split(",", 1)[0].split("_", 1)[0]
    return expected


def nats_probe(expected_version="2.15.1"):
    with socket.create_connection(("127.0.0.1", 4222), timeout=3) as stream:
        stream.settimeout(3)
        greeting = bytearray()
        deadline = time.monotonic() + 3
        while not greeting.endswith(b"\r\n") and len(greeting) <= 16384:
            greeting.extend(recv_exact(stream, 1, deadline))
        if len(greeting) > 16384 or not greeting.startswith(b"INFO "):
            raise InputError("NATS local greeting is invalid.")
        info = json.loads(greeting[5:])
        if (not isinstance(info.get("version"), str) or not info["version"]
                or (expected_version is not None and info["version"] != expected_version)
                or info.get("auth_required", False) is not False):
            raise InputError("NATS local protocol version/auth contract changed.")
        stream.sendall(b'CONNECT {"verbose":false,"pedantic":true}\r\nPING\r\n')
        if recv_exact(stream, 6, deadline) != b"PONG\r\n":
            raise InputError("NATS local PING failed.")


def websocket_frame(payload, mask):
    if len(mask) != 4 or len(payload) > 65535:
        raise InputError("Invalid bounded WebSocket probe frame.")
    header = bytes((0x81, 0x80 | len(payload))) if len(payload) < 126 else b"\x81\xfe" + struct.pack("!H", len(payload))
    return header + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload))


def janus_probe(public, expected_version="1.4.3"):
    # One read-only Janus info request, no session/create/attach/admin call.
    with socket.create_connection(("127.0.0.1", 8188), timeout=3) as stream:
        stream.settimeout(3)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = ("GET / HTTP/1.1\r\nHost: 127.0.0.1:8188\r\nUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                   "Sec-WebSocket-Protocol: janus-protocol\r\nSec-WebSocket-Key: " + key + "\r\n\r\n")
        stream.sendall(request.encode("ascii"))
        header = bytearray()
        deadline = time.monotonic() + 3
        while not header.endswith(b"\r\n\r\n") and len(header) <= 8192:
            header.extend(recv_exact(stream, 1, deadline))
        lines = bytes(header).decode("ascii").split("\r\n")
        headers = {}
        for line in lines[1:]:
            if line:
                name, value = line.split(":", 1)
                name = name.lower()
                if name in headers:
                    raise InputError("Duplicate Janus handshake header.")
                headers[name] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if (len(header) > 8192 or lines[0].split(" ")[:2] != ["HTTP/1.1", "101"]
                or headers.get("sec-websocket-accept") != expected
                or headers.get("sec-websocket-protocol") != "janus-protocol"
                or headers.get("upgrade", "").lower() != "websocket"
                or "upgrade" not in [v.strip() for v in headers.get("connection", "").lower().split(",")]):
            raise InputError("Janus WebSocket upgrade validation failed.")
        transaction = secrets.token_hex(12)
        stream.sendall(websocket_frame(json.dumps({"janus": "info", "transaction": transaction}).encode(), secrets.token_bytes(4)))
        first, second = recv_exact(stream, 2, deadline)
        if first != 0x81 or second & 0x80 or second & 0x7f == 127:
            raise InputError("Unexpected Janus WebSocket probe frame.")
        length = second & 0x7f
        if length == 126:
            length = struct.unpack("!H", recv_exact(stream, 2, deadline))[0]
        info = json.loads(recv_exact(stream, length, deadline))
        if (info.get("janus") != "server_info" or info.get("transaction") != transaction
                or not isinstance(info.get("version_string"), str) or not info["version_string"]
                or (expected_version is not None and info["version_string"] != expected_version)
                or info.get("local-ip") != public.talk_ip
                or set(info.get("plugins", {})) != {"janus.plugin.videoroom"}
                or set(info.get("transports", {})) != {"janus.transport.websockets"}
                or set(info.get("events", {})) != {"janus.eventhandler.wsevh"}):
            raise InputError("Janus native version/plugin/control evidence failed.")
        return info["version_string"]


def http_json(address, path):
    connection = http.client.HTTPConnection(address, 8080, timeout=3)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        data = response.read(65537)
        if response.status != 200 or len(data) > 65536:
            raise InputError("Local signaling observation failed or exceeded its bound.")
        return json.loads(data), response.getheader("X-Spreed-Signaling-Features", "")
    finally:
        connection.close()


def signaling_probe(public, expected_version="2.1.1", expected_janus="1.4.3"):
    welcome, header = http_json(public.talk_ip, "/api/v1/welcome")
    info, _ = http_json(public.talk_ip, "/api/v1/serverinfo")
    if (not isinstance(welcome.get("version"), str) or not welcome["version"]
            or not isinstance(info.get("version"), str) or not info["version"]
            or welcome["version"].lstrip("v") != info["version"].lstrip("v")
            or (expected_version is not None and info["version"].lstrip("v") != expected_version)):
        raise InputError("Local signaling native version differs from the selected package.")
    sfu = info.get("sfu", {})
    janus = sfu.get("janus", {})
    if (sfu.get("mode") != "janus" or janus.get("connected") is not True
            or janus.get("url") != "ws://127.0.0.1:8188" or janus.get("version") != expected_janus
            or not janus.get("videoroom") or info.get("nats", {}).get("connected") is not True):
        raise InputError("Actual signaling Janus/VideoRoom/NATS connection evidence failed.")
    features = [part.strip() for part in header.split(",") if part.strip()]
    if not set(features) <= set(info.get("features", [])):
        raise InputError("Signaling observed capabilities disagree.")
    return _talk_module().check_capabilities(features, janus_connected=True)


def allocate_request(transaction):
    if len(transaction) != 12:
        raise InputError("Invalid TURN probe transaction.")
    # RFC5766 REQUESTED-TRANSPORT UDP; deliberately no username/integrity.
    return struct.pack("!HHI", 0x0003, 8, 0x2112A442) + transaction + b"\x00\x19\x00\x04\x11\x00\x00\x00"


def parse_stun(data, transaction):
    if len(data) < 20:
        raise InputError("Short native TURN challenge.")
    kind, length, cookie = struct.unpack("!HHI", data[:8])
    if (kind & 0xc000 or length % 4 or len(data) != 20 + length
            or cookie != 0x2112A442 or data[8:20] != transaction):
        raise InputError("Invalid bound STUN response header.")
    attributes, offset = {}, 20
    while offset < len(data):
        if offset + 4 > len(data):
            raise InputError("Malformed TURN attribute header.")
        key, size = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        end = offset + size
        if end > len(data) or key in attributes:
            raise InputError("Malformed or duplicate TURN challenge attribute.")
        attributes[key] = data[offset:end]
        offset += (size + 3) & ~3
    if offset != len(data):
        raise InputError("Invalid padded STUN attribute bounds.")
    return kind, attributes


def validate_turn_challenge(data, transaction, realm):
    kind, attributes = parse_stun(data, transaction)
    error = attributes.get(0x0009, b"")
    if (kind != 0x0113 or len(error) < 4 or error[:4] != b"\x00\x00\x04\x01"
            or attributes.get(0x0014) != realm.encode("utf-8") or not attributes.get(0x0015)
            or 0x0016 in attributes):
        raise InputError("TURN unauthenticated Allocate was not denied with the expected realm/nonce.")


def turn_probe(public):
    for transport in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        transaction = secrets.token_bytes(12)
        request = allocate_request(transaction)
        with socket.socket(socket.AF_INET, transport) as stream:
            stream.settimeout(3)
            stream.connect((public.talk_ip, public.talk_turn_port))
            stream.sendall(request)
            if transport == socket.SOCK_DGRAM:
                response = stream.recv(65537)
            else:
                deadline = time.monotonic() + 3
                header = recv_exact(stream, 20, deadline)
                response = header + recv_exact(stream, struct.unpack("!H", header[2:4])[0], deadline)
            validate_turn_challenge(response, transaction, public.realm)


def parse_sockets(text):
    """FreeBSD15.1 sockstat -46nqw: UID COMMAND PID FD PROTO LOCAL FOREIGN."""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 7:
            raise InputError("Unexpected native sockstat observation format.")
        uid, command, pid, fd, protocol, local, foreign = parts
        if protocol not in ("tcp4", "tcp6", "udp4", "udp6"):
            raise InputError("Unreviewed Internet protocol socket in Talk jail.")
        if not uid.isdigit() or not pid.isdigit() or not fd.isdigit():
            # Kernel-owned retired connected TCP state is not a listening daemon.
            if protocol.startswith("tcp") and foreign != "*:*" and uid == "?" and pid == "?":
                continue
            raise InputError("Unattributed Internet socket in Talk jail.")
        try:
            address, port = local.rsplit(":", 1)
            number = int(port)
        except ValueError:
            raise InputError("Unreviewed native socket address/port format.") from None
        if not 1 <= number <= 65535:
            raise InputError("Unreviewed native socket port.")
        rows.append((int(uid), int(pid), protocol, address.strip("[]"), number, foreign))
    return rows


def check_sockets(public, accounts, text, process):
    """Own-IP UDP exception has no port ACL: reject every unapproved UDP bind.

    process(pid) returns observed numeric UID and native executable path.
    No host PF claim. Includes connected UDP, not just sockstat -l listeners.
    """
    names = {"nats": "/usr/local/bin/nats-server", "cloudjanus": "/usr/local/bin/janus",
             "_turnserver": "/usr/local/bin/turnserver", "signaling": "/usr/local/bin/ncs-signaling"}
    uid_names = {value[0]: name for name, value in accounts.items()}
    required = {("nats", "tcp4", "127.0.0.1", 4222),
                ("cloudjanus", "tcp4", "127.0.0.1", 8188),
                ("signaling", "tcp4", public.talk_ip, 8080),
                ("_turnserver", "tcp4", public.talk_ip, public.talk_turn_port),
                ("_turnserver", "udp4", public.talk_ip, public.talk_turn_port)}
    required_connections = {("signaling", "127.0.0.1:4222"),
                            ("signaling", "127.0.0.1:8188"),
                            ("cloudjanus", public.talk_ip + ":8080")}
    connected = set()
    found, checked = set(), {}
    for uid, pid, proto, address, port, foreign in parse_sockets(text):
        name = uid_names.get(uid)
        if name:
            if pid not in checked:
                checked[pid] = process(pid)
            if checked[pid] != (uid, names[name]):
                raise InputError("Talk socket process identity differs from its dedicated account/binary.")
        if proto.startswith("udp"):
            allowed = (name == "cloudjanus" and public.talk_media_port_min <= port <= public.talk_media_port_max
                       or name == "_turnserver" and (port == public.talk_turn_port
                           or public.talk_relay_port_min <= port <= public.talk_relay_port_max))
            if proto != "udp4" or address != public.talk_ip or not allowed:
                raise InputError("Unapproved UDP bind invalidates the co-located TURN own-IP boundary.")
            found.add((name, proto, address, port))
        elif foreign == "*:*":
            binding = (name, proto, address, port)
            if binding not in required:
                raise InputError("Unapproved public/wildcard/control TCP listener in Talk jail.")
            found.add(binding)
        elif name:
            connected.add((name, foreign))
    if not required <= found:
        raise InputError("A required native Talk listener is missing.")
    if not required_connections <= connected:
        raise InputError("A required native Talk NATS/Janus/events connection is absent.")


def process_identity(pid):
    # No ps args/environment. procstat binary gives the real executable path,
    # not a spoofable command basename or a secret-bearing argument list.
    value = native_command(["/bin/ps", "-p", str(pid), "-o", "uid="], capture=True).strip()
    binary = native_command(["/usr/bin/procstat", "-h", "-b", str(pid)], capture=True).split()
    if (not value.isdigit() or len(binary) != 4 or binary[0] != str(pid)
            or not binary[2].isdigit() or not binary[3].startswith("/usr/local/bin/")):
        raise InputError("Native Talk process identity is unavailable.")
    info = os.stat(binary[3], follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise InputError("Native Talk executable protection changed.")
    return int(value), binary[3]


def _verify_local(public):
    accounts = service_accounts()
    check_directories(accounts)
    check_rc_settings(require_disabled=False)
    check_rotation()
    module_inventory()
    for service in SERVICE_ORDER:
        if service_command(service, "onestatus") != 0:
            raise InputError("A required native Talk service is not running.")
    text = native_command(["/usr/bin/sockstat", "-46nqw"], capture=True)
    check_sockets(public, accounts, text, process_identity)
    expected = probe_versions()
    nats_probe(expected["nats"])
    janus_version = janus_probe(public, expected["janus"])
    warnings = signaling_probe(public, expected["signaling"],
                               janus_version if expected["janus"] is None else expected["janus"])
    turn_probe(public)
    return warnings


def verify_local(public):
    # Bound the entire observation set, including a pathological local HTTP
    # peer that trickles data more slowly than per-read socket timeouts.
    def expired(signum, frame):
        raise InputError("Talk local observation deadline expired.")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(45)
    try:
        return _verify_local(public)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def configure(public, identity, saved, stream):
    # Consume the single stdin payload once, before any config/service mutation.
    configs = read_configs(stream)
    intended = validate_configs(public, configs)
    if saved is None:
        raise InputError("Complete Talk prepare before configure.")
    if saved["phase"] != "prepared" and saved["configs"] != intended:
        raise InputError("Talk configure secret/config identity changed; assess recovery.")
    check_ca_trust(identity)  # Before any daemon start/restart or config writes.
    if saved["phase"] == "configured":
        read_configured(public, saved)
        return verify_local(public)  # Completed retry is observational only.
    current = config_hashes(allow_missing=True)
    if any(current[path] not in (saved["baseline"][path], intended[path]) for path in DESTINATIONS):
        raise InputError("Talk configuration changed outside the saved intent; assess recovery.")
    check_rc_settings()
    stop_services()
    save_state(identity, public.instance, "configuring", intended, saved["baseline"])
    stage = "fixed-path config writes"
    try:
        write_configs(configs)
        temporary_state = {"configs": intended}
        read_configured(public, temporary_state)
        stage = "ordered service startup/local protocol observations"
        # Retry only bounded read-only observations, never repair/migrate here.
        advisory = []
        def probe():
            deadline = time.monotonic() + 20
            while True:
                try:
                    advisory[:] = verify_local(public)
                    return True
                except (InputError, OSError, ValueError):
                    if time.monotonic() >= deadline:
                        raise InputError("Talk local readiness deadline expired.") from None
                    time.sleep(0.2)
        start_for_probe(probe)
        stage = "positive local configure checkpoint"
        save_state(identity, public.instance, "configured", intended, saved["baseline"])
        return tuple(advisory)
    except BaseException:
        try:
            stop_services()
        except InputError:
            raise InputError("Talk configuration failed; shutdown unconfirmed, host must stop the owned jail.") from None
        raise InputError("Talk configuration failed during " + stage + "; services stopped and publication remains forbidden.") from None


def main(argv=None):
    if sys.version_info < (3, 11):
        sys.stderr.write("Talk runtime requires Python 3.11 or newer for its code ABI.\n")
        return 1
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["boot-runtime"]:
        try:
            boot_runtime()
            return 0
        except BaseException:
            sys.stderr.write("Talk volatile runtime initialization failed (details suppressed).\n")
            return 1
    if len(argv) == 1 and argv[0] in ("reopen-janus", "reopen-turnserver"):
        try:
            reopen_log(argv[0])
            return 0
        except BaseException:
            sys.stderr.write("Talk log reopening failed (details suppressed).\n")
            return 1
    if len(argv) != 1 or argv[0] not in ("prepare", "configure", "verify"):
        sys.stderr.write("Talk runtime: expected prepare|configure|verify.\n")
        return 1
    phase = argv[0]
    os.umask(0o077)
    try:
        public = load_public()
        native_guard(public)
        identity = payload_identity()
        saved = read_state(identity, public.instance)
        if phase == "prepare":
            prepare(public, identity, saved)
            warnings = ()
        elif phase == "configure":
            warnings = configure(public, identity, saved, sys.stdin.buffer)
        else:
            if saved is None or saved["phase"] != "configured":
                raise InputError("Talk has no positively checked local configured state.")
            check_ca_trust(identity)  # Observational: never certctl or repair.
            read_configured(public, saved)
            warnings = verify_local(public)
        for warning in warnings:
            sys.stdout.write(warning + "\n")
        sys.stdout.write("Talk " + phase + " checks passed (local only; no publication/boot grant).\n")
        return 0
    except BaseException as error:
        # Never print raw parse/config/socket/subprocess exceptions or responses.
        # Fixed diagnostic categories contain no input values or command output.
        reason = str(error) if type(error) is InputError else "Input or native observation failure (details suppressed)."
        message = "Talk " + phase + " failed: " + reason + " Publication forbidden; host must confirm stopped jail on mutation failure.\n"
        if phase != "verify":
            try:
                atomic_public(STATE + "/failure.txt", "phase=" + phase + "\nresult=failed\nreason=" + reason + "\nshutdown=host-confirmation-required\n", mode=0o600)
            except BaseException:
                pass
        sys.stderr.write(message)
        return 1


if __name__ == "__main__":
    sys.exit(main())
