"""Pure Client Push components. No discovery, filesystem or process IO.

Integration contract: Client Push is a default requirement independent of Talk.
Real occ installs/signature-checks the PHP app. The host separately freezes and
validates native bytes before staging, then installs returned files with declared
ownership/modes. Templates are supplied by the caller (no import-time reads).
Execution admission lives in service_execution, not this module. Reviewed wiring
is available for disposable trials; this does not claim native acceptance.
External TLS requires an explicitly trusted frontend overwriting XFF with one IP.
"""

from dataclasses import dataclass
import copy
import hashlib
import ipaddress
import json
import re
import struct
from urllib.parse import urlsplit

from .office_config import public_base_url


EXECUTION_AVAILABLE = True
APP_ID = "notify_push"
BINARY = "/usr/local/libexec/cloud-installer/notify_push"
CONFIG = "/usr/local/www/nextcloud/config/config.php"
SERVICE = "cloud_notify_push"
PIDFILE = "/var/run/cloud-notify-push/supervisor.pid"
CHILD_PIDFILE = "/var/run/cloud-notify-push/child.pid"
LOGFILE = "/var/log/cloud-notify-push/notify_push.log"
REQUIRED_CHECKS = (
    "native-loader-exact-binary-version-and-app-major-minor",
    "app-signature-and-enabled-state",
    "unprivileged-process-and-loopback-only-listener",
    "redis-database-callback-and-trusted-proxy-self-test",
    "independent-strict-tls-public-hostname-and-chain",
    "authenticated-websocket-and-delivered-event",
    "forged-forwarded-header-rejection",
    "bounded-stop-restart-and-reboot-readiness",
)


@dataclass(frozen=True)
class ArtifactLock:
    version: str
    url: str
    sha256: str
    size: int
    architecture: str


# Reviewed vendor FreeBSD asset, NOT the Linux binary bundled in the PHP app.
REVIEWED_ARTIFACT = ArtifactLock(
    "1.4.2",
    "https://github.com/nextcloud/notify_push/releases/download/v1.4.2/"
    "notify_push-x86_64-unknown-freebsd",
    "96fb41c23a84e9524cf0d7272d6744645d06a4bfc60845e6dee7d2fa6e8f646a",
    22800432,
    "amd64",
)


@dataclass(frozen=True)
class ManagedFile:
    path: str
    content: str
    mode: int
    owner: str = "root"
    group: str = "wheel"


def validate_lock(lock):
    """Validate an exact official asset identity; never discover or select here.

    The caller binds this to its saved lock. Legacy native-v1 additionally checks
    REVIEWED_ARTIFACT in native_runtime/services; structural validation alone is
    not authorization to replace an installed binary.
    """
    if (type(lock) is not ArtifactLock or type(lock.size) is not int
            or not 64 <= lock.size <= 64 * 1024 * 1024
            or not isinstance(lock.version, str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", lock.version)
            or lock.url != ("https://github.com/nextcloud/notify_push/releases/download/v"
                            + lock.version + "/notify_push-x86_64-unknown-freebsd")
            or not isinstance(lock.sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", lock.sha256)
            or lock.architecture != "amd64"):
        raise ValueError("Invalid Client Push FreeBSD artifact identity")
    return lock


def validate_pair(app_version, lock):
    """Upstream SelfTest pairs major.minor, not patch (v1.4.2 tagged source)."""
    validate_lock(lock)
    if (not isinstance(app_version, str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", app_version)
            or app_version.rsplit(".", 1)[0] != lock.version.rsplit(".", 1)[0]):
        raise ValueError("Client Push app/native major.minor mismatch")
    return lock


def validate_selection(value, *, instance, source_sha256, plan_sha256, app_version=None):
    """Run-local deferred phase input; exact identity, not an app release policy."""
    from .versions import object_fields
    object_fields(value, ("schema_version", "instance", "source_sha256", "plan_sha256", "app_version", "native"), label="Push phase input")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["instance"] != instance or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", instance)
            or value["source_sha256"] != source_sha256 or not re.fullmatch(r"[a-f0-9]{64}", source_sha256)
            or value["plan_sha256"] != plan_sha256 or not re.fullmatch(r"[a-f0-9]{64}", plan_sha256)
            or (app_version is not None and value["app_version"] != app_version)):
        raise ValueError("Push phase input identity changed; explicit recovery is required")
    try:
        validate_pair(value["app_version"], ArtifactLock(**value["native"]))
    except (TypeError, KeyError):
        raise ValueError("Invalid native Push phase input") from None
    return copy.deepcopy(value)


def validate_artifact(data, lock):
    """Validate bounded downloaded bytes, without reading paths or executing ELF."""
    validate_lock(lock)
    if type(data) is not bytes or len(data) != lock.size:
        raise ValueError("Client Push artifact size mismatch")
    if hashlib.sha256(data).hexdigest() != lock.sha256:
        raise ValueError("Client Push artifact checksum mismatch")
    # The checksum is authoritative; explicit ELF checks also guard target errors.
    if (data[:8] != b"\x7fELF\x02\x01\x01\x09"
            or struct.unpack_from("<HH", data, 16) != (3, 62)):
        raise ValueError("Client Push requires a FreeBSD amd64 PIE ELF")
    return lock


def required_apps():
    """Unconditional default requirement, including a Talk-free installation."""
    return (APP_ID,)


def public_endpoint(config):
    """Use Config.public_url, preserving the configured public HTTPS port."""
    base = public_base_url(config.public_url)
    host = urlsplit(base).hostname
    if (len(host) > 253 or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in host.split("."))):
        raise ValueError("Invalid Client Push public hostname")
    return base + "push"


def trusted_proxies(existing):
    """Merge only exact IPv4 loopback; caller retains validated external policy.

    This is a proposal for native config, not permission to accept remote headers.
    A callback route must actually originate from 127.0.0.1 before using it.
    """
    if not isinstance(existing, (tuple, list)) or any(type(x) is not str for x in existing):
        raise ValueError("Expected existing validated trusted proxy list")
    return tuple(dict.fromkeys((*existing, "127.0.0.1")))


def verification_plan(config, lock):
    """Describe checks, not a health result or executable deployment plan.

    occ self-test writes transient test values and upstream disables TLS verify.
    Neither that command nor app-enabled state is sufficient for readiness.
    Authenticated WebSocket credentials must be supplied via protected stdin by
    the future worker, never argv/environment. No invented /health endpoint.
    """
    validate_lock(lock)
    endpoint = public_endpoint(config)
    if config.tls_mode not in ("acme", "provided", "external"):
        raise ValueError("Unknown Client Push TLS mode")
    return {
        "status": "NOT_WIRED", "execution_available": False,
        "required_apps": required_apps(), "app_version": lock.version,
        "endpoint": endpoint, "websocket_url": "wss://" + endpoint[8:] + "/ws",
        "setup_occ_args": ("notify_push:setup", endpoint),
        "self_test_occ_args": ("notify_push:self-test",),
        "metrics_occ_args": ("notify_push:metrics",),
        "strict_tls_required": True, "checks": REQUIRED_CHECKS,
        "mutating_install_only": ("setup_occ_args", "self_test_occ_args", "push-proof"),
        "observational_php_modes": ("push-observe", "push-listener"),
        "external_header_contract_review_required": config.tls_mode == "external",
    }


def render_proxy(config):
    """Public vhost fragment with direct/external physical-peer header policy.

    Requires existing proxy/http/wstunnel/headers modules. Keep this scoped to
    /push/: callback /index.php/apps/notify_push must retain daemon-generated XFF.
    CONN_REMOTE_ADDR is the underlying peer even if mod_remoteip is later loaded.
    No operator-supplied or client-supplied text is interpolated into directives.
    """
    public_endpoint(config)
    external = config.tls_mode == "external"
    if config.tls_mode not in ("acme", "provided", "external") or (not external and config.proxy_networks):
        raise ValueError("Client Push direct proxy requires direct TLS without external proxies")
    source = '    RequestHeader set X-Forwarded-For "expr=%{CONN_REMOTE_ADDR}"\n'
    if external:
        proxies = ([value.strip() for value in config.proxy_networks.split(",") if value.strip()]
                   if isinstance(config.proxy_networks, str) else config.proxy_networks)
        if not proxies:
            raise ValueError("Explicit trusted external frontend required")
        networks = [ipaddress.IPv4Network(n, strict=True) for n in proxies]
        if (len(networks) > 32 or len(set(networks)) != len(networks)
                or any(n.prefixlen < 24 or n.is_loopback or n.is_multicast or n.is_link_local
                       or n.network_address.is_unspecified for n in networks)):
            raise ValueError("Invalid external frontend trust")
        peers = " || ".join(f"%{{CONN_REMOTE_ADDR}} -ipmatch '{n}'" for n in networks)
        # Only the explicit frontend may submit one parseable client IP. It must
        # overwrite, not append, outside XFF. Chains and alternate headers fail.
        # Apache -ipmatch uses getaddrinfo: reject hostnames/whitespace/chains
        # before evaluating it, preventing client-driven DNS resolution.
        octet = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
        literal = rf"^(?:(?:{octet}\.){{3}}{octet}|[0-9A-Fa-f]{{0,4}}:[0-9A-Fa-f:]{{1,39}})$"
        source = (
            f'    Require expr "({peers}) && '
            f"(req('X-Forwarded-For') =~ m#{literal}#) && "
            "((req('X-Forwarded-For') -ipmatch '0.0.0.0/0') || "
            "(req('X-Forwarded-For') -ipmatch '::/0'))\"\n"
        )
    return ManagedFile(
        "/usr/local/etc/apache24/cloud-client-push.conf",
        '# Include only inside the selected Nextcloud application VirtualHost.\n'
        '<Location /push/>\n'
        '    ProxyAddHeaders Off\n'
        '    RequestHeader unset Forwarded\n'
        '    RequestHeader unset X-Real-IP\n'
        + ('' if external else '    RequestHeader unset X-Forwarded-For\n') +
        '    RequestHeader unset X-Client-IP\n'
        '    RequestHeader unset Client-IP\n'
        '    RequestHeader unset True-Client-IP\n'
        '    RequestHeader unset CF-Connecting-IP\n'
        + source +
        '</Location>\n'
        'ProxyPass /push/ws ws://127.0.0.1:7867/ws\n'
        'ProxyPass /push/ http://127.0.0.1:7867/\n'
        'ProxyPassReverse /push/ http://127.0.0.1:7867/\n',
        0o644,
    )


def native_runtime(config, plan, *, talk_public=None):
    """Exact PUBLIC runtime.json.native_services, derived from a saved plan.

    Caller has already validated the full plan; this helper additionally binds
    its services selection and known push bytes. Stage services.json using
    version_runtime.services_text, notify-push.tar.gz and notify-push.bin as
    root0600. No secret fields may enter this object.
    """
    service = plan.get("services")
    if not isinstance(service, dict) or set(service) != {"profile", "policy_sha256", "talk", "push"}:
        raise ValueError("Missing exact native services lock")
    if (service["profile"] != "native-v1" or type(service["talk"]) is not bool
            or not re.fullmatch("[a-f0-9]{64}", service["policy_sha256"])
            or getattr(config, "service_profile", "") != "native-v1"):
        raise ValueError("Native services selection mismatch")
    if getattr(config, "talk", service["talk"]) is not service["talk"]:
        raise ValueError("Native Talk selection differs from saved services")
    push = service["push"]
    fresh = "app_installation" in plan
    if fresh:
        if push != {"app": "occ", "native": "deferred"}:
            raise ValueError("Fresh Push requires native occ and deferred binary selection")
        app = None
    else:
        app = push.get("app")
    if not fresh and (set(push) != {"app", "native"} or set(push["app"]) != {"release", "sha256", "size"}):
        raise ValueError("Invalid push lock")
    if not fresh and validate_lock(ArtifactLock(**push["native"])) != REVIEWED_ARTIFACT:
        raise ValueError("Legacy native-v1 Push artifact identity changed")
    if not fresh and (app["release"]["version"] != "1.4.2"
            or app["sha256"] != "4bd2d62de2de3814e399297bc2443ed127a3ca730e540976a959c0b5a89cc380"
            or type(app["size"]) is not int or app["size"] != 26025475):
        raise ValueError("Unreviewed signed push app identity")
    render_proxy(config)  # same TLS/ingress fences as the installed fragment
    talk = None
    if service["talk"]:
        from .talk import TalkConfig
        if not isinstance(talk_public, TalkConfig) or talk_public.backend_url + "/" != config.public_url:
            raise ValueError("Talk public settings differ from selected Nextcloud")
        talk_public.__post_init__()
        hostname = getattr(config, "talk_media_hostname", "")
        if (hostname != talk_public.talk_media_hostname
                or (hostname and getattr(config, "talk_public_ip", ""))):
            raise ValueError("Talk media hostname differs from the selected instance")
        names = ("talk_turn_port", "nextcloud_ip", "talk_ip", "talk_gateway")
        if not hostname:
            names += ("talk_public_ip",)
        for name in names:
            if hasattr(config, name) and getattr(config, name) != getattr(talk_public, name):
                raise ValueError("Talk endpoint differs from the selected instance")
        if hasattr(config, "has_office") and talk_public.office_ip != (config.onlyoffice_ip if config.has_office else ""):
            raise ValueError("Talk office endpoint differs from the selected instance")
        talk = {"signaling_url": talk_public.signaling_url,
                "turn_server": talk_public.turn_authority}
    elif talk_public is not None:
        raise ValueError("Unselected Talk public settings")
    if fresh:
        return {"profile": "native-v1", "push": {"app": "occ", "native": "deferred", "endpoint": public_endpoint(config)}, "talk": talk}
    return {"profile": "native-v1", "push": {
        "app": {"version": app["release"]["version"], "sha256": app["sha256"], "size": app["size"]},
        "native": copy.deepcopy(push["native"]), "endpoint": public_endpoint(config)}, "talk": talk}


def callback_proxy():
    """Only local daemon auth/self-test callbacks; no arbitrary PHP/HTTP proxy."""
    return ManagedFile("/usr/local/etc/apache24/cloud-push-callback.conf", '''Listen 127.0.0.1:7868
<VirtualHost 127.0.0.1:7868>
    ServerName 127.0.0.1
    DocumentRoot /usr/local/www/nextcloud
    ProxyRequests Off
    <Directory /usr/local/www/nextcloud>
        Options None
        AllowOverride None
        Require all denied
        AcceptPathInfo On
        <Files index.php>
            Require ip 127.0.0.1
            ProxyFCGIBackendType FPM
            SetEnvIfNoCase Authorization "(.+)" HTTP_AUTHORIZATION=$1
            SetHandler "proxy:unix:/var/run/php-fpm/nextcloud.sock|fcgi://localhost/"
        </Files>
    </Directory>
    <Location />
        Require all denied
    </Location>
    <LocationMatch "^/index\\.php/apps/notify_push/(uid|test/(cookie|remote))$">
        Require ip 127.0.0.1
        <LimitExcept GET>
            Require all denied
        </LimitExcept>
    </LocationMatch>
</VirtualHost>
''', 0o644)


def integration_stdin(config, *, connector, talk=None):
    """SECRET finish-only JSON bytes. Never pass as argv/env or persist/log.

    connector is {} for none/Collabora, otherwise {jwt_secret: ...}.
    talk is absent unless selected; only signaling_secret and turn_secret belong
    here, never the Talk session keys or the complete host secret bundle.
    Legacy callers must retain their old phase format and cannot use this API.
    """
    if getattr(config, "service_profile", "") != "native-v1":
        raise ValueError("Integration input requires the native service profile")
    backend = config.backend
    if backend not in ("none", "onlyoffice", "eurooffice", "collabora"):
        raise ValueError("Unknown office backend")
    expected = {"jwt_secret"} if backend in ("onlyoffice", "eurooffice") else set()
    if type(connector) is not dict or set(connector) != expected:
        raise ValueError("Invalid connector phase subset")
    if expected:
        value = connector["jwt_secret"]
        if (not isinstance(value, str) or not 32 <= len(value) <= 1024
                or re.search(r"[\x00-\x1f\x7f]", value)
                or (backend == "eurooffice" and not re.fullmatch(r"[a-fA-F0-9]{64}", value))):
            raise ValueError("Invalid connector credential")
    result = {"connector": dict(connector)}
    if config.talk:
        if (type(talk) is not dict or set(talk) != {"signaling_secret", "turn_secret"}
                or any(not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{64}", v) for v in talk.values())
                or talk["signaling_secret"] == talk["turn_secret"]):
            raise ValueError("Invalid NC-side Talk shared-secret subset")
        result["talk"] = dict(talk)
    elif talk is not None:
        raise ValueError("Unselected Talk credentials")
    return (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def render_service(template, lock):
    """Return fixed rc payload; no user-controlled shell text or environment."""
    validate_lock(lock)
    if not isinstance(template, str) or "@@" in template or not template.startswith("#!/bin/sh\n"):
        raise ValueError("Expected the reviewed complete Client Push rc template")
    return ManagedFile("/usr/local/etc/rc.d/" + SERVICE, template, 0o555)


def log_policy():
    """Periodic bounded retention, not a hard instantaneous file-size ceiling.

    Keep the existing logs dataset quota. Install both private directories and
    initial root:wheel0600 log before enabling service. HUP goes to supervisor.
    """
    return ManagedFile(
        "/usr/local/etc/newsyslog.conf.d/cloud-client-push.conf",
        f"{LOGFILE} root:wheel 600 3 1024 24 BZ {PIDFILE} 1\n",
        0o600,
    )


def installation_layout():
    """Declarative worker requirements; no directories/files are created here."""
    return {
        "binary": (BINARY, "root", "wheel", 0o555),
        "binary_directory": ("/usr/local/libexec/cloud-installer", "root", "wheel", 0o755),
        "pid_directory": ("/var/run/cloud-notify-push", "root", "wheel", 0o700),
        "pidfiles": (PIDFILE, CHILD_PIDFILE),
        "log_directory": ("/var/log/cloud-notify-push", "root", "wheel", 0o700),
        "log": (LOGFILE, "root", "wheel", 0o600),
        "service_user": "www", "config": CONFIG,
        "secret_environment": (), "listener": ("127.0.0.1", 7867),
    }
