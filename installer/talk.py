"""Unwired native Talk component: public validation and secret-safe rendering.

No Config dependency, host probes, package selection or service mutations. The
worker intentionally refuses execution until the parent integrates ownership,
immutable package locks, PF, staging and native readiness/abuse checks.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import ipaddress
import json
from pathlib import Path
import re
from string import Template
from typing import Mapping
from urllib.parse import urlsplit


class TalkError(ValueError):
    """Deliberately value-free error: callers must not print secret inputs."""


# Reviewed source line, not package selection policy. Revisions/closure belong
# to the parent's immutable talk group, including an explicit python3 root.
REVIEWED_UPSTREAM = {
    "talk_signaling": "2.1.1", "talk_nats": "2.15.1",
    "talk_janus": "1.4.3", "talk_turn": "4.16.0",
}
REQUIRED_FEATURES = frozenset({
    "audio-video-permissions", "federation", "incall-all", "hello-v2",
    "switchto", "mcu",
})
SERVICES = ("nats", "janus", "turnserver", "ncs_signaling")
SECRET_KEYS = frozenset({
    "talk_signaling_secret", "talk_turn_secret", "talk_session_hashkey",
    "talk_session_blockkey",
})

# Explicit ranges rather than interpreter-dependent is_private alone. IPv6
# peer relay is entirely denied (this profile offers IPv4 only).
DENIED_PEER_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "::/0",
))


def _ipv4(value: object, *, public: bool = False) -> str:
    if not isinstance(value, str):
        raise TalkError("Talk requires explicit IPv4 addresses.")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise TalkError("Invalid Talk IPv4 address.") from None
    if public and (not address.is_global or any(
        address in n for n in DENIED_PEER_NETWORKS if n.version == 4
    )):
        raise TalkError("Talk public address must be ordinary public unicast IPv4.")
    return str(address)


@dataclass(frozen=True)
class TalkConfig:
    """Explicit public subset; construct after Config-derived Talk selection.

    Parent must supply the resolved HTTPS route separately to networking. This
    component never resolves DNS or rewrites backend HTTPS to private HTTP.
    no_other_sensitive_udp_services is an explicit topology acknowledgment, not
    a claim that an offline renderer inspected sockets.
    """

    instance: str
    talk_ip: str
    talk_gateway: str
    nextcloud_ip: str
    backend_url: str
    talk_public_ip: str
    talk_turn_port: int
    talk_media_port_min: int
    talk_media_port_max: int
    talk_relay_port_min: int
    talk_relay_port_max: int
    no_other_sensitive_udp_services: bool
    office_ip: str = ""
    # Explicit host/public/management endpoints to forbid as relay peers.
    forbidden_peer_ips: tuple[str, ...] = ()
    talk_media_hostname: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.instance, str) or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", self.instance):
            raise TalkError("Invalid Talk instance identity.")
        for name in ("talk_ip", "talk_gateway", "nextcloud_ip"):
            address = _ipv4(getattr(self, name))
            if not any(ipaddress.IPv4Address(address) in ipaddress.ip_network(n)
                       for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
                raise TalkError("Talk endpoints must use owned RFC1918 IPv4 addresses.")
        _ipv4(self.talk_public_ip, public=True)
        if not isinstance(self.talk_media_hostname, str) or (self.talk_media_hostname and (
                not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                                 self.talk_media_hostname)
                or re.fullmatch(r"[0-9.]+", self.talk_media_hostname))):
            raise TalkError("Talk media hostname must be a canonical DNS name.")
        segment = ipaddress.ip_network(self.talk_ip + "/30", strict=False)
        if (self.talk_ip != str(segment.network_address + 2)
                or self.talk_gateway != str(segment.network_address + 1)):
            raise TalkError("Talk endpoints must occupy the owned /30 gateway/runtime positions.")
        endpoints = [self.talk_ip, self.talk_gateway, self.nextcloud_ip]
        if not isinstance(self.office_ip, str):
            raise TalkError("Invalid optional office endpoint.")
        if self.office_ip:
            endpoints.append(_ipv4(self.office_ip))
        if len(set(endpoints)) != len(endpoints):
            raise TalkError("Talk endpoint identities overlap.")
        if not isinstance(self.forbidden_peer_ips, tuple):
            raise TalkError("Talk forbidden peers must be an immutable address tuple.")
        for value in self.forbidden_peer_ips:
            _ipv4(value)
        if self.talk_ip in self.forbidden_peer_ips:
            raise TalkError("Own Talk peer exception conflicts with a forbidden endpoint.")
        for name in ("talk_turn_port", "talk_media_port_min", "talk_media_port_max",
                     "talk_relay_port_min", "talk_relay_port_max"):
            value = getattr(self, name)
            if type(value) is not int or not 1024 <= value <= 65535:
                raise TalkError("Talk ports must be unprivileged integer ports.")
        ranges = ((self.talk_media_port_min, self.talk_media_port_max),
                  (self.talk_relay_port_min, self.talk_relay_port_max))
        if any(lo > hi for lo, hi in ranges):
            raise TalkError("Talk port range is reversed.")
        if max(ranges[0][0], ranges[1][0]) <= min(ranges[0][1], ranges[1][1]):
            raise TalkError("Talk media and relay ranges overlap.")
        # TCP controls and the UDP/TCP TURN listener must never collide locally.
        if self.talk_turn_port in (4222, 8080, 8188) or any(
            lo <= self.talk_turn_port <= hi for lo, hi in ranges
        ):
            raise TalkError("Talk TURN listener collides with a local service/range.")
        if self.no_other_sensitive_udp_services is not True:
            raise TalkError("Own-IP TURN exception requires no other sensitive UDP services on TalkIP.")
        if not isinstance(self.backend_url, str) or not re.fullmatch(
            r"https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?", self.backend_url
        ):
            raise TalkError("Talk backend must be an explicit canonical HTTPS origin.")
        try:
            url = urlsplit(self.backend_url)
            port = url.port
        except ValueError:
            raise TalkError("Invalid Talk backend HTTPS authority.") from None
        host = url.hostname or ""
        if not host or len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                           for p in host.split(".")) or (port is not None and port == 0):
            raise TalkError("Invalid Talk backend hostname or port.")

    @property
    def realm(self) -> str:
        return urlsplit(self.backend_url).hostname or ""

    @property
    def signaling_url(self) -> str:
        return self.backend_url + "/standalone-signaling/"

    @property
    def turn_authority(self) -> str:
        return f"{self.talk_media_hostname or self.talk_public_ip}:{self.talk_turn_port}"

    def to_dict(self) -> dict[str, object]:
        """Keep the additive empty hostname absent from retained runtime bytes."""
        return {f.name: getattr(self, f.name) for f in fields(self)
                if f.name != "talk_media_hostname" or self.talk_media_hostname}


def normalize_public(values: Mapping[str, object]) -> TalkConfig:
    """Strict public-only schema, independent of the not-yet-shared Config API."""
    if not isinstance(values, Mapping) or set(values) - {f.name for f in fields(TalkConfig)}:
        raise TalkError("Unknown Talk public settings.")
    clean = dict(values)
    if "forbidden_peer_ips" in clean and isinstance(clean["forbidden_peer_ips"], list):
        clean["forbidden_peer_ips"] = tuple(clean["forbidden_peer_ips"])
    try:
        return TalkConfig(**clean)
    except (TypeError, AttributeError):
        raise TalkError("Incomplete or invalid Talk public settings.") from None


def public_from_config(config, *, no_other_sensitive_udp_services: bool,
                       forbidden_peer_ips: tuple[str, ...] = (),
                       resolved_address: str | None = None) -> TalkConfig:
    """Project A's selected model; acknowledgment remains explicit for F."""
    if config.service_profile != "native-v1" or config.talk is not True:
        raise TalkError("Talk public projection requires explicit selected native services.")
    hostname = getattr(config, "talk_media_hostname", "")
    if hostname:
        if config.talk_public_ip or resolved_address is None:
            raise TalkError("Hostname Talk requires its separate prepared numeric address.")
        address = resolved_address
    else:
        address = config.talk_public_ip
        if resolved_address is not None and resolved_address != address:
            raise TalkError("Prepared address differs from retained numeric Talk settings.")
    callback = (getattr(config, "frontend_callback_address", "") if hostname
                else getattr(config, "dns_address", ""))
    forbidden = tuple(sorted(set((*forbidden_peer_ips, config.ingress_address,
                                  *((callback,) if callback else ())))))
    return TalkConfig(
        instance=config.instance, talk_ip=config.talk_ip, talk_gateway=config.talk_gateway,
        nextcloud_ip=config.nextcloud_ip, office_ip=config.onlyoffice_ip if config.has_office else "",
        backend_url=config.public_url.rstrip("/"), talk_public_ip=address,
        talk_turn_port=config.talk_turn_port, talk_media_port_min=config.talk_media_port_min,
        talk_media_port_max=config.talk_media_port_max, talk_relay_port_min=config.talk_relay_port_min,
        talk_relay_port_max=config.talk_relay_port_max,
        no_other_sensitive_udp_services=no_other_sensitive_udp_services, forbidden_peer_ips=forbidden,
        talk_media_hostname=hostname,
    )


@dataclass(frozen=True, repr=False)
class TalkSecrets:
    talk_signaling_secret: str
    talk_turn_secret: str
    talk_session_hashkey: str
    talk_session_blockkey: str

    def __post_init__(self) -> None:
        values = (self.talk_signaling_secret, self.talk_turn_secret, self.talk_session_hashkey)
        if any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for v in values):
            raise TalkError("Talk shared/session secrets require random 64-hex values.")
        if (not isinstance(self.talk_session_blockkey, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32}", self.talk_session_blockkey)):
            raise TalkError("Talk encryption key requires exactly 32 URL-safe ASCII bytes.")
        if len(set(values)) != 3:
            raise TalkError("Talk secrets must be distinct.")


def normalize_secrets(values: Mapping[str, object]) -> TalkSecrets:
    """Accept only the phase subset, never the complete host secret bundle."""
    if not isinstance(values, Mapping) or set(values) != SECRET_KEYS:
        raise TalkError("Talk configure requires exactly its four phase-specific secrets.")
    return TalkSecrets(**values)


# Native packaged paths and service groups, not caller-selected destinations.
# Every generated config is root-owned / service-group-readable mode 0640.
CONFIG_FILES = {
    "/usr/local/etc/ncs/server.conf": ("signaling.conf", "signaling"),
    "/usr/local/etc/nats.conf": ("nats.conf", "nats"),
    "/usr/local/etc/janus/janus.jcfg": ("janus.jcfg", "cloudjanus"),
    "/usr/local/etc/janus/janus.transport.websockets.jcfg": ("websockets.jcfg", "cloudjanus"),
    "/usr/local/etc/janus/janus.eventhandler.wsevh.jcfg": ("events.jcfg", "cloudjanus"),
    "/usr/local/etc/janus/janus.plugin.videoroom.jcfg": ("videoroom.jcfg", "cloudjanus"),
    "/usr/local/etc/turnserver.conf": ("turnserver.conf", "_turnserver"),
}


def render_configs(public: TalkConfig, secrets: TalkSecrets) -> dict[str, str]:
    """Render all configs in memory. Result is SECRET; stdin only, never log it."""
    # Revalidate even typed inputs: no unchecked namespace/duck-typed secret bag.
    if not isinstance(public, TalkConfig) or not isinstance(secrets, TalkSecrets):
        raise TalkError("Validated Talk public settings and secret subset are required.")
    public.__post_init__()
    secrets.__post_init__()
    values = {f.name: getattr(public, f.name) for f in fields(public)}
    values.update({f.name: getattr(secrets, f.name) for f in fields(secrets)})
    denied = [f"denied-peer-ip={n.network_address}-{n.broadcast_address}"
              for n in DENIED_PEER_NETWORKS]
    denied.extend("denied-peer-ip=" + v for v in sorted(set((
        public.talk_public_ip, public.talk_gateway, public.nextcloud_ip,
        *public.forbidden_peer_ips, *((public.office_ip,) if public.office_ip else ()),
    ))))
    values.update(realm=public.realm, denied_peers="\n".join(denied))
    directory = Path(__file__).resolve().parent.parent / "resources/templates/talk"
    return {path: Template((directory / template).read_text(encoding="utf-8")).substitute(values)
            for path, (template, _) in CONFIG_FILES.items()}


def configure_stdin(public: TalkConfig, secrets: TalkSecrets) -> bytes:
    """Bounded fixed-path contents mapping; only configure receives this pipe."""
    result = json.dumps({"schema": 1, "configs": render_configs(public, secrets)},
                        sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(result) > 65536:
        raise TalkError("Talk configure input exceeds its bound.")
    return result


def runtime_public(public: TalkConfig, repository: str, versions: Mapping[str, str]) -> dict[str, object]:
    """F staging envelope; versions must be B's talk-group runtime_versions."""
    from .version_runtime import validate_runtime_versions
    if repository not in ("latest", "quarterly"):
        raise TalkError("Invalid Talk repository.")
    checked = validate_runtime_versions(versions)
    if checked.get("service_profile") != "native-v1" or checked.get("talk_selected") != "yes":
        raise TalkError("Talk runtime requires explicit native-v1 Talk selection.")
    public.__post_init__()
    return {"repository": repository, "versions": checked,
            "talk": public.to_dict()}


def nextcloud_app_config(public: TalkConfig, secrets: TalkSecrets) -> dict[str, object]:
    """SECRET logical settings for a reviewed typed native stdin importer.

    NOT a generic occ config:import wire format. Talk25.0.7 requires sensitive
    typed ARRAY turn_servers, but JSON-text signaling_servers. The importer must
    preserve those native types/sensitivity and verify readback (as D's PHP
    integration-import does), never stringify the TURN list or use secret argv.
    TURN secret feeds Talk's expiring HMAC credentials, not a static browser
    password. Signaling backend certificate verification remains enabled.
    """
    public.__post_init__()
    secrets.__post_init__()
    return {"apps": {"spreed": {
        "signaling_servers": json.dumps({"servers": [{"server": public.signaling_url,
                                                       "verify": True}],
                                          "secret": secrets.talk_signaling_secret}),
        "turn_servers": [{"server": public.turn_authority,
                          "schemes": "turn", "secret": secrets.talk_turn_secret,
                          "protocols": "udp,tcp"}],
    }}}


def check_capabilities(features: object, *, janus_connected: bool) -> tuple[str, ...]:
    """No welcome-only readiness. Actual Janus connection evidence is required.

    This checks already-observed facts, not sockets/media/TURN reachability.
    Parent must obtain janus_connected from the reviewed native SFU probe.
    """
    if not isinstance(features, (list, tuple, set, frozenset)) or any(
        not isinstance(v, str) for v in features
    ):
        raise TalkError("Invalid observed Talk capability list.")
    if not REQUIRED_FEATURES.issubset(features):
        raise TalkError("Required Talk signaling/MCU capability is absent.")
    if janus_connected is not True:
        raise TalkError("Talk Janus media gateway is not confirmed connected.")
    return () if "changed-users" in features else ("Optional signaling feature changed-users is absent.",)


def rc_settings() -> dict[str, dict[str, str]]:
    """Public reviewed rc settings; enable remains NO until parent acceptance.

    rc.subr supplies janus_user/chdir; the packaged rc script otherwise runs
    Janus as root. Precreate /var/log/janus.log for cloudjanus and its private
    runtime directory before starting; do not replace the native rc script.
    """
    return {
        "cloud_talk_runtime": {"cloud_talk_runtime_enable": "NO"},
        # FreeBSD's single -s still opens UDP; double -s has no network socket.
        "syslogd": {"syslogd_flags": "-ss"},
        "nats": {"nats_enable": "NO", "nats_user": "nats", "nats_group": "nats",
                 "nats_options": "-c /usr/local/etc/nats.conf"},
        "janus": {"janus_enable": "NO", "janus_user": "cloudjanus",
                  "janus_chdir": "/var/run/cloud-janus",
                  "janus_config_dir": "/usr/local/etc/janus",
                  "janus_conf": "/usr/local/etc/janus/janus.jcfg"},
        "turnserver": {"turnserver_enable": "NO", "turnserver_user": "_turnserver",
                       "turnserver_group": "_turnserver",
                       "turnserver_config": "/usr/local/etc/turnserver.conf"},
        "ncs_signaling": {"ncs_signaling_enable": "NO",
                          "ncs_signaling_config": "/usr/local/etc/ncs/server.conf"},
    }
