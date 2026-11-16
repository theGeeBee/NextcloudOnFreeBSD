"""Pure, positive-allowlist Apache routing for signaling 2.1.1, never secrets."""

import ipaddress

from .talk import TalkConfig, public_from_config


PREFIX = "/standalone-signaling"
ROOM = r"[A-Za-z0-9_-]{1,255}"


def render_proxy(config, public: TalkConfig) -> str:
    """Include only in the selected NC application vhost; no catch-all proxy.

    Raw request-line validation also rejects encoded separators/traversal before
    a normalized Apache path could match. Room POST authentication remains the
    signaling daemon's HMAC contract; this fragment does not supply credentials.
    """
    config.validate_provisioning()
    if not isinstance(public, TalkConfig) or public != public_from_config(
            config, no_other_sensitive_udp_services=True, forbidden_peer_ips=public.forbidden_peer_ips,
            resolved_address=public.talk_public_ip):
        raise ValueError("Talk proxy public settings differ from the selected instance")
    external = config.tls_mode == "external"
    if config.tls_mode not in ("acme", "provided", "external") or (not external and config.proxy_networks):
        raise ValueError("Talk proxy requires the reviewed direct/external TLS header contract")

    authorization = (
        f"((%{{REQUEST_METHOD}} == 'GET' && %{{REQUEST_URI}} == '{PREFIX}/api/v1/welcome') || "
        f"(%{{REQUEST_METHOD}} == 'POST' && %{{REQUEST_URI}} =~ m#^{PREFIX}/api/v1/room/{ROOM}$#) || "
        f"(%{{REQUEST_METHOD}} == 'GET' && %{{REQUEST_URI}} == '{PREFIX}/spreed' && "
        "tolower(req('Upgrade')) == 'websocket')) && "
        f"(%{{THE_REQUEST}} =~ m#^[A-Z]+ {PREFIX}/(?:spreed|api/v1/welcome|api/v1/room/{ROOM})"
        r"(?:\?[^ \t]*)? HTTP/[0-9.]+$#)"
    )
    headers = "    RequestHeader unset X-Forwarded-For\n"
    if external:
        values = config.trusted_proxy_networks
        networks = [ipaddress.IPv4Network(value, strict=True) for value in values]
        if (not networks or len(networks) > 32 or len(set(networks)) != len(networks)
                or any(n.prefixlen < 24 or n.is_loopback or n.is_multicast or n.is_link_local
                       or n.network_address.is_unspecified for n in networks)):
            raise ValueError("Talk proxy requires narrow explicit external frontend networks")
        peers = " || ".join(f"%{{CONN_REMOTE_ADDR}} -ipmatch '{n}'" for n in networks)
        octet = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
        literal = rf"^(?:(?:{octet}\.){{3}}{octet}|[0-9A-Fa-f]{{0,4}}:[0-9A-Fa-f:]{{1,39}})$"
        # Order matters: reject hostname/chain/whitespace BEFORE DNS-capable
        # Apache -ipmatch. Only the physical, explicitly trusted frontend may
        # submit a single client IP; it must overwrite outside XFF itself.
        authorization += (f" && ({peers}) && (req('X-Forwarded-For') =~ m#{literal}#) && "
                          "((req('X-Forwarded-For') -ipmatch '0.0.0.0/0') || "
                          "(req('X-Forwarded-For') -ipmatch '::/0'))")
        headers = ""
    else:
        headers += '    RequestHeader set X-Forwarded-For "expr=%{CONN_REMOTE_ADDR}"\n'

    return (
        '# Include only inside the selected Nextcloud application VirtualHost.\n'
        f'<LocationMatch "^{PREFIX}(?:/|$)">\n'
        '    ProxyPreserveHost On\n'
        '    ProxyAddHeaders Off\n'
        '    RequestHeader unset Forwarded\n'
        '    RequestHeader unset X-Real-IP\n'
        '    RequestHeader unset X-Client-IP\n'
        '    RequestHeader unset Client-IP\n'
        '    RequestHeader unset True-Client-IP\n'
        '    RequestHeader unset CF-Connecting-IP\n'
        + headers + f'    Require expr "{authorization}"\n'
        '</LocationMatch>\n'
        # Exact WebSocket rule FIRST. No prefix ProxyPass can reach stats,
        # serverinfo, metrics, debug or the daemon's TURN credentials API.
        # Apache appends the original URI when the target has no backreference.
        # Capture only these fixed allowlisted paths to preserve exact mapping.
        f'ProxyPassMatch "^{PREFIX}/(spreed)$" "ws://{public.talk_ip}:8080/$1"\n'
        f'ProxyPassMatch "^{PREFIX}/(api/v1/welcome)$" "http://{public.talk_ip}:8080/$1"\n'
        f'ProxyPassMatch "^{PREFIX}/api/v1/room/({ROOM})$" "http://{public.talk_ip}:8080/api/v1/room/$1"\n'
    )
