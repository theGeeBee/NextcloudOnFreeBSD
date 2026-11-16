"""Render selected isolated jail topologies; never configure the host here."""

import ipaddress


def _talk_ranges(config):
    return ((config.talk_media_port_min, config.talk_media_port_max),
            (config.talk_relay_port_min, config.talk_relay_port_max))


def _talk_address(config, talk_addresses):
    """Consume a prepared observation, never resolve or read deployment state."""
    from .config import validate_talk_public_ip
    value = ((talk_addresses or {}).get(config.instance) if config.talk_media_hostname
             else config.talk_public_ip)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Missing prepared Talk address for {config.instance}")
    return validate_talk_public_ip(value, live=bool(config.talk_media_hostname))


def _talk_rules(config, configs, talk_addresses):
    """Host transit only: same-jail coturn/Janus traffic does NOT cross PF."""
    c = config
    talk, bridge = c.talk_ip, c.talk_bridge
    pair = f"{{ {c.nextcloud_bridge}, {bridge} }}"
    lines = [f"# Instance {c.instance} Talk (same-jail TURN peers require service ACLs)",
             f"pass quick on {pair} inet proto tcp from {c.nextcloud_ip} to {talk} port 8080 flags S/SA keep state"]
    if c.tls_mode != "external":
        # The NC-IP-bound private TLS listener preserves the saved public
        # authority for strict backend callbacks, independently of host DNAT443.
        lines.append(f"pass quick on {pair} inet proto tcp from {talk} to {c.nextcloud_ip} port {c.public_https_port} flags S/SA keep state")
    else:
        lines.append(f"pass in quick on {bridge} inet proto tcp from {talk} to {c.frontend_callback_address} port {c.public_https_port} flags S/SA keep state")
    lines.extend([
        f"pass in quick on {bridge} inet proto {{ udp, tcp }} from {talk} to {c.dns_server} port 53 keep state",
         f"block in quick on {bridge} inet from any to (self)",
        f"block in quick on {bridge} inet from {talk} to <cloud_noninternet>"])
    # Supplement the legacy table without changing its bytes/meaning for existing
    # instances or introducing a new mutable table outside committed snapshots.
    denied = ["192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15",
              "198.51.100.0/24", "203.0.113.0/24"]
    for item in configs:
        denied.extend((item.management_network, item.ingress_address))
        if item.frontend_callback_address or item.dns_address:
            denied.append(item.frontend_callback_address or item.dns_address)
        if item.talk:
            denied.append(_talk_address(item, talk_addresses))
    destinations = ", ".join(dict.fromkeys(denied))
    lines.extend([
        f"block in quick on {bridge} inet from {talk} to {{ {destinations} }}",
        f"pass in quick on {bridge} inet proto tcp from {talk} to ! <cloud_noninternet> port {{ 80, 443 }} flags S/SA keep state"])
    for low, high in _talk_ranges(c):
        lines.append(f"pass in quick on {bridge} inet proto udp from {talk} port {low}:{high} to ! <cloud_noninternet> keep state")
    for protocol, ports in (("tcp", str(c.talk_turn_port)),
                            ("udp", str(c.talk_turn_port)),
                            *(("udp", f"{low}:{high}") for low, high in _talk_ranges(c))):
        flags = " flags S/SA" if protocol == "tcp" else ""
        lines.extend([
            f"pass in quick on $ext_if inet proto {protocol} from any to {talk} port {ports}{flags} keep state",
            f"pass out quick on {bridge} inet proto {protocol} from any to {talk} port {ports}{flags} keep state received-on $ext_if"])
    lines.extend([
        f"pass out quick on {bridge} inet proto icmp from ({bridge}) to {talk} icmp-type unreach code needfrag no state",
        f"pass out quick on {bridge} inet proto tcp from {c.talk_gateway} to {talk} port 8080 flags S/SA keep state"])
    return lines


def pf_rules(config, ssh_connection=None, *, host_config=None, talk_addresses=None):
    """Render only the project anchor for all managed instances.
    Integrated instances have two routed /30 segments;
    Nextcloud-only instances have one, with no office allowances.
    """
    configs = list(config) if isinstance(config, (list, tuple)) else [config]
    configs = sorted((item.validate() for item in configs), key=lambda item: item.instance)
    c = (host_config or (configs[0] if configs else None))
    if c is None:
        raise ValueError("A host configuration is required even when removing the last instance")
    c.validate()
    for item in configs:
        if item.talk:
            _talk_address(item, talk_addresses)
        peers = [item.dns_server] if item.talk else []
        if item.has_native_services and item.tls_mode == "external" and item.frontend_callback_address:
            peers.append(item.frontend_callback_address)
            if any(item.frontend_callback_address == other.ingress_address for other in configs):
                raise ValueError("Native services require a separate external HTTPS frontend, not managed host ingress")
        if any(ipaddress.IPv4Address(peer) in other.network for peer in peers for other in configs):
            raise ValueError("Talk DNS/external frontend must not route into any managed instance network")
    addresses = ", ".join(endpoint.ip for item in configs for endpoint in item.network_endpoints)
    # Snapshots/boot guards query both tables even after the last instance is
    # removed. PF may discard an unreferenced table unless it is persistent.
    lines = ["# nextcloudonfreebsd anchor; no physical uplink is bridged.",
             f'ext_if = "{c.external_interface}"', f"table <cloud_jails> const persist {{ {addresses} }}",
              "table <cloud_noninternet> const persist { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }"]
    # FreeBSD 15.1 pf.conf(5): the FIRST matching translation wins. Preserve
    # only the approved UDP source intervals, before the legacy generic NAT.
    for item in configs:
        if item.talk:
            for low, high in _talk_ranges(item):
                # Host admission verifies this assigned ingress address. Using
                # the interface primary would collapse distinct alias/public
                # mappings whose approved UDP intervals may intentionally match.
                lines.append(f"nat on $ext_if inet proto udp from {item.talk_ip} port {low}:{high} to ! <cloud_noninternet> -> {item.ingress_address} static-port")
    if configs:
        lines.append("nat on $ext_if inet from <cloud_jails> to any -> ($ext_if:0)")
    # PF translation rules precede every filter rule.
    for item in configs:
        source = "{ " + ", ".join(item.trusted_proxy_networks) + " }" if item.tls_mode == "external" else "any"
        lines.append(f"rdr on $ext_if inet proto tcp from {source} to {item.ingress_address} port {item.http_port} -> {item.nextcloud_ip} port 80")
        if item.tls_mode != "external":
            lines.append(f"rdr on $ext_if inet proto tcp from any to {item.ingress_address} port {item.https_port} -> {item.nextcloud_ip} port 443")
        if item.talk:
            for protocol in ("tcp", "udp"):
                lines.append(f"rdr on $ext_if inet proto {protocol} from any to {item.ingress_address} port {item.talk_turn_port} -> {item.talk_ip} port {item.talk_turn_port}")
            for low, high in _talk_ranges(item):
                # A single target port collapses the range. low:* preserves
                # its offset, including the inclusive high endpoint.
                lines.append(f"rdr on $ext_if inet proto udp from any to {item.ingress_address} port {low}:{high} -> {item.talk_ip} port {low}:*")
        if item.jail_ssh:
            endpoints = [(item.nextcloud_ip, item.ssh_nextcloud_port)]
            if item.native_office:
                endpoints.append((item.onlyoffice_ip, item.ssh_onlyoffice_port))
            for address, port in endpoints:
                lines.append(f"rdr on $ext_if inet proto tcp from {item.management_network} to {item.ingress_address} port {port} -> {address} port 22")
    # Anti-spoofing precedes every project quick pass.
    for item in configs:
        lines.extend([f"block in quick on $ext_if inet from {item.private_network} to any",
                      f"block in quick on {item.nextcloud_bridge} inet from ! {item.nextcloud_ip} to any"])
        if item.has_office:
            lines.extend([
                      f"block in quick on {item.onlyoffice_bridge} inet from ! {item.onlyoffice_ip} to any",
                      f"block quick on {{ {item.nextcloud_bridge}, {item.onlyoffice_bridge} }} inet6 all"])
        else:
            lines.append(f"block quick on {item.nextcloud_bridge} inet6 all")
        if item.talk:
            lines.extend([f"block in quick on {item.talk_bridge} inet from ! {item.talk_ip} to any",
                          f"block quick on {item.talk_bridge} inet6 all"])
    for item in configs:
        nc, nb = item.nextcloud_ip, item.nextcloud_bridge
        source = "{ " + ", ".join(item.trusted_proxy_networks) + " }" if item.tls_mode == "external" else "any"
        public_ports = "80" if item.tls_mode == "external" else "{ 80, 443 }"
        if item.has_native_services and item.tls_mode == "external" and item.frontend_callback_address:
            # This precedes the NC self/private egress denial, but grants only
            # the explicitly configured frontend socket, never proxy CIDRs.
            lines.append(f"pass in quick on {nb} inet proto tcp from {nc} to {item.frontend_callback_address} port {item.public_https_port} flags S/SA keep state")
        if item.has_office:
            oo, ob = item.onlyoffice_ip, item.onlyoffice_bridge
            lines.append(f"# Instance {item.instance}")
            if item.native_office:
                lines.extend([f"block quick inet proto tcp from any to {oo} port {{ 8000, 8126 }}",
                              f"block quick inet proto udp from any to {oo} port 8125"])
            lines.extend([
                      f"pass in quick on $ext_if inet proto tcp from {source} to {nc} port {public_ports} flags S/SA keep state",
                      f"pass out quick on {nb} inet proto tcp from {source} to {nc} port {public_ports} flags S/SA keep state received-on $ext_if",
                      f"pass quick on {{ {nb}, {ob} }} inet proto tcp from {nc} to {oo} port 8081 flags S/SA keep state",
                      f"pass quick on {{ {nb}, {ob} }} inet proto tcp from {oo} to {nc} port {item.callback_port} flags S/SA keep state",
                      f"pass in quick on {{ {nb}, {ob} }} inet proto {{ udp, tcp }} from {{ {nc}, {oo} }} to {item.dns_server} port 53 keep state",
                       f"block in quick on {{ {nb}, {ob} }} inet from any to (self)",
                      f"pass in quick on {{ {nb}, {ob} }} inet proto tcp from {{ {nc}, {oo} }} to ! <cloud_noninternet> port {{ 80, 443 }} flags S/SA keep state"])
        else:
            lines.extend([f"# Instance {item.instance} (Nextcloud only)",
                          f"pass in quick on $ext_if inet proto tcp from {source} to {nc} port {public_ports} flags S/SA keep state",
                          f"pass out quick on {nb} inet proto tcp from {source} to {nc} port {public_ports} flags S/SA keep state received-on $ext_if",
                          f"pass in quick on {nb} inet proto {{ udp, tcp }} from {nc} to {item.dns_server} port 53 keep state",
                           f"block in quick on {nb} inet from any to (self)",
                          f"pass in quick on {nb} inet proto tcp from {nc} to ! <cloud_noninternet> port {{ 80, 443 }} flags S/SA keep state"])
        if item.mail_client:
            lines.append("# Explicit Mail selection: outbound secure mailbox ports, Nextcloud only")
            lines.append(f"pass in quick on {nb} inet proto tcp from {nc} to ! <cloud_noninternet> port {{ 465, 587, 993 }} flags S/SA keep state")
        if item.talk:
            lines.extend(_talk_rules(item, configs, talk_addresses))
            if item.tls_mode != "external" and item.public_https_port != 443:
                # Read-only host probe of the private listener: exact source,
                # destination and port; never add it to public ingress ports.
                lines.append(f"pass out quick on {nb} inet proto tcp from {item.nextcloud_gateway} to {nc} port {item.public_https_port} flags S/SA keep state")
        endpoints = [(nb, nc, item.nextcloud_gateway, public_ports)]
        if item.has_office:
            endpoints.append((ob, oo, item.onlyoffice_gateway, "8081"))
        for bridge, address, gateway, ports in endpoints:
            lines.extend([f"pass out quick on {bridge} inet proto icmp from ({bridge}) to {address} icmp-type unreach code needfrag no state",
                          f"pass out quick on {bridge} inet proto tcp from {gateway} to {address} port {ports} flags S/SA keep state"])
            if item.jail_ssh and (address == nc or item.native_office):
                lines.extend([f"pass in quick on $ext_if inet proto tcp from {item.management_network} to {address} port 22 flags S/SA keep state",
                              f"pass out quick on {bridge} inet proto tcp from {item.management_network} to {address} port 22 flags S/SA keep state received-on $ext_if",
                               f"pass out quick on {bridge} inet proto tcp from {gateway} to {address} port 22 flags S/SA keep state"])
            if item.has_office and not item.native_office and address == oo:
                lines.append(f"pass out quick on {bridge} inet proto tcp from {gateway} to {address} port 22 flags S/SA keep state")
    for item in configs:
        # Outbound NAT has already changed the source. received-on binds this
        # second interface's state to an admitted endpoint. Repeat only that
        # endpoint's approved egress, never a host-wide uplink allowance.
        for endpoint in item.network_endpoints:
            prefix = "pass out quick on $ext_if inet"
            suffix = f" keep state received-on {endpoint.bridge}"
            dns_source = (f"{{ ($ext_if:0), {item.ingress_address} }}"
                          if item.talk and endpoint.ip == item.talk_ip else "($ext_if:0)")
            lines.extend([
                f"{prefix} proto {{ udp, tcp }} from {dns_source} to {item.dns_server} port 53{suffix}",
                f"{prefix} proto tcp from ($ext_if:0) to ! <cloud_noninternet> port {{ 80, 443 }} flags S/SA{suffix}"])
            if endpoint.ip == item.nextcloud_ip and item.mail_client:
                lines.append(f"{prefix} proto tcp from ($ext_if:0) to ! <cloud_noninternet> port {{ 465, 587, 993 }} flags S/SA{suffix}")
            if (item.has_native_services and item.tls_mode == "external" and item.frontend_callback_address
                    and endpoint.ip in (item.nextcloud_ip, item.talk_ip)):
                lines.append(f"{prefix} proto tcp from ($ext_if:0) to {item.frontend_callback_address} port {item.public_https_port} flags S/SA{suffix}")
            if item.talk and endpoint.ip == item.talk_ip:
                for low, high in _talk_ranges(item):
                    lines.append(f"{prefix} proto udp from {item.ingress_address} port {low}:{high} to ! <cloud_noninternet>{suffix}")
    # Optional storage/custom egress follows the narrow built-in service flows,
    # but precedes the final default deny. Every new allowance has BOTH legs:
    # the jail bridge and the interface-bound post-NAT uplink evaluation.
    protected = ", ".join(item.private_network for item in configs)
    for item in configs:
        if not (item.external_storage or item.custom_egress):
            continue
        nb, nc = item.nextcloud_bridge, item.nextcloud_ip
        scopes = (f"in quick on {nb} inet from {nc}",
                  f"out quick on $ext_if inet from ($ext_if:0)")
        for index, scope in enumerate(scopes):
            received = f" received-on {nb}" if index else ""
            lines.append(f"block {scope} to (self){received}")
            lines.append(f"block {scope} to {{ {protected} }}{received}")
            lines.append(f"block {scope} to {{ 0.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }}{received}")
        if item.external_storage:
            ports = ["22", "80", "443"]
            if item.external_storage_smb:
                ports.append("445")
            if item.external_storage_ftp:
                ports.extend(("21", "990", "1024:65535"))
            for index, scope in enumerate(scopes):
                received = f" received-on {nb}" if index else ""
                # Insert proto before from, preserving native PF grammar.
                scope = scope.replace(" inet from", " inet proto tcp from")
                lines.append(f"pass {scope} to {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} port {{ {', '.join(ports)} }} flags S/SA keep state{received}")
                lines.append(f"pass {scope} to ! <cloud_noninternet> port 22 flags S/SA keep state{received}")
        if item.custom_egress:
            lines.extend([
                f'anchor "admin-{item.instance}" in quick on {nb} inet from {nc} to any',
                f'anchor "admin-{item.instance}" out quick on $ext_if inet from ($ext_if:0) to any received-on {nb}'])
    for item in configs:
        bridges = "{ " + ", ".join(endpoint.bridge for endpoint in item.network_endpoints) + " }"
        lines.extend([f"block quick on {bridges} all",
                      f"block quick inet from {item.private_network} to any",
                      f"block quick inet from any to {item.private_network}"])
        # The post-NAT form no longer carries the private source address.
        # Keep unapproved transit from falling through to a permissive parent.
        for endpoint in item.network_endpoints:
            lines.append(f"block out quick on $ext_if all received-on {endpoint.bridge}")
    # Explicit per-rule state/drop policy; anchor loading cannot set globals.
    # FreeBSD's label optimization barrier also keeps reboot snapshots stable
    # when the administrator loads the parent using a different optimizer mode.
    return "\n".join(line.replace("keep state", "keep state (if-bound)")
                     .replace("block ", "block drop ")
                     + (f' label "ncof-{index}"' if line.startswith(("pass ", "block ")) else "")
                     for index, line in enumerate(lines)) + "\n"


def boot_network_script(state_root):
    """Owned early rc hook; rc.conf/loader/sysctl remain administrator-owned."""
    import shlex
    active = shlex.quote(str(state_root / "network/active"))
    return f'''#!/bin/sh
# PROVIDE: cloud_network
# REQUIRE: FILESYSTEMS netif routing
# BEFORE: pf
# KEYWORD: nojail
. /etc/rc.subr
name=cloud_network
rcvar=cloud_network_enable
start_cmd=cloud_network_start
stop_cmd=:
cloud_network_start() {{
    active={active}
    # A cancelled first transaction has no committed boot network.
    [ -e "$active" ] || [ -L "$active" ] || return 0
    /usr/local/bin/python3 -I -B "$active/firewall-watchdog.py" boot-bridges "$active"
}}
load_rc_config "$name"
: ${{cloud_network_enable:=YES}}
run_rc_command "$1"
'''


def storage_guard(config, storage, state_root=None, *, lifecycle=True):
    """Jail exec.prepare guard: validate policy and storage BEFORE nullfs mounts."""
    from .config import STATE_DIR, datasets
    root = state_root or STATE_DIR
    active = root / "network/active"
    c = config
    storage = tuple(storage)
    if c.talk:
        expected = {(item.name, item.mountpoint, item.jail, item.target)
                    for item in datasets(c) if item.jail == c.talk_jail}
        actual = {(item.name, item.mountpoint, item.jail, item.target)
                  for item in storage if item.jail == c.talk_jail}
        if actual != expected:
            raise ValueError("Talk prepare guard requires the complete exact owned Talk dataset set")
    lines = ["#!/bin/sh", "set -eu", f'[ -f "{root}/instances/{c.instance}/allow-start" ] || exit 1',
              f'[ -f "{active}/firewall-confirmed" ] || exit 1',
              '/usr/local/etc/rc.d/cloud_jails_guard onestatus || exit 1',
              f'/usr/local/bin/python3 -I -B "{active}/firewall-watchdog.py" check-parent "{active}" || exit 1']
    # Optional for unenrolled hosts; fail closed once lifecycle state exists.
    # Enrollment also installs a separate wrapper around historical guards.
    from .paths import PROJECT_ROOT
    from .maintenance import executor_identity
    import shlex
    program = ("import sys; sys.path.insert(0, sys.argv[1]); "
               "from installer.maintenance import boot_check; "
               "boot_check(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])")
    lifecycle_lines = [f'if [ -e "{root}/lifecycle" ] || [ -L "{root}/lifecycle" ] || '
                  f'[ -e "{root}/maintenance/pending.json" ] || [ -L "{root}/maintenance/pending.json" ]; then',
                  "    /usr/local/bin/python3 -I -B -c " + shlex.quote(program) + " "
                  + " ".join(shlex.quote(str(value)) for value in (PROJECT_ROOT, root, c.instance))
                  + ' "${1:-}" ' + shlex.quote(executor_identity()) + " || exit 1", "fi"]
    if lifecycle:
        lines[2:2] = lifecycle_lines
    for name, args in (("filter", "-sr"), ("nat", "-sn"),
                       ("jails", "-t cloud_jails -T show"), ("noninternet", "-t cloud_noninternet -T show")):
        lines.extend([f'active=$(/sbin/pfctl -a nextcloudonfreebsd {args}) || exit 1',
                      f'[ "$active" = "$(/bin/cat {active}/pf-{name}.expected)" ] || exit 1'])
    for name, value in (("net.inet.ip.forwarding", "1"), ("net.link.bridge.pfil_bridge", "1"),
                        ("net.link.bridge.pfil_member", "0"), ("net.link.bridge.pfil_local_phys", "0"),
                        ("net.link.bridge.pfil_onlyip", "1")):
        lines.append(f'[ "$(/sbin/sysctl -n {name})" = {value} ] || exit 1')
    endpoints = [(endpoint.bridge, endpoint.gateway, endpoint.name) for endpoint in c.jail_endpoints]
    for bridge, gateway, jail in endpoints:
        lines.append(f"/sbin/ifconfig {bridge} | /usr/bin/awk '$1 == \"inet\" && $2 == \"{gateway}\" {{ found=1 }} $1 == \"member:\" && $2 != \"e0a_{jail}\" {{ foreign=1 }} END {{ exit !found || foreign }}' || exit 1")
    if c.has_office and not c.native_office:
        name=c.instance+'office'
        lines.extend([
            f"members=$(/sbin/ifconfig {c.onlyoffice_bridge} | /usr/bin/awk '$1 == \"inet\" && $2 == \"{c.onlyoffice_gateway}\" {{ found=1 }} $1 == \"member:\" {{ count++; print $2 }} END {{ exit !found || count > 1 }}') || exit 1",
            'if [ -n "$members" ]; then',
            '    case "$members" in tap*) number=${members#tap} ;; *) exit 1 ;; esac',
            '    case "$number" in ""|*[!0-9]*) exit 1 ;; esac',
            f"    /sbin/ifconfig \"$members\" | /usr/bin/awk '$1 == \"description:\" && $2 == \"vmnet/{name}/0/{name}\" {{ found=1 }} END {{ exit !found }}' || exit 1",
            'fi'])
    lines.append('case "${1:-}" in')
    for jail in config.jails:
        lines.append(f"{jail})")
        targets = [(item.name, item.mountpoint) for item in storage if item.jail == jail]
        targets.append((f"{c.bastille_dataset}/jails/{jail}/root", f"{c.bastille_root}/jails/{jail}/root"))
        for name, mountpoint in targets:
            lines.extend([
                f'    [ "$(/sbin/zfs get -H -o value mounted {name})" = yes ] || exit 1',
                f'    [ "$(/sbin/zfs get -H -o value org.cloud-installer:instance {name})" = "{c.instance}" ] || exit 1',
                f'    [ "$(/sbin/zfs get -H -o value mountpoint {name})" = "{mountpoint}" ] || exit 1',
                f'    [ "$(/bin/realpath {mountpoint})" = "{mountpoint}" ] || exit 1',
                f"    /sbin/mount -p | /usr/bin/awk '$1 == \"{name}\" && $2 == \"{mountpoint}\" && $3 == \"zfs\" {{ found=1 }} END {{ exit !found }}' || exit 1",
                f"    /bin/df -P {mountpoint} | /usr/bin/awk 'NR == 2 && $1 == \"{name}\" {{ found=1 }} END {{ exit !found }}' || exit 1",
            ])
        lines.append("    ;;")
    lines.extend(["*) exit 1 ;;", "esac", ""])
    return "\n".join(lines)
