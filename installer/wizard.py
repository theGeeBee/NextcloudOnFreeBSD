"""Interactive configuration; configuration remains data, never shell code."""

from dataclasses import replace
import ipaddress
import secrets
import sys

from .config import (COMPREHENSIVE_FONT_ESTIMATE, DEFAULT_NEXTCLOUD_APPS, DEFAULT_ONLYOFFICE_PLUGINS, NEXTCLOUD_APP_CHOICES, MAIL_CLIENT_CHOICES,
                     Config, OFFICE_BACKENDS, OFFICE_LABELS, PLUGIN_CHOICES, QUOTA_FIELDS, deployment_plan, storage_summary,
                      validate_nextcloud_apps, validate_plugin_selection)
from .config import IngressBinding, TALK_FIELDS, binding_conflicts, ingress_bindings, ingress_conflicts
from .ui import TerminalUI


def ask(label, default="", convert=str, *, ui=None):
    ui = ui or TerminalUI()
    while True:
        try:
            return convert(ui.input(label, default))
        except (ValueError, TypeError) as error:
            ui.message(f"Invalid value: {error}")


def choose(label, choices, default, *, ui=None):
    return (ui or TerminalUI()).menu(label, [(choice, choice) for choice in choices], default)


def confirm(label, *, ui=None):
    return (ui or TerminalUI()).confirm(label)


def identity_options(config, *, ui):
    """Shared by the wizard and read-only native UI fixtures."""
    from .region_ui import country_label
    return ui.menu("Identity and software", [
        ("continue", "Continue"),
        ("country", "Country / default phone region"),
        ("timezone", "Timezone"),
        ("hostnames", "Advanced jail hostnames"),
        ("software", "Advanced software settings"),
    ], "continue", text=(
        f"Country: {country_label(config.default_phone_region)}\n"
        f"Timezone: {config.timezone}\n"
        f"Nextcloud: {config.nextcloud_exact or config.version_families.get('nextcloud', 'default')}; "
        f"PHP: {config.version_families.get('php', 'default')}; "
        f"MariaDB: {config.version_families.get('database', 'default')}\n"
        f"FreeBSD-ports: {config.repository}"))


def edit_region(config, action, *, ui):
    from .region_ui import select_country, select_timezone
    if action == "country":
        value = select_country(config.default_phone_region, ui=ui)
        config.default_phone_region = value
    elif action == "timezone":
        value = select_timezone(config.timezone, ui=ui)
        config.timezone = value
    else:
        raise ValueError("Unknown regional setting")
    # Commit only after the selector returns; Cancel/Escape leave the draft intact.
    config.nextcloud_defaults = "v1"


def version_family_choices(config, policy=None):
    """The old prompt defaults, shared by common and advanced paths."""
    from .versions import load_policy, selected_profiles, stable_version
    policy = load_policy() if policy is None else policy
    profiles = selected_profiles(config, policy)
    def lower(rule):
        return rule.get("exact", rule.get("min", rule.get("family")))

    profile = max(profiles, key=lambda item: stable_version(
        lower(item["applications"]["nextcloud"])))
    choices = [("nextcloud", "Nextcloud", profile["applications"]["nextcloud"], 1),
               ("php", "PHP", profile["roles"]["php"]["range"], 2),
               ("database", "Database", profile["roles"]["database"]["range"], 2)]
    if config.native_office and not config.has_native_services:
        choices.append(("onlyoffice", "ONLYOFFICE", profile["applications"]["onlyoffice"], 2))
    return [(key, label, rule.get("family", ".".join(lower(rule).split(".")[:components])))
            for key, label, rule, components in choices]


def materialize_software_defaults(config):
    from .versions import constraints, load_policy
    effective = constraints(config, load_policy())
    selected = dict(config.version_families)
    selected.pop("connector", None)
    for key, _, default in version_family_choices(config):
        selected.setdefault(key, default)
    config.version_families = selected
    for name in (("nextcloud_min",) if config.has_native_services else ("nextcloud_min", "onlyoffice_min")):
        if name != "onlyoffice_min" or config.native_office:
            setattr(config, name, effective[name])
    config.freebsd_release, config.architecture = config.release, config.arch


def select_version_families(config, *, ui, policy=None, preserve_missing=False):
    """Edit families; grouped drafts materialize defaults only at initialization.

    Standalone historical callers retain their policy-default prompt contract.
    An absent family in an already initialized draft is an explicit omission,
    not permission to fill the choice again when reopening Advanced.
    """
    if config.has_native_services:
        return select_software_versions(config, ui=ui, policy=policy, preserve_missing=preserve_missing)
    from .versions import validate_families
    selected = dict(config.version_families)
    selected.pop("connector", None)  # Native occ, not the installer, selects apps.
    ui.message(("Package flavors select versioned names, not version locks; '-' clears a choice. "
                "Native pkg chooses package versions and dependencies. Nextcloud release assertions remain separate."
                if config.has_native_services else
                "Version families select a stable major or major.minor line; '-' clears a choice. "
                "Minimums and exact pins still apply. Other roles/packages can be selected in JSON recipes."))
    for key, label, proposed in version_family_choices(config, policy):
        default = selected.get(key, "" if preserve_missing else proposed)

        def family(value):
            if value in ("", "-"):
                return ""
            return validate_families({key: value})[key]

        prompt = " package flavor" if config.has_native_services and key in ("php", "database") else " version family"
        value = ask(label + prompt, default, family, ui=ui)
        if value:
            selected[key] = value
        else:
            selected.pop(key, None)
    config.version_families = selected


def select_software_versions(config, *, ui, policy=None, preserve_missing=False):
    """One fresh-install form; numeric selections are not compatibility gates."""
    from .versions import NUMBER, TRIPLE, text, validate_families
    defaults = dict((key, value) for key, _, value in version_family_choices(
        replace(config, version_families={}, nextcloud_exact="", nextcloud_min=""), policy))
    selected = dict(config.version_families)
    selected.pop("connector", None)
    previous_nc = config.nextcloud_exact or selected.get("nextcloud", "")
    values = {key: selected.get(key, "" if preserve_missing else defaults[key])
              for key in ("nextcloud", "php", "database")}
    values["nextcloud"] = config.nextcloud_exact or values["nextcloud"]
    labels = (("nextcloud", "Nextcloud version"), ("php", "PHP package flavor"),
              ("database", "MariaDB package flavor"))
    context = ("Tested defaults are editable, not restrictions. Other combinations are untested; "
               "installation is attempted normally. You handle compatibility/debugging.")
    help_text = ("Nextcloud: major/minor selects the newest stable release in that family; "
                 "three components select that exact stable release (for example 36, 36.0 or 36.0.1). "
                 "PHP 8.6 selects php86 and matching modules; MariaDB 11.4 selects "
                 "mariadb114-server/client. These are examples, not availability claims. "
                 "Native pkg selects package versions. Blank or '-' uses the default selection. "
                 "No fallback or compatibility guarantee. Existing minimum assertions are cleared "
                 "when you change the Nextcloud selection.")
    error_text = ""
    while True:
        values = grouped_fields(ui, "Nextcloud and package flavors",
                                [(key, label, values[key]) for key, label in labels],
                                text=context + error_text, help_text=help_text)
        try:
            candidate = dict(selected)
            exact = ""
            for key, _ in labels:
                value = "" if values[key] == "-" else values[key]
                candidate.pop(key, None)
                if not value:
                    continue
                if key == "nextcloud" and value.count(".") == 2:
                    text(value, TRIPLE, "Nextcloud exact stable release")
                    exact = value
                else:
                    if key != "nextcloud":
                        text(value, r"[1-9][0-9]*\." + NUMBER, "PHP/MariaDB package flavor (major.minor)")
                    candidate[key] = validate_families({key: value})[key]
        except (ValueError, TypeError) as error:
            error_text = f"\nInvalid value: {error}. Correct these entries; other values are retained."
            continue
        current_nc = exact or candidate.get("nextcloud", "")
        if current_nc != previous_nc:
            config.nextcloud_min = ""
        config.nextcloud_exact = exact
        config.version_families = candidate
        return


def select_onlyoffice_plugins(value="", *, ui=None):
    ui = ui or TerminalUI()
    selected = set(validate_plugin_selection(value))
    all_plugins = {slug for slug, _, _ in PLUGIN_CHOICES}
    context = ("Optional ONLYOFFICE plugins do not autostart. External providers may receive selected content "
               "when invoked; accounts/API keys are configured separately. Installation does not establish service functionality.\n"
               "WordPress sends OAuth credentials/tokens and article content through an ONLYOFFICE-hosted proxy.\n"
               "EasyBib is discontinued/unavailable. Macros is built-in, not a standalone plugin.")
    standard = set(DEFAULT_ONLYOFFICE_PLUGINS.split(","))
    default = "all" if selected == all_plugins else "standard" if selected == standard else "custom" if selected else "none"
    action = ui.menu("ONLYOFFICE plugins", [("none", "None"), ("standard", "Standard (9)"), ("all", "All (10)"),
                                           ("custom", "Choose individually")], default, text=context)
    if action == "none":
        return ""
    if action == "standard":
        return DEFAULT_ONLYOFFICE_PLUGINS
    if action == "all":
        return ",".join(sorted(all_plugins))
    if action != "custom":
        raise ValueError("Unknown ONLYOFFICE plugin selection")
    selected = ui.checklist("Choose individual ONLYOFFICE plugins",
                            [(slug, name) for slug, name, _ in PLUGIN_CHOICES], sorted(selected),
                            text=context, help_text="\n".join(f"{name}: {summary}" for _, name, summary in PLUGIN_CHOICES))
    return ",".join(sorted(validate_plugin_selection(",".join(selected))))


def select_nextcloud_apps(value, *, ui):
    selected = set(validate_nextcloud_apps(value))
    mail_client = "snappymail" if "snappymail" in selected else "mail"
    if "snappymail" in selected:
        selected.remove("snappymail")
        selected.add("mail")
    all_apps = {slug for slug, _ in NEXTCLOUD_APP_CHOICES}
    details = ("Nextcloud installs/enables selected apps through occ; no separate app feature tests. "
               "Mail offers Nextcloud Mail (default) or SnappyMail, not both. "
               "Either permits NC-jail outbound public TCP 993/465/587 (IMAPS/SMTP submission); "
               "configure accounts afterward. No inbound mail server or system SMTP. "
               "Fresh native-v1 installs always include Client Push, independently of these 8 apps. "
               "Selecting Talk adds a dedicated HPB + coturn jail, 2048 MiB planning allowance and explicit public media forwarding. "
               "Antivirus includes ClamAV and is log-only, not blocking/deletion; adds 3072 MiB RAM planning headroom.")
    default = "all" if selected == all_apps else "custom" if selected else "none"
    context = ("Setup 1/8 — Applications. Client Push is mandatory.\n"
               "Talk: dedicated HPB/TURN jail; +2048 MiB; public media forwarding.\n"
               "Antivirus: +3072 MiB; log-only (no blocking/deletion).\n"
               "Mail: NC outbound public TCP 993/465/587 only; no inbound/system SMTP.")
    while True:
        action = ui.menu("Nextcloud apps", [("all", "All 8 selections"), ("none", "None"),
                                          ("custom", "Choose individually"), ("details", "Application details")], default, text=context)
        if action != "details":
            break
        ui.details("Application details", details)
    if action == "all":
        selected = all_apps
    elif action == "none":
        return "none" if value else ""
    elif action == "custom":
        selected = set(ui.checklist("Choose individual Nextcloud apps", list(NEXTCLOUD_APP_CHOICES),
                                   sorted(selected), text=context, help_text=details))
    else:
        raise ValueError("Unknown Nextcloud app selection")
    if "mail" in selected:
        mail_client = ui.menu("Mail client", list(MAIL_CLIENT_CHOICES), mail_client,
                              text="Choose one webmail app. Configure mail domains/accounts after installation.\n"
                                   "NC outbound public TCP 993/465/587 only; no inbound mail server or system SMTP.")
        if mail_client not in dict(MAIL_CLIENT_CHOICES):
            raise ValueError("Unknown mail client")
        selected.remove("mail")
        selected.add(mail_client)
    return ",".join(validate_nextcloud_apps(",".join(sorted(selected)))) or "none"


def service_memory(config):
    return config.memory_budget_mb - config.host_reserved_mb


def select_external_storage(config, *, ui):
    """Separate opt-in: ordinary app presets never enable storage egress."""
    # Do not silently clear deferred selections from an existing draft.
    config.require_fresh_storage_eligible()
    enabled = ui.menu("External files", [("off", "Disabled"), ("on", "Enable external files")],
                      "on" if config.external_storage else "off",
                      text="Optional administrator-configured storage mounts. SFTP and HTTP/HTTPS on standard ports; "
                           "LAN access excludes this host and managed instance networks. No mounts or credentials are created.")
    if enabled not in ("off", "on"):
        raise ValueError("Unknown external files selection")
    config.external_storage = enabled == "on"


def remaining_memory(facts, registered, reserve):
    return facts["memory_mb"] - reserve - sum(service_memory(c) for c in registered)


def resource_review(facts, config, registered):
    """Describe initial allocations using the same accounting as validation."""
    remaining = remaining_memory(facts, registered, config.host_reserved_mb)
    allocated = service_memory(config)
    php = (f"PHP-FPM: {config.php_children} workers "
           + (f"({config.php_children - config.php_callback_children} web + {config.php_callback_children} office callback); "
              if config.has_office else "(web only); ") +
           f"{config.php_memory_mb} MiB/request."
           if config.php_memory_mb > 0 and config.php_children >= (3 if config.has_office else 2) else
           "PHP-FPM: invalid worker budget/limit; adjust budgets before approval.")
    return "\n".join([
        f"Initial sizing: {facts['memory_mb']} MiB detected RAM; {config.host_reserved_mb} MiB host/ZFS reserve; "
        f"{sum(service_memory(c) for c in registered)} MiB reserved by {len(registered)} other instance(s).",
        f"{remaining} MiB remains for this instance after those reservations; "
        f"selected {allocated} MiB (includes 640 MiB service overhead); {remaining - allocated} MiB left unallocated.",
        (f"{OFFICE_LABELS[config.backend]} {config.office_memory_mb} MiB; " if config.has_office else "") +
        f"MariaDB buffer {config.db_buffer_mb} MiB; "
         f"Redis {config.redis_memory_mb} MiB; PHP pool {config.php_budget_mb} MiB; antivirus {config.antivirus_memory_mb} MiB.",
        f"Client Push {config.client_push_memory_mb if config.client_push else 0} MiB; Talk {config.talk_memory_mb if config.talk else 0} MiB (planning estimates pending native observation).",
        php,
        f"Upload chunk limit: {config.upload_max_mb} MiB; temporary-data quota: "
        + (f"{config.temporary_quota_gib} GiB. " if config.temporary_quota_gib else "no quota. ") +
        "Choose upload limits for your usage and storage, not CPU/RAM alone.",
        f"Pool {config.pool}: {facts['available_gib'][config.pool]} GiB currently available; "
        "retain free storage headroom for growth, package operations and snapshots.",
        storage_summary(config),
        "Budgets are conservative starting estimates, not enforced memory limits or measured workload optimization. "
        "Leave room for other host workloads and future instances; adjust the initial budgets if needed. "
        "Selected settings apply before first startup, not in a post-install tuning pass.",
    ])


def storage_inspection(facts, pool):
    """Present native facts without adding overlapping parent/child usage."""
    storage = facts.get("storage", {}).get(pool)
    if not storage:
        return (f"Pool {pool}: {facts['available_gib'][pool]} GiB currently available. "
                "Detailed native storage inspection unavailable; no ancestor/snapshot assessment shown.")

    def gib(value):
        return f"{value / (1024 ** 3):.1f} GiB"

    lines = [f"Native storage inspection: pool {pool}; health {storage['health']}; "
             f"size {gib(storage['size'])}; allocated {gib(storage['allocated'])}; free {gib(storage['free'])}.",
             "Dataset figures overlap across ancestors; do not sum them. Snapshot usage is per dataset."]
    for name, properties in sorted(storage["datasets"].items()):
        limits = "; ".join(f"{key}={gib(properties[key])}" for key in
                          ("quota", "refquota", "reservation", "refreservation") if properties[key])
        lines.append(f"  {name}: used {gib(properties['used'])}; available {gib(properties['available'])}; "
                     f"referenced {gib(properties['referenced'])}; snapshots {gib(properties['usedbysnapshots'])}; "
                     f"{limits or 'no local caps/reservations'}.")
    return "\n".join(lines)


def unused_network(facts, registered, *, prefix=29):
    occupied = [c.network for c in registered]
    for value in (facts.get("management_network"), *facts.get("networks", ())):
        if value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version == 4:
                occupied.append(network)
    address = ipaddress.IPv4Address(facts["address"])
    for block in ("10.77.0.0/16", "172.30.0.0/16", "192.168.240.0/20"):
        for candidate in ipaddress.IPv4Network(block).subnets(new_prefix=prefix):
            if address not in candidate and not any(candidate.overlaps(network) for network in occupied):
                return str(candidate)
    raise ValueError(f"No unused default private /{prefix} is available in the managed network ranges")


def used_ports(registered, address, management_port):
    ports = {management_port}
    for c in registered:
        if c.ingress_address != address:
            continue
        ports.update(c.ingress_ports)
        if c.talk:
            ports.add(c.talk_turn_port)
    return ports


def next_port(start, occupied):
    for port in range(start, 65536):
        if port not in occupied:
            occupied.add(port)
            return port
    raise ValueError("No unused ingress port is available")


def allocate_talk_ports(config, registered, facts):
    """Allocate bounded ranges across both host ingress and public NAT domains."""
    occupied = [binding for other in registered for binding in ingress_bindings(other)]
    occupied.extend(facts.get("ingress_reservations", ()))
    occupied.extend(facts.get("listener_bindings", ()))
    occupied.append(IngressBinding("*", "tcp", config.management_port, config.management_port, "host SSH"))
    occupied.extend(binding for binding in ingress_bindings(config) if binding.role not in ("TURN", "media", "relay"))

    def available(protocols, low, high):
        return not any(binding_conflicts(IngressBinding(address, protocol, low, high, "Talk", domain), other)
                       for domain, address in (("host", config.ingress_address), ("public", config.talk_public_ip))
                       if address
                       for protocol in protocols for other in occupied)

    for port in range(3478, 65536):
        if port not in (8080, 8188, 4222) and available(("tcp", "udp"), port, port):
            config.talk_turn_port = port
            break
    else:
        raise ValueError("No unused TURN TCP/UDP listener is available")
    for domain, address in (("host", config.ingress_address), ("public", config.talk_public_ip)):
        if not address:
            continue
        occupied.append(IngressBinding(address, "udp", port, port, "TURN", domain))
    for prefix, start in (("talk_media", 20000), ("talk_relay", 30000)):
        for low in range(start, 64537, 1000):
            high = low + 999
            if available(("udp",), low, high):
                setattr(config, prefix + "_port_min", low)
                setattr(config, prefix + "_port_max", high)
                for domain, address in (("host", config.ingress_address), ("public", config.talk_public_ip)):
                    if not address:
                        continue
                    occupied.append(IngressBinding(address, "udp", low, high, prefix, domain))
                break
        else:
            raise ValueError("No unused bounded Talk UDP range is available")


def recompute_service_topology(config, facts, registered, *, previous_talk):
    """Only unsaved wizard selections: never migrate loaded legacy profiles."""
    if not config.has_native_services:
        return
    if previous_talk != config.talk:
        prefix = (28 if config.has_office else 29) if config.talk else (29 if config.has_office else 30)
        config.private_network = unused_network(facts, registered, prefix=prefix)
    if not config.talk:
        for name in TALK_FIELDS:
            setattr(config, name, "" if name in ("talk_bridge", "talk_public_ip", "talk_media_hostname") else 0)
        return
    if not config.talk_bridge:
        occupied = {name for other in registered for name in other.bridges}
        occupied.update(facts.get("bridges", ()))
        occupied.update(facts.get("interfaces", ()))
        occupied.update((config.nextcloud_bridge, config.onlyoffice_bridge))
        config.talk_bridge = next((f"bridge{number}" for number in range(240, 10000)
                                   if f"bridge{number}" not in occupied), "")
        if not config.talk_bridge:
            raise ValueError("No unused Talk bridge is available")
    if not previous_talk:
        config.talk_memory_mb = 2048
        config.talk_turn_port = 3478
        config.talk_media_port_min, config.talk_media_port_max = 20000, 20999
        config.talk_relay_port_min, config.talk_relay_port_max = 30000, 30999


def configure_talk_routing(config, facts, registered, *, previous_talk, ui, preserve_ports=False, approved_subject=None):
    """Public routing follows HTTPS, independently of private topology review."""
    if not config.talk:
        return
    if config.tls_mode == "external" and not config.proxy_callback_address:
        config.proxy_callback_address = ask("Private/VPN HTTPS frontend callback IPv4 (Push and Talk)", ui=ui)
    context = (f"HTTPS: {config.public_hostname}; callback {config.frontend_callback_address}; host {config.ingress_address}.\n"
               "The web hostname default is appropriate only when the same endpoint receives Talk traffic; a remote HTTPS proxy may need a different media hostname. "
               "HTTPS forwarding alone is insufficient. Talk needs TURN TCP/UDP and both UDP ranges "
               "forwarded port-preservingly. No TURN TLS/DTLS or Talk jail SSH is enabled.")
    values = grouped_fields(ui, "Talk endpoint", [("talk_media_hostname", "Talk media hostname", config.talk_media_hostname or config.public_hostname)], text=context)
    value = values["talk_media_hostname"].lower()
    changed = config.talk_media_hostname != value
    config.talk_media_hostname, config.talk_public_ip = value, ""
    if changed or not previous_talk:
        proposal = replace(config)
        allocate_talk_ports(proposal, registered, facts)
        use_proposal = not preserve_ports
        if preserve_ports:
            use_proposal = ui.menu("Talk port allocation", [("keep", "Keep custom ports"), ("generated", "Use allocated ports")], "keep",
                                   text="Media endpoint/topology changed. Existing ports are retained unless you explicitly replace them. "
                                        f"Generated proposal: TURN {proposal.talk_turn_port}; media {proposal.talk_media_port_min}-{proposal.talk_media_port_max}; "
                                        f"relay {proposal.talk_relay_port_min}-{proposal.talk_relay_port_max}. Correct any conflicts below.") == "generated"
        if use_proposal:
            for name in ("talk_turn_port", "talk_media_port_min", "talk_media_port_max", "talk_relay_port_min", "talk_relay_port_max"):
                setattr(config, name, getattr(proposal, name))
            preserve_ports = False
    port_names = ("talk_turn_port", "talk_media_port_min", "talk_media_port_max", "talk_relay_port_min", "talk_relay_port_max")
    before_ports = tuple(getattr(config, name) for name in port_names)
    edit_fields(config, ui, "Talk ports", [
        ("talk_turn_port", "TURN TCP/UDP port", int),
        ("talk_media_port_min", "Media UDP first", int), ("talk_media_port_max", "Media UDP last", int),
        ("talk_relay_port_min", "Relay UDP first", int), ("talk_relay_port_max", "Relay UDP last", int)],
        text=context + f"\nMedia hostname: {value}" +
        ("\nExisting custom ports are retained; correct any new conflicts explicitly." if preserve_ports else ""))
    forwarding = (f"Acknowledge operator-managed port-preserving Talk forwarding from {value} to {config.ingress_address} (not a reachability test): "
                  f"TCP/UDP {config.talk_turn_port}; UDP {config.talk_media_port_min}-{config.talk_media_port_max}; "
                  f"UDP {config.talk_relay_port_min}-{config.talk_relay_port_max}?")
    subject = (value, config.ingress_address, config.frontend_callback_address, config.tls_mode,
               config.talk_turn_port, config.talk_media_port_min, config.talk_media_port_max,
               config.talk_relay_port_min, config.talk_relay_port_max)
    if approved_subject != subject and not ui.confirm(forwarding):
        raise ValueError("Talk forwarding must be explicitly confirmed")
    return preserve_ports or before_ports != tuple(getattr(config, name) for name in port_names)


def configure_native_services(config, facts, registered, *, previous_talk, ui):
    """Historical helper for callers outside the grouped wizard."""
    if not config.has_native_services:
        return
    recompute_service_topology(config, facts, registered, previous_talk=previous_talk)
    ui.message("Client Push is mandatory core integration, even when no optional apps are selected (256 MiB initial allowance).")
    if previous_talk != config.talk:
        ui.message(f"App selection changed topology: proposed unused private allocation {config.private_network}; bridges {config.bridges}. Review this complete plan before saving.")
        config.private_network = ask("Review unused private allocation after app selection", config.private_network, ui=ui)
    if config.tls_mode == "external" and not config.proxy_callback_address:
        config.proxy_callback_address = ask("Private/VPN HTTPS frontend callback IPv4 (Client Push)", ui=ui)
    if not config.talk:
        return
    config.talk_bridge = ask("Unused Talk bridge name", config.talk_bridge, ui=ui)
    ui.message("Talk uses a media hostname, defaulting to the web hostname only when the same endpoint receives Talk traffic. "
               "Forward TURN TCP/UDP and both UDP ranges port-preservingly to host ingress. "
               "No TURN TLS/DTLS or Talk jail SSH is enabled.")
    value = ask("Talk media hostname", config.talk_media_hostname or config.public_hostname, ui=ui).lower()
    changed = config.talk_media_hostname != value
    config.talk_media_hostname, config.talk_public_ip = value, ""
    if changed or not previous_talk:
        allocate_talk_ports(config, registered, facts)
    for name, label in (("talk_turn_port", "TURN TCP/UDP listener port"),
                         ("talk_media_port_min", "Janus UDP media first port"),
                         ("talk_media_port_max", "Janus UDP media last port"),
                         ("talk_relay_port_min", "TURN UDP relay first port"),
                         ("talk_relay_port_max", "TURN UDP relay last port")):
        setattr(config, name, ask(label, getattr(config, name), int, ui=ui))
    if not ui.confirm(f"Acknowledge operator-managed port-preserving forwarding from {value} to {config.ingress_address}: TCP/UDP {config.talk_turn_port}; UDP {config.talk_media_port_min}-{config.talk_media_port_max}; UDP {config.talk_relay_port_min}-{config.talk_relay_port_max} (not a reachability test)?"):
        raise ValueError("Talk forwarding must be explicitly acknowledged")


def grouped_fields(ui, title, fields, *, text="", help_text=""):
    values = ui.form(title, [(key, label, str(value)) for key, label, value in fields],
                     text=text, help_text=help_text)
    if set(values) != {key for key, _, _ in fields}:
        raise ValueError("Malformed form response")
    return values


def edit_fields(config, ui, title, fields, *, text="", defaults=None):
    """Retry conversion in place; never discard the other entries in a form."""
    defaults = defaults or {}
    values = {name: str(defaults.get(name, getattr(config, name))) for name, _, _ in fields}
    error_text = ""
    while True:
        values = grouped_fields(ui, title, [(name, label, values[name]) for name, label, _ in fields],
                                text=text + error_text, help_text="Use '-' to clear optional text values.")
        try:
            converted = {name: convert("" if values[name] == "-" and convert is str else values[name])
                         for name, _, convert in fields}
        except (ValueError, TypeError) as error:
            error_text = f"\nInvalid value: {error}. Correct these entries; other values are retained."
            continue
        for name, value in converted.items():
            setattr(config, name, value)
        return


def vm_initial_budgets(config, available_mb, *, policy=None):
    """Pure VM allocation including three PHP workers for callback headroom.

    available_mb already excludes the shared host, other instances and selected
    app allowance. Never shrink the reviewed guest default to fit a small host.
    """
    from .versions import vm_resource_policy
    allocation = vm_resource_policy(config, policy)['defaults']
    office = allocation['memory_mb']
    php_floor = 3 * config.php_memory_mb
    minimum = office + php_floor + 256 + 64 + 640
    if available_mb < minimum:
        raise ValueError(f'Only {available_mb} MiB remains after host/registered/app budgets; '
                         f'a new VM-backed instance needs at least {minimum} MiB')
    database, redis, php = 256, 64, php_floor
    if available_mb >= office + 2048 + 256 + max(3072, php_floor) + 640:
        database, redis, php = 2048, 256, max(3072, php_floor)
    elif available_mb >= office + 768 + 128 + max(2048, php_floor) + 640:
        database, redis, php = 768, 128, max(2048, php_floor)
    return dict(office_memory_mb=office, office_vm_cpus=allocation['cpus'],
                office_vm_disk_gib=allocation['disk_gib'], db_buffer_mb=database,
                redis_memory_mb=redis, php_budget_mb=php)


def initial_config(facts, registered=(), *, nextcloud_apps="", office_backend=""):
    backend = office_backend or "onlyoffice"
    if backend not in OFFICE_BACKENDS:
        raise ValueError("Unknown office backend")
    native = backend == "onlyoffice"
    vm = backend in ('eurooffice','collabora')
    registered = tuple(registered)
    memory = facts["memory_mb"]
    first = registered[0] if registered else None
    managed = facts.get("managed_host") or {}
    host = first.host_reserved_mb if first else managed.get("host_reserved_mb", max(2048, memory // 4))
    antivirus = Config(nextcloud_apps=nextcloud_apps).antivirus_memory_mb
    remaining = remaining_memory(facts, registered, host) - antivirus
    minimum = 4544 if native else 1984  # Two 512 MiB PHP workers, DB 256, Redis 64, overhead 640.
    native_allowance = 256 + (2048 if "spreed" in Config(nextcloud_apps=nextcloud_apps).selected_nextcloud_apps else 0)
    if remaining < minimum + native_allowance:
        raise ValueError(f"Only {remaining} MiB remains after host/registered/app budgets; a new instance needs at least {minimum + native_allowance} MiB including Client Push/Talk")
    # Size a fresh draft against all selected services. Later app changes never
    # re-run this sizing or consume already-selected office/PHP/database budgets.
    remaining -= native_allowance
    # Conservative defaults leave room for another instance on a 16 GiB host.
    vm_budgets = {}
    if vm:
        candidate = Config(office_backend=backend, freebsd_release=facts.get('freebsd_release',''),
                           architecture=facts.get('architecture',''))
        vm_budgets = vm_initial_budgets(candidate, remaining)
        office, database, redis, php = (vm_budgets[key] for key in
            ('office_memory_mb','db_buffer_mb','redis_memory_mb','php_budget_mb'))
    elif not native:
        office = 0
        if memory >= 32768 and remaining >= 6144:
            database, redis, php = 2048, 256, 3072
        elif remaining >= 3584:
            database, redis, php = 768, 128, 2048
        else:
            database, redis, php = 256, 64, 1024
    elif memory >= 32768 and remaining >= 10240:
        office, database, redis, php = 4096, 2048, 256, 3072
    elif remaining >= 6144:
        office, database, redis, php = 3072, 768, 128, 1536
    else:
        office, database, redis, php = 2048, 256, 64, 1536
    config = Config(pool=first.pool if first else managed.get("pool", facts["pools"][0]),
                    service_profile="native-v1", client_push_memory_mb=256, nextcloud_defaults="v1", custom_egress="v1",
                    office_backend="" if native else backend,
                    onlyoffice_plugins=DEFAULT_ONLYOFFICE_PLUGINS if native else "",
                    storage_policy="optional", **{name: 0 for name in QUOTA_FIELDS},
                    freebsd_release=facts.get("freebsd_release", ""), architecture=facts.get("architecture", ""),
                    external_interface=first.external_interface if first else managed.get("external_interface", facts["interface"]),
                    ingress_address=facts["address"], dns_server=facts["dns"],
                    management_network=first.management_network if first else managed.get("management_network", facts["management_network"]),
                    management_port=first.management_port if first else managed.get("management_port", facts["ssh_port"]),
                    nextcloud_apps=nextcloud_apps,
                    host_reserved_mb=host, office_memory_mb=office, php_budget_mb=php,
                     db_buffer_mb=database, redis_memory_mb=redis)
    if vm:
        config.office_vm_cpus = vm_budgets['office_vm_cpus']
        config.office_vm_disk_gib = vm_budgets['office_vm_disk_gib']
    names = {c.instance for c in registered} | set(facts.get("reserved_instances", ()))
    for name in ("cloud", *(f"cloud{number}" for number in range(2, 1000))):
        if name not in names:
            config.instance = name
            break
    else:
        raise ValueError("Choose a new instance name; the default names are already registered")
    config.private_network = unused_network(facts, registered, prefix=29 if config.has_office else 30)
    bridges = {name for c in registered for name in c.bridges}
    bridges.update(facts.get("bridges", ()))
    bridges.update(facts.get("interfaces", ()))
    available_bridges = (f"bridge{number}" for number in range(240, 10000)
                         if f"bridge{number}" not in bridges)
    try:
        config.nextcloud_bridge = next(available_bridges)
        if config.has_office:
            config.onlyoffice_bridge = next(available_bridges)
        else:
            config.onlyoffice_bridge = ""
    except StopIteration:
        raise ValueError("No unused default bridge names are available") from None
    occupied = used_ports(registered, config.ingress_address, config.management_port)
    if any(c.ingress_address == config.ingress_address for c in registered):
        config.tls_mode = "external"
        config.http_port = next_port(8080 + len(registered) - 1, occupied)
        config.https_port = next_port(8443 + len(registered) - 1, occupied)
    else:
        occupied.update((config.http_port, config.https_port))
    config.ssh_nextcloud_port = next_port(2201, occupied)
    if config.native_office:
        config.ssh_onlyoffice_port = next_port(2202, occupied)
    recompute_service_topology(config, facts, registered, previous_talk=False)
    return config


def configure(facts, existing=None, registered=(), *, ui=None):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ValueError("The installer requires an interactive terminal for configuration and approval")
    ui = ui or TerminalUI()
    others = tuple(c for c in registered if existing is None or c.instance != existing.instance)
    if existing is None:
        backend = ui.menu("Office backend (fresh installation)", [
            ("onlyoffice", "ONLYOFFICE"), ("eurooffice", "Euro-Office"),
            ("collabora", "Collabora CODE"), ("none", "Nextcloud only"),
        ], "onlyoffice", text="Setup 1/8 — Applications. Fresh-install choice, not migration. "
           "ONLYOFFICE uses two native jails; Euro-Office/Collabora use a Nextcloud jail and dedicated Alpine/bhyve/Docker VM. "
           "Nextcloud only installs no office runtime or connector. This choice cannot be switched later.")
        c = initial_config(facts, others, office_backend=backend)
    else:
        c = replace(existing)
    apps_selected_early = False
    if existing is None:
        # Establish baseline capacity first, then let the operator resolve app headroom
        # before sizing. The ordinary Applications section follows this sequence.
        c.nextcloud_apps = DEFAULT_NEXTCLOUD_APPS
        remaining = remaining_memory(facts, others, c.host_reserved_mb)
        minimum = 4544 if c.has_office else 1984
        if c.backend in ('eurooffice','collabora'):
            from .versions import vm_resource_policy
            minimum = vm_resource_policy(c)['defaults']['memory_mb'] + 3*c.php_memory_mb + 256 + 64 + 640
        while remaining < minimum + c.antivirus_memory_mb + c.client_push_memory_mb + (2048 if c.talk else 0):
            ui.message(f"Only {remaining} MiB remains after host/registered budgets. "
                         f"Selected apps need at least {minimum + c.antivirus_memory_mb + c.client_push_memory_mb + (2048 if c.talk else 0)} MiB including core services. "
                       "Adjust the Nextcloud apps before RAM sizing; antivirus adds 3072 MiB. "
                       "No apps will be deselected automatically.")
            c.nextcloud_apps = select_nextcloud_apps(c.nextcloud_apps, ui=ui)
            apps_selected_early = True
        c = initial_config(facts, others, nextcloud_apps=c.nextcloud_apps, office_backend=c.office_backend)
    first = others[0] if others else None
    shared_keys = ("pool", "external_interface", "management_network", "management_port", "host_reserved_mb")
    shared = {key: getattr(first, key) for key in shared_keys} if first else (facts.get("managed_host") or {})
    if shared:
        for field in shared_keys:
            setattr(c, field, shared[field])
    automatic_external = existing is None and first is not None and c.tls_mode == "external"

    if existing is None:
        materialize_software_defaults(c)
    # Loaded drafts may contain deliberate overrides (including cleared families).
    # Treat them conservatively; only fresh generated values can be replaced freely.
    custom_network = existing is not None
    custom_ports = existing is not None and c.talk
    retained_talk = {name: getattr(c, name) for name in TALK_FIELDS} if c.talk else {}
    routing_subject = None
    acme_subject = c.acme_email if existing is not None and c.tls_mode == "acme" else None
    admin_subject = None

    def ssh_subject():
        return c.ssh_username, c.ssh_key_file, c.nextcloud_jail, c.onlyoffice_jail if c.native_office else ""

    if c.ssh_admin:
        admin_subject = ssh_subject()

    def talk_subject():
        return (c.talk_media_hostname, c.ingress_address, c.frontend_callback_address, c.tls_mode,
                c.talk_turn_port, c.talk_media_port_min, c.talk_media_port_max,
                c.talk_relay_port_min, c.talk_relay_port_max)

    if existing is not None and c.talk:
        routing_subject = talk_subject()

    def edit_talk_routing():
        nonlocal custom_ports, routing_subject
        try:
            custom_ports = configure_talk_routing(c, facts, others, previous_talk=routing_subject is not None,
                                                  ui=ui, preserve_ports=custom_ports, approved_subject=routing_subject)
        except ValueError:
            # A declined forwarding approval still leaves deliberate port edits
            # in the canonical draft. A retry must not allocate over them.
            custom_ports = True
            raise
        routing_subject = talk_subject()

    def topology_text():
        lines = [f"Reserved block: {c.private_network}", "Service       Address          Gateway          Bridge"]
        endpoints = [("Nextcloud", c.nextcloud_ip, c.nextcloud_gateway, c.nextcloud_bridge)]
        if c.has_office:
            endpoints.append(("Office", c.onlyoffice_ip, c.onlyoffice_gateway, c.onlyoffice_bridge))
        if c.talk:
            endpoints.append(("Talk", c.talk_ip, c.talk_gateway, c.talk_bridge))
        for label, address, gateway, bridge in endpoints:
            lines.append(f"{label:<13} {address:<16} {gateway:<16} {bridge}")
        return "\n".join(lines)

    def applications():
        nonlocal apps_selected_early, routing_subject, retained_talk
        previous = c.talk
        if not apps_selected_early:
            value = select_nextcloud_apps(c.nextcloud_apps, ui=ui)
            candidate = replace(c, nextcloud_apps=value)
            if previous != candidate.talk:
                saved = {name: getattr(c, name) for name in TALK_FIELDS}
                if previous:
                    retained_talk = saved
                if custom_network:
                    if not ui.confirm("Changing Talk affects the customized private allocation and Talk settings. "
                                      f"Keep {c.private_network}, bridges {c.bridges}, media {c.talk_media_hostname or '(not configured)'}, "
                                      f"TURN {c.talk_turn_port}, media UDP {c.talk_media_port_min}-{c.talk_media_port_max}, "
                                      f"relay UDP {c.talk_relay_port_min}-{c.talk_relay_port_max} for explicit review/correction?"):
                        return
                c.nextcloud_apps = value
                network = c.private_network
                recompute_service_topology(c, facts, others, previous_talk=previous)
                if custom_network:
                    c.private_network = network
                if candidate.talk and retained_talk:
                    for name, retained in retained_talk.items():
                        setattr(c, name, retained)
                routing_subject = None
            else:
                c.nextcloud_apps = value
        apps_selected_early = False
        c.nextcloud_branding = ui.menu("Enable NextcloudOnFreeBSD branding", [
            ("enabled", "Enabled"), ("disabled", "Disabled"),
        ], "enabled" if c.nextcloud_branding else "disabled",
            text="Disabled keeps Nextcloud's original branding.") == "enabled"
        if c.has_native_services:
            select_external_storage(c, ui=ui)
        if not c.native_office:
            return
        if not c.accept_microsoft_fonts:
            consent = ui.menu("Required Microsoft webfonts license", [
                ("decline", "Decline; cancel"), ("accept", "Accept EULA")], "decline",
                text="The native package requires Microsoft core webfonts with either open-font profile. "
                     "Review https://corefonts.sourceforge.net/eula.htm\n"
                     "Port license: https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/webfonts/Makefile")
            if consent != "accept":
                raise KeyboardInterrupt
            c.accept_microsoft_fonts = True
        c.font_profile = ui.menu("Font packages", [("comprehensive", "Comprehensive (~+4 GiB)"),
                                                  ("standard", "Standard")], c.font_profile,
                                 text=COMPREHENSIVE_FONT_ESTIMATE)
        value = ui.input("Optional absolute directory of additional fonts ('-' clears)", c.additional_fonts_dir)
        c.additional_fonts_dir = "" if value == "-" else value
        c.onlyoffice_plugins = select_onlyoffice_plugins(c.onlyoffice_plugins, ui=ui)

    def identity():
        edit_fields(c, ui, "Identity — 2/8", [
            ("instance", "Instance name", str), ("public_hostname", "Public Nextcloud hostname", str),
            ("admin_username", "Administrator username", str), ("admin_email", "Administrator email", str)],
            text="Use 1–8 lowercase letters/digits for the instance, starting with a letter. "
            "Jail hostname overrides are optional; generated names remain automatic.\n"
            f"Current jail hostnames: {c.nextcloud_hostname or c.instance + 'nc'}" +
            (f", {c.onlyoffice_hostname or c.instance + 'oo'}" if c.native_office else ""))
        c.public_hostname = c.public_hostname.lower()
        while True:
            action = identity_options(c, ui=ui)
            if action == "continue":
                break
            if action in ("country", "timezone"):
                edit_region(c, action, ui=ui)
            elif action == "hostnames":
                fields = [("nextcloud_hostname", "Nextcloud jail hostname", str)]
                if c.native_office:
                    fields.append(("onlyoffice_hostname", "ONLYOFFICE jail hostname", str))
                edit_fields(c, ui, "Jail hostnames", fields, text="Blank or '-' keeps generated instance+nc/oo names. Short names or FQDNs supported.")
                for name, _, _ in fields:
                    setattr(c, name, getattr(c, name).lower())
            elif action == "software":
                c.repository = choose("FreeBSD-ports branch", ("latest", "quarterly"), c.repository, ui=ui)
                select_version_families(c, ui=ui, preserve_missing=True)
                if c.has_native_services:
                    continue
                fields = [("nextcloud_min", "Minimum Nextcloud stable version", str),
                          ("nextcloud_exact", "Optional exact Nextcloud release", str)]
                if c.native_office and not c.has_native_services:
                    fields += [("onlyoffice_min", "Minimum ONLYOFFICE stable version", str),
                               ("onlyoffice_exact", "Optional exact ONLYOFFICE release", str)]
                edit_fields(c, ui, "Software constraints", fields,
                            text=("These assertions select the Nextcloud application release, not FreeBSD package versions. '-' clears optional assertions."
                                  if c.has_native_services else
                                  "Minimums and exact pins do not establish support. '-' clears optional pins. Other package choices remain available in recipes."))
            else:
                raise ValueError("Unknown identity action")

    def storage():
        if not shared:
            c.pool = choose("Existing ZFS pool", facts["pools"], c.pool, ui=ui)
        warning = ("Actual destination storage, not a quota recommendation or a fit guarantee. "
                   "Dataset figures overlap; do not sum them. "
                   "Leave room for jail bases, packages, fonts, database, uploads, updates and snapshots.")
        native = facts.get("storage", {}).get(c.pool)
        context = (f"Setup 3/8 — Storage. {'Inherited pool' if shared else 'Pool'}: {c.pool}.\n"
                   f"Currently available: {facts['available_gib'][c.pool]} GiB. " +
                   (f"Native pool health: {native['health']}." if native else "Detailed native inspection unavailable.") +
                   "\nQuota policy: " + ("saved legacy limits" if c.storage_policy != "optional" else
                   "optional caps configured" if any(getattr(c, name) for name in QUOTA_FIELDS) else "no installer quotas") +
                   ".\n" + warning)
        while True:
            limits = ui.menu("Storage limits", [("none", "No installer quotas"), ("caps", "Set optional caps"),
                                                ("details", "Complete storage details")],
                             "caps" if any(getattr(c, name) for name in QUOTA_FIELDS) else "none", text=context)
            if limits != "details":
                break
            ui.details("Complete storage details", storage_inspection(facts, c.pool) + "\n\n" + storage_summary(c) + "\n\n" + warning)
        if limits == "none":
            c.storage_policy = "optional"
            for name in QUOTA_FIELDS:
                setattr(c, name, 0)
        elif limits == "caps":
            fields = [("data_quota_gib", "User data", int), ("database_quota_gib", "Database data", int),
                      ("temporary_quota_gib", "Temporary/upload data", int)]
            if c.has_office:
                fields.append(("office_quota_gib", "Office working data" if c.native_office else "Office VM dataset cap", int))
            fields += [("logs_quota_gib", "Each log dataset", int), ("system_quota_gib", "Combined jail roots", int)]
            edit_fields(c, ui, "Storage caps (GiB)", fields,
                        text="0 means no quota under optional policy. " +
                        ("Saved legacy parent/application limits retained. " if c.storage_policy != "optional" else "") +
                        "A VM dataset cap is distinct from guest disk capacity.")
        else:
            raise ValueError("Unknown storage limits selection")

    def private_network():
        nonlocal custom_network
        fields = [("private_network", "Reserved IPv4 block", lambda value: str(ipaddress.IPv4Network(value, strict=True))),
                  ("nextcloud_bridge", "Nextcloud bridge", str)]
        if c.has_office:
            fields.append(("onlyoffice_bridge", "Office bridge", str))
        if c.talk:
            fields.append(("talk_bridge", "Talk bridge", str))
        edit_fields(c, ui, "Private networking", fields,
                    text="Advanced overrides. Service IPs/gateways are derived, never entered individually. "
                         "Use an unused allocation of the size required by selected services.")
        custom_network = True

    def networking():
        fields = [("ingress_address", "Host IPv4", str), ("dns_server", "DNS resolver", str)]
        if not shared:
            fields.insert(0, ("external_interface", "Host interface", str))
            fields += [("management_network", "Management CIDR", str), ("management_port", "Management SSH port", int)]
        edit_fields(c, ui, "Networking — 4/8", fields,
                    text="Existing host ingress is not public DNS A. The resolver serves jails/VMs; management CIDR controls SSH. "
                         "Managed PF blocks host inbound IPv6. " +
                         (f"Inherited uplink {c.external_interface}; management {c.management_network}:{c.management_port}." if shared else ""))
        while True:
            try:
                topology = topology_text()
            except ValueError as error:
                # A preflight-return draft may already contain malformed data.
                # Keep the editor reachable without deriving any endpoints.
                ui.message(f"Invalid private allocation: {error}. Correct the existing draft below.")
                private_network()
                continue
            if ui.menu("Private topology", [("continue", "Use this allocation"), ("edit", "Advanced private network")],
                       "continue", text=topology) != "edit":
                break
            private_network()

    def https():
        nonlocal automatic_external, acme_subject
        if automatic_external:
            if not any(item.ingress_address == c.ingress_address for item in others):
                c.tls_mode, c.http_port, c.https_port = "acme", 80, 443
            automatic_external = False
        c.tls_mode = ui.menu("HTTPS termination", [("acme", "Let's Encrypt / ACME"),
            ("provided", "Supplied certificate"), ("external", "External reverse proxy")], c.tls_mode,
            text=f"Setup 5/8 — HTTPS and Talk. Hostname: {c.public_hostname}. Host ingress: {c.ingress_address}.")
        external = c.tls_mode == "external"
        def frontend(value):
            if value in ("", "-"):
                raise ValueError("Private/VPN frontend callback IPv4 is required for Client Push")
            return str(ipaddress.IPv4Address(value))

        c.dns_address = ""
        fields = [("public_https_port", "Public HTTPS port", int), ("http_port", "Host HTTP port", int)]
        if external:
            fields.insert(0, ("proxy_callback_address", "Private callback IPv4", frontend))
        if not external:
            fields.append(("https_port", "Host HTTPS port", int))
        if c.tls_mode == "acme":
            fields.append(("acme_email", "ACME account email", str))
        if external:
            fields.append(("proxy_networks", "Trusted proxy CIDRs", str))
        edit_fields(c, ui, "HTTPS settings", fields,
                    defaults={"acme_email": c.acme_email or c.admin_email},
                    text=f"Hostname: {c.public_hostname} (already entered). " +
                         ("Proxy must serve HTTPS and set forwarded headers. Only explicit trusted CIDRs may reach the HTTP backend. "
                           "The explicit private/VPN callback route is required for Client Push even without Talk; it need not appear in public DNS." if external else
                           "Public hostname DNS and router forwarding are operator-managed. ACME needs public TCP 80. HTTPS must reach its selected listener."))
        if not external:
            c.proxy_networks = ""
            c.proxy_callback_address = ""
        if c.tls_mode == "acme":
            c.certificate_file = c.private_key_file = c.ca_file = ""
            if acme_subject != c.acme_email:
                if not ui.confirm(f"Accept Let's Encrypt subscriber agreement https://letsencrypt.org/repository/ for ACME account {c.acme_email}?"):
                    raise ValueError("ACME agreement was not accepted for this account")
                acme_subject = c.acme_email
        elif c.tls_mode == "provided":
            edit_fields(c, ui, "Certificate paths", [("certificate_file", "PEM certificate chain", str),
                        ("private_key_file", "PEM private key path", str), ("ca_file", "Optional CA bundle", str)],
                        text="Absolute host paths. Key must be matching unencrypted PEM. Optional CA bundle: blank or '-' for normal trust.")
            c.acme_email = ""
            acme_subject = None
        else:
            c.acme_email = c.certificate_file = c.private_key_file = c.ca_file = ""
            acme_subject = None
        if c.talk:
            edit_talk_routing()

    def administration():
        nonlocal admin_subject
        c.jail_ssh = ui.menu("SSH into both jails" if c.native_office else "SSH into the Nextcloud jail",
                            [("off", "Disabled"), ("on", "Key-only login")], "on" if c.jail_ssh else "off",
                            text=f"Setup 6/8 — Optional administration. Management CIDR: {c.management_network}. "
                                 "No Talk jail or office VM SSH is configured here.") == "on"
        if not c.jail_ssh:
            c.ssh_key_file, c.ssh_admin, admin_subject = "", False, None
            return
        fields = [("ssh_username", "Jail SSH username", str), ("ssh_key_file", "Public SSH key file", str),
                  ("ssh_nextcloud_port", "Nextcloud SSH port", int)]
        if c.native_office:
            fields.append(("ssh_onlyoffice_port", "ONLYOFFICE SSH port", int))
        edit_fields(c, ui, "Jail SSH", fields, text=f"Key-only access from {c.management_network}; unprivileged by default.")
        c.ssh_shell = ui.menu("Jail login shell", [("sh", "FreeBSD sh"), ("zsh", "zsh")], c.ssh_shell)
        admin = ui.menu("Jail SSH privileges", [("user", "Unprivileged"), ("admin", "Root via doas")],
                        "admin" if c.ssh_admin else "user")
        if admin == "admin":
            if admin_subject != ssh_subject():
                c.ssh_admin = ui.confirm(f"Grant {c.ssh_username} using {c.ssh_key_file} root administration through doas in "
                                         f"{c.nextcloud_jail}" + (f" and {c.onlyoffice_jail}" if c.native_office else "") + "?")
                admin_subject = ssh_subject() if c.ssh_admin else None
        else:
            c.ssh_admin, admin_subject = False, None

    def resources():
        over = service_memory(c) > remaining_memory(facts, others, c.host_reserved_mb)
        review = resource_review(facts, c, others)
        ui.message(review)
        rows = [("Host/ZFS reserve", c.host_reserved_mb), ("PHP worker pool", c.php_budget_mb),
                ("PHP per request", c.php_memory_mb), ("Database buffer", c.db_buffer_mb),
                ("Redis", c.redis_memory_mb)]
        if c.has_office:
            rows.append(("Office service/guest", c.office_memory_mb))
        if c.client_push:
            rows.append(("Client Push", c.client_push_memory_mb))
        if c.talk:
            rows.append(("Talk", c.talk_memory_mb))
        context = "Setup 7/8 — Resource budgets. Planning estimates, not enforced limits.\n"
        context += "\n".join(f"{label:<23} {value:>7} MiB" for label, value in rows)
        context += (f"\nInstance services: {service_memory(c)} MiB (includes apps and 640 MiB overhead). "
                    f"Available after reserve/other instances: {remaining_memory(facts, others, c.host_reserved_mb)} MiB.")
        if over:
            context += "\nSelected services exceed available memory. Budgets were not lowered. Edit budgets or apps before approval."
        while True:
            action = ui.menu("Resource budgets", [("keep", "Use these budgets"), ("edit", "Adjust budgets"),
                                                   ("details", "Complete resource review")],
                             "edit" if over else "keep", text=context)
            if action != "details":
                break
            ui.details("Complete resource review", review)
        if action != "edit":
            return
        fields = [] if shared else [("host_reserved_mb", "Host/ZFS reserve", int)]
        if c.has_office:
            fields.append(("office_memory_mb", "ONLYOFFICE budget" if c.native_office else "Office guest RAM", int))
        fields += [("db_buffer_mb", "Database buffer", int), ("redis_memory_mb", "Redis limit", int),
                   ("php_memory_mb", "PHP per-request limit", int), ("php_budget_mb", "PHP pool budget", int)]
        if c.client_push:
            fields.append(("client_push_memory_mb", "Client Push allowance", int))
        if c.talk:
            fields.append(("talk_memory_mb", "Talk allowance", int))
        edit_fields(c, ui, "Memory budgets (MiB)", fields,
                    text="Conservative planning estimates, not enforced process limits. Existing allocations are not recalculated.")
        edit_fields(c, ui, "Upload budget (MiB)", [("upload_max_mb", "Upload chunk limit", int)],
                    text="Choose for workload/storage, not CPU/RAM alone.")
        if c.backend in ("eurooffice", "collabora"):
            edit_fields(c, ui, "Office guest resources", [("office_vm_cpus", "Guest vCPUs", int),
                        ("office_vm_disk_gib", "Guest disk (GiB)", int)],
                        text="Guest disk capacity is distinct from the ZFS dataset cap.")

    sections = [("apps", "Applications", applications), ("identity", "Identity and software", identity),
                ("storage", "Storage", storage), ("network", "Networking", networking),
                ("https", "HTTPS and Talk", https), ("admin", "Optional administration", administration),
                ("resources", "Resource budgets", resources)]
    if existing is None:
        for _, _, section in sections:
            while True:
                try:
                    section()
                    break
                except ValueError as error:
                    ui.message(f"Configuration needs correction: {error}. Current entries are retained.")
    validation_error = ""
    while True:
        validation_error = ""
        remaining = remaining_memory(facts, others, c.host_reserved_mb)
        try:
            c.validate_provisioning()
            if c.backend in ('eurooffice','collabora'):
                from .versions import vm_resource_policy
                floor=vm_resource_policy(c)['minimum']
                if (c.office_vm_cpus<floor['cpus'] or c.office_memory_mb<floor['memory_mb']
                        or c.office_vm_disk_gib<floor['disk_gib']):
                    raise ValueError('Selected VM allocation is below reviewed guest/container resource policy')
                if c.office_quota_gib and c.office_quota_gib<c.office_vm_disk_gib:
                    raise ValueError('Office VM dataset cap cannot accommodate the guest disk capacity')
            if c.instance in facts.get("reserved_instances", ()):
                raise ValueError("This instance name remains reserved in the host audit registry; select a new name")
            if service_memory(c) > remaining:
                raise ValueError("Combined instance budgets and the host reserve exceed installed RAM")
            occupied = used_ports(others, c.ingress_address, c.management_port)
            selected = set(c.ingress_ports)
            if selected & occupied:
                raise ValueError("An ingress port is already reserved on this host address")
            for other in others:
                if ingress_conflicts(c, other):
                    raise ValueError("Host/public address/protocol interval is already reserved by another instance")
                if c.instance == other.instance:
                    raise ValueError("This instance name is already registered")
                if c.network.overlaps(other.network):
                    raise ValueError("Private network overlaps a registered instance")
                if set(c.bridges) & set(other.bridges):
                    raise ValueError("A bridge name is already registered")
            if facts.get("ssh_peer"):
                peer = ipaddress.IPv4Address(facts["ssh_peer"])
                if peer not in ipaddress.IPv4Network(c.management_network, strict=False) or c.management_port != facts["ssh_port"]:
                    raise ValueError("The managed SSH rule must preserve the current SSH client and port")
        except ValueError as error:
            validation_error = f"Configuration needs correction: {error}. Current entries are retained."
            ui.message(validation_error)
        summary = (f"Setup 8/8 — Review. Configuration acceptance is not APPLY.\n"
                   f"Applications: {OFFICE_LABELS[c.backend]}; {len(c.selected_nextcloud_apps)} apps; "
                   f"Talk {'on' if c.talk else 'off'}; Push {'on' if c.client_push else 'off'}; "
                   f"Branding {'enabled' if c.nextcloud_branding else 'disabled'}\n"
                   f"Identity/software: {c.instance}; {c.public_hostname}; {c.repository}\n"
                   f"Storage: {c.pool}; {c.storage_policy or 'legacy'} quota policy\n"
                   f"Networking: {c.ingress_address}; {c.private_network}; management {c.management_network}:{c.management_port}\n"
                   f"HTTPS/Talk: {c.tls_mode}; public port {c.public_https_port}; Talk {'on' if c.talk else 'off'}\n"
                   f"Administration: SSH {'on' if c.jail_ssh else 'off'}; doas {'on' if c.ssh_admin else 'off'}\n"
                   f"Resources: {c.memory_budget_mb} MiB total including host reserve.\n" + validation_error)
        action = ui.menu("Review configuration", [("accept", "Accept configuration"), ("edit", "Edit a section"),
                                                  ("details", "View complete plan"), ("quit", "Cancel")], "edit", text=summary)
        if action == "accept":
            if c.talk and routing_subject != talk_subject():
                try:
                    edit_talk_routing()
                except ValueError as error:
                    ui.message(f"Configuration needs correction: {error}")
                # Routing may have changed fields; run authoritative validation again.
                continue
            if validation_error:
                continue
            if c.ssh_admin and admin_subject != ssh_subject():
                c.ssh_admin = ui.confirm(f"Grant {c.ssh_username} using {c.ssh_key_file} root administration through doas in "
                                         f"{c.nextcloud_jail}" + (f" and {c.onlyoffice_jail}" if c.native_office else "") + "?")
                admin_subject = ssh_subject() if c.ssh_admin else None
            if c.tls_mode == "acme" and acme_subject != c.acme_email:
                if not ui.confirm(f"Accept Let's Encrypt subscriber agreement https://letsencrypt.org/repository/ for ACME account {c.acme_email}?"):
                    continue
                acme_subject = c.acme_email
            return c
        if action == "details":
            ui.details("Complete configuration plan", deployment_plan(c) + "\n\n" + resource_review(facts, c, others))
        elif action == "edit":
            selected = ui.menu("Edit section", [(key, label) for key, label, _ in sections], "identity",
                               text="Edit only this section, then return to Review. Current draft values are retained.")
            section = next((section for key, _, section in sections if key == selected), None)
            if section is None:
                raise ValueError("Unknown configuration section")
            try:
                section()
            except ValueError as error:
                ui.message(f"Configuration needs correction: {error}. Current entries are retained.")
        elif action == "quit":
            raise KeyboardInterrupt


def create_secrets(*, ui=None, generate=False, backend="onlyoffice", config=None):
    if config is not None:
        backend = config.backend
    if (backend or "onlyoffice") not in OFFICE_BACKENDS:
        raise ValueError("Unknown office backend")
    ui = ui or TerminalUI()
    ui.message("\nFresh credentials will be generated in the private credentials file." if generate else
               "\nAdministrator password: leave blank to generate one in the private credentials file.")
    while True:
        password = "" if generate else ui.secret("Password (not displayed)")
        if not password:
            password = secrets.token_urlsafe(24)
            break
        if len(password) < 14 or len(password.encode("utf-8")) > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in password):
            ui.message("Use at least 14 characters, at most 1024 UTF-8 bytes, without control characters.")
            continue
        if password == ui.secret("Confirm password"):
            break
        ui.message("Passwords differ; please retry.")
    credentials = {"admin_password": password, "db_password": secrets.token_hex(32)}
    if (backend or 'onlyoffice') in ('onlyoffice','eurooffice'):
        credentials["jwt_secret"] = secrets.token_hex(32)
    if config is not None and config.talk:
        for name in ("talk_signaling_secret", "talk_turn_secret", "talk_session_hashkey"):
            credentials[name] = secrets.token_hex(32)
        credentials["talk_session_blockkey"] = secrets.token_urlsafe(24)
    return credentials
