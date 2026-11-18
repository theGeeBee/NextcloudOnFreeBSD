"""Lazy policy loading and numeric versions; no probes, writes or network calls.

Application minima accept one to three components. Exact application pins use
three: an ONLYOFFICE triple pins upstream, while a suffix (_revision and/or
,epoch) pins the entire package string. Numeric package ordering is epoch,
upstream, then PORTREVISION. Non-numeric dependency versions remain opaque.
"""

from copy import deepcopy
from datetime import date
import hashlib
import json
from pathlib import PurePosixPath
import re


GROUPS = ("host", "nextcloud", "onlyoffice")
FIELDS = ("freebsd_release", "architecture", "nextcloud_min", "onlyoffice_min",
          "nextcloud_exact", "onlyoffice_exact")
NC_FIELDS = tuple(field for field in FIELDS if not field.startswith("onlyoffice_"))
VM_BACKENDS = ("eurooffice", "collabora")
VM_ROLES = ("vm_manager", "vm_image_tools", "vm_firmware")
CONNECTOR_APPS = {"onlyoffice": "onlyoffice", "eurooffice": "eurooffice", "collabora": "richdocuments"}
NAME = r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}"
ORIGIN = NAME + "/" + NAME
NUMBER = r"(?:0|[1-9][0-9]*)"
STABLE = NUMBER + r"(?:\." + NUMBER + r"){0,3}"
TRIPLE = NUMBER + r"\." + NUMBER + r"\." + NUMBER
PACKAGE = "(" + STABLE + r")(?:_(" + NUMBER + r"))?(?:,(" + NUMBER + r"))?"
FAMILY = NUMBER + r"(?:\." + NUMBER + r")?"
ALPINE_CLOUD_DIRECTORY = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/cloud/"
ALPINE_CLOUD_FILENAME = r"alpine-(" + TRIPLE + r")-x86_64-cloudinit-r(" + NUMBER + r")\.qcow2"
LATEST_CONTAINERS = {"ghcr.io/euro-office/documentserver:latest": 80,
                     "docker.io/collabora/code:latest": 9980}


def validate_families(values):
    """Optional numeric constraints, never additional package roots or authority."""
    if not isinstance(values, dict) or len(values) > 128:
        raise ValueError("version_families must be a bounded object of string families")
    for name, family in values.items():
        text(name, NAME, "version family component/package")
        text(family, FAMILY, "major or major.minor version family")
    return deepcopy(values)


def in_family(value, family):
    """Match upstream numeric components, not FreeBSD epoch or PORTREVISION."""
    text(family, FAMILY, "version family")
    key = package_version(value)[1]
    parts = tuple(map(int, family.split(".")))
    return key[:len(parts)] == parts


def object_fields(value, required, optional=(), label="metadata"):
    if (not isinstance(value, dict) or set(required) - value.keys()
            or value.keys() - set(required) - set(optional)):
        raise ValueError(f"Malformed {label}: expected fields {', '.join(required)}")
    return value


def text(value, pattern, label):
    if not isinstance(value, str) or len(value) > 512 or not re.fullmatch(pattern, value):
        raise ValueError(f"Invalid {label}: {value!r}")
    return value


def stable_version(value):
    """Return a four-component numeric key, including Nextcloud build numbers."""
    text(value, STABLE, "stable numeric version")
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (4 - len(parts))


def package_version(value):
    """Numeric FreeBSD package key: (PORTEPOCH, upstream tuple, PORTREVISION)."""
    text(value, PACKAGE, "numeric package version")
    match = re.fullmatch(PACKAGE, value)
    if not match[1]:
        raise ValueError(f"Missing upstream package version: {value!r}")
    return int(match[3] or 0), stable_version(match[1]), int(match[2] or 0)


def package_upstream(value):
    package_version(value)
    return re.fullmatch(PACKAGE, value)[1]


def release_base(value):
    text(value, NUMBER + r"\." + NUMBER + r"-(?:RELEASE(?:-p" + NUMBER + r")?|STABLE|CURRENT)",
         "FreeBSD release (N.N-RELEASE[-pN], N.N-STABLE or N.N-CURRENT)")
    return value.split("-p", 1)[0]


def in_range(value, rule):
    """Compatibility ranges describe upstream versions, independent of pkg epoch."""
    key = package_version(value)[1]
    if "family" in rule:
        return (in_family(value, rule["family"])
                and ("min" not in rule or key >= stable_version(rule["min"])))
    if "exact" in rule:
        return key == stable_version(rule["exact"])
    return stable_version(rule["min"]) <= key < stable_version(rule["max_exclusive"])


def _range(rule):
    if isinstance(rule, dict) and "family" in rule:
        object_fields(rule, ("family",), ("min",), label="version family range")
        text(rule["family"], FAMILY, "version family")
        if "min" in rule and not in_family(rule["min"], rule["family"]):
            raise ValueError("Family minimum must belong to its family")
        return
    object_fields(rule, ("exact",) if isinstance(rule, dict) and "exact" in rule
                  else ("min", "max_exclusive"), label="bounded version range")
    for value in rule.values():
        stable_version(value)
    if "min" in rule and stable_version(rule["min"]) >= stable_version(rule["max_exclusive"]):
        raise ValueError("Version range must have an exclusive upper bound above its minimum")


def target(policy, release, architecture):
    base = release_base(release)
    for item in policy["targets"]:
        if (item["release"], item["architecture"]) == (base, architecture):
            return deepcopy(item)
    supported = ", ".join(item["release"] + "/" + item["architecture"] for item in policy["targets"])
    raise ValueError(f"Unsupported target {release}/{architecture}; reviewed targets: {supported}")


def repository_current_platform(policy):
    """Only an explicit fresh-platform marker broadens exact target admission."""
    value = policy.get("repository_current_platform")
    if "repository_current_platform" in policy and (
            not isinstance(value, dict) or set(value) != {"minimum_major", "architecture"}
            or type(value.get("minimum_major")) is not int or value["minimum_major"] != 15
            or value.get("architecture") != "amd64"):
        raise ValueError("repository_current_platform requires minimum_major=15, architecture=amd64")
    return value


def repository_current_release(platform, release, architecture, *, normalized=False):
    """Compare against a validated fresh-platform rule without loading policy.

    Host selections may carry RELEASE patch suffixes; worker frames must already
    contain the base identity. Callers retain their own policy/discriminator and
    error-reporting boundaries.
    """
    base = release_base(release)
    if ((normalized and base != release)
            or int(base.split(".", 1)[0]) < platform["minimum_major"]
            or architecture != platform["architecture"]):
        raise ValueError("Requires FreeBSD 15 or higher (amd64), using a supported release listed by the installer")
    return base


def repository_current_target(policy, release, architecture):
    """Fresh native target; no ABI override, repository fallback or key contents.

    Unlisted targets require the ordinary OS pkg fingerprint as a prerequisite,
    not as authentication of RELEASE pkgbase. Bastille's native --pkgbase owns
    release-specific trust setup/verification and propagates any failure. Never
    derive future RELEASE signing-key filenames. Listed targets keep exact bytes.
    """
    platform = repository_current_platform(policy)
    if platform is None:
        return target(policy, release, architecture)
    base = repository_current_release(platform, release, architecture)
    major = int(base.split(".", 1)[0])
    abi = f"FreeBSD:{major}:amd64"
    for item in policy["targets"]:
        if (item["release"], item["architecture"]) == (base, architecture):
            if item["abi"] != abi:
                raise ValueError("Policy target ABI differs from its native release/architecture")
            return deepcopy(item)
    keys = ["/usr/share/keys/pkg/trusted/pkg.freebsd.org.2013102301"]
    return {"release": base, "architecture": architecture, "abi": abi, "pkgbase_keys": keys}


def office_backend(config):
    """Omitted/empty selection preserves the historical native backend."""
    backend = getattr(config, "office_backend", "") or "onlyoffice"
    if backend not in ("onlyoffice", "none", "eurooffice", "collabora"):
        raise ValueError(f"No reviewed version policy for office_backend={backend!r}; resolution/discovery is unavailable")
    return backend


def selected_groups(config):
    """Historical groups plus only explicitly derived service groups."""
    from .services import talk_selected
    groups = GROUPS if office_backend(config) == "onlyoffice" else ("host", "nextcloud")
    return groups + (("talk",) if talk_selected(config) else ())


def selected_profiles(config, policy, *, repository_current=False):
    """Filter backend and target before any availability queries."""
    if repository_current:
        from .package_policy import validate_constraints
        return validate_constraints(config, policy)
    backend = office_backend(config)
    effective = constraints(config, policy)
    identity = effective["freebsd_release"] + "/" + effective["architecture"]
    profiles = [profile for profile in policy["profiles"]
                if profile.get("office_backend", "onlyoffice") == backend
                and identity in profile["targets"]]
    if not profiles:
        label = "No reviewed version policy" if backend in VM_BACKENDS else "No reviewed compatibility profiles"
        raise ValueError(f"{label} for office_backend={backend!r} on {identity}")
    return profiles


def constraints(config, policy=None, *, repository_current=False, input_only=False):
    """Interpret constraints without inferring execution policy from saved inputs.

    Native-v1 config parsing may permit an explicit Nextcloud choice without an
    inherited minimum. It must still read older ONLYOFFICE/package family fields;
    only the actual discovery/plan discriminator selects repository-current rules.
    """
    policy = load_policy() if policy is None else policy
    backend = office_backend(config)
    families = validate_families(getattr(config, "version_families", {}))
    if repository_current:
        from .package_policy import validate_constraints
        validate_constraints(config, policy)
    values = {}
    for field in NC_FIELDS if backend != "onlyoffice" else FIELDS:
        value = getattr(config, field, "")
        if not isinstance(value, str):
            raise ValueError(f"{field} must be a string")
        values[field] = "" if repository_current and field.startswith("onlyoffice_") else value or policy["defaults"][field]
        if ((repository_current or input_only) and field == "nextcloud_min" and not value
                and (getattr(config, "nextcloud_exact", "") or families.get("nextcloud"))):
            values[field] = "0.0.0"
    if getattr(config, "_legacy_target", None):
        release, architecture = config._legacy_target.split("/")
        values["freebsd_release"], values["architecture"] = release, architecture
    select_target = repository_current_target if repository_current or input_only else target
    values["freebsd_release"] = select_target(policy, values["freebsd_release"], values["architecture"])["release"]
    for app in ("nextcloud",) if backend != "onlyoffice" else ("nextcloud", "onlyoffice"):
        if repository_current and app == "onlyoffice":
            continue
        minimum, exact = values[app + "_min"], values[app + "_exact"]
        text(minimum, NUMBER + r"(?:\." + NUMBER + r"){0,2}", app + " minimum")
        values[app + "_min"] = ".".join(map(str, stable_version(minimum)[:3]))
        if exact:
            pattern = TRIPLE + (r"(?:_" + NUMBER + r")?(?:," + NUMBER + r")?" if app == "onlyoffice" else "")
            text(exact, pattern, app + " exact pin (three upstream components)")
            if package_version(exact)[1] < stable_version(minimum):
                raise ValueError(f"{app} exact pin is below its minimum")
    if backend != "onlyoffice" and "onlyoffice" in families:
        raise ValueError("onlyoffice family applies only to the native backend")
    if backend == "none" and "connector" in families:
        raise ValueError("Nextcloud-only has no connector version family")
    if backend not in VM_BACKENDS and any(name in families for name in VM_ROLES):
        raise ValueError("VM package families require a VM backend")
    for app in ("nextcloud", "onlyoffice"):
        if app in families and values.get(app + "_exact") and not in_family(values[app + "_exact"], families[app]):
            raise ValueError(f"{app} exact pin is outside its configured family")
    if families:
        values["version_families"] = families
    return values


def satisfies(value, application, effective):
    key = package_version(value)[1]
    pin = effective[application + "_exact"]
    return (key >= stable_version(effective[application + "_min"])
            and (application not in effective.get("version_families", {})
                 or in_family(value, effective["version_families"][application]))
            and (not pin or (value == pin if "_" in pin or "," in pin
                              else key == stable_version(pin))))


def nextcloud_major(effective, profiles):
    """One pinned major; exact/minor pins must not hide newer stable releases."""
    family = effective.get("version_families", {}).get("nextcloud")
    if family:
        return int(family.split(".")[0])
    majors = set()
    for profile in profiles:
        rule = profile["applications"]["nextcloud"]
        if "family" in rule or "exact" in rule:
            majors.add(int(rule.get("family", rule.get("exact")).split(".")[0]))
        else:
            lower, upper = stable_version(rule["min"]), stable_version(rule["max_exclusive"])
            if upper[0] != lower[0] and upper != (lower[0] + 1, 0, 0, 0):
                raise ValueError("Ambiguous Nextcloud major in reviewed profiles; specify version_families.nextcloud")
            majors.add(lower[0])
    if len(majors) != 1:
        raise ValueError("Ambiguous Nextcloud major in reviewed profiles; specify version_families.nextcloud")
    return majors.pop()


def latest_nextcloud(releases, effective, profiles, *, check_constraints=True, repository_current=False):
    """Newest advertised stable release within the applicable selection contract.

    Fresh exact/family requests filter before selection. Historical strict input
    still tests constraints after selecting the newest release in its major.
    Retained-plan validation never calls this function.
    """
    major = (int(effective["nextcloud_exact"].split(".")[0])
             if repository_current and effective["nextcloud_exact"] else nextcloud_major(effective, profiles))
    candidates = []
    for version in releases:
        try:
            text(version, TRIPLE, "stable Nextcloud release")
        except ValueError:
            continue
        if stable_version(version)[0] == major and (not repository_current or satisfies(version, "nextcloud", effective)):
            candidates.append(version)
    if not candidates:
        raise ValueError(f"No stable Nextcloud release discovered in pinned major {major}; no older fallback or major change is permitted")
    latest = max(candidates, key=stable_version)
    if check_constraints and not satisfies(latest, "nextcloud", effective):
        raise ValueError(f"Latest stable Nextcloud {latest} in pinned major {major} is blocked by the configured minimum, exact pin or version family; no older fallback is permitted")
    return latest


def _root_list(values, label):
    if not isinstance(values, list) or len(values) != len(set(map(str, values))):
        raise ValueError(f"Invalid or duplicate {label}")
    for value in values:
        text(value, "(?:" + NAME + "|" + ORIGIN + ")", label)


def validate_guest_image(image):
    """Public identity shape only; neither existence nor checksum authentication."""
    fields = ("url", "sha512", "architecture", "firmware", "bootstrap", "alpine_branch")
    object_fields(image, fields, label="guest image identity")
    if (image["architecture"] != "x86_64" or image["firmware"] != "limine" or image["bootstrap"] != "cloudinit"
            or not isinstance(image["alpine_branch"], str)
            or not re.fullmatch(r"[1-9][0-9]*\.(?:0|[1-9][0-9]*)", image["alpine_branch"])):
        raise ValueError("Unsupported guest firmware/bootstrap identity")
    branch = re.escape(image["alpine_branch"])
    if (not isinstance(image["url"], str) or len(image["url"]) > 512 or not re.fullmatch(
            rf"https://dl-cdn\.alpinelinux\.org/alpine/(?:v{branch}|latest-stable)/releases/cloud/"
            rf"alpine-{branch}\.(?:0|[1-9][0-9]*)-x86_64-cloudinit-r(?:0|[1-9][0-9]*)\.qcow2", image["url"])
            or not isinstance(image["sha512"], str) or not re.fullmatch(r"[a-f0-9]{128}", image["sha512"])):
        raise ValueError("Guest image needs an exact official branch-matched URL and SHA512")
    return deepcopy(image)


def connector_php_spec(value):
    """The exact VM connector manifest forms; no invented upper bound for '*'."""
    if value == "*":
        return
    if isinstance(value, str) and re.fullmatch(r">=" + TRIPLE, value):
        stable_version(value[2:])
        return
    if isinstance(value, str):
        match = re.fullmatch(r">=(" + TRIPLE + r") +<(" + TRIPLE + ")", value)
        if match and stable_version(match[1]) < stable_version(match[2]):
            return
    raise ValueError("Unsupported connector PHP manifest declaration")


def validate_office_runtime(runtime, *, policy=False):
    object_fields(runtime, ("guest_image", "container"), ('resources', 'selection'), label="office VM runtime")
    if 'selection' in runtime:
        if runtime['selection'] != 'latest':
            raise ValueError('Unsupported office VM selection')
        image = runtime['guest_image']
        if policy:
            object_fields(image, ('directory', 'architecture', 'firmware', 'bootstrap'), label='Alpine latest selector')
            if image != {'directory': ALPINE_CLOUD_DIRECTORY, 'architecture': 'x86_64',
                         'firmware': 'limine', 'bootstrap': 'cloudinit'}:
                raise ValueError('Unsupported Alpine latest selector')
        else:
            validate_guest_image(image)
            if not image['url'].startswith(ALPINE_CLOUD_DIRECTORY):
                raise ValueError('Latest Alpine observation must use the official latest-stable directory')
        container = object_fields(runtime['container'], ('reference', 'architecture', 'frontend_port', 'guest_port'), label='latest container selection')
        if (not isinstance(container['reference'], str) or container['reference'] not in LATEST_CONTAINERS
                or container['architecture'] != 'amd64' or type(container['frontend_port']) is not int
                or container['frontend_port'] != LATEST_CONTAINERS[container['reference']]
                or type(container['guest_port']) is not int or container['guest_port'] != 8081):
            raise ValueError('Unsupported latest container selection')
        return _runtime_resources(runtime)
    validate_guest_image(runtime["guest_image"])
    if '/latest-stable/' in runtime['guest_image']['url']:
        raise ValueError('Legacy guest identity requires its exact versioned branch URL')
    container = object_fields(runtime["container"], ("reference", "index_digest", "release", "architecture", "frontend_port", "guest_port"), ('entrypoint_sha256','configuration_sha256','product_version'), label="container identity")
    release = container['release']
    valid_release = False
    if isinstance(release, str) and len(release) <= 64:
        valid_release = re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,4}', release) is not None
        rebuild = re.fullmatch(r'([0-9]+\.[0-9]+\.[0-9]+)-[1-9][0-9]*', release)
        if rebuild:
            # Euro's tagged CI publishes positive numeric stable rebuilds, not
            # prereleases. Keep the image label distinct from its reported
            # product version, with both still bound to the exact OCI digest.
            valid_release = (isinstance(container['reference'], str)
                             and container['reference'].split('@', 1)[0] == 'ghcr.io/euro-office/documentserver'
                             and container.get('product_version') == rebuild[1])
    pattern = r"(?:ghcr\.io|docker\.io)/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}"
    if (not isinstance(container["reference"], str) or len(container["reference"]) > 512
            or not re.fullmatch(pattern, container["reference"])
            or not isinstance(container["index_digest"], str)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", container["index_digest"])
            or not valid_release
            or container["architecture"] != "amd64" or type(container["frontend_port"]) is not int
            or not 1 <= container["frontend_port"] <= 65535
            or type(container["guest_port"]) is not int or container["guest_port"] != 8081):
        raise ValueError("Unsupported or mutable container runtime identity")
    if 'entrypoint_sha256' in container:
        text(container['entrypoint_sha256'],r'[a-f0-9]{64}','container entrypoint SHA256')
    if 'configuration_sha256' in container:
        text(container['configuration_sha256'],r'[a-f0-9]{64}','container configuration SHA256')
    if 'product_version' in container:
        text(container['product_version'],r'[0-9]+(?:\.[0-9]+){2,3}','reported container product version')
    return _runtime_resources(runtime)


def _runtime_resources(runtime):
    if 'resources' in runtime:
        resources=object_fields(runtime['resources'],('minimum','defaults'),label='VM resource policy')
        for name in ('minimum','defaults'):
            values=object_fields(resources[name],('cpus','memory_mb','disk_gib'),label='VM resource allocation')
            if any(type(v) is not int or v<1 for v in values.values()):
                raise ValueError('VM resource policy must contain explicit positive integers')
        if any(resources['defaults'][key]<resources['minimum'][key] for key in resources['minimum']):
            raise ValueError('VM default allocation is below its reviewed minimum')
    return deepcopy(runtime)


def validate_runtime_artifacts(runtime, proof):
    """Match discovery evidence; latest containers are retrieved by Docker, not probed."""
    validate_office_runtime(runtime)
    if runtime.get('selection') == 'latest':
        object_fields(proof, ('guest_image',), label='latest VM artifact observation')
        image = object_fields(proof['guest_image'], tuple(runtime['guest_image']) + ('available',), label='guest availability')
        if image['available'] is not True or {k: v for k, v in image.items() if k != 'available'} != runtime['guest_image']:
            raise ValueError('Selected latest guest image observation is unavailable or mismatched')
        return deepcopy(proof)
    object_fields(proof, ("guest_image", "container"), label="VM artifact availability")
    image = object_fields(proof["guest_image"], ("url", "sha512", "available"), label="guest availability")
    container = object_fields(proof["container"], ("reference", "index_digest", "architecture", "os", "available"), label="container availability")
    if (image["available"] is not True or container["available"] is not True or container["os"] != "linux"
            or any(image[key] != runtime["guest_image"][key] for key in ("url", "sha512"))
            or any(container[key] != runtime["container"][key] for key in ("reference", "index_digest", "architecture"))):
        raise ValueError("Selected VM image/container identity is unavailable or mismatched")
    return deepcopy(proof)


def _evidence(values):
    if not isinstance(values, list) or not values:
        raise ValueError("Policy requires dated source evidence")
    for item in values:
        object_fields(item, ("url", "reviewed", "scope"), label="source evidence")
        text(item["url"], r"https://[^\s]+", "evidence URL")
        text(item["reviewed"], r"[0-9]{4}-[0-9]{2}-[0-9]{2}", "review date")
        date.fromisoformat(item["reviewed"])
        text(item["scope"], r"[^\x00-\x1f\x7f]+", "evidence scope")


def validate_policy(policy):
    object_fields(policy, ("schema_version", "defaults", "legacy_target", "targets", "fonts", "profiles", "evidence"), ("package_installation", "repository_current_platform"), label="version policy")
    repository_current_platform(policy)
    if "package_installation" in policy:
        from .package_policy import repository_current
        repository_current(policy)
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise ValueError("Unsupported version policy schema")
    object_fields(policy["defaults"], FIELDS, label="policy defaults")
    if not all(isinstance(value, str) for value in policy["defaults"].values()):
        raise ValueError("Policy defaults must be strings")
    if not isinstance(policy["targets"], list) or not policy["targets"]:
        raise ValueError("Policy requires explicit targets")
    targets = set()
    for item in policy["targets"]:
        object_fields(item, ("release", "architecture", "abi", "pkgbase_keys"), label="policy target")
        if release_base(item["release"]) != item["release"]:
            raise ValueError("Policy targets must use an unpatched release base")
        text(item["architecture"], r"[a-z0-9]+", "architecture")
        if item["abi"] != "FreeBSD:" + item["release"].split(".")[0] + ":" + item["architecture"]:
            raise ValueError("Policy target ABI does not match its release/architecture")
        if not isinstance(item["pkgbase_keys"], list) or not item["pkgbase_keys"]:
            raise ValueError("Target requires explicit pkgbase trust-key paths")
        for path in item["pkgbase_keys"]:
            text(path, r"/[A-Za-z0-9_./-]+", "pkgbase key path")
            if ".." in PurePosixPath(path).parts:
                raise ValueError("pkgbase key paths must not traverse parents")
        identity = item["release"] + "/" + item["architecture"]
        if identity in targets:
            raise ValueError("Duplicate policy target")
        targets.add(identity)
    if policy["legacy_target"] not in targets:
        raise ValueError("The historical schema-2 target must remain explicitly supported")
    constraints(object(), policy)
    object_fields(policy["fonts"], ("required", "optional"), label="font policy")
    for values in policy["fonts"].values():
        _root_list(values, "font package names")
        for value in values:
            text(value, NAME, "font package name")
    if not policy["fonts"]["required"] or set(policy["fonts"]["required"]) & set(policy["fonts"]["optional"]):
        raise ValueError("Font policy requires distinct mandatory and optional packages")
    if not isinstance(policy["profiles"], list) or not policy["profiles"]:
        raise ValueError("Policy requires compatibility profiles")
    ids = set()
    for profile in policy["profiles"]:
        backend = profile.get("office_backend", "onlyoffice") if isinstance(profile, dict) else "onlyoffice"
        none, vm = backend == "none", backend in VM_BACKENDS
        common = ("id", "targets", "applications", "dependency_policy", "php_suffix", "roles", "roots",
                  "php_extensions", "extension_ranges", "optional_roots")
        extra = ("office_backend",) if none else ("office_backend", "connector", "office_runtime", "evidence") if vm else ("connector", "onlyoffice_runtime")
        object_fields(profile, common + extra, ("extension_origins", "repository_current_targets"), label="profile")
        groups = GROUPS if backend == "onlyoffice" else ("host", "nextcloud")
        text(profile["id"], NAME, "profile identifier")
        if profile["id"] in ids:
            raise ValueError("Duplicate profile identifier")
        ids.add(profile["id"])
        _root_list(profile["targets"], "profile targets")
        if not profile["targets"] or set(profile["targets"]) - targets:
            raise ValueError("Profile references an unknown target")
        if "repository_current_targets" in profile:
            _root_list(profile["repository_current_targets"], "repository-current profile targets")
            if (backend != "onlyoffice" or not profile["repository_current_targets"]
                    or set(profile["repository_current_targets"]) - targets):
                raise ValueError("Repository-current native profile references an unknown target/backend")
        object_fields(profile["applications"], ("nextcloud", "onlyoffice") if backend == "onlyoffice" else ("nextcloud",), label="application ranges")
        for rule in profile["applications"].values():
            _range(rule)
        if vm:
            connector = object_fields(profile["connector"], ("app_id", "version", "nextcloud", "php_manifest"), label="VM connector compatibility")
            if connector["app_id"] != CONNECTOR_APPS[backend]:
                raise ValueError("Connector app ID does not match selected backend")
            _range(connector["version"])
            _range(connector["nextcloud"])
            connector_php_spec(connector["php_manifest"])
            runtime = profile['office_runtime']
            validate_office_runtime(runtime, policy=runtime.get('selection') == 'latest')
            if runtime.get('selection') == 'latest' and runtime['container']['reference'] != {
                    'eurooffice': 'ghcr.io/euro-office/documentserver:latest',
                    'collabora': 'docker.io/collabora/code:latest'}[backend]:
                raise ValueError('Latest container selection does not match the backend')
            if runtime.get('selection') != 'latest' and backend=='eurooffice' and 'entrypoint_sha256' not in profile['office_runtime']['container']:
                raise ValueError('Euro-Office runtime requires its reviewed standalone entrypoint identity')
            if runtime.get('selection') != 'latest' and backend=='collabora' and not {'configuration_sha256','product_version'}<=set(profile['office_runtime']['container']):
                raise ValueError('Collabora runtime requires its reviewed configuration and product identity')
            if 'resources' not in profile['office_runtime']:
                raise ValueError('VM profile requires reviewed resource policy')
            _evidence(profile["evidence"])
            if any(not item.endswith("/amd64") for item in profile["targets"]):
                raise ValueError("VM runtime has no reviewed target architecture")
        elif not none:
            object_fields(profile["connector"], ("version", "nextcloud", "php"), label="connector compatibility")
            for rule in profile["connector"].values():
                _range(rule)
        if ((backend == "onlyoffice" and profile["onlyoffice_runtime"] != "native-community-memory-embedded")
                or profile["dependency_policy"] != "exact-repository-closure"):
            raise ValueError("Unsupported runtime/dependency policy")
        text(profile["php_suffix"], r"[0-9]{2,3}", "PHP package suffix")
        roles = ("manager", "php", "database", "database_client", "web", "cache")
        required_roles = roles + VM_ROLES if vm else roles if none else roles + ("onlyoffice",)
        object_fields(profile["roles"], required_roles, label="roles")
        for role, rule in profile["roles"].items():
            object_fields(rule, ("package", "origin", "groups"), ("range", "version_exact") if vm else ("range",), label=role + " rule")
            text(rule["package"], NAME, "role package")
            text(rule["origin"], ORIGIN, "role origin")
            _root_list(rule["groups"], "role groups")
            if not rule["groups"] or set(rule["groups"]) - set(groups):
                raise ValueError("Unknown or missing role group")
            if "range" in rule and "version_exact" not in rule:
                _range(rule["range"])
            elif vm and role in VM_ROLES and "version_exact" in rule and "range" not in rule:
                text(rule["version_exact"], r"[A-Za-z0-9][A-Za-z0-9_+.,~:-]*", "exact VM host package version")
            else:
                raise ValueError(f"Missing bounded range for {role}")
            if vm and role.startswith("vm_") and rule["groups"] != ["host"]:
                raise ValueError("VM tools belong only on the host")
        if profile["roles"]["php"]["package"] != "php" + profile["php_suffix"]:
            raise ValueError("PHP suffix and runtime package disagree")
        object_fields(profile["roots"], groups, label="root groups")
        for group, roots in profile["roots"].items():
            _root_list(roots, group + " roots")
        extensions = profile["php_extensions"]
        if not isinstance(extensions, list) or not extensions:
            raise ValueError("Missing PHP extension policy")
        for extension in extensions:
            text(extension, r"php\{suffix\}-[A-Za-z0-9_+-]+", "PHP extension template")
        if len(set(extensions)) != len(extensions):
            raise ValueError("Duplicate PHP extension template")
        if not isinstance(profile["extension_ranges"], dict) or set(profile["extension_ranges"]) - set(extensions):
            raise ValueError("Extension compatibility ranges must name required PHP extensions")
        for rule in profile["extension_ranges"].values():
            _range(rule)
        origins = profile.get("extension_origins", {})
        if not isinstance(origins, dict) or set(origins) - set(extensions):
            raise ValueError("Extension origins must name required PHP extensions")
        for origin in origins.values():
            text(origin, ORIGIN, "PHP extension origin")
        object_fields(profile["optional_roots"], ("acme", "zsh", "ssh_admin"), optional=("antivirus",), label="conditional roots")
        for conditional in profile["optional_roots"].values():
            object_fields(conditional, (), groups, label="conditional root groups")
            for roots in conditional.values():
                _root_list(roots, "conditional roots")
    _evidence(policy["evidence"])
    return policy


def load_policy():
    """Read the authoritative resource on demand; never freeze defaults at import."""
    from .paths import RESOURCES
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate policy field: {key}")
            result[key] = value
        return result
    try:
        policy = json.loads((RESOURCES / "versions.json").read_text(), object_pairs_hook=unique)
        # Reuse the established font catalog rather than maintain another copy.
        # Expanded contents participate in the immutable policy digest.
        if policy.get("fonts") == {"catalog": "packages/fonts.txt"}:
            fonts = {"required": [], "optional": []}
            for line in (RESOURCES / "packages/fonts.txt").read_text().splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                fields = line.split()
                if len(fields) != 2 or fields[0] not in fonts:
                    raise ValueError("Malformed font package catalog")
                fonts[fields[0]].append(fields[1])
            policy["fonts"] = fonts
        return validate_policy(policy)
    except (OSError, ValueError) as error:
        raise ValueError(f"Cannot load resources/versions.json: {error}") from error


def vm_resource_policy(config, policy=None):
    """Select one reviewed allocation policy without host probes or writes."""
    if office_backend(config) not in VM_BACKENDS:
        raise ValueError('VM resource policy requires a selected VM backend')
    policy = load_policy() if policy is None else validate_policy(policy)
    current = bool(getattr(config, "has_native_services", False))
    profiles = selected_profiles(config, policy, repository_current=current)
    effective = constraints(config, policy, repository_current=current)
    def matches(profile):
        rule = profile['applications']['nextcloud']
        if effective['nextcloud_exact']:
            return in_range(effective['nextcloud_exact'], rule)
        lower, upper = _range_bounds(rule)
        lower = max(lower, stable_version(effective['nextcloud_min']))
        family = effective.get('version_families', {}).get('nextcloud')
        if family:
            floor, ceiling = _range_bounds({'family': family})
            lower, upper = max(lower, floor), min(upper, ceiling)
        return lower < upper
    profiles = [p for p in profiles if current or matches(p)]
    if len(profiles) != 1:
        raise ValueError('Narrow the Nextcloud family or pin to one reviewed VM resource profile')
    return deepcopy(profiles[0]['office_runtime']['resources'])


def _range_bounds(rule):
    """Half-open numeric interval used only to disambiguate static VM sizing."""
    if 'family' in rule:
        parts = list(map(int, rule['family'].split('.')))
        lower = stable_version(rule.get('min', rule['family']))
        parts[-1] += 1
        return lower, stable_version('.'.join(map(str, parts)))
    if 'exact' in rule:
        lower = stable_version(rule['exact'])
        return lower, lower[:3] + (lower[3] + 1,)
    return stable_version(rule['min']), stable_version(rule['max_exclusive'])


def defaults(policy=None):
    return deepcopy((load_policy() if policy is None else validate_policy(policy))["defaults"])


def policy_hash(policy, backend="onlyoffice"):
    validate_policy(policy)
    if backend not in ("onlyoffice", "none", *VM_BACKENDS):
        raise ValueError(f"No reviewed version policy for office_backend={backend!r}")
    # Adding a disjoint backend must not change historical native lock bytes.
    selected = deepcopy(policy)
    selected["profiles"] = [profile for profile in policy["profiles"]
                            if profile.get("office_backend", "onlyoffice") == backend]
    return hashlib.sha256(json.dumps(selected, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def manager_supported(version, policy=None):
    policy = load_policy() if policy is None else validate_policy(policy)
    try:
        if "package_installation" in policy:
            # A tested Bastille release is not an ordinary package version gate.
            # Origin/ABI and native command behavior remain separate checks.
            text(version, r"[A-Za-z0-9._+][A-Za-z0-9_+.,~:-]*", "Bastille package version")
            return True
        return any(in_range(version, profile["roles"]["manager"]["range"]) for profile in policy["profiles"])
    except ValueError:
        return False
