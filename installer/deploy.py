"""Checkpointed instance orchestration on an exclusively managed FreeBSD host."""

from pathlib import Path
import hashlib
import json
import os
import re
import select
import shutil
import sys
import time
import uuid

from .config import STATE_DIR, Dataset, datasets
from .bastille import BASTILLE
from .host import write_json, write_private
from .network import pf_rules, storage_guard
from . import firewall
from .paths import PROJECT_ROOT as ROOT, RESOURCES
from .state import Journal, Registry, atomic_json, atomic_write, private_json, private_directory
from .service_deadlines import require_resolved, run_jail_action, ServiceControlError, REFUSAL


PF_FILE = Path("/etc/pf.cloud-installer.conf")
OWNER = "org.cloud-installer:instance"
COMPLETE_MESSAGE = "Installer checks passed; external proxy/browser/reboot acceptance remains required.\n"
BRANDING_FILES = tuple("assets/branding/nextcloud/" + name for name in
                       ("logo.png", "logoheader.png", "favicon.png", "background.jpg"))


def talk_payload_sources(plan):
    """Host copy selection only; the Talk worker authenticates its own inputs."""
    from .package_policy import repository_current
    sources = ("installer/__init__.py", "installer/talk.py", "resources/templates/talk", "resources/jails/talk.sh",
               "resources/jails/talk-runtime.py", "resources/jails/versions.sh", "resources/native-services.json")
    if repository_current(plan):
        sources += ("installer/version_runtime.py", "installer/package_policy.py", "installer/versions.py",
                    "resources/versions.json")
    return sources


def source_digest():
    """Identity of execution code/resources, independent of live credentials."""
    digest = hashlib.sha256()
    for directory in (ROOT / "installer", RESOURCES):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes())
    for relative in BRANDING_FILES:
        path = ROOT / relative
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != ROOT):
            raise ValueError("Branding source must not contain symlinks")
        if path.is_file():
            digest.update(relative.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest() + "\n"


def public_directories(path, boundary):
    """Create public jail/host ancestors without inheriting the private umask.

    Existing directory modes are never widened; callers must supply an already
    verified root. Private state/payload directories must not use this helper.
    """
    boundary = Path(boundary)
    parts = Path(path).relative_to(boundary).parts
    if (boundary.is_symlink() or not boundary.is_dir()
            or any(part in (".", "..") for part in parts)):
        raise ValueError("Unexpected public directory boundary")
    current = boundary
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Public directory ancestors must not be symlinks")
        if current.exists():
            if not current.is_dir():
                raise ValueError("Public directory ancestor is not a directory")
        else:
            current.mkdir(mode=0o755)
            current.chmod(0o755)


def managed_block(path, label, contents, mode=0o644):
    """Replace our delimited block only; preserve unrelated packaged defaults."""
    path = Path(path)
    start, end = f"# BEGIN cloud-installer {label}", f"# END cloud-installer {label}"
    text = path.read_text() if path.exists() else ""
    if text.count(start) != text.count(end) or text.count(start) > 1:
        raise ValueError(f"Ambiguous managed block in {path}")
    block = start + "\n" + contents.rstrip() + "\n" + end
    if start in text:
        text = re.sub(re.escape(start) + r".*?" + re.escape(end), lambda _: block, text, flags=re.S)
    else:
        text = text.rstrip() + "\n\n" + block + "\n"
    atomic_write(path, text, mode)


class Deployment:
    def __init__(self, config, secrets, runner, ssh_connection=None, *, registry=None, progress=None):
        self.config = config.validate()
        config.require_jail_backend("Deployment operations")
        self.secrets = secrets
        self.runner = runner
        self.ssh_connection = ssh_connection
        self.registry = registry or Registry()
        self.state = self.registry.instance_path(config.instance)
        self.progress = progress
        self.storage = datasets(config)
        self.manifest = {}
        self._versions = None
        self._vm_image = None

    @property
    def versions(self):
        from .resolution import validate_plan
        if self._versions is None:
            path = self.registry.evidence_path(self.config.instance, "versions.json")
            if not path.is_file() or path.is_symlink():
                raise ValueError("No retained version lock: use the original installer artifact for an older deployment; do not infer an upgrade")
            policy_reader = getattr(self.registry, "version_policy", None)
            policy = policy_reader(self.config.instance) if policy_reader is not None else None
            self._versions = validate_plan(self.config, private_json(path), policy=policy)
        return self._versions

    def prepare_versions(self):
        """Resolve once, before host/storage mutations; Resume never reselects."""
        self.require_control_resolution()
        from .discovery import discover, probe_packages
        from .resolution import resolve
        from .package_policy import repository_current
        path = self.state / "versions.json"
        if path.exists() or path.is_symlink():
            plan = self.versions
        else:
            if (self.state / "deployment.json").exists() or (self.state / "source.sha256").exists():
                raise ValueError("An existing deployment without a version lock requires its original artifact; automatic adoption/upgrades are unsupported")
            plan = resolve(self.config, discover(self.config, self.runner, directory=self.registry.root))
        if not repository_current(plan):
            probe_packages(self.config, plan, self.runner, directory=self.registry.root)
            # Retained artifacts keep their exact host/closure contract.
            for name, package in plan["packages"]["host"].items():
                current = self.runner.run("pkg", "query", "%v|%o", name, check=False)
                if current.returncode == 0 and current.stdout.strip() != package["version"] + "|" + package["origin"]:
                    raise ValueError(f"Installed host package {name} differs from the resolved plan; an explicit host maintenance assessment is required")
        if not path.exists():
            atomic_json(path, plan)
        self._versions = plan
        return plan

    def checkpoint(self):
        self.require_control_resolution()
        atomic_json(self.state / "inventory.json", self.manifest)

    def require_control_resolution(self):
        from .service_runtime import require_host_controls_resolved
        require_resolved(self)
        require_host_controls_resolved(self.registry)

    def verify_jail_stopped(self, name, seconds=60):
        """Observe closure only: no repeated stop, live/dying aliases included."""
        from .initialization import _jail
        deadline = time.monotonic() + min(60, seconds)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Owned jail closure deadline expired")
            live = _jail(self, name, timeout=min(10, remaining))
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned jail closure deadline expired")
            if live is None:
                break
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Owned jail closure deadline expired")
        rows = [line.split() for line in self.runner.run("mount", "-p", timeout=min(10, remaining)).stdout.splitlines() if line.strip()]
        if time.monotonic() >= deadline or not rows or any(len(row) < 6 for row in rows):
            raise RuntimeError("Cannot establish the stopped jail mount inventory")
        root = str(self.jail_root(name)) + "/"
        if any(row[2] == "nullfs" and row[1].startswith(root) for row in rows):
            raise RuntimeError("Stopped owned jail retains nullfs mounts")

    def verify_jail_running(self, name, seconds=60):
        from .initialization import _jail
        deadline = time.monotonic() + min(60, seconds)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Owned jail did not become running within its budget")
            live = _jail(self, name, timeout=min(10, remaining))
            if live is not None and not live[1]:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.require_running_jail(name, timeout=min(10, remaining)) != live[0]:
                    raise RuntimeError("Owned jail changed during startup observation")
                if time.monotonic() >= deadline:
                    raise RuntimeError("Owned jail running observation exceeded its budget")
                return
            time.sleep(min(1, max(0, deadline - time.monotonic())))

    def control_jail(self, action, name, *, prepared=True):
        self.require_control_resolution()
        try:
            return run_jail_action(self.runner, action, name, deployment=self, prepared=prepared,
                                   verify_stopped=self.verify_jail_stopped, verify_running=self.verify_jail_running,
                                   capture=False)
        except BaseException:
            self._uncertain_jail = name
            raise

    def contain_jail(self, name):
        """Stop the exact reserved jail and establish closure before more writes."""
        from .initialization import _jail
        self.require_control_resolution()
        root = self.jail_root(name)
        try:
            if private_json(self.state / (name + ".creating.json")) != {"name": name, "root": str(root), "release": self.config.release}:
                raise ValueError("Jail containment requires its exact creation reservation")
            configured = self.runner.run(*BASTILLE, "config", name, "get", "path",
                                         check=False, hide_output=True, timeout=10)
            if configured.returncode or configured.stdout.strip() != str(root):
                raise ValueError("Bastille exact jail root cannot be confirmed for containment")
            live = _jail(self, name)
            if live and not live[1]:
                if self.require_running_jail(name) != live[0]:
                    raise RuntimeError("Owned jail identity changed before containment")
                prepared = "exec.prepare" in (root.parent / "jail.conf").read_text()
                try:
                    self.control_jail("stop", name, prepared=prepared)
                except ServiceControlError:
                    self.require_control_resolution()  # Never race an unclosed host group.
                    self.verify_jail_stopped(name)
                    return  # Containment proved, not success of the failed phase.
            self.verify_jail_stopped(name)
        except BaseException:
            # Diagnostic only; no automatic marker clearing or uncertain replay.
            if not (self.state / REFUSAL).exists() and not (self.state / REFUSAL).is_symlink():
                atomic_json(self.state / REFUSAL, {"jail": name, "state": "unresolved", "reason": "jail-containment-unconfirmed"})
            raise

    @property
    def plugin_lock(self):
        from .plugins import validate_lock
        from .package_policy import repository_current
        from .versions import in_family, package_upstream
        path = self.registry.evidence_path(self.config.instance, "plugins.json")
        if not path.is_file() or path.is_symlink():
            raise ValueError("Selected plugins require their original retained lock; no automatic plugin adoption")
        lock = private_json(path)
        validate_lock(lock, self.config.onlyoffice_plugins)
        # Keep the catalog immutable. Repository-current manifests are checked
        # against actual Docs at execution; retained artifacts keep their gate.
        if not repository_current(self.versions):
            version = package_upstream(self.versions["packages"]["onlyoffice"]["onlyoffice-documentserver"]["version"])
            if not in_family(version, "9.4"):
                raise ValueError("Selected plugins are not reviewed for this ONLYOFFICE version")
        return lock

    def prepare_plugins(self):
        self.require_control_resolution()
        from .plugins import check_cache, check_payloads, make_lock, prepare
        from .package_policy import repository_current
        from .versions import package_upstream
        if not self.config.onlyoffice_plugins:
            return
        path = self.state / "plugins.json"
        if (self.state / "source.sha256").exists():
            self.require_original_artifact()
        if not path.exists() and not path.is_symlink():
            if (self.state / "deployment.json").exists() or (self.state / "source.sha256").exists():
                raise ValueError("An existing deployment cannot acquire a guessed plugin lock")
            atomic_json(path, make_lock(self.config.onlyoffice_plugins))
        lock = self.plugin_lock
        # Authenticate all selected bytes before provisioning; Resume reuses only
        # this exact selection and refuses changed/unavailable locked inputs.
        prepare(lock, self.state / "plugin-artifacts")
        if repository_current(self.versions):
            # Authenticate catalog bytes now; vendor manifest compatibility must
            # use the actually installed Docs version at execution, not preview.
            check_cache(lock, self.state / "plugin-artifacts")
        else:
            check_payloads(lock, self.state / "plugin-artifacts", docs_version=package_upstream(
                self.versions["packages"]["onlyoffice"]["onlyoffice-documentserver"]["version"]))

    def installed_onlyoffice_version(self):
        from .package_policy import repository_current
        from .versions import package_upstream
        if repository_current(self.versions):
            from .service_runtime import inspect_package_requirements
            observed, _ = inspect_package_requirements(self, "onlyoffice", names=("onlyoffice-documentserver",))
            return package_upstream(observed["onlyoffice-documentserver"][0])
        return package_upstream(self.versions["packages"]["onlyoffice"]["onlyoffice-documentserver"]["version"])

    def stage_plugins(self, target):
        from .plugins import check_cache
        lock = self.plugin_lock
        source = self.state / "plugin-artifacts"
        check_cache(lock, source)
        atomic_json(target / "plugins.json", lock)
        destination = private_directory(target / "plugin-artifacts")
        for name, record in lock["plugins"].items():
            for item in record["artifacts"]:
                relative = Path(name) / item["path"]
                parent = destination
                for component in relative.parts[:-1]:
                    parent = private_directory(parent / component)
                output = destination / relative
                if output.is_symlink() or (output.exists() and not output.is_file()):
                    raise ValueError("Unsafe plugin staging destination")
                shutil.copyfile(source / relative, output, follow_symlinks=False)
                output.chmod(0o600)
        check_cache(lock, destination)

    def plugin_command(self, mode):
        from .package_policy import repository_current
        if mode not in ("install", "verify"):
            raise ValueError("Unknown managed plugin operation")
        if not self.config.onlyoffice_plugins:
            return
        self.plugin_lock  # Bind the staged jail operation to the immutable host selection.
        payload = self.jail_root(self.config.onlyoffice_jail) / "root/cloud-installer"
        if private_json(payload / "plugins.json") != self.plugin_lock:
            raise ValueError("Staged plugin lock differs from retained host selection")
        current = repository_current(self.versions)
        docs_version = self.installed_onlyoffice_version()
        if current and mode == "install":
            from .plugins import check_payloads
            check_payloads(self.plugin_lock, self.state / "plugin-artifacts", docs_version=docs_version,
                           repository_current=True)
        self.jail(self.config.onlyoffice_jail, "python3", "/root/cloud-installer/installer/plugins.py", mode,
                  "--lock", "/root/cloud-installer/plugins.json",
                   "--cache", "/root/cloud-installer/plugin-artifacts",
                   "--docs-version", docs_version,
                  "--root", "/usr/local/www/onlyoffice/documentserver/sdkjs-plugins",
                   "--state", "/var/db/cloud-installer-onlyoffice/plugins",
                  *(("--repository-current",) if current else ()))
        if mode == "verify":
            self.manifest["onlyoffice_plugins"] = {
                name: {"version": record["version"], "guid": record["guid"]}
                for name, record in self.plugin_lock["plugins"].items()}

    def pkg(self, *args, **kwargs):
        return self.runner.run("/usr/bin/env", "-i",
                               "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C",
                               "pkg", "-C", "/dev/null", "-o", f"REPOS_DIR={self.registry.root / 'repos'}", *args, **kwargs)

    def jail_root(self, name):
        if name not in self.config.jails:
            raise ValueError("Unexpected jail name")
        return Path(self.config.bastille_root, "jails", name, "root")

    def require_running_jail(self, name, *, timeout=10):
        if name not in self.config.jails:
            raise ValueError("Refusing to execute in an unmanaged jail")
        result = self.runner.run("jls", "-j", name, "jid", "name", "path",
                                 check=False, hide_output=True, timeout=timeout)
        identity = (result.stdout or "").split()
        if (result.returncode or len(identity) != 3 or not identity[0].isdigit()
                or int(identity[0]) < 1 or identity[1] != name or identity[2] != str(self.jail_root(name))):
            raise RuntimeError(f"Managed jail {name} is stopped or has an unexpected identity/root")
        return int(identity[0])

    def jail(self, name, *args, **kwargs):
        self.require_control_resolution()
        # Bastille 1.4.4 cmd skips stopped jails with exit status zero. Require
        # the same live jail identity on both sides, not just command success.
        jid = self.require_running_jail(name)
        # jexec receives stdin unchanged. Bastille's multi-target cmd helper may
        # consume stdin; pin execution to the live JID already checked above.
        check = kwargs.pop("check", True)
        try:
            result = self.runner.run("jexec", str(jid), *args, check=False, **kwargs)
            if result.returncode in (70, 124):
                self._uncertain_jail = name
        finally:
            # Raised transport errors and cancellation also require the same
            # numeric JID/name/root check before any caller interprets an outcome.
            if self.require_running_jail(name) != jid:
                raise RuntimeError(f"Managed jail {name} restarted during command execution") from None
        if check and result.returncode:
            raise RuntimeError(f"Private jail command failed (exit status {result.returncode})")
        return result

    def install_manager(self):
        self.require_control_resolution()
        from .package_policy import repository_current
        repos = private_directory(self.registry.root / "repos")
        atomic_write(repos / "FreeBSD.conf", '''FreeBSD-ports: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/''' + self.config.repository + '''",
  mirror_type: "srv", signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg", enabled: yes
}
''')
        if repository_current(self.versions):
            from .service_runtime import install_host_requirements
            install_host_requirements(self)
        else:
            self.install_locked_host_packages()
        self.manifest["bastille_package"] = self.runner.output("pkg", "query", "%nv", "bastille")
        from .bastille import CONFIG_PATH, SAMPLE_PATH, configuration, owned_text, reserve_devfs
        owned_text(SAMPLE_PATH)  # Installed package defaults, never administrator config.
        text = configuration(self.config, reserve_devfs(self.registry, self.runner))
        path = Path(CONFIG_PATH)
        if path.exists() or path.is_symlink():
            if owned_text(path) != text:
                raise ValueError("Project Bastille configuration changed; refusing replacement")
        else:
            atomic_write(path, text)

    def install_locked_host_packages(self):
        """Retained exact-package path; never infer repository-current semantics."""
        packages, missing = self.versions["packages"]["host"], []
        for name, record in packages.items():
            installed = self.runner.run("pkg", "query", "%v|%o", name, check=False)
            if installed.returncode:
                missing.append(name)
            elif installed.stdout.strip() != record["version"] + "|" + record["origin"]:
                raise ValueError(f"Installed host package {name} differs from the retained version plan; refusing an implicit upgrade/downgrade")
        if missing:
            self.pkg("update", "-r", "FreeBSD-ports", capture=False)
            for name, record in packages.items():
                identity = self.pkg("rquery", "-U", "-r", "FreeBSD-ports", "%n|%v|%o|%u%d%{%|%}", name).stdout.strip()
                edges = self.pkg("rquery", "-U", "-r", "FreeBSD-ports", "%dn|%dv|%do", name).stdout.strip().splitlines()
                expected_edges = [f"{key}|{value['version']}|{value['origin']}" for key, value in record["dependencies"].items()]
                if identity != "|".join(record[key] for key in ("name", "version", "origin", "checksum")) or sorted(edges) != sorted(expected_edges):
                    raise ValueError(f"Host package {name} repository version/dependencies differ from the retained plan; no substitution is permitted")
            from .service_runtime import install_missing_host_packages
            args = [name + "-" + packages[name]["version"] for name in sorted(missing)]
            install_missing_host_packages(self, missing, arguments=args)
        for name, record in packages.items():
            if self.runner.output("pkg", "query", "%v|%o", name) != record["version"] + "|" + record["origin"]:
                raise RuntimeError(f"Installed host package {name} does not match the resolved version/origin")

    def ensure_dataset(self, dataset, owner):
        self.require_control_resolution()
        exists = self.runner.run("zfs", "list", "-H", dataset.name, check=False).returncode == 0
        if exists:
            if self.runner.output("zfs", "get", "-H", "-o", "value", OWNER, dataset.name) != owner:
                raise ValueError(f"Refusing unowned dataset: {dataset.name}")
            if self.runner.output("zfs", "get", "-H", "-o", "value", "mountpoint", dataset.name) != dataset.mountpoint:
                raise ValueError(f"Managed dataset mountpoint changed: {dataset.name}")
        else:
            target = Path(dataset.mountpoint)
            if target.is_symlink() or (target.exists() and any(target.iterdir())):
                raise ValueError(f"Refusing to cover existing storage: {dataset.mountpoint}")
            command = ["zfs", "create", "-o", f"{OWNER}={owner}", "-o", "org.cloud-installer:owner=cloud-installer"]
            for name, value in dataset.properties.items():
                command.extend(["-o", f"{name}={value}"])
            self.runner.run(*command, dataset.name)
        if self.runner.output("zfs", "get", "-H", "-o", "value", "mounted", dataset.name) != "yes":
            self.runner.run("zfs", "mount", dataset.name)
        # ZFS properties and the actual mount must agree, not just a directory.
        if self.runner.output("df", "-P", dataset.mountpoint).splitlines()[-1].split()[0] != dataset.name:
            raise RuntimeError(f"Dataset is not the actual filesystem at {dataset.mountpoint}")

    def create_shared_storage(self):
        c = self.config
        shared = [Dataset(f"{c.pool}/cloud-installer", "/srv/cloud-installer", executable=True),
                        Dataset(f"{c.pool}/cloud-installer/instances", "/srv/cloud-installer/instances", executable=True),
                        Dataset(c.bastille_dataset, c.bastille_root, executable=True)]
        if c.backend in ('eurooffice','collabora'):
            from .office_vm import vm_paths
            paths = vm_paths(c)
            shared.append(Dataset(paths['manager_dataset'], paths['manager_root']))
        for dataset in shared:
            self.ensure_dataset(dataset, "shared")
            self.runner.run("chmod", "700", dataset.mountpoint)

    def create_storage(self):
        for dataset in self.storage:
            self.ensure_dataset(dataset, self.config.instance)
            if dataset.name in (self.config.dataset_root, self.config.dataset_root + '/office-vm'):
                # Jail processes enter their root vnodes directly, but ordinary
                # host users must not traverse into raw document caches/secrets.
                self.runner.run("chmod", "700", dataset.mountpoint)

    def configure_network(self, *, removing=False):
        self.require_control_resolution()
        from .host import _check_ingress, read_private, verify_managed_network
        from .bastille import owned_text
        from .network import boot_network_script
        c = self.config
        if firewall.pending_transactions(self.registry.root):
            raise ValueError("An unconfirmed network transaction remains; use recover-network before another PF change")
        firewall.verify_parent(self.runner)
        if not removing:
            _check_ingress(c, self.runner)
        active = self.registry.root / "network/active"
        previous = active.resolve() if active.is_symlink() else None
        if previous:
            verify_managed_network(self.registry, self.runner)
            if private_json(previous / "firewall-transition.json").get("architecture") != firewall.OWNERSHIP:
                raise ValueError("Legacy PF transaction requires the original retained installer")
        else:
            for args in (("-sr",), ("-sn",), ("-s", "Anchors"), ("-s", "Tables")):
                if self.runner.output("pfctl", "-a", firewall.PF_ANCHOR, *args):
                    raise ValueError("Unregistered project PF anchor is not empty; refusing adoption")
            if firewall._parent_rows(read_private(PF_FILE)):
                raise ValueError("Unregistered project anchor file is not empty; refusing adoption")
        configs = self.registry.network_configs(exclude=c.instance)
        if not removing:
            configs.append(c)
        custom_instances = sorted(item.instance for item in configs if item.custom_egress == "v1")
        firewall.stage_custom_files(custom_instances)
        from .service_runtime import load_talk_address
        talk_addresses = {item.instance: load_talk_address(self.registry, item)
                          for item in configs if item.talk and item.talk_media_hostname}
        for module in ("if_bridge", "if_epair", "pf"):
            self.runner.run("kldload", "-n", module)
        # Install before arming: a committed transaction must already have its
        # pre-PF boot consumer. An uncommitted first attempt leaves a harmless
        # helper with no active pointer; no shared rc/loader/sysctl entry is used.
        script = firewall.BOOT_SCRIPT
        text = boot_network_script(self.registry.root)
        if script.exists() or script.is_symlink():
            if owned_text(script) != text or script.stat().st_mode & 0o777 != 0o700:
                raise ValueError("Project network boot helper changed; refusing replacement")
        else:
            atomic_write(script, text, mode=0o700)
        state = private_directory(self.registry.root / "transactions" / uuid.uuid4().hex)
        backup = PF_FILE.name + ".before"
        # Only the anchor is ours. Shared rc/sysctl/loader files never enter a
        # transaction, including on an initially empty prepared host.
        policy = (private_json(previous / "firewall-transition.json")["network"]["pf_rules"]
                  if previous else read_private(PF_FILE))
        write_private(state / backup, policy)
        bridges = {} if removing else {
            endpoint.bridge: endpoint.gateway for endpoint in c.network_endpoints
            if self.runner.run("ifconfig", endpoint.bridge, check=False).returncode != 0}
        transaction = {"architecture": firewall.OWNERSHIP,
                        "boot_identity": self.runner.output("sysctl", "-n", "kern.boottime"),
                        "instances": sorted(item.instance for item in configs),
                        "bridges": list(bridges),
                        "previous_pf_file": str(state / backup),
                        "active_link": str(active), "previous_active": str(previous) if previous else None,
                        "backups": {str(PF_FILE): backup}, "deadline": time.monotonic() + 180,
                        "network": {"bridge_addresses": bridges,
                                     "boot_bridge_addresses": {endpoint.bridge: endpoint.gateway
                                         for item in configs for endpoint in item.network_endpoints},
                                     "pf_file": str(PF_FILE),
                                       "pf_rules": pf_rules(configs, self.ssh_connection, host_config=c,
                                                            talk_addresses=talk_addresses)}}
        if custom_instances:
            transaction["network"]["custom_egress"] = custom_instances
        write_json(state / "firewall-transition.json", transaction)
        # The detached supervisor owns a separate process-group worker. The
        # interactive parent must NEVER hold a network lock: SIGSTOP or a stall
        # here must not prevent independent rollback.
        controller = firewall.arm(state)
        try:
            controller.wait_applied()
            self.enable_firewall_with_confirmation(controller)
        except BaseException:
            controller.cancel()
            raise

    def enable_firewall_with_confirmation(self, controller):
        deadline = controller.deadline
        remaining = max(0, int(deadline - time.monotonic()) - 5)
        print("\nPF is active. Open a SECOND SSH session to confirm management access.")
        print(f"Type KEEP within {remaining} seconds. Otherwise PF/network changes are rolled back.", flush=True)
        if not select.select([sys.stdin], [], [], remaining)[0] or sys.stdin.readline().strip() != "KEEP":
            raise RuntimeError("Firewall not confirmed")
        controller.confirm()

    def configure_devfs(self):
        self.require_control_resolution()
        from .bastille import DEVFS_PATH, devfs_loader, devfs_text, owned_text, reserve_devfs
        number = reserve_devfs(self.registry, self.runner)
        rules = Path(DEVFS_PATH)
        private_directory(rules.parent)
        if not rules.exists():
            atomic_write(rules, devfs_text(number))
        loader = devfs_loader(number)
        self.runner.run("/bin/sh", "-c", loader + "load_project_devfs\n")
        # rc ordering alone is insufficient: the per-jail exec.prepare guard
        # below enforces policy/mount readiness even if this rc command fails.
        script = Path("/usr/local/etc/rc.d/cloud_jails_guard")
        text = '''#!/bin/sh
# PROVIDE: cloud_jails_guard
# REQUIRE: NETWORKING pf zfs devfs
# KEYWORD: nojail
. /etc/rc.subr
name=cloud_jails_guard
rcvar=cloud_jails_guard_enable
start_cmd=cloud_jails_guard_start
status_cmd=check_project_devfs
stop_cmd=:
''' + loader + '''
cloud_jails_guard_start() {
    load_project_devfs
}
load_rc_config "$name"
run_rc_command "$1"
'''
        if script.exists() or script.is_symlink():
            if owned_text(script) != text:
                raise ValueError("Project devfs boot helper changed; refusing replacement")
        else:
            atomic_write(script, text, mode=0o700)
        self.runner.run("sysrc", "cloud_jails_guard_enable=YES")

    def bootstrap_jails(self):
        self.require_control_resolution()
        c = self.config
        release = Path(c.bastille_root, "releases", c.release)
        if not (release / "bin/sh").is_file():
            self.runner.run(*BASTILLE, "bootstrap", "--pkgbase", c.release, capture=False)
        for index, endpoint in enumerate(c.jail_endpoints):
            name = endpoint.name
            address, bridge, gateway, hostname = endpoint.ip, endpoint.bridge, endpoint.gateway, endpoint.hostname
            intent = self.state / (name + ".creating.json")
            root = self.jail_root(name)
            if not root.parent.exists():
                atomic_json(intent, {"name": name, "root": str(root), "release": c.release})
                from .bastille import command
                self.runner.run(*command("create", creating=name), "-T", "-B", "--no-boot", "-g", gateway, "-n", c.dns_server,
                                name, c.release, address + "/30", bridge, capture=False)
            elif not intent.exists() or private_json(intent) != {"name": name, "root": str(root), "release": c.release}:
                raise ValueError("A jail path exists without this instance's creation reservation; refusing adoption")
            if not (root / "bin/sh").is_file() or not (root.parent / "jail.conf").is_file():
                raise RuntimeError(f"Incomplete Bastille root for {name}; remove this failed instance through the menu before recreating it")
            actual_path = self.runner.output(*BASTILLE, "config", name, "get", "path")
            if actual_path != str(self.jail_root(name)):
                raise ValueError("Bastille returned an unexpected jail root path")
            # create starts a jail even with --no-boot; stop before mounting storage.
            from .initialization import _jail
            live = _jail(self, name)
            if live and not live[1]:
                if self.require_running_jail(name) != live[0]:
                    raise RuntimeError("Initial jail identity changed before stopping")
                self.control_jail("stop", name, prepared=False)
            self.verify_jail_stopped(name)
            self.runner.run("zfs", "set", f"{OWNER}={c.instance}", f"{c.bastille_dataset}/jails/{name}")
            # Thick send/receive can carry release properties. Pin the actual
            # root explicitly rather than depending on inherited ownership.
            self.runner.run("zfs", "set", f"{OWNER}={c.instance}", f"{c.bastille_dataset}/jails/{name}/root")
            quota = c.system_quota_gib
            if quota:
                share, remainder = divmod(quota, len(c.jails))
                quota = share + (remainder if index == len(c.jails) - 1 else 0)
            if quota:
                self.runner.run("zfs", "set", f"quota={quota}G", f"{c.bastille_dataset}/jails/{name}")
            self.runner.run(*BASTILLE, "config", name, "set", "host.hostname", hostname)
            if name == c.nextcloud_jail:
                # PHP sem_get (Nextcloud previews) needs SysV semaphores. Give
                # only this jail its own namespace, never host IPC inheritance.
                self.runner.run(*BASTILLE, "config", name, "set", "sysvsem", "new")
                atomic_json(self.state / "nextcloud-sysvsem.json", {"jail": name, "sysvsem": "new"})

    def attach_storage(self):
        self.require_control_resolution()
        c = self.config
        guard_path = Path(f"/usr/local/libexec/{c.instance}-storage-guard")
        public_directories(guard_path.parent, Path("/usr/local"))
        atomic_write(guard_path, storage_guard(c, self.storage, self.registry.root), mode=0o700)
        for jail in c.jails:
            from .initialization import _jail
            live = _jail(self, jail)
            if live and not live[1]:
                if self.require_running_jail(jail) != live[0]:
                    raise RuntimeError("Jail identity changed before storage attachment")
                prepared = "exec.prepare" in (self.jail_root(jail).parent / "jail.conf").read_text()
                self.control_jail("stop", jail, prepared=prepared)
            self.verify_jail_stopped(jail)
            root = self.jail_root(jail)
            if not root.is_dir() or root.is_symlink():
                raise ValueError("Unexpected Bastille jail root layout")
            mappings = sorted((item for item in self.storage if item.jail == jail),
                              key=lambda item: len(Path(item.target).parts))
            for dataset in mappings:
                # Seed base log files before nullfs hides the jail's /var/log.
                if dataset.target == "/var/log":
                    for source in (root / "var/log").iterdir():
                        destination = Path(dataset.mountpoint) / source.name
                        if not destination.exists() and not destination.is_symlink():
                            if source.is_dir() and not source.is_symlink():
                                shutil.copytree(source, destination, symlinks=True)
                            else:
                                shutil.copy2(source, destination, follow_symlinks=False)
                parents = [item for item in mappings if item != dataset and
                           Path(item.target) in Path(dataset.target).parents]
                if parents:
                    parent = max(parents, key=lambda item: len(item.target))
                    target = Path(parent.mountpoint) / Path(dataset.target).relative_to(parent.target)
                    boundary = Path(parent.mountpoint)
                else:
                    target = root / dataset.target.lstrip("/")
                    boundary = root
                public_directories(target, boundary)
            jail_dir = root.parent
            conf_path = jail_dir / "jail.conf"
            jail_conf = conf_path.read_text()
            if "mount.fstab" not in jail_conf:
                raise ValueError("Bastille jail.conf has no persistent fstab; port layout changed")
            # Bastille's fstab is the native persistent-mount interface. Direct
            # editing here avoids starting a jail before its mounts are complete.
            fstab = jail_dir / "fstab"
            managed_block(fstab, "persistent mounts", "\n".join(
                f"{dataset.mountpoint} {root}{dataset.target} nullfs rw 0 0" for dataset in mappings))
            self.install_prepare_guard(jail, guard_path)
            # Internal DNS keeps HTTPS hostname validation and avoids NAT hairpinning.
            public_route = (c.frontend_callback_address if c.has_native_services and c.tls_mode == "external"
                            and jail in (c.nextcloud_jail, c.talk_jail) else c.nextcloud_ip)
            hosts = f"{public_route} {c.public_hostname}\n{c.nextcloud_ip} {c.nextcloud_host}"
            if c.native_office:
                hosts += f"\n{c.onlyoffice_ip} {c.onlyoffice_host}"
            if c.talk:
                hosts += f"\n{c.talk_ip} {c.talk_jail}"
            managed_block(root / "etc/hosts", "instance hosts", hosts)
        atomic_write(self.state / "allow-start", "Instance resource ownership and mount graph installed.\n")
        self.ensure_running()

    def ensure_running(self):
        self.require_control_resolution()
        from .initialization import _jail
        for jail in self.config.jails:
            self.runner.run(f"/usr/local/libexec/{self.config.instance}-storage-guard", jail)
            live = _jail(self, jail)
            if live and live[1]:
                raise RuntimeError("Owned jail is still dying; startup refused")
            if live is None:
                self.control_jail("start", jail)
            self.verify_jail_running(jail)

    def install_prepare_guard(self, jail, script):
        # Use the native property interface. VNET jail.conf contains shell
        # ${epair0}/${epair0%a} expressions; brace counting/replacement corrupts it.
        # exec.prepare is distinct from Bastille's existing exec.prestart hooks.
        self.runner.run(*BASTILLE, "config", jail, "set", "exec.prepare", f"{script} {jail}")

    def stage_payloads(self):
        self.require_control_resolution()
        from .version_runtime import connector_text
        from .package_policy import repository_current
        from .service_runtime import stage_package_inputs
        c = self.config
        if c.external_storage and (not c.has_native_services or not repository_current(self.versions)
                                   or "app_installation" not in self.versions):
            raise ValueError("External storage staging requires native-v1, repository-current packages and native occ apps")
        # Only runtime settings belong in a jail, not host management addresses,
        # dataset administration settings or source private-key paths.
        common = {key: getattr(c, key) for key in (
            "instance", "public_hostname", "admin_username", "admin_email", "timezone", "repository",
            "tls_mode", "acme_email", "php_memory_mb", "db_buffer_mb", "redis_memory_mb", "upload_max_mb",
            "font_profile")}
        common.update(nextcloud_ip=c.nextcloud_ip, **({"onlyoffice_ip": c.onlyoffice_ip} if c.has_office else {}),
                       php_children=c.php_children, db_name="nextcloud", public_url=c.public_url,
                       storage_url=c.storage_url, proxy_networks=c.trusted_proxy_networks)
        if c.backend == "none":
            common.pop("storage_url")
        # Copy an allowlist, never the repository root, .git, saved configs or logs.
        for endpoint in c.jail_endpoints:
            jail = endpoint.name
            target = self.jail_root(jail) / "root/cloud-installer"
            target.mkdir(mode=0o700, exist_ok=True)
            if target.is_symlink():
                raise ValueError("Provisioning payload directory must not be a symlink")
            if c.has_native_services and any(path.is_symlink() for path in target.rglob("*")):
                raise ValueError("Native-service payload destinations must not contain symlinks")
            vhosts = ('www-none.conf','https-none.conf','external-none.conf') if c.backend == 'none' else (
                'www.conf','https.conf','external.conf')
            sources = ("installer", "resources") if c.native_office else (
                *("resources/templates/nextcloud/" + name for name in (
                    "certbot-cron", "certbot-deploy", "challenge.conf", "cloud_php_dirs", "httpd.conf",
                    "my.cnf", "mysql-flush-logs", "newsyslog.conf", "php-fpm.conf", "php.ini", "redis.conf",
                    "www-crontab", *vhosts)),
                *("resources/jails/" + name for name in ("nextcloud.sh", "nextcloud-bootstrap.php",
                    "nextcloud-cron-fence.php", "runtime-inventory.php", "maintenance.php", "versions.sh", "ssh.sh")))
            if endpoint.role == "talk":
                sources = talk_payload_sources(self.versions)
            elif endpoint.role == "nc" and c.has_native_services:
                sources = ("installer", "resources/templates/nextcloud", "resources/native-services.json",
                           *("resources/jails/" + name for name in ("nextcloud.sh", "nextcloud-bootstrap.php",
                             "nextcloud-cron-fence.php", "runtime-inventory.php", "maintenance.php", "versions.sh", "ssh.sh")))
            if (repository_current(self.versions) and "resources" not in sources
                    and "resources/versions.json" not in sources):
                sources += ("resources/versions.json",)
            for relative in sources:
                source = ROOT / relative
                if source.is_symlink() or any(path.is_symlink() for path in source.rglob("*")):
                    raise ValueError("Payload source must not contain symlinks")
                destination = target / relative
                if source.is_dir():
                    shutil.copytree(source, destination,
                                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"), dirs_exist_ok=True)
                else:
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copy2(source, destination, follow_symlinks=False)
            runtime = dict(common)
            if endpoint.role == "talk":
                runtime = {"repository": c.repository}
            elif endpoint.role == "nativeoo":
                runtime = {key: common[key] for key in ("public_hostname", "public_url", "storage_url",
                            "nextcloud_ip", "onlyoffice_ip", "repository", "tls_mode", "font_profile")}
                runtime["additional_fonts"] = bool(c.additional_fonts_dir)
                runtime["accept_microsoft_fonts"] = c.accept_microsoft_fonts
            else:
                runtime.pop("instance")
                runtime.pop("font_profile")
                if c.nextcloud_defaults:
                    runtime["nextcloud_defaults"] = c.nextcloud_defaults
                    if c.default_phone_region:
                        runtime["default_phone_region"] = c.default_phone_region
                if c.nextcloud_apps or c.additional_nextcloud_apps or c.external_storage:
                    runtime["nextcloud_apps"] = ",".join(c.selected_nextcloud_apps) or "none"
                for key in ("external_storage", "external_storage_smb", "external_storage_ftp"):
                    if getattr(c, key):
                        runtime[key] = True
            from .service_runtime import package_group
            group = package_group(endpoint)
            runtime["versions"] = stage_package_inputs(self, target, group)
            if endpoint.role == "talk":
                from .service_runtime import deployment_talk_public
                from .talk import runtime_public
                runtime = runtime_public(deployment_talk_public(self), c.repository, runtime["versions"])
            if c.has_native_services:
                from .version_runtime import services_text
                atomic_write(target / "services.json", services_text(self.versions))
            if c.has_native_services and endpoint.role == "nc":
                from .service_runtime import stage_nextcloud_services
                stage_nextcloud_services(self, target, runtime)
            if c.has_office and endpoint.role != "talk" and "app_installation" not in self.versions:
                atomic_write(target / "connector.json", connector_text(self.versions))
            if c.native_office:
                atomic_write(target / "fonts-unavailable", "".join(name + "\n" for name in self.versions.get("fonts_unavailable", [])))
            atomic_json(target / "runtime.json", runtime)
            tls = target / "tls"
            tls.mkdir(mode=0o700, exist_ok=True)
            if c.tls_mode == "provided":
                if jail == c.nextcloud_jail:
                    atomic_write(tls / "fullchain.pem", Path(c.certificate_file).read_text())
                    atomic_write(tls / "privkey.pem", Path(c.private_key_file).read_text())
            if c.ca_file:
                atomic_write(tls / "ca.pem", Path(c.ca_file).read_text())
            if jail == c.onlyoffice_jail and c.additional_fonts_dir:
                self.stage_fonts(target / "fonts")
            if jail == c.onlyoffice_jail and c.onlyoffice_plugins:
                self.stage_plugins(target)

    def stage_fonts(self, target):
        source = Path(self.config.additional_fonts_dir)
        target.mkdir(mode=0o700, exist_ok=True)
        total, count = 0, 0
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise ValueError("Custom font inputs must not contain symlinks")
            if path.is_dir():
                continue
            if not path.is_file() or path.suffix.lower() not in (".ttf", ".otf", ".ttc"):
                raise ValueError("Custom font directory may contain only regular TTF, OTF and TTC font files")
            total += path.stat().st_size
            count += 1
            if total > 2 * 1024 ** 3 or count > 10000:
                raise ValueError("Custom fonts exceed the 2 GiB / 10,000-file input limit")
            with path.open("rb") as stream:
                if stream.read(4) not in (b"\x00\x01\x00\x00", b"OTTO", b"ttcf", b"true"):
                    raise ValueError("Unrecognized custom font file header")
            destination = target / path.relative_to(source)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(path, destination, follow_symlinks=False)
            destination.chmod(0o600)

    def install_nextcloud(self):
        self.nextcloud_phase("prepare")

    def nextcloud_phase(self, phase, keys=()):
        kwargs = {"input": json.dumps({key: self.secrets[key] for key in keys}),
                  "progress_label": "Nextcloud " + phase} if keys else {"capture": False}
        self.jail(self.config.nextcloud_jail, "/bin/sh", "/root/cloud-installer/resources/jails/nextcloud.sh", phase, **kwargs)

    def brand_nextcloud(self, journal):
        """Optional first attempt only; the journal records intent before copying."""
        record = journal.data["steps"]["Nextcloud branding"]
        if (not self.config.nextcloud_branding or "app_installation" not in self.versions
                or "Nextcloud publication" in journal.data["steps"]
                or (self.state / "complete").exists()):
            return
        if record["attempt"] != 1:
            print("WARNING: Nextcloud branding was already attempted; it will not be reapplied on Resume.", flush=True)
            return
        try:
            jail = self.config.nextcloud_jail
            self.verify_jail_running(jail)
            temporary = self.jail_root(jail) / "tmp"
            if temporary.is_symlink() or not temporary.is_dir():
                raise ValueError("Unsafe jail temporary directory")
            target = temporary / "nextcloudonfreebsd-branding"
            # Never adopt an existing directory, even if it appears empty.
            target.mkdir(mode=0o755)
            target.chmod(0o755)
            for relative in BRANDING_FILES:
                source = ROOT / relative
                if not source.is_file() or source.is_symlink() or any(
                        parent.is_symlink() for parent in source.parents if parent != ROOT):
                    raise ValueError("Unsafe branding source")
                with source.open("rb") as incoming, (target / source.name).open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                (target / source.name).chmod(0o644)
            self.verify_jail_running(jail)
            self.nextcloud_phase("branding")
        except Exception:
            # No retry or rollback: native Theming may already contain a subset.
            record["warning"] = "Branding incomplete; no automatic retry"
            print("WARNING: Optional Nextcloud branding or its temporary-file cleanup failed; "
                  "installation continues. Partial settings/files may remain. "
                  "Review Administration > Theming; Resume will not retry branding.", flush=True)

    def talk_phase(self, phase):
        from .service_runtime import talk_phase
        if not self.config.talk:
            raise ValueError("No Talk jail selected")
        return talk_phase(self, phase)

    def finish_input(self, connector):
        from .service_runtime import integration_input
        return json.dumps(integration_input(self.config, self.secrets, connector))

    def install_onlyoffice(self):
        self.config.require_native_backend("ONLYOFFICE installation")
        self.jail(self.config.onlyoffice_jail, "/bin/sh", "/root/cloud-installer/resources/jails/onlyoffice.sh",
                  input=json.dumps({"jwt_secret": self.secrets["jwt_secret"]}), progress_label="ONLYOFFICE packages/fonts/services")
        unavailable = self.jail_root(self.config.onlyoffice_jail) / "var/db/cloud-installer-onlyoffice/fonts-unavailable"
        if unavailable.is_file():
            names = unavailable.read_text().splitlines()
            if names and all(re.fullmatch(r"[A-Za-z0-9_+-]+", name) for name in names):
                print("Optional font packages unavailable in this repository: " + ", ".join(names), flush=True)

    def prepare_office_vm_image(self):
        self.require_control_resolution()
        from .office_vm import vm_paths, native_vm_identity, acquire_guest_image
        if self.config.backend not in ('eurooffice','collabora'):
            raise ValueError('The selected VM installation path is not implemented')
        paths=vm_paths(self.config)
        receipt=self.state/(paths['name']+'.creating.json')
        if receipt.exists() or receipt.is_symlink():
            record=private_json(receipt)
            if isinstance(record,dict) and 'vm_config_sha256' in record:
                native_vm_identity(self) # Sealed creation does not need the old acquisition cache.
                self._vm_image=None
                return
        if Path(paths['root']).exists() or Path(paths['root']).is_symlink():
            raise ValueError('Uncertain partial VM creation requires inspection before host mutations')
        self._vm_image=acquire_guest_image(self)

    def create_office_vm(self):
        self.require_control_resolution()
        from .office_vm import create_native_vm
        return create_native_vm(self,getattr(self,'_vm_image',None))

    def start_office_vm(self):
        self.require_control_resolution()
        from .office_vm import start_native_vm, wait_native_guest
        start_native_vm(self,install_continuation=True)
        return wait_native_guest(self)

    def bootstrap_office_vm(self):
        self.require_control_resolution()
        from .office_vm import bootstrap_native_guest
        return bootstrap_native_guest(self)

    def install_vm_office(self):
        self.require_control_resolution()
        from .office_vm import install_eurooffice_container,install_collabora_container
        return (install_collabora_container if self.config.backend=='collabora' else install_eurooffice_container)(self)

    def check_office_vm_bootstrap(self):
        from .office_vm import verify_native_guest_bootstrap
        return verify_native_guest_bootstrap(self)

    def continue_vm_office(self):
        self.require_control_resolution()
        from .office_vm import install_eurooffice_container,install_collabora_container
        return (install_collabora_container if self.config.backend=='collabora' else install_eurooffice_container)(self,require_existing=True)

    def restart_office_vm(self):
        self.require_control_resolution()
        from .office_vm import stop_native_vm
        stop_native_vm(self)
        self.start_office_vm()

    def integrate(self):
        self.require_control_resolution()
        from .operations import _database_guard
        # The caller already holds the host operation lock. Keep the database
        # guard through writer closure, initial cron and schedule publication.
        with _database_guard(self):
            self._integrate()

    def _integrate(self):
        c = self.config
        if c.backend == "none":
            if c.has_native_services:
                self.jail(c.nextcloud_jail, "/bin/sh", "/root/cloud-installer/resources/jails/nextcloud.sh", "finish",
                          input=self.finish_input({}), progress_label="Nextcloud native service integration")
            else:
                self.nextcloud_phase("finish")
            return
        if c.backend == 'eurooffice':
            from .office_vm import vm_apache_proxy, vm_connector_settings
            settings = vm_connector_settings(c,jwt_secret=self.secrets.get('jwt_secret'))
            self.wait_for_vm_office()
            payload = self.jail_root(c.nextcloud_jail) / 'root/cloud-installer'
            atomic_write(payload / 'apache-onlyoffice.conf',vm_apache_proxy(c))
            self.jail(c.nextcloud_jail,'/bin/sh','/root/cloud-installer/resources/jails/nextcloud.sh','finish',
                      input=self.finish_input(settings),
                      progress_label='Nextcloud Euro-Office integration')
            return
        if c.backend=='collabora':
            from .office_vm import vm_apache_proxy,vm_connector_settings
            self.collabora_readiness_identity(publish=True)
            payload=self.jail_root(c.nextcloud_jail)/'root/cloud-installer'
            atomic_write(payload/'apache-onlyoffice.conf',vm_apache_proxy(c))
            self.jail(c.nextcloud_jail,'/bin/sh','/root/cloud-installer/resources/jails/nextcloud.sh','finish',
                       input=self.finish_input(vm_connector_settings(c)),progress_label='Nextcloud Collabora activation')
            self.verify_connector_urls()
            return
        c.require_native_backend("Document integration")
        from .office import apache_proxy, connector_settings
        from .service_runtime import package_runtime_versions
        # Resume can skip office provisioning after ensure_running starts jails.
        # Supervisor/DocService startup is asynchronous even when rc succeeds.
        self.wait_for_office()
        runtime = {"public_hostname": c.public_hostname, "nextcloud_ip": c.nextcloud_ip,
                   "onlyoffice_ip": c.onlyoffice_ip, "jwt_secret": self.secrets["jwt_secret"],
                   "repository": c.repository, "tls_mode": c.tls_mode,
                    "public_url": c.public_url, "storage_url": c.storage_url}
        runtime["versions"] = package_runtime_versions(self, "nextcloud")
        payload = self.jail_root(c.nextcloud_jail) / "root/cloud-installer"
        atomic_write(payload / "apache-onlyoffice.conf", apache_proxy(runtime))
        self.jail(c.nextcloud_jail, "/bin/sh", "/root/cloud-installer/resources/jails/nextcloud.sh", "finish",
                  input=self.finish_input(connector_settings(runtime)), progress_label="Nextcloud document integration")

    def enable_boot(self):
        self.require_control_resolution()
        if self.config.talk:
            self.talk_phase("verify")
            from .talk import SERVICES
            services = ("cloud_talk_runtime", *SERVICES)
            for service in services:
                self.jail(self.config.talk_jail, "sysrc", "-f", "/etc/rc.conf.d/" + service,
                          service + "_enable=YES", hide_output=True)
            for service in services:
                effective = self.jail(self.config.talk_jail, "sysrc", "-n", "-s", service,
                                      service + "_enable", hide_output=True)
                if (effective.returncode != 0 or not isinstance(effective.stdout, str)
                        or effective.stdout.strip() != "YES"):
                    raise RuntimeError("Talk effective service boot flag is missing or differs; jail boot remains ungranted")
        if self.config.has_office and not self.config.native_office:
            from .office_vm import publish_vm_boot_service
            publish_vm_boot_service(self)
        for name in self.config.jails:
            self.runner.run(*BASTILLE, "config", name, "set", "boot", "on")
        from .bastille import CONFIG_PATH, RC_DIRECTORY, boot_service, configuration, owned_text, ruleset
        number = ruleset(self.registry.host())
        expected = configuration(self.config, number)
        if owned_text(CONFIG_PATH) != expected:
            raise ValueError("Project Bastille configuration changed before boot publication")
        from .service_deadlines import qualify
        jail_files = {}
        for jail in self.config.jails:
            qualify(self, jail)
            jail_files[jail] = {filename: hashlib.sha256(owned_text(self.jail_root(jail).parent / filename).encode()).hexdigest()
                                for filename in ("jail.conf", "fstab")}
        text = boot_service(self.config, number,
            config_sha256=hashlib.sha256(expected.encode()).hexdigest(),
            guard_sha256=hashlib.sha256(storage_guard(self.config, self.storage, self.registry.root).encode()).hexdigest(),
            jail_files=jail_files)
        name = "cloud_" + self.config.instance + "_jails"
        path = RC_DIRECTORY / name
        from .state import config_digest
        receipt = self.state / "jail-boot-service.json"
        value = dict(schema_version=1, config_sha256=config_digest(self.config), service_path=str(path),
                     service_sha256=hashlib.sha256(text.encode()).hexdigest())
        if receipt.exists() or receipt.is_symlink():
            if private_json(receipt) != value:
                raise ValueError("Project jail boot publication receipt changed")
        else:
            if path.exists() or path.is_symlink():
                raise ValueError("Unreserved project jail boot helper; refusing adoption")
            atomic_json(receipt, value)
        if path.exists() or path.is_symlink():
            if owned_text(path) != text:
                raise ValueError("Project jail boot helper changed; refusing replacement")
        else:
            atomic_write(path, text, mode=0o700)
        self.runner.run("sysrc", name + "_enable=YES")

    def restart_jails(self):
        self.require_control_resolution()
        # Exercise mount/service persistence before announcing a new deployment.
        # This is not a substitute for a host reboot and external-network test.
        for name in reversed(self.config.jails):
            self.require_running_jail(name)
            self.control_jail("restart", name)
            if self.config.talk and name == self.config.talk_jail:
                from .service_runtime import start_talk
                start_talk(self)

    def wait_for_office(self):
        self.config.require_native_backend("ONLYOFFICE readiness")
        # Supervisor starts asynchronously; a successful jail/rc restart is not
        # proof that DocService is already accepting conversion requests.
        self.jail(self.config.onlyoffice_jail, "python3", "-c", '''import sys, time, urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
for attempt in range(60):
    try:
        with opener.open(sys.argv[1], timeout=5) as response:
            if response.read(1024).strip()==b'true':
                raise SystemExit(0)
    except (OSError, ValueError):
        pass
    time.sleep(2)
raise SystemExit('ONLYOFFICE did not become ready after startup')
''', f"http://{self.config.onlyoffice_ip}:8081/healthcheck")

    def wait_for_vm_office(self):
        if self.config.backend != 'eurooffice':
            raise ValueError('No implemented readiness probe for the selected VM backend')
        from .office_vm import native_vm_identity, _vm_network_ready
        target = native_vm_identity(self)
        if not target['state'].startswith('Running ('):
            raise ValueError('Selected office VM is not running')
        _vm_network_ready(self,target)
        # NC -> selected private frontend, not a VM-local curl. No proxy env,
        # insecure HTTPS or arbitrary user URL. Health is not editor acceptance.
        self.jail(self.config.nextcloud_jail,'python3','-c','''import sys,time,urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
deadline=time.monotonic()+120
while time.monotonic()<deadline:
    try:
        with opener.open(sys.argv[1],timeout=5) as response:
            if response.status==200 and response.read(1024).strip()==b'true': raise SystemExit(0)
    except (OSError,ValueError): pass
    time.sleep(2)
raise SystemExit('Selected Euro-Office frontend health deadline expired')
''','http://'+self.config.onlyoffice_ip+':8081/healthcheck',timeout=135,hide_output=True)

    def read_collabora_endpoints(self, *, expected_proof_sha256=None):
        """Read-only bounded NC->CODE discovery, not activation or saved readiness."""
        if self.config.backend!='collabora':
            raise ValueError('CODE endpoint inspection requires its selected backend')
        import base64
        import binascii
        from .office_vm import native_vm_identity, _vm_network_ready, verify_collabora_container, validate_collabora_endpoints
        target=native_vm_identity(self)
        if not target['state'].startswith('Running ('):raise ValueError('Selected CODE VM is not running')
        _vm_network_ready(self,target)
        verify_collabora_container(self)
        from .state import config_digest
        proof=private_json(self.state/'collabora-proof.json')
        if (not isinstance(proof,dict) or type(proof.get('schema_version')) is not int or proof['schema_version']!=2
                or proof.get('config_sha256')!=config_digest(self.config)
                or not isinstance(proof.get('public_key_sha256'),str) or not re.fullmatch(r'[a-f0-9]{64}',proof['public_key_sha256'])):
            raise ValueError('CODE endpoint inspection requires its provisioned public key identity')
        program='''import base64,json,time,urllib.request,urllib.error,sys
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('Unexpected CODE endpoint redirect')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
base='http://'+sys.argv[1]+':8081/collabora/hosting/'
deadline=time.monotonic()+120
while time.monotonic()<deadline:
    try:
        values={}
        for name,limit in (('discovery',1048576),('capabilities',65536)):
            with opener.open(base+name,timeout=5) as response:
                if response.status!=200: raise ValueError('Unexpected CODE endpoint status')
                body=response.read(limit+1)
            if not 0<len(body)<=limit: raise ValueError('CODE endpoint response exceeded bounds')
            values[name]=base64.b64encode(body).decode()
        print(json.dumps(values));break
    except urllib.error.HTTPError as error:
        if error.code not in (502,503,504): raise
    except OSError: pass
    time.sleep(2)
else:raise SystemExit('CODE endpoint readiness deadline expired')
'''
        response=self.jail(self.config.nextcloud_jail,'python3','-c',program,self.config.onlyoffice_ip,timeout=135,hide_output=True)
        try:
            if len(response.stdout)>2*1024**2:raise ValueError
            value=json.loads(response.stdout)
            if not isinstance(value,dict) or set(value)!={'discovery','capabilities'}:raise ValueError
            discovery=base64.b64decode(value['discovery'],validate=True)
            capabilities=base64.b64decode(value['capabilities'],validate=True)
        except (ValueError,TypeError,binascii.Error):
            raise ValueError('CODE endpoint transport returned no valid bounded response') from None
        return validate_collabora_endpoints(self.config,self.versions,discovery,capabilities,
                                            expected_proof_sha256=expected_proof_sha256,
                                            expected_public_key_sha256=proof['public_key_sha256'])

    def collabora_readiness_identity(self, *, publish=False):
        from .state import config_digest
        if self.config.backend!='collabora' or type(publish) is not bool:
            raise ValueError('CODE readiness identity requires its selected backend')
        path=self.state/'collabora-readiness.json'
        exists=path.exists() or path.is_symlink()
        if not exists and not publish:
            raise ValueError('CODE saved endpoint identity is missing; verification never publishes it')
        previous=private_json(path) if exists else None
        reference=self.versions['office_runtime']['container']['reference']
        if exists and (not isinstance(previous,dict) or type(previous.get('schema_version')) is not int
                or previous['schema_version']!=1 or previous.get('config_sha256')!=config_digest(self.config)
                or previous.get('image')!=reference or not isinstance(previous.get('proof_sha256'),str)
                or not re.fullmatch(r'[a-f0-9]{64}',previous['proof_sha256'])):
            raise ValueError('CODE saved endpoint identity changed')
        value=self.read_collabora_endpoints(expected_proof_sha256=previous['proof_sha256'] if exists else None)
        expected={'schema_version':1,'config_sha256':config_digest(self.config),'image':reference,
                  'proof_sha256':value['proof_sha256'],'public_key_sha256':value['public_key_sha256'],
                  'product_version':value['product_version'],'public_url':value['public_url']}
        if exists and previous!=expected:raise ValueError('CODE endpoint identity differs; no rotation/reselection inferred')
        if not exists:atomic_json(path,expected)
        return {**value,'state':'running','image':reference,'discovery_verified':True}

    def verify_database_configuration(self):
        result = self.jail(
            self.config.nextcloud_jail, "mariadb", "--no-defaults", "--protocol=socket",
            "--socket=/var/run/mysql/mysql.sock", "--user=root", "--batch",
            "--skip-column-names", "--execute", "SELECT @@innodb_log_file_size",
            timeout=30, hide_output=True)
        value = result.stdout.strip()
        if not re.fullmatch(r"[0-9]{1,20}", value) or int(value) < 128 * 1024 * 1024:
            raise RuntimeError("MariaDB effective innodb_log_file_size must be at least 128 MiB; "
                               "verification does not change database configuration")
        self.manifest["database_configuration"] = {"innodb_log_file_size": int(value)}

    def verify_connector_urls(self):
        c = self.config
        if c.backend=='collabora':
            from .office_vm import vm_connector_settings
            app,label='richdocuments','Collabora'
            expected={**vm_connector_settings(c)['apps']['richdocuments'],'public_wopi_url':c.public_url.rstrip('/')}
        elif c.backend=='eurooffice':
            app,label='eurooffice','Euro-Office'
        else:
            c.require_native_backend("ONLYOFFICE connector verification")
            app,label='onlyoffice','ONLYOFFICE'
        if c.backend!='collabora':
            expected = {"DocumentServerUrl": c.public_url + app + "/",
                        "DocumentServerInternalUrl": f"http://{c.onlyoffice_ip}:8081/",
                        "StorageUrl": c.storage_url}
        for key, value in expected.items():
            result = self.jail(c.nextcloud_jail, "mdo", "-u", "www", "php",
                               "/usr/local/www/nextcloud/occ", "config:app:get", app, key,
                               timeout=30, hide_output=True)
            if result.stdout.strip() != value:
                raise RuntimeError(f"{label} {key} differs from the retained configuration; "
                                   "verification never rewrites connector settings")

    def verify_nextcloud_sysvsem(self):
        # Older installations have no marker: verification must not silently
        # migrate their jail policy or invalidate their retained plans/artifacts.
        marker = self.state / "nextcloud-sysvsem.json"
        if not marker.exists() and not marker.is_symlink():
            return
        name = self.config.nextcloud_jail
        if private_json(marker) != {"jail": name, "sysvsem": "new"}:
            raise ValueError("Unexpected Nextcloud semaphore policy identity")
        if self.runner.output(*BASTILLE, "config", name, "get", "sysvsem") != "new":
            raise RuntimeError("Nextcloud jail must retain its private sysvsem=new policy")
        jid = self.require_running_jail(name)
        live = self.runner.output("jls", "-j", name, "jid", "name", "path", "sysvsem").split()
        if live != [str(jid), name, str(self.jail_root(name)), "new"]:
            raise RuntimeError("Nextcloud jail identity/private semaphore namespace differs from its policy")
        if self.require_running_jail(name) != jid:
            raise RuntimeError("Nextcloud jail restarted during semaphore verification")

    def verify_ssh(self):
        """Observe the selected SSH roles after restart; never configure/repair."""
        if not self.config.jail_ssh:
            return
        for endpoint in self.config.jail_endpoints:
            if endpoint.role not in ("nc", "nativeoo"):
                continue
            enabled = self.jail(endpoint.name, "sysrc", "-n", "-s", "sshd", "sshd_enable",
                                check=False, hide_output=True, timeout=30)
            if (enabled.returncode != 0 or not isinstance(enabled.stdout, str)
                    or enabled.stdout.strip() != "YES"):
                raise RuntimeError("Selected jail SSH is not effectively enabled; verification does not repair settings")
            running = self.jail(endpoint.name, "service", "sshd", "onestatus",
                                check=False, hide_output=True, timeout=30)
            if running.returncode != 0:
                raise RuntimeError("Selected jail SSH is not running after restart; verification does not start services")

    def verify(self):
        c = self.config
        from .package_policy import repository_current
        from .service_runtime import verify_package_requirements
        for name in c.jails:
            self.require_running_jail(name)
        if c.has_native_services:
            for endpoint in c.jail_endpoints:
                if (self.runner.output("jls", "-j", endpoint.name, "host.hostname") != endpoint.hostname
                        or self.jail(endpoint.name, "hostname", hide_output=True).stdout.strip() != endpoint.hostname):
                    raise RuntimeError("A native-service jail's live hostname differs from its owned endpoint")
        self.verify_nextcloud_sysvsem()
        self.verify_ssh()
        current_packages = repository_current(self.versions)
        if current_packages:
            verify_package_requirements(self, "host")
        else:
            for name, record in self.versions["packages"]["host"].items():
                if self.runner.output("pkg", "query", "%v|%o", name) != record["version"] + "|" + record["origin"]:
                    raise RuntimeError("Host prerequisites differ from the retained version lock; verification never changes them")
        for name in c.jails:
            self.runner.run(f"/usr/local/libexec/{c.instance}-storage-guard", name)
        if c.native_office:
            self.wait_for_office()
            self.plugin_command("verify")
        elif c.backend=='eurooffice':
            from .office_vm import verify_eurooffice_container
            self.manifest['office_vm']=verify_eurooffice_container(self)
            self.wait_for_vm_office()
        elif c.backend=='collabora':
            self.manifest['office_vm']=self.collabora_readiness_identity()
        for service in ("mysql-server", "redis", "php_fpm", "apache24", "cron"):
            self.jail(c.nextcloud_jail, "service", service, "status", capture=False)
        if c.antivirus:
            for service in ("clamav_clamd", "clamav_freshclam"):
                self.jail(c.nextcloud_jail, "service", service, "onestatus", capture=False)
        self.verify_database_configuration()
        if c.native_office:
            self.verify_connector_urls()
            for service in ("supervisord", "nginx"):
                self.jail(c.onlyoffice_jail, "service", service, "status", capture=False)
            processes = self.jail(c.onlyoffice_jail, "supervisorctl", "status", "ds:docservice", "ds:metrics").stdout
            if any(not re.search(rf"(?m)^{name}\s+RUNNING\b", processes) for name in ("ds:docservice", "ds:metrics")):
                raise RuntimeError("Both native ONLYOFFICE processes must be RUNNING")
        elif c.backend=='eurooffice':
            self.verify_connector_urls()
            result=self.jail(c.nextcloud_jail,'mdo','-u','www','php','/usr/local/www/nextcloud/occ',
                             'eurooffice:documentserver','--check',timeout=120,hide_output=True)
            match=re.search(r'\bversion ([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?) is successfully connected\b',result.stdout)
            selected=self.versions['office_runtime']['container']
            latest=self.versions['office_runtime'].get('selection')=='latest'
            expected=None if latest else selected.get('product_version',selected['release'])
            if not match or (not latest and '.'.join(match[1].split('.')[:3])!=expected):
                raise RuntimeError('Euro-Office connector did not confirm the selected stable runtime version')
            self.manifest['office_vm']['reported_version']=match[1]
        elif c.backend=='collabora':
            self.verify_connector_urls()
            apps=self.jail(c.nextcloud_jail,'mdo','-u','www','php','/usr/local/www/nextcloud/occ',
                           'app:list','--output=json',timeout=30,hide_output=True).stdout
            try: enabled=json.loads(apps)['enabled']
            except (ValueError,TypeError,KeyError):raise RuntimeError('Invalid connector app inventory') from None
            expected_connector = self.versions['applications'].get('connector')
            if (not isinstance(enabled,dict) or not isinstance(enabled.get('richdocuments'), str)
                    or ("app_installation" not in self.versions and enabled['richdocuments'] != expected_connector)):
                raise RuntimeError('Selected richdocuments connector is not enabled at its locked version')
        self.jail(c.nextcloud_jail, "php-fpm", "-t", capture=False)
        self.jail(c.nextcloud_jail, "apachectl", "configtest", capture=False)
        if c.native_office:
            self.jail(c.onlyoffice_jail, "nginx", "-t", capture=False)
            self.jail(c.nextcloud_jail, "mdo", "-u", "www", "php", "/usr/local/www/nextcloud/occ",
                      "onlyoffice:documentserver", "--check", capture=False)
            # Test PF isolation across the routed segments, not just listener strings.
            self.jail(c.nextcloud_jail, "python3", "-c", '''import socket, sys
for port in (8000, 8126):
    sock = socket.socket()
    sock.settimeout(3)
    try:
        sock.connect((sys.argv[1], port))
    except (TimeoutError, ConnectionError, OSError):
        pass
    else:
        raise SystemExit("Unsafe access to ONLYOFFICE backend port " + str(port))
    finally:
        sock.close()
''', c.onlyoffice_ip)
        # Check public TLS/routing from each jail using the hostname (hosts entry
        # resolves to NC); an external check is still required for router/DNS ingress.
        # Host DNS may require router hairpinning. Connect directly to NC via a
        # subprocess in that jail instead; it has an explicit internal hosts entry.
        office_version = self.installed_onlyoffice_version() if c.native_office and current_packages else None
        health_script = '''import json, ssl, urllib.request, urllib.error, sys
from pathlib import Path
c=json.loads(Path('/root/cloud-installer/runtime.json').read_text())
ca=Path('/root/cloud-installer/tls/ca.pem')
ctx=ssl.create_default_context(cafile=str(ca) if ca.exists() else None)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
for path in ('/status.php', '/onlyoffice/healthcheck'):
    with opener.open(c['storage_url'].rstrip('/')+path, timeout=30) as response:
        body=response.read(4096)
    if path.endswith('healthcheck'):
        assert body.strip()==b'true', 'Unexpected document health response'
    else:
        status=json.loads(body)
        assert status['installed'] and not status['maintenance'] and '.'.join(status['version'].split('.')[:3])==c['versions']['nextcloud']
docs_version = sys.argv[1] if len(sys.argv) > 1 else c['versions']['onlyoffice']
for path in ('internal/', 'info/', 'admin/', 'example/', docs_version+'-0/internal/', docs_version+'-0/info/'):
    try:
        opener.open(c['storage_url']+'onlyoffice/'+path, timeout=30)
    except urllib.error.HTTPError as error:
        assert error.code == 403, 'Unexpected private endpoint response'
    else:
        raise SystemExit('A private ONLYOFFICE endpoint is exposed')
'''
        if c.backend=='eurooffice':
            health_script='''import json,ssl,urllib.request,urllib.error
from pathlib import Path
c=json.loads(Path('/root/cloud-installer/runtime.json').read_text())
ca=Path('/root/cloud-installer/tls/ca.pem')
ctx=ssl.create_default_context(cafile=str(ca) if ca.exists() else None)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
with opener.open(c['storage_url']+'status.php',timeout=30) as response: status=json.loads(response.read(4096))
assert status.get('installed') is True and status.get('maintenance') is False and status.get('needsDbUpgrade') is False
assert '.'.join(status['version'].split('.')[:3])==c['versions']['nextcloud']
with opener.open(c['storage_url']+'eurooffice/healthcheck',timeout=30) as response:
    assert response.status==200 and response.read(1024).strip()==b'true'
for path in ('internal/','info/','admin/','example/'):
    try: opener.open(c['storage_url']+'eurooffice/'+path,timeout=30)
    except urllib.error.HTTPError as error: assert error.code==403
    else: raise SystemExit('A private Euro-Office endpoint is exposed')
'''
        elif c.backend in ("none","collabora"):
            health_script = '''import json, ssl, urllib.request
from pathlib import Path
c=json.loads(Path('/root/cloud-installer/runtime.json').read_text())
ca=Path('/root/cloud-installer/tls/ca.pem')
ctx=ssl.create_default_context(cafile=str(ca) if ca.exists() else None)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
# Probe the jail listener, not the potentially different host/public HTTPS port.
url=('http://'+c['nextcloud_ip']+'/') if c['tls_mode']=='external' else ('https://'+c['public_hostname']+'/')
with opener.open(url.rstrip('/')+'/status.php', timeout=30) as response:
    status=json.loads(response.read(4096))
if (status.get('installed') is not True or status.get('maintenance') is not False
        or status.get('needsDbUpgrade') is not False or not isinstance(status.get('version'), str)
        or '.'.join(status['version'].split('.')[:3]) != c['versions']['nextcloud']):
    raise SystemExit('Nextcloud status is not ready at the selected version')
'''
            if c.backend=='collabora':
                health_script+='''
import xml.etree.ElementTree as ET
import urllib.error
with opener.open(url+'collabora/hosting/discovery',timeout=30) as response:
    body=response.read(1048577)
assert len(body)<=1048576 and b'<!DOCTYPE' not in body.upper() and b'<!ENTITY' not in body.upper()
discovery=ET.fromstring(body)
assert discovery.tag=='wopi-discovery' and discovery.find('proof-key') is not None
for path in ('cool/adminws','cool/getMetrics','cool/convert-to','browser/dist/admin/admin.html'):
    try:opener.open(url+'collabora/'+path,timeout=30)
    except urllib.error.HTTPError as error:assert error.code==403
    else:raise SystemExit('A private CODE endpoint is exposed')
'''
        self.jail(c.nextcloud_jail, "python3", "-c", health_script, *((office_version,) if office_version else ()))
        packages = {name: [line for line in self.jail(name, "pkg", "query", "%n %v %o").stdout.splitlines() if line.strip()]
                    for name in c.jails}
        if any(not values for values in packages.values()):
            raise RuntimeError("A managed jail returned an empty package inventory")
        for jail in c.jails:
            from .service_runtime import package_group
            group = package_group(next(endpoint for endpoint in c.jail_endpoints if endpoint.name == jail))
            rows = [line.split() for line in packages[jail]]
            if any(len(row) != 3 for row in rows) or len({row[0] for row in rows}) != len(rows):
                raise RuntimeError("A managed jail returned an ambiguous package inventory")
            inventory = {name: (version, origin) for name, version, origin in rows}
            if current_packages:
                verify_package_requirements(self, group)
                continue
            base_packages = {name for name, (_, origin) in inventory.items()
                             if re.fullmatch(r"FreeBSD-[A-Za-z0-9_+.-]+", name) and origin == "base/" + name}
            if (set(inventory) - set(self.versions["packages"][group]) - base_packages - {"pkg"}
                    or any(inventory.get(name) != (item["version"], item["origin"]) for name, item in self.versions["packages"][group].items())):
                raise RuntimeError("Installed package versions differ from the retained version lock; manual upgrade assessment is required")
        status = self.jail(
            c.nextcloud_jail, "mdo", "-u", "www", "php", "/usr/local/www/nextcloud/occ",
            "status", "--output=json").stdout.strip()
        try:
            status = json.loads(status)
        except (ValueError, TypeError):
            raise RuntimeError("Nextcloud did not return a valid JSON status") from None
        if (not isinstance(status, dict) or status.get("installed") is not True
                or status.get("maintenance") is not False or status.get("needsDbUpgrade") is not False
                or not isinstance(status.get("version"), str)
                or ".".join(status["version"].split(".")[:3]) != self.versions["applications"]["nextcloud"]):
            raise RuntimeError("Nextcloud is not an installed, ready instance of the locked version")
        if current_packages:
            packages["host"] = self.manifest["package_versions"]["host"]
        self.manifest.update(package_versions=packages, nextcloud_status=status)
        if c.has_native_services:
            from .service_runtime import verify_services
            verify_services(self)

    def apply(self):
        from .service_execution import require_services_execution
        require_services_execution(self.config)
        self.require_control_resolution()
        from .operations import configure_ssh
        from .initialization import checkpoint_initialization
        vm=self.config.has_office and not self.config.native_office
        if vm and self.config.backend not in ('eurooffice','collabora'):
            raise ValueError('The selected VM installation path is not implemented; no provisioning performed')
        if self.config.native_office and not self.config.accept_microsoft_fonts:
            raise ValueError("The reviewed ONLYOFFICE package requires Microsoft webfonts; explicit operator EULA consent is required before provisioning")
        # No dataset, package, network or service mutation precedes resolution.
        if self._versions is None:
            self.prepare_versions()
        self.versions
        if self.config.has_native_services:
            from .service_runtime import prepare_assets
            prepare_assets(self)
        self.prepare_plugins()
        self.verify_source()
        journal = Journal(self.state / "deployment.json", self.config, self.progress)
        self.validate_resume(journal)
        if vm:
            self.prepare_office_vm_image()
        self.registry.save_host(self.config)
        self.registry.set_status(self.config.instance, "installing")
        from .service_runtime import (install_apps, observe_apps, prepare_push,
                                      TALK_ADDRESS_PHASE, prepare_talk_address, load_talk_address)
        try:
            journal.run([
                *([(TALK_ADDRESS_PHASE, lambda: prepare_talk_address(self, journal))]
                  if self.config.talk and self.config.talk_media_hostname else []),
                ("shared ZFS hierarchy", self.create_shared_storage),
                ("host prerequisites", self.install_manager),
                ("instance ZFS storage", self.create_storage),
                ("private networking and PF", self.configure_network),
                ("VNET devfs and boot ordering", self.configure_devfs),
                ("FreeBSD jail roots", self.bootstrap_jails),
                ("persistent mounts", self.attach_storage),
                *([('Alpine VM creation',self.create_office_vm),
                   ('Alpine VM boot',self.start_office_vm),
                   ('guest Docker bootstrap',self.bootstrap_office_vm),
                   ('Collabora CODE container' if self.config.backend=='collabora' else 'Euro-Office container',self.install_vm_office)] if vm else []),
                ("public provisioning payloads", self.stage_payloads),
                ("Nextcloud prerequisites", self.install_nextcloud),
                ("Nextcloud database", lambda: self.nextcloud_phase("database", ("db_password",))),
                ("quiesced initialization checkpoint", lambda: checkpoint_initialization(self)),
                ("Nextcloud installation", lambda: self.nextcloud_phase("install", ("admin_password", "db_password"))),
                *([("Nextcloud apps", lambda: install_apps(self))]
                  if "app_installation" in self.versions else []),
                *([("Client Push native artifact", lambda: prepare_push(self, journal))]
                  if "app_installation" in self.versions and self.config.has_native_services else []),
                *([("Nextcloud branding", lambda: self.brand_nextcloud(journal))]
                  if "app_installation" in self.versions and self.config.nextcloud_branding else []),
                ("Nextcloud publication", lambda: self.nextcloud_phase("publish")),
                *([("Talk packages", lambda: self.talk_phase("prepare")),
                   ("Talk configuration and local services", lambda: self.talk_phase("configure")),
                   ("Talk local control-plane checks", lambda: self.talk_phase("verify"))] if self.config.talk else []),
                *([("ONLYOFFICE and fonts", self.install_onlyoffice)] if self.config.native_office else []),
                *([("selected ONLYOFFICE plugins", lambda: self.plugin_command("install"))]
                  if self.config.onlyoffice_plugins else []),
                ("document integration" if self.config.has_office else "Nextcloud finish", self.integrate),
                ("optional jail SSH", lambda: configure_ssh(self)),
                *([('office VM restart persistence',self.restart_office_vm)] if vm else []),
                ("jail restart persistence", self.restart_jails),
                ("readiness checks", self.initial_readiness),
                ("boot activation", self.enable_boot)], checks={**({TALK_ADDRESS_PHASE: lambda: load_talk_address(self.registry, self.config)}
                                                                    if self.config.talk and self.config.talk_media_hostname else {}),
                                                               "shared ZFS hierarchy": self.create_shared_storage,
                                                               "instance ZFS storage": self.create_storage,
                                                               "persistent mounts": self.ensure_running,
                                                                "readiness checks": self.verify,
                                                                 "boot activation": self.enable_boot,
                                                                   **({"Nextcloud apps": lambda: observe_apps(self),
                                                                       "Client Push native artifact": lambda: prepare_push(self, journal)} if "app_installation" in self.versions else {}),
                                                                   **self.package_phase_checks(),
                                                                  **({'Alpine VM creation':self.create_office_vm,
                                                                     'Alpine VM boot':self.start_office_vm,
                                                                     'guest Docker bootstrap':self.check_office_vm_bootstrap,
                                                                     ('Collabora CODE container' if self.config.backend=='collabora' else 'Euro-Office container'):self.continue_vm_office} if vm else {})})
            self.checkpoint()
            if vm:
                atomic_write(self.state / "complete", COMPLETE_MESSAGE)
                self.registry.set_status(self.config.instance, "ready")
            else:
                self.registry.set_status(self.config.instance, "ready")
                atomic_write(self.state / "complete", COMPLETE_MESSAGE)
        except BaseException as error:
            # Retain every dataset and this instance's recovery journal. Do not
            # stop another instance, weaken shared PF, or erase application data.
            try:
                self.require_control_resolution()
                names = list(reversed(self.config.jails))
                uncertain = getattr(self, "_uncertain_jail", None)
                if uncertain in names:
                    names.remove(uncertain)
                    names.insert(0, uncertain)
                for jail in names:
                    self.require_control_resolution()
                    if (self.state / (jail + ".creating.json")).exists():
                        self.contain_jail(jail)
                        self.runner.run(*BASTILLE, "config", jail, "set", "boot", "off", timeout=10)
            except BaseException as containment:
                # No VM/network/next-jail mutation beneath an uncertain host
                # group or unconfirmed jail. Only retain private failure facts.
                try:
                    self.registry.set_status(self.config.instance, "failed", error_type=type(error).__name__,
                                             containment_error_type=type(containment).__name__)
                except Exception:
                    print("Could not retain failed containment status; manual assessment is required.", file=sys.stderr)
                raise
            if vm:
                from .office_vm import vm_paths, stop_native_vm, disable_vm_boot_service
                try:
                    disable_vm_boot_service(self)
                except Exception:
                    print('Could not safely disable the owned VM boot flag; inspect its retained service identity.',file=sys.stderr)
                marker=self.state/'allow-vm-start'
                if marker.exists() and not marker.is_symlink():
                    try: marker.rename(self.state/'allow-vm-start.disabled')
                    except OSError: print('Could not withdraw VM startup permission; instance is not declared ready.',file=sys.stderr)
                try:
                    paths=vm_paths(self.config)
                    receipt=self.state/(paths['name']+'.creating.json')
                    if receipt.exists() or receipt.is_symlink():
                        record=private_json(receipt)
                        if isinstance(record,dict) and 'vm_config_sha256' in record:
                            stop_native_vm(self)
                except Exception:
                    print('Cleanup could not confirm the owned VM stopped; retain its disk and inspect identity from the host console.',file=sys.stderr)
            try:
                self.registry.set_status(self.config.instance, "failed", error_type=type(error).__name__)
            except Exception:
                print("Failed status could not be saved; inspect retained state from the host console.", file=sys.stderr)
            raise

    def package_phase_checks(self):
        """Completed package phases observe installed requirements, not catalogs."""
        from .package_policy import repository_current
        from .service_runtime import verify_package_requirements
        if not repository_current(self.versions):
            return {}
        checks = {"host prerequisites": lambda: verify_package_requirements(self, "host"),
                  "Nextcloud prerequisites": lambda: verify_package_requirements(self, "nextcloud")}
        if self.config.native_office:
            checks["ONLYOFFICE and fonts"] = lambda: verify_package_requirements(self, "onlyoffice")
        if self.config.talk:
            checks["Talk packages"] = lambda: verify_package_requirements(self, "talk")
        return checks

    def initial_readiness(self):
        self.verify()
        from .enrollment import capture_baseline, BASELINE
        # Enrollment evidence must never be reconstructed for an already
        # published/verified instance. Unsupported static layouts do not change
        # the existing installation contract: report the limitation explicitly
        # and leave enrollment unavailable, rather than inventing a baseline.
        if (self.state / BASELINE).exists() or (self.state / "enrollment-unavailable.json").exists():
            return
        if not self.config.native_office or self.config.has_native_services:
            atomic_json(self.state / "enrollment-unavailable.json",
                        {"schema_version": 1, "eligible": False, "office_backend": self.config.backend,
                          "reason": "Not enrolled: native lifecycle enrollment is unsupported for this backend/service profile."})
            print("NOTICE: Installation checks passed; this backend/service profile is not enrolled. Native lifecycle enrollment is unsupported.",
                  file=sys.stderr)
            return
        try:
            capture_baseline(self)
        except (ValueError, OSError, RuntimeError) as error:
            atomic_json(self.state / "enrollment-unavailable.json",
                        {"schema_version": 1, "eligible": False, "error_type": type(error).__name__,
                         "reason": "First-readiness enrollment evidence could not be established; no baseline was adopted."})
            print("NOTICE: Installation checks passed, but lifecycle enrollment evidence is unavailable. "
                  "See the private enrollment-unavailable.json record; enrollment will refuse this instance.", file=sys.stderr)

    def require_original_artifact(self):
        """Read-only maintenance gate; never create an identity for old state."""
        from .host import read_private
        path = self.registry.evidence_path(self.config.instance, "source.sha256")
        if not path.is_file() or path.is_symlink() or read_private(path) != source_digest():
            raise ValueError("Maintenance requires the original installer artifact and retained source identity; no automatic adoption is supported")

    def verify_source(self):
        self.require_control_resolution()
        path = self.state / "source.sha256"
        value = source_digest()
        if path.exists() and path.read_text() != value:
            raise ValueError("Resume requires the same installer artifact that started this instance; use its retained release/check-out")
        self.registry.write_source(self.config.instance, value)
        inputs = hashlib.sha256(json.dumps(self.secrets, sort_keys=True).encode())
        for field in ("certificate_file", "private_key_file", "ca_file", "ssh_key_file"):
            filename = getattr(self.config, field)
            if filename:
                inputs.update(field.encode() + b"\0" + Path(filename).read_bytes())
        if self.config.additional_fonts_dir:
            directory = Path(self.config.additional_fonts_dir)
            for filename in sorted(directory.rglob("*")):
                if filename.is_symlink():
                    raise ValueError("Custom font inputs must not contain symlinks")
                if filename.is_file():
                    inputs.update(str(filename.relative_to(directory)).encode() + b"\0")
                    with filename.open("rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            inputs.update(block)
        pinned = self.state / "inputs.sha256"
        value = inputs.hexdigest() + "\n"
        if pinned.exists() and pinned.read_text() != value:
            raise ValueError("Credentials/certificate/public-key/font inputs changed; resume requires the original inputs")
        atomic_write(pinned, value)

    def validate_resume(self, journal):
        """Check persisted ownership before trusting completed host phases."""
        done = {name for name, record in journal.data["steps"].items() if record["state"] == "complete"}
        c = self.config
        if c.talk and c.talk_media_hostname:
            from .service_runtime import TALK_ADDRESS_PHASE, load_talk_address
            dependent = set(journal.data["steps"]) - {TALK_ADDRESS_PHASE}
            if dependent and TALK_ADDRESS_PHASE not in done:
                raise ValueError("Deployment phases exist without a completed Talk installation address")
            if TALK_ADDRESS_PHASE in done:
                load_talk_address(self.registry, c)
        if (getattr(self, "_versions", None) or {}).get("app_installation"):
            dependencies = {"Nextcloud apps": "Nextcloud installation",
                            "Nextcloud publication": "Client Push native artifact" if c.has_native_services else "Nextcloud apps"}
            if c.has_native_services:
                dependencies["Client Push native artifact"] = "Nextcloud apps"
            if any(name in done and parent not in done for name, parent in dependencies.items()):
                raise ValueError("Native app/Push initialization checkpoints are inconsistent; explicit recovery required")
        if c.has_office and not c.native_office:
            container='Collabora CODE container' if c.backend=='collabora' else 'Euro-Office container'
            dependencies={'Alpine VM creation':'persistent mounts','Alpine VM boot':'Alpine VM creation',
                          'guest Docker bootstrap':'Alpine VM boot',container:'guest Docker bootstrap',
                          'document integration':container,'office VM restart persistence':'document integration'}
            if any(name in done and parent not in done for name,parent in dependencies.items()):
                raise ValueError('VM installation checkpoints are inconsistent; explicit recovery assessment required')
            if 'Alpine VM creation' in done:
                from .office_vm import native_vm_identity
                native_vm_identity(self)
        if "instance ZFS storage" in done:
            for dataset in self.storage:
                if self.runner.output("zfs", "get", "-H", "-o", "value", OWNER, dataset.name) != c.instance:
                    raise ValueError("A checkpointed dataset is missing or has changed ownership")
        if "private networking and PF" in done:
            from .host import verify_managed_network
            verify_managed_network(self.registry, self.runner)
        if "FreeBSD jail roots" in done:
            for endpoint in c.jail_endpoints:
                jail, hostname = endpoint.name, endpoint.hostname
                if (self.runner.output(*BASTILLE, "config", jail, "get", "path") != str(self.jail_root(jail))
                        or self.runner.output(*BASTILLE, "config", jail, "get", "host.hostname") != hostname
                        or self.runner.output("zfs", "get", "-H", "-o", "value", OWNER,
                                              f"{c.bastille_dataset}/jails/{jail}") != c.instance):
                    raise ValueError("A checkpointed jail identity/hostname/ownership has changed")
