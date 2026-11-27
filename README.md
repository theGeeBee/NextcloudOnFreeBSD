![NextcloudOnFreeBSD](assets/branding/nextcloud/logoheader.png)

# NextcloudOnFreeBSD

**An integrated Nextcloud installer for FreeBSD.**

NextcloudOnFreeBSD sets up **Nextcloud 35** by default with ZFS storage,
private networking, HTTPS, and optional office and Talk services. It is an
independent project, not official Nextcloud AIO. It installs and integrates
services; you remain in control of maintenance and backups.

**Stable release: v1.1.0.** [Release notes and verified download](https://github.com/theGeeBee/NextcloudOnFreeBSD/releases/tag/v1.1.0).

[Repository](https://github.com/theGeeBee/NextcloudOnFreeBSD) ·
[Website](https://theGeeBee.github.io/NextcloudOnFreeBSD/) ·
[Wiki](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki)

## What you can set up

- **Guided or recipe-based setup.** Review the plan before installation.
  New deployments can opt out of project branding in the wizard or recipe.
- **FreeBSD-native isolation.** Nextcloud runs in a jail with its own ZFS
  datasets and private network. A prepared host can also run existing jails
  and independently managed VMs. The installer does not adopt existing
  Nextcloud deployments.
- **Four office choices.** Native ONLYOFFICE in a separate jail (default),
  Euro-Office or Collabora CODE in a dedicated Alpine VM, or Nextcloud only.
  An installed backend cannot be switched.
- **Apps and storage.** Client Push is included. Optional Talk adds a dedicated
  HPB/TURN jail. Choose other apps or connect existing SFTP or HTTP/HTTPS storage.
- **Software and HTTPS.** Choose Nextcloud, PHP and MariaDB versions. Use
  Let's Encrypt, a supplied certificate or an external HTTPS proxy. If the
  primary release-key download fails, the Ubuntu keyserver fallback still
  requires a valid signature from the same pinned Nextcloud key.

See the [architecture guide](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Architecture)
and [comparison with Nextcloud AIO](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Nextcloud-AIO-comparison).

## Requirements

- FreeBSD 15 or later on amd64, ZFS, and root access outside a jail. Use a
  maintained RELEASE for production.
- An assigned host IPv4 address (static or DHCP), a public hostname, and
  working DNS. Reserve the address if you use DHCP so forwarding stays stable.
- [Prepared host networking and PF](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Coexistence),
  console recovery access, and a second SSH connection.
- Enough memory and storage for the selected workload. Euro-Office and
  Collabora also need working bhyve virtualization.

Defaults are **Nextcloud 35, PHP 8.5 and MariaDB 12.3**. Untested version
choices show a warning but are not blocked by policy; actual installation
still depends on package availability and working integration.

The v1.1.0 runtime was qualified on FreeBSD 15.1-RELEASE. Earlier
default-profile tests also covered 15.2-STABLE and 16-CURRENT.

## Install

From a reviewed checkout or verified unpacked installer, run one as root:

```sh
sh install.sh install                         # Guided terminal wizard
sh install.sh install --config settings.json  # JSON recipe
```

Read the [installation guide](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Installation-Guide)
for host setup, forwarding and the **APPLY** and **KEEP** confirmations.
Use `examples/` and the [recipe guide](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Unattended-CLI-install)
to start a settings file. Both paths require attendance, even with `--yes`.
Use `--plain` for text prompts.

## After installation

Open the displayed HTTPS address. Generated credentials are stored in
`/var/db/cloud-installer/instances/INSTANCE/secrets.json`, readable only by root.
Keep the original installer for Resume and recovery.

```sh
sh install.sh status INSTANCE
sh install.sh verify INSTANCE
sh install.sh --help
```

The dashboard shows recorded state without checking for updates. `self-update`
changes only the installer. Rollback requires a previous retained selection.
Eligible completed instances support attended FreeBSD jail ports or Alpine
office VM package updates. Restart affected services yourself and run Verify.

Compatible newer installers can Verify or uninstall eligible completed v1.1
deployments. [Uninstall](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Uninstall)
retains application data by default. Its optional database and configuration
export is for manual recovery, excludes user files, and is not a full backup.

Manage Nextcloud core, the host OS and jail bases, and Docker images separately.
Keep tested backups; fresh deployments do not include installer-managed backup or restore.
See [Software versions and maintenance](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Software-Versions).

## License

[BSD 3-Clause](LICENSE). Installed applications have their own licences.
