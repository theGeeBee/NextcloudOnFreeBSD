![NextcloudOnFreeBSD](assets/branding/nextcloud/logoheader.png)

# NextcloudOnFreeBSD

**An integrated Nextcloud installer for FreeBSD.**

NextcloudOnFreeBSD sets up **Nextcloud 35** by default and its supporting services
through one guided installer. Think of it as an AIO-style setup experience built
around FreeBSD: ZFS storage, isolated jails, HTTPS, and optional office and Talk services.

Nextcloud runs natively in a FreeBSD jail. Choose native ONLYOFFICE, or Euro-Office
or Collabora CODE in a dedicated Linux VM. The installer handles their configuration
and connections.

This is an independent project—not official Nextcloud AIO or a FreeBSD port of it.
It focuses on installation and integration; ongoing updates and backups remain
under your control.

See the [comparison with Nextcloud AIO](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Nextcloud-AIO-comparison)
and [architecture guide](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Architecture).

**Stable release: v1.0.1.** Bug fixes, ONLYOFFICE 10 support and FreeBSD 15+
support for new deployments. See the [release notes and downloads](https://github.com/theGeeBee/NextcloudOnFreeBSD/releases/tag/v1.0.1).

[Repository](https://github.com/theGeeBee/NextcloudOnFreeBSD) ·
[Website](https://theGeeBee.github.io/NextcloudOnFreeBSD/) ·
[Wiki](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki)

## Choose your setup

| Office choice | What runs on your host |
| --- | --- |
| **ONLYOFFICE** — default | Nextcloud and native ONLYOFFICE in separate FreeBSD jails |
| **Euro-Office** or **Collabora CODE** | A Nextcloud jail and an Alpine Linux VM running the office server in Docker |
| **Nextcloud only** | A Nextcloud jail without an office server |

Client Push is included. Optional Talk adds its own HPB/TURN jail with any office
choice. You can also select apps such as Calendar, Contacts, Deck and Tasks, or
connect existing SFTP or HTTP/HTTPS storage with **External files**.

Multiple instances can share a host, each with its own storage and private
network. Switching an installed office backend is not supported.

A clean or dedicated FreeBSD host is not required. Install alongside existing
jails on a suitably configured host; see the
[host preparation guide](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Coexistence)
for networking, PF and resource-conflict requirements. The installer creates new
deployments; it does not adopt or upgrade existing Nextcloud installations.

The defaults are **Nextcloud 35, PHP 8.5 and MariaDB 12.3**. Use **Advanced software
settings** to choose other versions. Untested choices show a warning but can still
be attempted; unavailable or incompatible software may fail to install.

## Requirements

- **Requires FreeBSD 15 or later (amd64).**
- ZFS and root access outside a jail.
- A fixed host/LAN IPv4 address, a public hostname and working DNS.
- Host networking and PF configured as described in the
  [host preparation guide](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Coexistence).
- Enough memory and storage for your choices; **16 GiB RAM or more** is recommended.
- Working bhyve virtualization for Euro-Office or Collabora CODE.
- Console recovery access and a second SSH connection.

*Tested on FreeBSD 15.1-RELEASE, 15.2-STABLE and 16-CURRENT.*

New deployments accept FreeBSD 15+ RELEASE, STABLE and CURRENT versions.
Use a maintained RELEASE for production.

HTTPS can use Let's Encrypt, supplied certificates or an external reverse proxy.
The [installation guide](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Installation-Guide)
covers DNS, forwarding and the extra ports needed for Talk.

## Install

From a reviewed checkout or verified unpacked installer, run this as root:

```sh
sh install.sh install
```

Follow the wizard and review your settings before choosing **APPLY**. Stay at the
terminal: when prompted, open a new SSH connection to check access, then enter
`KEEP` before the deadline. Use `sh install.sh --plain install` for text prompts.

To use a settings file, copy the matching example from `examples/`, edit it for
your host and run:

```sh
sh install.sh install --config settings.json
```

See the [recipe guide](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Unattended-CLI-install)
for examples, file permissions and consent options. Recipe installation still
requires your attendance, even with `--yes`.

## After installation

Open the displayed HTTPS address. Generated credentials are saved in
`/var/db/cloud-installer/instances/INSTANCE/secrets.json`, readable only by root.
Keep the original installer directory for Resume, recovery and removal.

```sh
sh install.sh status INSTANCE
sh install.sh resume INSTANCE
sh install.sh --help
```

Replace `INSTANCE` with your instance name. If installation stops, follow its
recovery message before resuming. See the
[uninstall guide](https://github.com/theGeeBee/NextcloudOnFreeBSD/wiki/Uninstall)
before removing an instance or deleting its data.

The installer's backup/restore commands and upgrade assistant are unavailable for
new installations. Manage updates and maintain your own backups.

## License

[BSD 3-Clause](LICENSE). Installed applications have their own licences.
