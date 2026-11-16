#!/bin/sh
# Dedicated Talk jail worker; host fresh-profile admission remains fenced.
# prepare: no stdin; configure: only fixed-path rendered configs JSON on stdin;
# verify: no stdin, observational only. Never pass the host secret bundle.
set +x
set +v
set -eu
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
ulimit -c 0

fail() { printf '%s\n' "Talk worker: $*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'Expected prepare|configure|verify.'
case "$1" in prepare|configure|verify) ;; *) fail 'Unknown phase.' ;; esac

mode=$1
[ "$(id -u)" -eq 0 ] || fail 'Run as root in the owned Talk jail.'
[ "$(uname -s)" = FreeBSD ] || fail 'FreeBSD is required.'
[ "$(sysctl -n security.jail.jailed)" = 1 ] || fail 'Refusing execution outside a jail.'
[ "$(sysctl -n security.jail.vnet)" = 1 ] || fail 'A dedicated VNET Talk jail is required.'
PAYLOAD=/root/cloud-installer
RUNTIME=$PAYLOAD/runtime.json
STATE=/var/db/cloud-installer-talk
private() {
    [ -f "$1" ] && [ ! -L "$1" ] || fail 'Missing regular protected payload file.'
    case "$(stat -f '%u:%Lp' "$1")" in 0:400|0:600) ;; *) fail 'Private payload ownership/mode changed.' ;; esac
}
trusted() {
    [ -f "$1" ] && [ ! -L "$1" ] || fail 'Missing regular trusted worker input.'
    case "$(stat -f '%u:%Lp' "$1")" in 0:400|0:444|0:555|0:600|0:644|0:700|0:755) ;; *) fail 'Trusted payload ownership/mode changed.' ;; esac
}
[ -d "$PAYLOAD" ] && [ ! -L "$PAYLOAD" ] && [ "$(stat -f '%u:%Lp' "$PAYLOAD")" = 0:700 ] \
    || fail 'The owned payload must be root-owned mode 0700.'
private "$RUNTIME"
private "$PAYLOAD/services.json"
trusted "$PAYLOAD/resources/native-services.json"
trusted "$PAYLOAD/resources/jails/versions.sh"
trusted "$PAYLOAD/resources/jails/talk-runtime.py"
trusted "$PAYLOAD/installer/talk.py"
. "$PAYLOAD/resources/jails/versions.sh"
version_load talk
version_environment
[ "$version_release" = 15.1-RELEASE ] && [ "$version_architecture" = amd64 ] \
    && [ "$version_service_profile" = native-v1 ] && [ "$version_talk_selected" = yes ] \
    || fail 'Unreviewed Talk target or service selection.'
# Validate the public envelope before installing the explicit Python root.
/usr/libexec/flua - "$RUNTIME" >/dev/null 2>&1 <<'LUA' || fail 'Invalid Talk public envelope.'
local p = require('ucl').parser()
assert(p:parse_file(arg[1]))
local r = p:get_object()
for k in pairs(r) do assert(k == 'repository' or k == 'versions' or k == 'talk') end
assert(type(r.talk) == 'table')
local t = r.talk
local required = {'instance','talk_ip','talk_gateway','nextcloud_ip','backend_url','talk_public_ip',
    'talk_turn_port','talk_media_port_min','talk_media_port_max','talk_relay_port_min',
    'talk_relay_port_max','no_other_sensitive_udp_services'}
local allowed = {office_ip=true, forbidden_peer_ips=true, talk_media_hostname=true}
for _, k in ipairs(required) do allowed[k]=true; assert(t[k] ~= nil) end
for k in pairs(t) do assert(allowed[k]) end
assert(type(t.instance) == 'string' and t.instance:match('^[a-z][a-z0-9]*$') and #t.instance <= 8)
assert(t.no_other_sensitive_udp_services == true)
local function ip(value)
    assert(type(value) == 'string')
    local a,b,c,d = value:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
    assert(a and b and c and d)
    a,b,c,d = tonumber(a),tonumber(b),tonumber(c),tonumber(d)
    assert(a <= 255 and b <= 255 and c <= 255 and d <= 255)
    assert(value == string.format('%d.%d.%d.%d',a,b,c,d))
    return a,b,c,d, ((a*256+b)*256+c)*256+d
end
local function private(value)
    local a,b,c,d,n = ip(value)
    assert(a == 10 or (a == 172 and b >= 16 and b <= 31) or (a == 192 and b == 168))
    return n
end
local tk,gw,nc = private(t.talk_ip),private(t.talk_gateway),private(t.nextcloud_ip)
assert(tk % 4 == 2 and gw == tk-1 and tk ~= nc and gw ~= nc)
if t.office_ip ~= nil then
    assert(type(t.office_ip) == 'string')
    if t.office_ip ~= '' then local _,_,_,_,oo = ip(t.office_ip); assert(oo ~= tk and oo ~= gw and oo ~= nc) end
end
local a,b,c,d = ip(t.talk_public_ip)
assert(a ~= 0 and a ~= 10 and a ~= 127 and a < 224)
assert(not (a == 100 and b >= 64 and b <= 127) and not (a == 169 and b == 254))
assert(not (a == 172 and b >= 16 and b <= 31) and not (a == 192 and b == 168))
assert(not (a == 192 and ((b == 0 and (c == 0 or c == 2)) or (b == 88 and c == 99))))
assert(not (a == 198 and (b == 18 or b == 19 or (b == 51 and c == 100))))
assert(not (a == 203 and b == 0 and c == 113))
if t.talk_media_hostname ~= nil then
    local name = t.talk_media_hostname
    assert(type(name) == 'string' and #name >= 3 and #name <= 253)
    assert(name:find('.',1,true) and not name:match('^[%d%.]+$'))
    assert(not name:match('^%.') and not name:match('%.$') and not name:find('..',1,true))
    for label in name:gmatch('[^.]+') do
        assert(#label <= 63 and label:match('^[a-z0-9][a-z0-9%-]*$') and not label:match('%-$'))
    end
end
for _, k in ipairs({'talk_turn_port','talk_media_port_min','talk_media_port_max','talk_relay_port_min','talk_relay_port_max'}) do
    assert(type(t[k]) == 'number' and t[k] % 1 == 0 and t[k] >= 1024 and t[k] <= 65535)
end
assert(t.talk_media_port_min <= t.talk_media_port_max and t.talk_relay_port_min <= t.talk_relay_port_max)
assert(t.talk_media_port_max < t.talk_relay_port_min or t.talk_relay_port_max < t.talk_media_port_min)
local turn = t.talk_turn_port
assert(turn ~= 4222 and turn ~= 8080 and turn ~= 8188)
assert(turn < t.talk_media_port_min or turn > t.talk_media_port_max)
assert(turn < t.talk_relay_port_min or turn > t.talk_relay_port_max)
assert(type(t.backend_url) == 'string' and #t.backend_url <= 280)
local authority = assert(t.backend_url:match('^https://([a-z0-9%.:%-]+)$'))
local host,port = authority:match('^([^:]+):(%d+)$')
if port then assert(tonumber(port) >= 1 and tonumber(port) <= 65535) else host=authority; assert(not host:find(':',1,true)) end
assert(#host <= 253 and not host:match('^%.') and not host:match('%.$') and not host:find('..',1,true))
for label in host:gmatch('[^.]+') do
    assert(#label <= 63 and label:match('^[a-z0-9][a-z0-9%-]*$') and not label:match('%-$'))
end
if t.forbidden_peer_ips ~= nil then
    assert(type(t.forbidden_peer_ips) == 'table')
    for key,value in pairs(t.forbidden_peer_ips) do
        assert(type(key) == 'number' and key >= 1 and key % 1 == 0)
        local _,_,_,_,n = ip(value); assert(n ~= tk)
    end
end
LUA
[ -d "$STATE" ] && [ ! -L "$STATE" ] || fail 'Missing mounted Talk runtime directory.'
[ "$(stat -f '%u' "$STATE")" = 0 ] || fail 'Talk runtime must be root-owned.'
state_mode=$(stat -f '%Lp' "$STATE")
[ "$((0$state_mode & 022))" -eq 0 ] || fail 'Talk runtime must not be group/world writable.'
# FreeBSD install -d applies -m only to the leaf; missing intermediate parents
# otherwise inherit our private umask. Check ALL existing public parents before
# creating anything, and never widen an existing directory during any phase.
public_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -f '%u:%g:%Lp' "$1")" = 0:0:755 ] \
        || fail 'Native package public parent must be a real root:wheel 0755 directory.'
}
fresh_public_parents=no
if [ "$mode" = prepare ] && [ ! -e "$STATE/state.json" ] && [ ! -L "$STATE/state.json" ]; then
    fresh_public_parents=yes
fi
public_directory /usr
for directory in /usr/local /usr/local/etc /usr/local/etc/pkg /usr/local/etc/pkg/repos; do
    if [ -e "$directory" ] || [ -L "$directory" ]; then
        public_directory "$directory"
    else
        [ "$fresh_public_parents" = yes ] || fail 'Missing native package public parent; assess recovery.'
    fi
done
for directory in /usr/local /usr/local/etc /usr/local/etc/pkg /usr/local/etc/pkg/repos; do
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
        [ "$fresh_public_parents" = yes ] || fail 'Missing native package public parent; assess recovery.'
        (umask 022; install -d -o root -g wheel -m 755 "$directory")
    fi
    public_directory "$directory"
done
if [ "$mode" = prepare ]; then
    if [ -e "$STATE/state.json" ] || [ -L "$STATE/state.json" ]; then
        [ "$(stat -f '%u:%Lp' "$STATE")" = 0:700 ] || fail 'Saved Talk runtime protection changed.'
        private "$STATE/state.json"
        version_packages_check < /dev/null >/dev/null
        [ -x /usr/local/bin/python3 ] || fail 'The selected Talk Python worker interpreter is missing.'
        exec /usr/bin/env -i PATH="$PATH" /usr/local/bin/python3 -I -B "$PAYLOAD/resources/jails/talk-runtime.py" prepare < /dev/null
    fi
    chmod 700 "$STATE"
    if [ -e "$STATE/packages.log" ] || [ -L "$STATE/packages.log" ]; then
        private "$STATE/packages.log"
    fi
    # Public-only package diagnostics; never attach configure stdin to a command.
    REPO=/usr/local/etc/pkg/repos/cloud-installer.conf
    if [ ! -e "$REPO" ] && [ ! -L "$REPO" ]; then
        /usr/bin/install -o root -g wheel -m 644 /dev/null "$REPO"
        cat > "$REPO" <<EOF
FreeBSD-ports: {
  url: "pkg+https://pkg.FreeBSD.org/\${ABI}/${repository}",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
EOF
    fi
    trusted "$REPO"
    # Refuse repository changes rather than selecting a different mirror/source.
    expected="pkg+https://pkg.FreeBSD.org/\${ABI}/${repository}"
    /usr/libexec/flua - "$REPO" "$expected" >/dev/null 2>&1 <<'LUA' || fail 'Owned signed repository configuration changed.'
local p = require('ucl').parser(); assert(p:parse_file(arg[1]))
local r = p:get_object(); local c = assert(r['FreeBSD-ports'])
assert(c.url == arg[2] and c.mirror_type == 'srv' and c.signature_type == 'fingerprints')
assert(c.fingerprints == '/usr/share/keys/pkg' and c.enabled == true)
for k in pairs(r) do assert(k == 'FreeBSD-ports') end
for k in pairs(c) do assert(k == 'url' or k == 'mirror_type' or k == 'signature_type' or k == 'fingerprints' or k == 'enabled') end
LUA
    if [ ! -x /usr/local/sbin/pkg ]; then
        (umask 022; pkg bootstrap -y -r FreeBSD-ports < /dev/null) > "$STATE/packages.log" 2>&1 \
            || fail 'Signed package bootstrap failed; inspect private packages.log.'
    fi
    pkg update -r FreeBSD-ports < /dev/null >> "$STATE/packages.log" 2>&1 \
        || fail 'Signed catalog update failed; inspect private packages.log.'
    (version_packages_install) < /dev/null >> "$STATE/packages.log" 2>&1 \
        || fail 'Talk package installation failed; retain the original requirements/lock and private log.'
else
    [ "$(stat -f '%u:%Lp' "$STATE")" = 0:700 ] || fail 'Talk runtime protection changed.'
    version_packages_check < /dev/null >/dev/null
fi
[ -x /usr/local/bin/python3 ] || fail 'The selected Talk Python worker interpreter is required.'
if [ "$mode" = configure ]; then
    exec /usr/bin/env -i PATH="$PATH" /usr/local/bin/python3 -I -B "$PAYLOAD/resources/jails/talk-runtime.py" configure
else
    exec /usr/bin/env -i PATH="$PATH" /usr/local/bin/python3 -I -B "$PAYLOAD/resources/jails/talk-runtime.py" "$mode" < /dev/null
fi
