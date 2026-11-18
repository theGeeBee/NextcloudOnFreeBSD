#!/bin/sh
# Trusted common worker functions. Only public validated scalars cross from UCL
# into shell variables; runtime.json and packages.lock are never shell programs.

# Do not inherit pkg environment overrides (ABI, repositories, signature/TLS
# exceptions) from the operator. The base shim is used only for pkg bootstrap.
pkg() {
    if [ -x /usr/local/sbin/pkg ]; then
        /usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/local/sbin/pkg -C /dev/null "$@"
    else
        /usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/sbin/pkg "$@"
    fi
}

version_private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || fail 'Missing regular version payload input.'
    [ "$(stat -f '%u:%Lp' "$1")" = "0:$2" ] || fail 'Version payload ownership or mode changed.'
    [ "$(stat -f '%z' "$1")" -le "$3" ] || fail 'Version payload exceeds the size limit.'
}

version_load() {
    case "$(stat -f '%u:%Lp' "$RUNTIME")" in
        0:600|0:400) ;;
        *) fail 'runtime.json must be root-owned and private-mode.' ;;
    esac
    [ -f "$RUNTIME" ] && [ ! -L "$RUNTIME" ] && [ "$(stat -f '%z' "$RUNTIME")" -le 65536 ] \
        || fail 'Invalid public runtime input.'
    VERSION_LOCK=$PAYLOAD/packages.lock
    VERSION_DEPENDENCIES=$PAYLOAD/packages.dependencies
    VERSION_CONNECTOR=$PAYLOAD/connector.json
    VERSION_SERVICES=$PAYLOAD/services.json
    VERSION_REQUIREMENTS=$PAYLOAD/packages.requirements.json
    [ -x /usr/libexec/flua ] || fail 'FreeBSD base flua is required to validate the version plan.'
    version_settings=$(/usr/libexec/flua - "$RUNTIME" "$VERSION_LOCK" "$VERSION_DEPENDENCIES" "$1" "$VERSION_SERVICES" "$PAYLOAD/resources/native-services.json" "$VERSION_REQUIREMENTS" "$PAYLOAD/resources/versions.json" <<'LUA'
local ok, result = pcall(function()
    local parser = require("ucl").parser()
    assert(parser:parse_file(arg[1]))
    local runtime = parser:get_object()
    assert(type(runtime) == "table")
    assert(runtime.repository == "latest" or runtime.repository == "quarterly")
    local v = runtime.versions
    assert(type(v) == "table")
    local keys = {"nextcloud", "onlyoffice", "connector", "php", "database", "freebsd_release",
        "architecture", "php_package", "plan_sha256", "packages_sha256", "dependencies_sha256", "connector_sha256"}
    local none = v.office_backend == "none"
    local vm = v.office_backend == "eurooffice" or v.office_backend == "collabora"
    local fresh = v.app_installation ~= nil
    if none then
        assert(arg[4] == "nextcloud" or arg[4] == "talk")
        assert(runtime.onlyoffice_ip == nil and runtime.storage_url == nil)
        keys = {"nextcloud", "php", "database", "freebsd_release", "architecture", "php_package",
            "plan_sha256", "packages_sha256", "dependencies_sha256", "office_backend"}
    elseif vm then
        assert(arg[4] == "nextcloud" or arg[4] == "talk")
        if not fresh then assert(v.connector_app == (v.office_backend == "eurooffice" and "eurooffice" or "richdocuments")) end
        keys = {"nextcloud", "php", "database", "freebsd_release", "architecture", "php_package",
            "plan_sha256", "packages_sha256", "dependencies_sha256", "connector", "connector_app", "connector_sha256", "office_backend"}
    end
    if fresh then
        assert(v.app_installation == "occ")
        assert(none or vm or v.office_backend == "onlyoffice")
        keys = {"nextcloud", "php", "database", "freebsd_release", "architecture", "php_package",
            "plan_sha256", "packages_sha256", "dependencies_sha256", "office_backend", "app_installation"}
        if not none and not vm then keys[#keys + 1] = "onlyoffice" end
    end
    local current = v.package_installation ~= nil
    if current then
        assert(v.package_installation == "pkg")
        local retained = {}
        for _, key in ipairs(keys) do
            if key ~= "packages_sha256" and key ~= "dependencies_sha256" then retained[#retained + 1] = key end
        end
        keys = retained
        keys[#keys + 1], keys[#keys + 2] = "package_installation", "requirements_sha256"
    end
    local service_keys = {}
    local services, service_policy
    local function exact(object, fields)
        assert(type(object) == "table")
        local allowed = {}
        for _, key in ipairs(fields) do assert(object[key] ~= nil); allowed[key] = true end
        for key in pairs(object) do assert(allowed[key]) end
    end
    local function load(path)
        local p = require("ucl").parser()
        assert(p:parse_file(path))
        return p:get_object()
    end
    local function platform(policy)
        if not current or not fresh or policy.repository_current_platform == nil then return false end
        local rule = policy.repository_current_platform
        exact(rule, {"minimum_major", "architecture"})
        assert(math.type(rule.minimum_major) == "integer" and rule.minimum_major == 15 and rule.architecture == "amd64")
        local major, minor, channel = v.freebsd_release:match("^(%d+)%.(%d+)%-([A-Z]+)$")
        assert(major and (major == "0" or not major:match("^0")) and (minor == "0" or not minor:match("^0")))
        assert(tonumber(major) >= rule.minimum_major and v.architecture == rule.architecture)
        assert(channel == "RELEASE" or channel == "STABLE" or channel == "CURRENT")
        return true
    end
    if v.service_profile ~= nil then
        assert(v.service_profile == "native-v1")
        assert(v.talk_selected == "yes" or v.talk_selected == "no")
        assert(type(v.services_sha256) == "string" and #v.services_sha256 == 64 and v.services_sha256:match("^[a-f0-9]+$"))
        services, service_policy = load(arg[5]), load(arg[6])
        exact(services, {"profile", "policy_sha256", "talk", "push"})
        assert(services.profile == "native-v1" and type(services.talk) == "boolean")
        assert(services.talk == (v.talk_selected == "yes"))
        assert(type(services.policy_sha256) == "string" and #services.policy_sha256 == 64 and services.policy_sha256:match("^[a-f0-9]+$"))
        assert(service_policy.schema_version == 1 and service_policy.profile == services.profile)
        local targets = {service_policy.target}
        if current then
            for _, item in ipairs(service_policy.repository_current_targets or {}) do targets[#targets + 1] = item end
        end
        local matched = platform(service_policy)
        for _, item in ipairs(targets) do
            if item.release == v.freebsd_release and item.architecture == v.architecture then matched = true end
        end
        assert(matched)
        if not current then assert(v.nextcloud:match("^35%.") and v.php:match("^8%.5%.")) end
        exact(services.push, {"app", "native"})
        if fresh then
            assert(services.push.app == "occ" and services.push.native == "deferred")
        else
        exact(services.push.app, {"release", "sha256", "size"})
        exact(services.push.native, {"version", "url", "sha256", "size", "architecture"})
        for key, value in pairs(service_policy.push.native) do assert(services.push.native[key] == value) end
        local app, rule = services.push.app, service_policy.push.app
        assert(type(app.size) == "number" and app.size == rule.size and app.sha256 == rule.sha256)
        exact(app.release, {"version", "download", "phpVersionSpec", "platformVersionSpec", "isNightly", "signatureDigest", "signature", "certificate"})
        for _, key in ipairs({"version", "download", "phpVersionSpec", "platformVersionSpec"}) do assert(app.release[key] == rule[key]) end
        assert(app.release.isNightly == false and app.release.signatureDigest == "sha512")
        for _, key in ipairs({"signature", "certificate"}) do
            assert(type(app.release[key]) == "string" and #app.release[key] > 0 and #app.release[key] <= 65536 and not app.release[key]:find("\0", 1, true))
        end
        end
        service_keys = {"service_profile", "services_sha256", "talk_selected"}
    end
    local allowed = {}
    for _, key in ipairs(service_keys) do allowed[key] = true end
    for _, key in ipairs(keys) do
        allowed[key] = true
        assert(type(v[key]) == "string" and #v[key] <= 128)
    end
    for key in pairs(v) do assert(allowed[key]) end
    local function numeric(value)
        return value:match("^%d+%.[%d.]+$") and not value:find("..", 1, true)
            and not value:match("%.$")
    end
    assert(v.nextcloud:match("^%d+%.%d+%.%d+$"))
    if not current and not none and not vm then
        assert(v.onlyoffice:match("^%d+%.%d+%.%d+$"))
    end
    if not none and not fresh then
        assert(v.connector:match("^%d+%.%d+%.%d+$"))
        assert(#v.connector_sha256 == 64 and v.connector_sha256:match("^[a-f0-9]+$"))
    end
    if current then
        for _, key in ipairs((none or vm) and {"php", "database"} or {"php", "database", "onlyoffice"}) do
            assert(v[key] == "" or v[key]:match("^[A-Za-z0-9%._+][A-Za-z0-9%.+_,~:%-]*$"))
        end
    else
        assert(numeric(v.php) and numeric(v.database))
    end
    local version_policy = current and load(arg[8]) or nil
    local generic = version_policy and platform(version_policy)
    local development = current and fresh and not none and not vm
        and (v.freebsd_release == "15.2-STABLE" or v.freebsd_release == "16.0-CURRENT") and v.architecture == "amd64"
    assert(v.freebsd_release:match("^%d+%.%d+%-RELEASE$") or development or generic)
    assert(v.architecture:match("^[a-z][a-z0-9_]*$"))
    assert(v.php_package:match("^php%d+$"))
    for _, key in ipairs(current and {"plan_sha256", "requirements_sha256"} or {"plan_sha256", "packages_sha256", "dependencies_sha256"}) do
        assert(#v[key] == 64 and v[key]:match("^[a-f0-9]+$"))
    end
    if current then
        local r = load(arg[7])
        exact(r, {"schema_version", "repository", "abi", "group", "roots"})
        assert((r.schema_version == 1 or r.schema_version == 2) and r.repository == runtime.repository)
        local selected
        for _, item in ipairs(version_policy.targets) do
            if item.release == v.freebsd_release and item.architecture == v.architecture then selected = item end
        end
        local abi
        if generic then
            abi = "FreeBSD:" .. v.freebsd_release:match("^(%d+)%.") .. ":amd64"
        else
            assert(selected and (v.freebsd_release == "15.1-RELEASE" or development) and v.architecture == "amd64")
            abi = selected.abi
        end
        assert(r.abi == abi)
        assert(r.group == arg[4] and (r.group == "nextcloud" or r.group == "onlyoffice" or r.group == "talk"))
        assert(type(r.roots) == "table" and next(r.roots))
        local count = 0
        local database
        for name, origin in pairs(r.roots) do
            count = count + 1; assert(count <= 1024)
            local origin_request = r.schema_version == 2 and name == origin and name:match("^[A-Za-z0-9][A-Za-z0-9_+%.%-]*/[A-Za-z0-9][A-Za-z0-9_+%.%-]*$")
            assert(type(name) == "string" and #name <= 257 and ((#name <= 128 and name:match("^[A-Za-z0-9][A-Za-z0-9_+%.%-]*$")) or origin_request))
            assert(type(origin) == "string" and #origin <= 257 and ((r.schema_version == 2 and origin == "") or origin:match("^[A-Za-z0-9][A-Za-z0-9_+%.%-]*/[A-Za-z0-9][A-Za-z0-9_+%.%-]*$")))
            if name:match("^php%d+$") or name:match("^php%d+%-") then
                assert(r.group == "nextcloud" and (name == v.php_package or name:sub(1, #v.php_package + 1) == v.php_package .. "-"))
            end
            if name:match("^mariadb%d+%-server$") then
                assert(not database and origin == "databases/" .. name)
                database = name:gsub("%-server$", "")
            end
        end
        if r.group == "nextcloud" then
            assert(r.roots[v.php_package] == "lang/" .. v.php_package)
            assert(database and r.roots[database .. "-client"] == "databases/" .. database .. "-client")
        elseif r.group == "onlyoffice" then
            assert(r.roots["onlyoffice-documentserver"] == "www/onlyoffice-documentserver")
        else
            assert(services and services.talk)
            for _, role in ipairs({"talk_signaling", "talk_nats", "talk_janus", "talk_turn", "talk_python"}) do
                local rule = service_policy.talk.roles[role]
                assert(r.roots[rule.package] == rule.origin)
            end
        end
        local prefix = services and ("native-v1 " .. v.services_sha256 .. " " .. v.talk_selected .. " ") or ""
        local function observed(value) return value ~= "" and value or "unobserved" end
        return prefix .. "pkg " .. (fresh and "occ" or "legacy") .. " " .. (v.office_backend or "onlyoffice") .. " "
            .. runtime.repository .. " " .. v.nextcloud .. " " .. observed(v.onlyoffice or "none") .. " "
            .. table.concat({observed(v.php), observed(v.database), v.freebsd_release, v.architecture, v.php_package, v.plan_sha256, v.requirements_sha256,
                v.connector or "none", v.connector_app or "none", v.connector_sha256 or "none", abi}, " ")
    end
    local file = assert(io.open(arg[2], "rb"))
    local text = assert(file:read("*a"))
    file:close()
    assert(#text > 0 and #text <= 1048576 and text:sub(-1) == "\n")
    local previous, names = nil, {}
    for line in text:gmatch("([^\n]*)\n") do
        local name, version, origin, checksum = line:match("^([^|]+)|([^|]+)|([^|]+)|([^|]+)$")
        assert(name and #name <= 256 and #version <= 256 and #origin <= 256 and #checksum <= 256)
        assert(name:match("^[A-Za-z0-9][A-Za-z0-9_+%.%-]*$"))
        assert(version:match("^[A-Za-z0-9%._+][A-Za-z0-9%.+_,~:%-]*$"))
        assert(origin:match("^[A-Za-z0-9][A-Za-z0-9_+%.%-]*/[A-Za-z0-9][A-Za-z0-9_+%.%-]*$"))
        assert(checksum:match("^%d+%$[A-Za-z0-9]+$") or (#checksum == 64 and checksum:match("^[a-fA-F0-9]+$")))
        assert(not names[name] and (not previous or previous < line))
        names[name], previous = {version=version, origin=origin}, line
    end
    file = assert(io.open(arg[3], "rb"))
    text = assert(file:read("*a"))
    file:close()
    assert(#text <= 1048576 and (#text == 0 or text:sub(-1) == "\n"))
    local edges = {}
    previous = nil
    for line in text:gmatch("([^\n]*)\n") do
        local owner, name, version, origin = line:match("^([^|]+)|([^|]+)|([^|]+)|([^|]+)$")
        assert(owner and names[owner] and names[name])
        assert(names[name].version == version and names[name].origin == origin)
        local edge = owner .. "|" .. name
        assert(not edges[edge] and (not previous or previous < line))
        edges[edge], previous = true, line
    end
    local function upstream(version)
        return version and version:gsub(",%d+$", ""):gsub("_%d+$", "")
    end
    if arg[4] == "nextcloud" then
        assert(names[v.php_package] and upstream(names[v.php_package].version) == v.php)
    elseif arg[4] == "onlyoffice" then
        assert(names["onlyoffice-documentserver"] and upstream(names["onlyoffice-documentserver"].version) == v.onlyoffice)
    elseif arg[4] == "talk" then
        assert(services and services.talk)
        for _, role in ipairs({"talk_signaling", "talk_nats", "talk_janus", "talk_turn", "talk_python"}) do
            local rule = service_policy.talk.roles[role]
            local package = assert(names[rule.package])
            assert(package.origin == rule.origin)
            if rule.version_exact then assert(package.version == rule.version_exact)
            elseif role == "talk_python" then
                assert(rule.package == "python3" and rule.range.family == "3")
                assert(upstream(package.version) == "3" or upstream(package.version):match("^3%."))
            else
                -- Fresh repository selection, not a tested-patch pin. The exact
                -- signed package bytes/version are already in the lock above.
                assert(upstream(package.version):match("^%d[%d.]*$"))
            end
        end
    else
        error("Unknown worker group")
    end
    local values = {runtime.repository}
    for _, key in ipairs(keys) do values[#values + 1] = v[key] end
    local prefix = services and ("native-v1 " .. v.services_sha256 .. " " .. v.talk_selected .. " ") or ""
    if fresh then
        return prefix .. "occ " .. v.office_backend .. " " .. runtime.repository .. " " .. v.nextcloud .. " " .. (v.onlyoffice or "none") .. " "
            .. table.concat({v.php, v.database, v.freebsd_release, v.architecture, v.php_package, v.plan_sha256, v.packages_sha256, v.dependencies_sha256}, " ")
    end
    return prefix .. (vm and (v.office_backend .. " ") or none and "none " or "") .. table.concat(values, " ")
end)
if not ok then os.exit(1) end
print(result)
LUA
    ) || fail 'Invalid public versions or package lock; retain the original plan and installer artifact.'
    version_service_profile=
    if [ "${version_settings%% *}" = native-v1 ]; then
        version_service_profile=native-v1
        version_settings=${version_settings#* }
        version_services_sha256=${version_settings%% *}
        version_settings=${version_settings#* }
        version_talk_selected=${version_settings%% *}
        version_settings=${version_settings#* }
        version_private_file "$VERSION_SERVICES" 600 196608
        [ "$(sha256 -q "$VERSION_SERVICES")" = "$version_services_sha256" ] \
            || fail 'services.json differs from the immutable runtime digest; retain the original artifact.'
    fi
    version_office_backend=onlyoffice
    version_app_installation=
    version_package_installation=
    if [ "${version_settings%% *}" = pkg ]; then
        version_package_installation=pkg
        version_settings=${version_settings#* }
        read -r version_app_installation version_office_backend repository version_nextcloud version_onlyoffice version_php version_database \
            version_release version_architecture version_php_package version_plan_sha256 version_requirements_sha256 \
            version_connector version_connector_app version_connector_sha256 version_abi <<EOF
$version_settings
EOF
        [ "$version_app_installation" != legacy ] || version_app_installation=
        version_private_file "$VERSION_REQUIREMENTS" 600 1048576
        [ "$(sha256 -q "$VERSION_REQUIREMENTS")" = "$version_requirements_sha256" ] \
            || fail 'packages.requirements.json differs from the immutable runtime digest.'
    elif [ "${version_settings%% *}" = occ ]; then
        version_app_installation=occ
        version_settings=${version_settings#* }
        read -r version_office_backend repository version_nextcloud version_onlyoffice version_php version_database \
            version_release version_architecture version_php_package version_plan_sha256 version_packages_sha256 version_dependencies_sha256 <<EOF
$version_settings
EOF
    elif [ "${version_settings%% *}" = none ]; then
        version_settings=${version_settings#* }
        read -r repository version_nextcloud version_php version_database version_release \
            version_architecture version_php_package version_plan_sha256 version_packages_sha256 \
            version_dependencies_sha256 version_office_backend <<EOF
$version_settings
EOF
    elif [ "${version_settings%% *}" = eurooffice ] || [ "${version_settings%% *}" = collabora ]; then
        version_settings=${version_settings#* }
        read -r repository version_nextcloud version_php version_database version_release \
            version_architecture version_php_package version_plan_sha256 version_packages_sha256 \
            version_dependencies_sha256 version_connector version_connector_app version_connector_sha256 version_office_backend <<EOF
$version_settings
EOF
    else
        read -r repository version_nextcloud version_onlyoffice version_connector version_php version_database \
        version_release version_architecture version_php_package version_plan_sha256 version_packages_sha256 version_dependencies_sha256 version_connector_sha256 <<EOF
$version_settings
EOF
    fi
    if [ "$version_app_installation" != occ ] && [ "$version_office_backend" != none ] && [ "$1" != talk ]; then
        version_private_file "$VERSION_CONNECTOR" 600 65536
        [ "$(sha256 -q "$VERSION_CONNECTOR")" = "$version_connector_sha256" ] \
            || fail 'connector.json differs from the immutable runtime digest; restore the original signed release record.'
    fi
    if [ "$version_package_installation" = pkg ]; then return; fi
    version_private_file "$VERSION_LOCK" 600 1048576
    version_private_file "$VERSION_DEPENDENCIES" 600 1048576
    [ "$(sha256 -q "$VERSION_LOCK")" = "$version_packages_sha256" ] \
        || fail 'packages.lock differs from the immutable runtime digest; restore the original staged lock.'
    [ "$(sha256 -q "$VERSION_DEPENDENCIES")" = "$version_dependencies_sha256" ] \
        || fail 'packages.dependencies differs from the immutable runtime digest; restore the original staged dependency lock.'
}

version_environment() {
    [ "$(uname -s)" = FreeBSD ] || fail 'The selected FreeBSD target is required.'
    [ "$(uname -m)" = "$version_architecture" ] || fail 'The jail architecture differs from the selected target.'
    version_kernel=$(uname -r) || fail 'Cannot read the running kernel release.'
    version_userland=$(freebsd-version -u) || fail 'Cannot read the jail userland release.'
    for version_actual in "$version_kernel" "$version_userland"; do
        case "$version_actual" in
            "$version_release") ;;
            "$version_release"-p*)
                case "$version_release" in *-RELEASE) ;; *) fail 'Development targets require the exact selected release identity.' ;; esac
                version_patch=${version_actual#"$version_release"-p}
                case "$version_patch" in ''|*[!0-9]*) fail 'Expected a stable patch of the selected FreeBSD release.' ;; esac
                ;;
            *) fail 'Kernel and jail userland must match the selected FreeBSD release; retain the original target.' ;;
        esac
    done
}

version_packages_check() {
    if [ "${version_package_installation:-}" = pkg ]; then
        version_requirements_check installed
        set --
        while IFS='|' read -r version_name version_origin; do
            set -- "$@" "$version_name"
        done <<EOF
$version_rows
EOF
        [ "$#" -gt 0 ] || fail 'An empty package requirement set cannot be checked.'
        # -d without -n can install missing dependencies. This is observation
        # only, including completed phases; never refresh a repository here.
        # Check validated roots, not unrelated inherited pkgbase/toolchain rows.
        # No arguments defaults to all packages, so empty rows must fail above.
        [ -d "${STATE:-}" ] && [ ! -L "$STATE" ] \
            && [ "$(stat -f '%u:%Lp' "$STATE")" = 0:700 ] \
            || fail 'Unsafe private state directory for native pkg evidence.'
        version_check_attempt=$(umask 077; mktemp -d "$STATE/pkg-check.XXXXXX") \
            || fail 'Cannot create private native pkg evidence directory.'
        [ -d "$version_check_attempt" ] && [ ! -L "$version_check_attempt" ] \
            && [ "$(stat -f '%u:%Lp' "$version_check_attempt")" = 0:700 ] \
            || fail 'Unsafe native pkg evidence directory.'
        (umask 077
            : > "$version_check_attempt/stdout" &&
            : > "$version_check_attempt/stderr" &&
            : > "$version_check_attempt/status" &&
            : > "$version_check_attempt/context" &&
            chmod 600 "$version_check_attempt/stdout" "$version_check_attempt/stderr" \
                "$version_check_attempt/status" "$version_check_attempt/context"
        ) || fail "Cannot prepare private native pkg evidence: $version_check_attempt"
        printf '%s\n' 'state=incomplete' 'exit_status=unknown' > "$version_check_attempt/status" \
            || fail "Cannot record native pkg evidence: $version_check_attempt"
        # FreeBSD releng/15.1 bin/sh/sh.1 and miscbltin.c: -f counts 512-byte
        # blocks, hence 128 = 65536 bytes PER file (not Linux bash's units).
        # An exact-cap output might be complete; truncation is then uncertain.
        printf '%s\n' 'command=pkg check -d -n -q' "roots=$*" \
            'output_cap_bytes=65536' 'limit_reached means >= cap; truncation uncertain' \
            > "$version_check_attempt/context" \
            || fail "Cannot record native pkg context: $version_check_attempt"
        version_check_status=0
        (ulimit -f 128 || exit 125
            pkg check -d -n -q "$@" < /dev/null
        ) > "$version_check_attempt/stdout" 2> "$version_check_attempt/stderr" \
            || version_check_status=$?
        version_check_stdout=$(stat -f '%z' "$version_check_attempt/stdout") \
            && version_check_stderr=$(stat -f '%z' "$version_check_attempt/stderr") \
            || fail "Cannot inspect native pkg evidence: $version_check_attempt"
        case "$version_check_stdout:$version_check_stderr" in
            *[!0-9:]*|:*|*:) fail "Invalid native pkg evidence sizes: $version_check_attempt" ;;
        esac
        version_check_limit=no
        if [ "$version_check_stdout" -ge 65536 ] || [ "$version_check_stderr" -ge 65536 ]; then
            version_check_limit=yes
        fi
        # Exit status includes signals (e.g. SIGXFSZ), or 125 if the bounding
        # ulimit itself failed before pkg ran. Neither can pass as a clean check.
        printf '%s\n' 'state=complete' "exit_status=$version_check_status" \
            "stdout_bytes=$version_check_stdout" "stderr_bytes=$version_check_stderr" \
            "limit_reached=$version_check_limit" 'truncation=unknown_if_limit_reached' \
            > "$version_check_attempt/status" \
            || fail "Cannot finalize native pkg evidence: $version_check_attempt"
        [ "$version_check_status" -eq 0 ] && [ "$version_check_stdout" -eq 0 ] \
            && [ "$version_check_stderr" -eq 0 ] && [ "$version_check_limit" = no ] \
            || fail "Native pkg consistency check produced findings or diagnostics; inspect private evidence: $version_check_attempt"
        return
    fi
    version_packages_inventory
    while IFS='|' read -r version_name version_value version_origin version_checksum; do
        version_installed=$(pkg query '%v|%o' "$version_name" < /dev/null) \
            || fail "Selected package is missing: $version_name. Resume requires the original package lock."
        [ "$version_installed" = "$version_value|$version_origin" ] \
            || fail "Installed package differs from the lock: $version_name. Automatic upgrades/downgrades are refused."
    done < "$VERSION_LOCK"
}

version_packages_inventory() {
    version_inventory=$(pkg query -a '%n|%v|%o' < /dev/null) || fail 'Cannot inspect installed package versions.'
    if [ "${version_package_installation:-}" = pkg ]; then
        [ -n "$version_inventory" ] || fail 'An empty installed package inventory is invalid.'
        printf '%s\n' "$version_inventory" | awk -F '|' '
            NF != 3 || $1 !~ /^[A-Za-z0-9][A-Za-z0-9_+.-]*$/ || $2 !~ /^[A-Za-z0-9._+][A-Za-z0-9.+_,~:-]*$/ || $3 !~ /^[A-Za-z0-9][A-Za-z0-9_+.-]*\/[A-Za-z0-9][A-Za-z0-9_+.-]*$/ || seen[$1]++ {exit 1}
        ' || fail 'Invalid installed package inventory.'
        return
    fi
    printf '%s\n' "$version_inventory" | awk -F '|' '
        NR == FNR {selected[$1]=1; next}
        # Thick pkgbase jails inherit the signed base-release package database.
        # Require both the reserved base name and its matching origin; this is
        # not permission for unselected ports or automatic OS upgrades.
        NF != 3 {exit 1}
        $1 ~ /^FreeBSD-[A-Za-z0-9_+.-]+$/ && $3 == "base/" $1 {next}
        $1 != "pkg" && !($1 in selected) {exit 1}
    ' "$VERSION_LOCK" - || fail 'Installed application packages outside the selected closure are refused; only bootstrap pkg and identified pkgbase packages may be extra.'
}

# Call only after signed pkg bootstrap/catalog update. Verify the entire closure
# before either install invocation; never resolve roots against a newer catalog.
version_packages_install() {
    if [ "${version_package_installation:-}" = pkg ]; then
        version_current_packages_install
        return
    fi
    version_packages_inventory
    set --
    while IFS='|' read -r version_name version_value version_origin version_checksum; do
        # Extended %u is the catalog's archive sum; legacy %X is not that sum.
        # Empty inline iteration selects pkg_printf without emitting any edges.
        version_remote=$(pkg rquery -U -r FreeBSD-ports '%n|%v|%o|%u%d%{%|%}' "$version_name" < /dev/null) \
            || fail "Exact package unavailable: $version_name-$version_value. Retain the original artifact and repository; do not change the lock."
        [ "$version_remote" = "$version_name|$version_value|$version_origin|$version_checksum" ] \
            || fail "Repository drift for $version_name-$version_value. Restore the original repository/artifact; do not change the lock."
        version_remote_dependencies=$(pkg rquery -U -r FreeBSD-ports '%dn|%dv|%do' "$version_name" < /dev/null) \
            || fail "Cannot verify exact dependencies for $version_name; retain the original repository and lock."
        version_remote_dependencies=$(printf '%s' "$version_remote_dependencies" | LC_ALL=C sort)
        version_expected_dependencies=$(awk -F '|' -v name="$version_name" '$1 == name {print $2 "|" $3 "|" $4}' "$VERSION_DEPENDENCIES")
        [ "$version_remote_dependencies" = "$version_expected_dependencies" ] \
            || fail "Repository dependency drift for $version_name. Restore the original repository/artifact; do not change the lock."
        version_installed=$(printf '%s\n' "$version_inventory" | awk -F '|' -v name="$version_name" '$1 == name {print $2 "|" $3}')
        [ -z "$version_installed" ] || [ "$version_installed" = "$version_value|$version_origin" ] \
            || fail "Installed package differs from the lock: $version_name. Automatic upgrades/downgrades are refused."
        set -- "$@" "$version_name-$version_value"
    done < "$VERSION_LOCK"
    [ "$#" -gt 0 ] || fail 'An empty package lock cannot be installed.'
    # pkg 2.8.4 needs -y for a successful dry-run status; retain -n.
    (umask 022; pkg install -n -y -U -r FreeBSD-ports "$@" < /dev/null) \
        || fail 'Locked package preflight failed; retain the original lock and repository.'
    (umask 022; pkg install -y -U -r FreeBSD-ports "$@" < /dev/null) \
        || fail 'Locked package installation failed; resume only with the original lock and repository.'
    version_packages_check
}

# The root requirements are configuration, not a catalog/dependency/checksum
# lock. Native pkg selects the signed branch's current packages and dependencies.
version_requirements_rows() {
    [ "$(sha256 -q "$VERSION_REQUIREMENTS")" = "$version_requirements_sha256" ] \
        || fail 'The staged package requirements changed.'
    /usr/libexec/flua - "$VERSION_REQUIREMENTS" <<'LUA'
local ok, result = pcall(function()
    local p = require('ucl').parser(); assert(p:parse_file(arg[1]))
    local r = p:get_object()
    assert(type(r.roots) == 'table' and next(r.roots))
    local names, rows = {}, {}
    for name in pairs(r.roots) do names[#names + 1] = name end
    table.sort(names)
    for _, name in ipairs(names) do
        local origin = r.roots[name]
        local origin_request = r.schema_version == 2 and name == origin and name:match('^[A-Za-z0-9][A-Za-z0-9_+%.%-]*/[A-Za-z0-9][A-Za-z0-9_+%.%-]*$')
        assert(type(name) == 'string' and #name <= 257 and ((#name <= 128 and name:match('^[A-Za-z0-9][A-Za-z0-9_+%.%-]*$')) or origin_request))
        assert(type(origin) == 'string' and #origin <= 257 and ((r.schema_version == 2 and origin == '') or origin:match('^[A-Za-z0-9][A-Za-z0-9_+%.%-]*/[A-Za-z0-9][A-Za-z0-9_+%.%-]*$')))
        rows[#rows + 1] = name .. '|' .. origin
    end
    return table.concat(rows, '\n')
end)
if not ok then os.exit(1) end
print(result)
LUA
}

version_requirement_record() {
    # Validate query framing before reading its scalars, including exact-name
    # matching (pkg accepts name-version and origin patterns as well as names).
    [ -n "${version_abi:-}" ] || fail 'Missing selected package target ABI.'
    printf '%s\n' "$1" | awk -F '|' -v abi="$version_abi" -v wildcard="${version_abi%:*}:*" '
        NR != 1 || NF != 3 || $1 !~ /^[A-Za-z0-9][A-Za-z0-9_+.-]*$/ || $2 !~ /^[A-Za-z0-9][A-Za-z0-9_+.-]*\/[A-Za-z0-9][A-Za-z0-9_+.-]*$/ || ($3 != abi && $3 != wildcard) {bad=1}
        END {exit bad || NR != 1}
    ' || fail "Invalid package identity or target ABI: $version_name."
    IFS='|' read -r version_observed_name version_observed_origin version_observed_abi <<EOF
$1
EOF
    { [ "$version_observed_name" = "$version_name" ] || [ "$version_name" = "$version_observed_origin" ]; } \
        && { [ -z "$version_origin" ] || [ "$version_observed_origin" = "$version_origin" ]; } \
        || fail "Package name or origin differs from requirements: $version_name."
}

version_requirements_check() {
    version_rows=$(version_requirements_rows) || fail 'Invalid staged package requirements.'
    [ -n "$version_rows" ] || fail 'An empty package requirement set cannot be checked.'
    printf '%s\n' "$version_rows" | awk -F '|' '
        NF != 2 || $1 == "" {bad=1}
        END {exit bad || NR == 0}
    ' || fail 'Blank or invalid package requirement rows cannot be checked.'
    if [ "$1" = repository ]; then
        # Query the signed catalogue successfully once. A missing row is merely
        # unobserved; pkg install itself reports unavailable requested roots.
        version_repository_catalog=$(pkg rquery -U -r FreeBSD-ports -a '%n|%o|%q' < /dev/null) \
            || fail 'Cannot inspect the selected signed repository.'
    fi
    while IFS='|' read -r version_name version_origin; do
        if [ "$1" = repository ]; then
            version_record=$(printf '%s\n' "$version_repository_catalog" | awk -F '|' -v name="$version_name" '$1 == name || $2 == name')
            [ -n "$version_record" ] || continue
        else
            version_record=$(pkg query '%n|%o|%q' "$version_name" < /dev/null) \
                || fail "Required installed package is missing: $version_name."
        fi
        version_requirement_record "$version_record"
    done <<EOF
$version_rows
EOF
}

version_current_packages_install() {
    version_requirements_check repository
    version_packages_inventory
    # Existing roots must retain origin/ABI identity, never a preview version.
    set --
    while IFS='|' read -r version_name version_origin; do
        version_existing=$(printf '%s\n' "$version_inventory" | awk -F '|' -v name="$version_name" '$1 == name || $3 == name {print $1}')
        if [ -n "$version_existing" ]; then
            version_record=$(pkg query '%n|%o|%q' "$version_name" < /dev/null) \
                || fail "Cannot inspect an already installed package: $version_name."
            version_requirement_record "$version_record"
        fi
        set -- "$@" "$version_name"
    done <<EOF
$version_rows
EOF
    [ "$#" -gt 0 ] || fail 'An empty package requirement set cannot be installed.'
    # Native pkg owns current versions and dependencies in this owned jail;
    # -U avoids another refresh after the selected signed branch was updated.
    (umask 022; pkg install -y -U -r FreeBSD-ports "$@" < /dev/null) \
        || fail 'Native repository-current package installation failed; retain state for explicit recovery.'
    version_packages_check
}
