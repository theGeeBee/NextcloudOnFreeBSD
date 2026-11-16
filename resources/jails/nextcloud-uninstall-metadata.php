<?php
declare(strict_types=1);

/* Ephemeral CLI metadata ABI for NC-only uninstall capture. Root stages this
 * outside the web root, root:www 0640 in a root:www 0710 directory. Never put
 * credentials on stdout, argv or in the environment. Historical maintenance.php
 * and its ONLYOFFICE-bound restore identity deliberately remain unchanged.
 */
function cloudUninstallMetadata(): array {
    $config = OCP\Server::get(OCP\IConfig::class);
    if ($config->getSystemValueString('dbtype') !== 'mysql'
        || $config->getSystemValueString('dbname') !== 'nextcloud'
        || $config->getSystemValueString('datadirectory') !== '/var/nc-data') {
        throw new RuntimeException('Unexpected managed application layout.');
    }
    $binding = [];
    foreach (['instanceid', 'secret', 'passwordsalt', 'dbpassword', 'dbtype',
        'dbname', 'dbuser', 'dbhost', 'datadirectory'] as $key) {
        $binding[$key] = $config->getSystemValueString($key);
        if ($binding[$key] === '') {
            throw new RuntimeException('Incomplete runtime configuration.');
        }
    }
    return [
        'abi' => 'nc-uninstall-v1',
        'instance_id' => $binding['instanceid'],
        'table_prefix' => $config->getSystemValueString('dbtableprefix', 'oc_'),
        'runtime_binding' => hash('sha256', json_encode($binding, JSON_THROW_ON_ERROR)),
    ];
}

function cloudUninstallMain(array $args): int {
    ob_start();
    try {
        $app = '/usr/local/www/nextcloud';
        $www = posix_getpwnam('www');
        if (PHP_SAPI !== 'cli' || count($args) !== 1 || $www === false
            || posix_geteuid() !== $www['uid']
            || fileowner($app . '/config/config.php') !== $www['uid'] || !chdir($app)) {
            throw new RuntimeException('Run the metadata helper as www.');
        }
        umask(0077);
        ini_set('display_errors', '0');
        ini_set('log_errors', '0');
        ini_set('zend.exception_ignore_args', '1');
        $GLOBALS['argv'] = $_SERVER['argv'] = [$app . '/occ'];
        $_SERVER['argc'] = 1;
        $_SERVER['SCRIPT_FILENAME'] = $_SERVER['SCRIPT_NAME'] = $_SERVER['PHP_SELF'] = $app . '/occ';
        define('OC_CONSOLE', 1);
        require $app . '/lib/versioncheck.php';
        require $app . '/lib/base.php';
        if (!OCP\Server::get(OCP\IConfig::class)->getSystemValueBool('installed', false)) {
            throw new RuntimeException('Nextcloud is not installed.');
        }
        $metadata = cloudUninstallMetadata();
        ob_end_clean();
        echo json_encode($metadata, JSON_THROW_ON_ERROR) . "\n";
        return 0;
    } catch (Throwable $error) {
        ob_end_clean();
        fwrite(STDERR, "Nextcloud uninstall metadata failed.\n");
        return 1;
    }
}

if (!defined('CLOUD_UNINSTALL_LIBRARY')) {
    exit(cloudUninstallMain($argv));
}
