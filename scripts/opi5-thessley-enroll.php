#!/usr/bin/env php
<?php
/**
 * OPI5-only, CLI-only Thessley web account enrollment helper.
 *
 * Usage:
 *   sudo php /usr/local/sbin/thessley-web-enroll.php list
 *   sudo php /usr/local/sbin/thessley-web-enroll.php wp <username>
 *   sudo php /usr/local/sbin/thessley-web-enroll.php drupal <username>
 * Add --add-another to enroll another device when that account already has
 * an active device. Enrollment requests expire after 120 seconds.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

function fail(string $message, int $status = 1): never {
    fwrite(STDERR, "Error: {$message}\n");
    exit($status);
}

function usage(): never {
    fwrite(STDERR, "Usage:\n  sudo php " . basename(__FILE__) . " list\n  sudo php " . basename(__FILE__) . " wp <username> [--add-another]\n  sudo php " . basename(__FILE__) . " drupal <username> [--add-another]\n");
    exit(2);
}

function output_json(array $data): void {
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
}

function run_cli(array $command): array {
    $pipes = [];
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) {
        fail('Could not start the site CLI.');
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $status = proc_close($process);
    if ($status !== 0) {
        fail(trim($stderr !== '' ? $stderr : $stdout), $status ?: 1);
    }
    return [$stdout, $stderr];
}

function wp_eval(string $code): string {
    [$stdout] = run_cli(['/usr/local/bin/wp', '--path=/var/www/wordpress', '--allow-root', 'eval', $code]);
    return trim($stdout);
}

function drupal_eval(string $code): string {
    [$stdout] = run_cli([
        '/var/www/fruitnweg/vendor/bin/drush',
        '--root=/var/www/fruitnweg/web',
        '--uri=https://fruitandvegreports.com',
        'php:eval',
        $code,
    ]);
    return trim($stdout);
}

if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
    fail('Run this command with sudo so it can bootstrap the site safely.');
}

$site = $argv[1] ?? '';
if ($site === 'list') {
    $wpCode = <<<'WP'
global $wpdb;
$rows = $wpdb->get_results("SELECT u.user_login,p.label,p.revoked_at FROM {$wpdb->users} u JOIN {$wpdb->prefix}thessley_passkeys p ON p.user_id=u.ID ORDER BY u.user_login,p.created_at", ARRAY_A);
$out = [];
foreach ($rows as $r) { $out[] = ['site'=>'dashboard.eagleeye-intelligence.com','username'=>$r['user_login'],'label'=>$r['label'],'active'=>empty($r['revoked_at'])]; }
echo json_encode($out, JSON_UNESCAPED_SLASHES);
WP;
    $drupalCode = <<<'DRUPAL'
$rows = \Drupal::database()->query("SELECT u.name,p.label,p.revoked FROM {thessley_passkeys} p JOIN {users_field_data} u ON u.uid=p.uid ORDER BY u.name")->fetchAll(\PDO::FETCH_ASSOC);
$out = [];
foreach ($rows as $r) { $out[] = ['site'=>'fruitandvegreports.com','username'=>$r['name'],'label'=>$r['label'],'active'=>empty($r['revoked'])]; }
echo json_encode($out, JSON_UNESCAPED_SLASHES);
DRUPAL;
    $all = array_merge(json_decode(wp_eval($wpCode), true, 512, JSON_THROW_ON_ERROR), json_decode(drupal_eval($drupalCode), true, 512, JSON_THROW_ON_ERROR));
    output_json($all);
    exit(0);
}

if (!in_array($site, ['wp', 'drupal'], true)) {
    usage();
}
$username = $argv[2] ?? '';
if (!preg_match('/\A[A-Za-z0-9_.@-]{1,100}\z/', $username)) {
    fail('Provide one exact username (letters, numbers, dot, underscore, @ or hyphen).', 2);
}
$addAnother = in_array('--add-another', $argv, true);

if ($site === 'wp') {
    $usernameLiteral = var_export($username, true);
    $allowDuplicate = $addAnother ? 'true' : 'false';
    $code = <<<PHP
\$u = get_user_by('login', {$usernameLiteral});
if (!\$u) { fwrite(STDERR, "No such WordPress login.\\n"); exit(3); }
\$rows = Thessley_Passkey_Store::devices_for_user((int) \$u->ID);
\$active = array_values(array_filter(\$rows, function (\$r) { return empty(\$r->revoked_at); }));
if (count(\$active) && !{$allowDuplicate}) { fwrite(STDERR, "This account already has an active Thessley device; use --add-another only if you intend to add another.\\n"); exit(4); }
\$r = Thessley_Passkey_Store::create_request('enroll', (int) \$u->ID, Thessley_Module_Passkey_Login::ENROLL_TTL);
\$origin = home_url();
\$params = ['type'=>'enroll','id'=>\$r['request_id'],'nonce'=>\$r['nonce'],'origin'=>\$origin];
echo json_encode(['site'=>\$origin,'username'=>\$u->user_login,'expires_in'=>\$r['expires_in'],'app_link'=>'thessleypasskey://auth?'.http_build_query(\$params),'fallback_url'=>\$origin.'/?thessley_auth_type=enroll&thessley_auth_id='.rawurlencode(\$r['request_id'])], JSON_UNESCAPED_SLASHES);
PHP;
    $output = json_decode(wp_eval($code), true, 512, JSON_THROW_ON_ERROR);
    if (!str_starts_with($output['site'] ?? '', 'https://')) {
        fail('The WordPress origin is not HTTPS; no enrollment link was issued.');
    }
    output_json($output);
    exit(0);
}

$usernameLiteral = var_export($username, true);
$allowDuplicate = $addAnother ? 'true' : 'false';
$code = <<<PHP
\$user = user_load_by_name({$usernameLiteral});
if (!\$user || !\$user->isActive()) { fwrite(STDERR, "No active Drupal account with that username.\\n"); exit(3); }
\$m = \Drupal::service('thessley_passkey.manager');
\$rows = \$m->store()->devicesForUser((int) \$user->id());
\$active = array_values(array_filter(\$rows, function (\$r) { return empty(\$r->revoked); }));
if (count(\$active) && !{$allowDuplicate}) { fwrite(STDERR, "This account already has an active Thessley device; use --add-another only if you intend to add another.\\n"); exit(4); }
\$r = \$m->store()->createRequest('enroll', (int) \$user->id(), \\Drupal\\thessley_passkey\\PasskeyManager::ENROLL_TTL, '');
\$origin = \$m->origin();
if (\$origin === '') { fwrite(STDERR, "Drupal has no configured public origin; no enrollment link was issued.\\n"); exit(5); }
echo json_encode(['site'=>\$origin,'username'=>\$user->getAccountName(),'expires_in'=>\$r['expires_in'],'app_link'=>\$m->appLink('enroll', \$r['request_id'], \$r['nonce'], \$r['ip']),'fallback_url'=>\$m->authUrl('enroll', \$r['request_id'])], JSON_UNESCAPED_SLASHES);
PHP;
$output = json_decode(drupal_eval($code), true, 512, JSON_THROW_ON_ERROR);
if (!str_starts_with($output['site'] ?? '', 'https://')) {
    fail('The Drupal origin is not HTTPS; no enrollment link was issued.');
}
output_json($output);
