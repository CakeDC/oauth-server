<?php
declare(strict_types=1);

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Example\AutoApprove;
use CakeDC\OAuth\Server\Example\DemoUsers;
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use Nyholm\Psr7\Factory\Psr17Factory;

require dirname(__DIR__, 2) . '/vendor/autoload.php';
require __DIR__ . '/AutoApprove.php';
require __DIR__ . '/DemoUsers.php';
require __DIR__ . '/LocalPath.php';

// DEMO ONLY: this fixed secret signs the consent and connections forms. Set OAUTH_EXAMPLE_SECRET to
// your own random value of at least 32 bytes for anything beyond a local try-out.
const DEMO_SECRET = 'demo-only-secret-change-it-0123456789';

$issuer = getenv('OAUTH_EXAMPLE_ISSUER') ?: 'http://127.0.0.1:8090';
$pdo = new PDO('sqlite:' . (getenv('OAUTH_EXAMPLE_DB') ?: __DIR__ . '/oauth.sqlite'));
PdoStorage::createTables($pdo);
$users = new DemoUsers();
$factory = new Psr17Factory();
// UNSAFE, conformance run only: OAUTH_EXAMPLE_AUTO_APPROVE=1 clicks "Allow" on every consent page.
$autoApprove = getenv('OAUTH_EXAMPLE_AUTO_APPROVE') === '1' ? new AutoApprove($factory) : null;

$server = new AuthorizationServer(
    ServerConfig::fromArray([
        'issuer' => $issuer,
        'secret' => getenv('OAUTH_EXAMPLE_SECRET') ?: DEMO_SECRET,
        'tokenPrefix' => 'demo',
        'resources' => [
            $issuer . '/api' => [
                'name' => 'Demo API',
                'scopes' => ['read' => 'Read your profile', 'write' => 'Change your profile'],
                'implies' => ['write' => ['read']],
                'defaultScopes' => ['read'],
            ],
        ],
    ]),
    new PdoStorage($pdo),
    $users,
    $users,
    $factory,
    $factory,
    consentRenderer: $autoApprove,
);

return [
    'server' => $server,
    'users' => $users,
    'factory' => $factory,
    'issuer' => $issuer,
    'autoApprove' => $autoApprove,
];
