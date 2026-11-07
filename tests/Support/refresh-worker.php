<?php
declare(strict_types=1);

/**
 * Rotates one refresh token in a process (and a database connection) of its own, for
 * ConcurrentRefreshTest. Arguments: the refresh token, the internal id of its client and the moment to
 * start (a float of microtime()), so that every worker presents the token at the same time. The
 * connection comes from OAUTH_REFRESH_DSN, OAUTH_REFRESH_USER and OAUTH_REFRESH_PASSWORD. Prints the
 * pair it got, or the error, as JSON.
 */

use CakeDC\OAuth\Server\Clock\SystemClock;
use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RecordingEventDispatcher;
use CakeDC\OAuth\Server\Token\RefreshTokenRotator;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenRevoker;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

$pdo = new PDO(
    (string)getenv('OAUTH_REFRESH_DSN'),
    (string)getenv('OAUTH_REFRESH_USER'),
    (string)getenv('OAUTH_REFRESH_PASSWORD'),
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 10],
);
$storage = new PdoStorage($pdo);
$clock = new SystemClock();
$events = new RecordingEventDispatcher();
$rotator = new RefreshTokenRotator(
    $storage,
    new TokenIssuer($storage, new TokenGenerator(), $clock, $events, new Lifetimes()),
    new TokenRevoker($storage, $storage, $clock, $events),
    new ScopeResolver(),
    Fixtures::resources(),
    $clock,
    $events,
    new FakeUsers(),
    30,
    'concurrent-refresh-test-secret',
);
$client = $storage->findClientById($argv[2] ?? '');
if ($client === null) {
    fwrite(STDOUT, (string)json_encode(['error' => 'unknown client']) . "\n");
    exit(1);
}

$wait = (float)($argv[3] ?? 0) - microtime(true);
if ($wait > 0) {
    usleep((int)($wait * 1000000));
}
try {
    $pair = $rotator->rotate($client, $argv[1] ?? '', null, []);
    $answer = ['access' => $pair->accessToken, 'refresh' => $pair->refreshToken];
} catch (OAuthException $e) {
    $answer = ['error' => $e->getMessage()];
}
fwrite(STDOUT, (string)json_encode($answer) . "\n");
