<?php
declare(strict_types=1);

/**
 * A plain PHP front controller. Run: php -S 127.0.0.1:8090 examples/standalone/server.php
 */

use CakeDC\OAuth\Server\Example\LocalPath;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

ini_set('display_errors', '0');
ini_set('log_errors', '1');
session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'path' => '/']);
// The server sets its own Cache-Control; the session cache limiter would add a second, conflicting one.
session_cache_limiter('');
session_start();
[
    'server' => $server,
    'factory' => $factory,
    'issuer' => $issuer,
    'autoApprove' => $autoApprove,
] = require __DIR__ . '/bootstrap.php';

$request = $factory->createServerRequest($_SERVER['REQUEST_METHOD'], $issuer . $_SERVER['REQUEST_URI'], $_SERVER);
foreach (getallheaders() as $name => $value) {
    $request = $request->withHeader($name, $value);
}
$request = $request
    ->withBody($factory->createStream((string)file_get_contents('php://input')))
    ->withQueryParams($_GET)
    ->withParsedBody($_POST);

$config = $server->config();
$path = $request->getUri()->getPath();
$me = new class implements RequestHandlerInterface {
    /**
     * Answers with the owner of the bearer token.
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $owner = $request->getAttribute(ResourceOwner::class);

        return new Response(200, ['Content-Type' => 'application/json'], (string)json_encode([
            'subject' => $owner?->subject,
            'name' => $owner?->displayName,
        ]));
    }
};

$response = match (true) {
    $path === $config->metadataPath() => $server->metadataHandler()->handle($request),
    $path === $config->endpointPath('authorize') => $autoApprove !== null
        ? $autoApprove->handle($server->authorizeHandler(), $request)
        : $server->authorizeHandler()->handle($request),
    $path === $config->endpointPath('token') => $server->tokenHandler()->handle($request),
    $path === $config->endpointPath('register') => $server->registerHandler()->handle($request),
    $path === $config->endpointPath('revoke') => $server->revokeHandler()->handle($request),
    $path === $config->endpointPath('introspect') => $server->introspectHandler()->handle($request),
    $path === $config->endpointPath('connections') => $server->connectionsHandler()->handle($request),
    $path === '/api/me' => $server->bearerMiddleware($issuer . '/api')->process($request, $me),
    $path === '/login' && $request->getMethod() === 'POST' => (function () use ($request): ResponseInterface {
        $body = (array)$request->getParsedBody();
        // A new session id on login, so an id planted before it is worthless.
        session_regenerate_id(true);
        $_SESSION['user'] = (string)($body['user'] ?? '');
        $return = (string)($request->getQueryParams()['return'] ?? '/oauth/connections');

        return new Response(302, ['Location' => LocalPath::orHome($return)]);
    })(),
    $path === '/login' => new Response(
        200,
        ['Content-Type' => 'text/html', 'Cache-Control' => 'no-store'],
        '<form method="post">'
        . '<select name="user"><option value="alice">Alice</option><option value="bob">Bob</option></select>'
        . '<button>Sign in</button></form>',
    ),
    default => new Response(404, ['Cache-Control' => 'no-store'], 'Not found'),
};

http_response_code($response->getStatusCode());
// Only these three are replaced (the session cache limiter is off, this is belt and braces); everything
// else is appended, so a handler's Set-Cookie never clobbers the session cookie.
foreach (['Cache-Control', 'Pragma', 'Expires'] as $cacheHeader) {
    header_remove($cacheHeader);
}
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header($name . ': ' . $value, false);
    }
}
echo $response->getBody();
