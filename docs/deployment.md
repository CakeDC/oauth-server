# Deployment

## HTTPS and the issuer

The issuer is the public URL of your authorization server, as a client sees it. Set it in the
configuration and keep it fixed:

```php
'issuer' => 'https://auth.example.com',
```

The library never builds URLs from the request. The metadata, the `iss` of every authorization answer
and the challenges all use the configured issuer. So it does not matter that a proxy or load balancer
speaks plain http to PHP, or rewrites the `Host` header. It matters that the configured issuer is
exactly what clients use, with the right scheme, host and port. Clients compare the `issuer` in the
metadata with the URL they fetched it from, and they refuse a mismatch.

The issuer must be https. Plain http is accepted only for loopback hosts (`localhost`, `127.0.0.1`,
`[::1]`), for local development. The same holds for resource URLs.

The scheme the PHP request sees does matter for your own code. Make sure your session cookie is marked
`Secure` and that your framework knows the request was https (trusted proxy settings of the framework).

## The client IP behind proxies

Rate limits count requests per client address. By default that address is `REMOTE_ADDR`. Behind a
reverse proxy or a CDN every request would then come from the proxy, and everyone would share one
counter (a `429` for all of them after a few requests). Pass a `$clientIp` closure to
`AuthorizationServer` that returns the real address.

Trust a forwarding header only when the request really came from your own proxy, otherwise anybody can
send `X-Forwarded-For: 1.2.3.4` and dodge the limits:

```php
use Psr\Http\Message\ServerRequestInterface;

$trustedProxies = ['10.0.0.5', '10.0.0.6']; // your load balancers

$clientIp = function (ServerRequestInterface $request) use ($trustedProxies): string {
    $remote = (string)($request->getServerParams()['REMOTE_ADDR'] ?? 'unknown');
    if (!in_array($remote, $trustedProxies, true)) {
        return $remote; // not from our proxy: ignore forwarding headers
    }
    // Walk the chain from the right and stop at the first address that is not one of our proxies.
    $chain = array_reverse(array_map('trim', explode(',', $request->getHeaderLine('X-Forwarded-For'))));
    foreach ($chain as $address) {
        if ($address !== '' && !in_array($address, $trustedProxies, true)) {
            return $address;
        }
    }

    return $remote;
};

$server = new AuthorizationServer(
    $config, $storage, $users, $users, $factory, $factory,
    cache: $cache,        // a shared PSR-16 cache, see below
    clientIp: $clientIp,
);
```

The closure must return a string. `ClientIp::fromServerParams()` is the default
(`REMOTE_ADDR`, or `unknown` when it is missing; requests without an address then share one counter).
Return the address as it is: the rate limiter groups IPv6 addresses by /64 itself (and reads an
IPv4-mapped address such as `::ffff:203.0.113.7` as the IPv4 address), whatever the closure returns.

A platform such as claude.ai calls from a shared range of addresses (`160.79.104.0/21`) that may serve
many people. Give the `token` limit enough room for that.

## Transactions

Never run the OAuth endpoints inside a request-wide database transaction (a framework or middleware
setting that wraps every request in `BEGIN ... COMMIT`). The library relies on single statements that
commit at once. Two reasons: a rollback after an error can undo tokens that were already handed out in
a response, and under snapshot reads the checks that follow an atomic update (for example the look at
the family after a rotation) read from the transaction's snapshot and can be stale. Racing requests are
still serialized by the row lock of the conditional `UPDATE`, so this is not about a code being used
twice. Exclude the OAuth routes from such a wrapper, or run the storage on its own connection.

## The rate limit cache

Rate limiting works only when you pass a PSR-16 cache to `AuthorizationServer` as `cache`. Use one that
all your PHP processes share: Redis, Memcached or APCu (APCu is shared by the workers of one machine
only). `CakeDC\OAuth\Server\Testing\ArrayCache` lives in one process and is for tests. Without a cache
nothing is limited. See [configuration](configuration.md#ratelimit).

If the cache fails (the Redis server is down, a timeout), the endpoints keep working without limits and
each request logs a warning, `Rate limiting is off for this request: the cache failed (...)`, with the
exception. Watch for it: while it lasts, nothing slows down an abuser. The memory of rejected metadata
documents uses the same cache and is skipped the same way.

## nginx

Route everything that is not a file to your front controller, and make sure `/.well-known/` is not
blocked. A common "deny dotfiles" rule blocks it by accident.

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;
    root /var/www/app/public;

    # Do not block /.well-known/ (the metadata lives there).
    location ^~ /.well-known/ {
        try_files $uri /index.php$is_args$args;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }

    location / {
        try_files $uri /index.php$is_args$args;
    }

    location ~ ^/index\.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root/index.php;
        fastcgi_param HTTPS on;
        fastcgi_pass unix:/run/php/php-fpm.sock;
    }
}
```

nginx passes the `Authorization` header to PHP-FPM as `HTTP_AUTHORIZATION`. Do not add `add_header`
lines for CORS on `/oauth/` or `/.well-known/`: the handlers already send them, and a duplicated
`Access-Control-Allow-Origin` makes browsers reject the response.

## Apache

```apache
<VirtualHost *:443>
    ServerName auth.example.com
    DocumentRoot /var/www/app/public

    <Directory /var/www/app/public>
        AllowOverride None
        Require all granted

        RewriteEngine On
        RewriteCond %{REQUEST_FILENAME} !-f
        RewriteRule ^ index.php [QSA,L]

        # PHP-FPM and CGI do not receive the Authorization header unless you pass it on.
        # Client secrets (Basic) and bearer tokens both need it.
        SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1
    </Directory>
</VirtualHost>
```

If your configuration blocks hidden files (`<FilesMatch "^\.">`), exempt `/.well-known/`. Test with
`curl -i -H 'Authorization: Bearer x' https://auth.example.com/api/me`: a `401` with a
`WWW-Authenticate` header means the header arrives. If you build the PSR-7 request yourself, take the
header from `getallheaders()` or `$_SERVER['HTTP_AUTHORIZATION']`, as `examples/standalone/server.php`
does.

Environment variables (for example `OAUTH_SECRET`) must reach PHP-FPM. Set `clear_env = no` in the pool,
or define them with `env[OAUTH_SECRET] = ...` in the pool file.

## Cloudflare and WAF notes

- **Do not block or challenge** `/.well-known/` and `/oauth/` (or your `routePrefix`). Bot protection,
  "Under Attack" mode and browser integrity checks assume a human with a browser. OAuth clients are
  programs. Add a rule that skips the challenge for those paths.
- **Do not block or challenge Anthropic's egress range `160.79.104.0/21`** on the OAuth and MCP paths.
  Requests from claude.ai (token, registration and your MCP endpoint) come from it. Skip the challenge
  for those paths only. Avoid a blanket allow-list for the whole range: it can bypass your WAF rules for
  every other path.
- **Do not cache** `/oauth/` or your MCP endpoint at the edge. Only the metadata may be cached, and
  it carries `Cache-Control: public, max-age=300` itself.
- **Client addresses**: Cloudflare puts the real address in `CF-Connecting-IP`. Read it in your
  `$clientIp` closure only when `REMOTE_ADDR` is a Cloudflare address, and keep the list of those ranges up
  to date.
- Rule sets that block requests with an `Authorization` header or a JSON body on `POST` can break
  `/oauth/register` and `/oauth/token`. Test with the real clients ([clients](clients.md)).

## CORS

Browser based clients (the MCP Inspector, single page apps) need CORS on the endpoints they call.

- The metadata, token, register, revoke and introspect handlers add the headers themselves:
  `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: GET, POST, OPTIONS`,
  `Access-Control-Allow-Headers: Authorization, Content-Type, MCP-Protocol-Version` and
  `Access-Control-Max-Age: 86400`. They answer preflights with `204`. Credentials are not allowed, which
  is right for bearer tokens.
- `/oauth/authorize` and `/oauth/connections` are pages. The browser navigates to them, so CORS does not
  apply.
- Your protected API or MCP route needs a CORS layer of its own, placed outside the bearer middleware,
  that also exposes `WWW-Authenticate` (`Access-Control-Expose-Headers: WWW-Authenticate`).
  See [protecting resources](protecting-resources.md#cors-preflights).

## Caches

| What | Cached by | Notes |
| --- | --- | --- |
| Metadata document | Anyone, for 300 seconds | `Cache-Control: public, max-age=300` |
| Token, register, revoke, introspect responses | Nobody | `Cache-Control: no-store`, `Pragma: no-cache` |
| Pages (consent, connections, errors) | Nobody | `Cache-Control: no-store` |
| Client metadata documents | The server, in `oauth_clients` | Between `cimd.cacheMin` and `cimd.cacheMax` seconds |
| Rate limit counters | Your PSR-16 cache | One entry per endpoint, address and window |

Do not put a cache in front of the endpoints that is allowed to ignore `Cache-Control`.

## Before you open the doors

Work through the checklist in [security](security.md#production-checklist) and set up the cron job in
[operations](operations.md#pruning).
