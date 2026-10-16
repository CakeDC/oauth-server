# Standalone example

A runnable OAuth 2.1 authorization server in plain PHP, built only on this library, a PDO SQLite
file and `php -S`. It is a demo: the login is a PHP session with two fixed people (Alice and Bob),
the form-signing secret is a fixed demo value and the data lives in a SQLite file. Change the
secret (set `OAUTH_EXAMPLE_SECRET` to your own random value of at least 32 bytes) and replace the
login and the storage before you use any of it for real.

## Run it

```bash
composer install
php examples/standalone/setup.php          # creates the tables, prints a client id
php -S 127.0.0.1:8090 examples/standalone/server.php
```

Open http://127.0.0.1:8090/oauth/connections, sign in as Alice or Bob and manage the connections
and personal access tokens.

`setup.php [name]` registers a public client with the redirect URI `http://127.0.0.1/callback`
(any port) and records Alice's consent for the default scopes of the demo API, so she is not asked
again.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `OAUTH_EXAMPLE_DB` | `examples/standalone/oauth.sqlite` | SQLite file |
| `OAUTH_EXAMPLE_ISSUER` | `http://127.0.0.1:8090` | Issuer URL; change it with the port |
| `OAUTH_EXAMPLE_SECRET` | demo value | Signs the consent and connections forms (32 bytes minimum) |
| `OAUTH_EXAMPLE_AUTO_LOGIN` | unset | `1` signs Alice in without the login form |

## Routes

| Route | What it does |
| --- | --- |
| `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `/oauth/authorize` | Authorization endpoint with the consent page |
| `/oauth/token` | Token endpoint (code, refresh, client credentials) |
| `/oauth/register` | Dynamic client registration (RFC 7591) |
| `/oauth/revoke` | Token revocation (RFC 7009) |
| `/oauth/introspect` | Token introspection (RFC 7662) |
| `/oauth/connections` | Connected applications and personal access tokens |
| `/api/me` | Protected demo resource: answers with the owner of the bearer token |
| `/login` | Demo login form |

Bob can only receive the `read` scope; Alice can receive every scope of the demo API.
