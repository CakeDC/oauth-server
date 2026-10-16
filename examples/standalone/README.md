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

`setup.php [name]` registers a NEW public native client on every run (each run prints a different
client id) with the redirect URI `http://127.0.0.1/callback` (any port). It records no consent: a
public loopback client is asked on every authorization, because any program on the computer could open
the same URL with its own port (RFC 8252 section 8.6).

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `OAUTH_EXAMPLE_DB` | `examples/standalone/oauth.sqlite` | SQLite file |
| `OAUTH_EXAMPLE_ISSUER` | `http://127.0.0.1:8090` | Issuer URL; change it with the port |
| `OAUTH_EXAMPLE_SECRET` | demo value | Signs the consent and connections forms (32 bytes minimum) |
| `OAUTH_EXAMPLE_AUTO_LOGIN` | unset | DEMO ONLY: `1` makes every visitor Alice, without the login form. Never run it on a host anyone else can reach |
| `OAUTH_EXAMPLE_AUTO_APPROVE` | unset | UNSAFE, for `tests/Conformance/run.sh` only: `1` answers every consent page with "Allow" by itself (`AutoApprove.php`), so any page or program that opens an authorization URL gets a code without the person seeing anything. Never set it anywhere else and never copy it into an application |

## Routes

| Route | What it does |
| --- | --- |
| `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `/oauth/authorize` | Authorization endpoint with the consent page |
| `/oauth/token` | Token endpoint (authorization code and refresh; client credentials are not available in the demo because `DemoUsers::forClient()` returns null) |
| `/oauth/register` | Dynamic client registration (RFC 7591) |
| `/oauth/revoke` | Token revocation (RFC 7009) |
| `/oauth/introspect` | Token introspection (RFC 7662) |
| `/oauth/connections` | Connected applications and personal access tokens |
| `/api/me` | Protected demo resource: answers with the owner of the bearer token |
| `/login` | Demo login form |

Bob can only receive the `read` scope; Alice can receive every scope of the demo API.

## Getting a token for `/api/me`

1. Run `setup.php` and note the client id (`CLIENT` below). Start the server and sign in at `/login`.
2. Open this URL in the browser (the challenge is the S256 of the verifier used in step 4):

   ```
   http://127.0.0.1:8090/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=http://127.0.0.1/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=http://127.0.0.1:8090/api
   ```

   The consent page appears (every time, for this loopback client). Click Allow: the browser goes to
   `http://127.0.0.1/callback?code=...` (the page fails to load; copy the `code` from the address bar).
3. Exchange the code within 60 seconds:

   ```bash
   curl -s http://127.0.0.1:8090/oauth/token \
     -d grant_type=authorization_code -d code=CODE -d client_id=CLIENT \
     -d redirect_uri=http://127.0.0.1/callback \
     -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk \
     -d resource=http://127.0.0.1:8090/api
   ```
4. Call the API: `curl -H "Authorization: Bearer ACCESS_TOKEN" http://127.0.0.1:8090/api/me`.

## Demo limits

- There is no CORS layer: browser preflights to `/api/me` are refused.
- The login form has no CSRF protection (demo only).
- Keep the SQLite file outside the web root, with restrictive permissions (for example `chmod 600`).
