# Conformance

The library is checked against the official MCP conformance suite for authorization servers,
`@modelcontextprotocol/conformance`. The run is `tests/Conformance/run.sh` and it is a job in CI.

## What the scenarios check

`authorization-server-metadata-endpoint`:

- The metadata endpoint answers 200 with `application/json`.
- The document has `issuer`, `authorization_endpoint`, `token_endpoint`, `response_types_supported`
  containing `code`, and `code_challenge_methods_supported` containing `S256`.
- `issuer` equals the URL the runner was given.
- A warning (not a failure) if `client_id_metadata_document_supported` is not `true`.

`authorization-code-grant`:

- Needs `--client-id` (and `--client-secret` for a confidential client).
- Sends `response_type`, `client_id`, `state`, `redirect_uri=http://127.0.0.1:<port>/callback`,
  `code_challenge` and `code_challenge_method=S256`, without `resource` or `scope`, prints the URL
  and waits for a browser to reach the callback.
- Checks the callback for the code, the state, `iss` and no duplicated parameters.
- Checks the token response: 200 JSON, `Cache-Control: no-store`, `access_token` and `token_type`.

## Version pin

The suite is pinned to `0.2.0-alpha.11`. The authorization server scenarios are new and still
change between alpha releases, and a moving version would make CI fail for reasons unrelated to
this library. It is also the version cakephp-mcp pins. Bump it on purpose and read the changelog
when you do.

## Running it locally

Needs PHP 8.2 or newer with `pdo_sqlite` and `curl`, Node 22 and network access to npm.

```bash
composer install
tests/Conformance/run.sh
```

Two variables change the ports (both servers bind to 127.0.0.1 only):

- `OAUTH_CONFORMANCE_PORT`: the authorization server, default `8090`.
- `OAUTH_CONFORMANCE_CALLBACK_PORT`: the runner's callback server, default `3000`.

## How the interactive step is answered

The `authorization-code-grant` scenario waits for a person to open a URL. The script runs the
standalone example (`examples/standalone`) with `OAUTH_EXAMPLE_AUTO_LOGIN=1`, which signs in the
demo user alice, and `setup.php` registers a public native client for `http://127.0.0.1/callback`
(loopback, any port, RFC 8252) with consent already granted. The script reads the authorization
URL from the runner's output and requests it with curl; the server redirects straight to the
runner's callback. A failed scenario or a `FAILURE` check in the results fails the script, and the
trap stops the PHP server and the runner when the script exits.

## Logs and results

Both directories are git-ignored.

- `tests/Conformance/tmp/`: `server.log` (the PHP server), `conformance.log` (the runner) and the
  SQLite database.
- `tests/Conformance/results/`: one folder per scenario with `checks.json`.

## What it does not cover

The suite has no scenarios for protected resources. Bearer validation, audience binding and the
challenge responses are covered by the unit, end-to-end and security tests.
