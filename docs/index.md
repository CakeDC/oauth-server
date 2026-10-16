# CakeDC OAuth Server documentation

An OAuth 2.1 authorization server for any PHP application, ready for MCP servers. Read the pages in
order the first time, then use them as a reference.

## Getting started

- [Concepts](concepts.md): OAuth in plain words, the authorization code flow with PKCE, and the three
  kinds of client.
- [Installation](installation.md): requirements, creating the tables, first configuration and routing.
- [Configuration](configuration.md): every setting, its type and default.
- [Users](users.md): connecting your people, permissions and login.
- [Storage](storage.md): `PdoStorage`, `InMemoryStorage`, your own storage and the schema.

## Using the server

- [Endpoints](endpoints.md): the HTTP reference for every endpoint, with curl examples.
- [Errors](errors.md): every error code, when it happens and what to do.
- [Protecting resources](protecting-resources.md): `BearerTokenMiddleware` and `TokenValidator`.
- [MCP servers](mcp.md): the bridge for the official MCP PHP SDK.
- [Frameworks](frameworks.md): plain PHP, Slim, Mezzio, Symfony and Laravel.
- [Clients](clients.md): client types, registering clients, claude.ai, Claude Code, the Inspector.
- [Pages](pages.md): the consent and connections pages, custom renderers and translations.
- [Personal tokens](personal-tokens.md): tokens people create for their scripts.
- [Events](events.md): PSR-14 events and an audit log.

## Running it

- [Security](security.md): the threat model, RFC 9700 item by item, and the production checklist.
- [Deployment](deployment.md): proxies, nginx, Apache, Cloudflare and CORS.
- [Operations](operations.md): pruning, revoking tokens, rotating the secret and monitoring.
- [Troubleshooting](troubleshooting.md): symptoms, causes and fixes.
- [Conformance](conformance.md): the official MCP conformance suite and how to run it.
