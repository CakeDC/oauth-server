# Clients

A client is a program that gets tokens for your people. This page explains the kinds of client, how to
register them, and how to connect the common ones.

## Client types and when to use each

| `ClientType` | How it is created | Authentication | Use it for |
| --- | --- | --- | --- |
| `MetadataDocument` | Automatically, when a request arrives with an https URL as `client_id` | None (public) | claude.ai and other hosted clients that publish a metadata document. Preferred |
| `Dynamic` | `POST /oauth/register` | None, or a secret | Clients that register themselves: desktop and CLI tools, editors |
| `Registered` | `ClientRegistrar::create()` | None, or a secret | Your own apps, scripts and services; client credentials; resource servers that introspect |

Public clients (no secret) are for programs that cannot keep a secret: mobile apps, desktop tools,
browser apps. They rely on PKCE. Confidential clients have a secret and are for servers.

The consent page names a metadata document client by the host of its `client_id` URL, which the client
cannot fake. A dynamically registered client picks its own name, so the page adds an "unverified"
notice. A client that only redirects to the person's own computer gets a warning that any program on the computer can use that
address.

## Redirect URI rules

These rules apply to dynamic registration, to metadata documents and to `ClientRegistrar::create()`.
A URI that breaks one is refused with `invalid_redirect_uri` (registration) or ignored (a metadata
document needs at least one usable URI, or the client is refused with `invalid_client`).

- At most 2000 characters, and at most 10 URIs per client.
- No spaces or control characters, and no fragment (`#`).
- Only RFC 3986 URI characters. No backslashes and no non-ASCII characters. An internationalized host
  name must be written in punycode (`xn--...`).
- No user information (`https://user:pass@host/`).
- It must be an absolute URI. The schemes `javascript`, `data`, `file`, `vbscript`, `about` and `blob`
  are never allowed.
- `https`: the host must be a plain host name (letters, digits and hyphens, at least two labels, the last
  one starting with a letter, no `%`, no trailing dot), an IP address, or a loopback name.
- `http`: only for loopback hosts (`127.0.0.1`, `[::1]` and `localhost`).
- Any other scheme (a private-use scheme such as `cursor://` or `com.example.app:/cb`): only for
  clients whose `application_type` is `native`, and only if `registration.allowPrivateSchemes` is not
  `false`. That setting applies to dynamic registration and metadata documents, not to
  `create()`.

How a requested `redirect_uri` is matched against the registered ones:

- Exactly, character by character. There is no normalisation: no case folding of the path, no
  removal of dot segments, no percent-decoding.
- The one exception is loopback `http` (RFC 8252). `http://127.0.0.1:51234/callback` matches a
  registered `http://127.0.0.1/callback`. The port is ignored. Scheme, host, path and query must
  still be equal.
- If a client has exactly one redirect URI it may leave `redirect_uri` out of `/authorize`. With
  more than one it must send it, at `/authorize` and again at `/token`.

A native client that does not say `application_type` at dynamic registration is registered as `web`.
The server does not guess. A client that only uses loopback URIs works either way, but one that wants a
private-use scheme must send `"application_type": "native"`. A metadata document that omits
`application_type` is treated as `native` when all its redirect URIs are `http` (loopback), and as
`web` otherwise.

## Registering clients by hand

```php
use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\GrantType;

$created = $server->clientRegistrar()->create(
    name: 'Reporting dashboard',
    redirectUris: ['https://dashboard.example.com/oauth/callback'],
    confidential: true,
);

$client = $created['client'];   // CakeDC\OAuth\Server\Client\Client
$secret = $created['secret'];   // the secret, shown once. Only its hash is stored
echo $client->clientId, "\n", $secret, "\n";
```

The signature:

```php
create(
    string $name,
    array $redirectUris,
    bool $confidential,
    array $grantTypes = [GrantType::AUTHORIZATION_CODE, GrantType::REFRESH_TOKEN],
    ?array $scopes = null,
    bool $allowIntrospection = false,
    ApplicationType $applicationType = ApplicationType::Web,
): array // ['client' => Client, 'secret' => string|null]
```

| Argument | Meaning |
| --- | --- |
| `name` | 1 to 255 characters, no control characters |
| `redirectUris` | Up to 10. May be empty only without the authorization code grant |
| `confidential` | `true` gives the client a secret (`<prefix>_cs_...`) and `client_secret_basic` authentication. `false` makes it public |
| `grantTypes` | Any of `GrantType::AUTHORIZATION_CODE`, `GrantType::REFRESH_TOKEN`, `GrantType::CLIENT_CREDENTIALS` |
| `scopes` | The scopes the client may ever get. `null` means any scope the resources declare |
| `allowIntrospection` | May call `/introspect`. Confidential clients only. Read the warning in [endpoints](endpoints.md#post-oauthintrospect) |
| `applicationType` | `ApplicationType::Web` or `ApplicationType::Native` |

It throws `InvalidArgumentException` for bad input, for example a public client with client credentials
or introspection. A `ClientRegistered` event is dispatched. A confidential client created here
authenticates with HTTP Basic (`client_secret_basic`).

A public native client for a local tool, as `examples/standalone/setup.php` does:

```php
$created = $server->clientRegistrar()->create(
    'Demo client',
    ['http://127.0.0.1/callback'],
    false,
    applicationType: ApplicationType::Native,
);
```

To list clients, use `$server->storage()->findClients()` (optionally with a `ClientType`). To revoke
one forever, see [operations](operations.md#revoking-a-client).

## Client credentials

The client credentials grant is for a program that acts for itself, with no person involved: a
nightly import, a service calling your API. It needs a confidential client and an identity for it.

1. Create a confidential client with the grant and no redirect URIs:

   ```php
   $created = $server->clientRegistrar()->create(
       name: 'Nightly import',
       redirectUris: [],
       confidential: true,
       grantTypes: [GrantType::CLIENT_CREDENTIALS],
       scopes: ['content:read'],
   );
   ```

2. Tell the server which identity it acts as, in `UserProviderInterface::forClient()`. See
   [users](users.md#forclient). Without it the grant answers `unauthorized_client`.
3. The client asks for a token:

   ```bash
   curl -s https://auth.example.com/oauth/token -u CLIENT_ID:CLIENT_SECRET \
     -d grant_type=client_credentials \
     -d resource=https://example.com/mcp \
     -d scope=content:read
   ```

The token has no refresh token. Its `subject` is the client's `client_id` and its `subjectType` is
`client`, so it can never pass for a person with the same identifier. The scopes are limited by the
client's `scopes`, by `scopesFor()` for the identity you return, and by the resource. Setting
`'clientCredentials' => false` turns the grant off.

Dynamic registration refuses `client_credentials`. Only an administrator creates such clients.

## Connecting claude.ai

claude.ai connects to your MCP server as a "custom connector".

1. Your MCP endpoint must be reachable from the internet over https, and the authorization server's
   [metadata](endpoints.md#get-well-knownoauth-authorization-server) too.
2. In claude.ai, add a custom connector and enter the URL of your MCP endpoint, for example
   `https://example.com/mcp`.
3. Claude finds your authorization server. It uses a Client ID Metadata Document when the metadata has
   `client_id_metadata_document_supported: true` and `"none"` in `token_endpoint_auth_methods_supported`
   (this server sends both when `cimd.enabled` is `true`):
   - `client_id`: `https://claude.ai/oauth/mcp-oauth-client-metadata`
   - callback: `https://claude.ai/api/mcp/auth_callback`
4. The person is sent to your login, then sees "claude.ai wants to access Example MCP" and approves.

Nothing needs registering. Some points to know:

- If either of those two metadata members is missing, Claude falls back to dynamic registration, and
  fails when there is no `registration_endpoint`. So with `cimd.enabled` set to `false` Claude needs
  `registration.mode` `open`, or you give Claude a client you registered yourself (the connector
  dialog has an option for your own client id). With `cimd.enabled` `false` and
  `registration.mode` `closed`, the connection cannot work, because the metadata then offers no way to
  get a client.

- The document lists grant types this server does not implement (for example the JWT bearer grant).
  The server ignores unknown grant types.
- If you set `cimd.allowedHosts`, include `claude.ai`.
- Claude's requests come from Anthropic's egress range `160.79.104.0/21`. Do not block or challenge that
  range on the OAuth and MCP paths (`/.well-known/`, `/oauth/` and your MCP endpoint). See
  [deployment](deployment.md#cloudflare-and-waf-notes).
- Many people may share those addresses, and rate limits are per address, so give `token` a generous
  limit.
- The resource URL you configure must be the one in the connector. It is compared after
  canonicalisation (lowercase host, no trailing slash, no default port). See
  [troubleshooting](troubleshooting.md#invalid_target).

The whole flow is tested in `tests/TestCase/EndToEnd/ClaudeConnectorFlowTest.php`.

## Connecting Claude Code

Add the server as an HTTP MCP server:

```bash
claude mcp add --transport http example https://example.com/mcp
```

Then run `/mcp` inside Claude Code and choose to authenticate. Claude Code supports both Client ID
Metadata Documents (its default) and dynamic registration, and this server accepts either:

- With CIMD, its `client_id` is `https://claude.ai/oauth/claude-code-client-metadata`, with the redirect
  URIs `http://localhost/callback` and `http://127.0.0.1/callback`. Nothing needs registering.
- Claude Code listens for the redirect on your own computer, on a free port that changes every time.
  That is a loopback redirect, and the server ignores the port.

One caveat: the loopback match compares the host exactly, and different Claude Code versions have sent
`localhost` or `127.0.0.1`. A client you register by hand, or that registers dynamically, should
therefore list both loopback forms (`http://localhost/callback` and `http://127.0.0.1/callback`).
CIMD already lists both.

## Browser based tools

A tool that runs in a browser and does the OAuth flow itself needs CORS to work. The metadata, token,
register, revoke and introspect endpoints send the needed headers (`Access-Control-Allow-Origin: *`,
`Authorization`, `Content-Type` and `MCP-Protocol-Version` allowed). Your MCP endpoint needs a CORS
layer of its own, outside the bearer middleware, which exposes `WWW-Authenticate`
([protecting resources](protecting-resources.md#cors-preflights)). If such a tool uses a loopback
redirect, the loopback rule applies.

## Other clients

- **Editors and desktop tools with a private-use scheme redirect** (for example `myeditor://callback`):
  the server accepts it when the client registers with `application_type` `native` and
  `registration.allowPrivateSchemes` is `true` (the default).
- **Tools with a loopback or https redirect**: both are accepted under the
  [redirect URI rules](#redirect-uri-rules).
- **Your own CLI or desktop tool**: register it as a native public client, use a loopback redirect
  with PKCE, and keep the refresh token safe. Use the `offline_access` scope to receive a refresh
  token when `refreshTokens` is `offline_access`.
- **Servers**: use client credentials, or the authorization code flow with a confidential client.

When a client does not work, read [troubleshooting](troubleshooting.md).
