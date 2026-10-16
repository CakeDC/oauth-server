# Pages

The server renders three pages: the consent page, the connections page and an error page (with or
without a link back to the client). They are
plain HTML, with inline CSS and no JavaScript, and work out of the box. You can reword them, translate
them or replace them completely.

All pages are sent with `HttpResponder::page()`, which adds these headers:

- `Cache-Control: no-store`
- `X-Frame-Options: DENY` and `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';
  frame-ancestors 'none'; base-uri 'none'`, so a page cannot be framed (clickjacking)
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`

The policy has no `form-action` on purpose: browsers apply it to the redirect that follows the consent
POST and would block the trip back to the client.

## The consent page

Shown at `/oauth/authorize` when the person has not yet accepted what the client asks for, and every
time for a public client with a loopback or private-use redirect URI, whose identity a remembered
consent cannot vouch for (see [endpoints](endpoints.md#get-start)). It shows:

- A title and a heading: "{client} wants to access {resource}". Only a client an administrator
  registered is named by `Client::$name`. A metadata document client is named by the host of its
  `client_id` URL, and a dynamically registered one by the host its answer is sent to, because a name
  is self-asserted: anyone can register a client called `claude.ai`. A dynamic client whose answer goes
  to a private-use scheme has no host at all (anyone can claim the scheme `claude.ai:`), so it gets the
  fixed text of the `client.local` message, "An application on this computer"; the scheme appears only
  as the destination, with its colon (`claude.ai:`), so it never reads as a host. A dynamic client's
  own name appears below as a quoted (`<q>`), unverified line ("It calls itself ..."), always for the
  private-scheme case and otherwise when it differs from the host.
- Where the request comes from and where the answer goes: "The request comes from {host}. Your answer
  is sent to {redirect}." For a metadata document the host is the `client_id` host; for a client that
  registered itself it is the host the answer goes to (never a redirect URI it merely listed); for an
  administrator's client, the host of its first redirect URI. A client that registered itself with a
  private-use redirect gets a sentence of its own, `consent.fromLocal`: "The request comes from an
  application on this computer. Your answer is sent to {redirect}." The destination of a private-use
  redirect is its scheme with the colon, `claude.ai:`.
- An **unverified** notice for dynamically registered clients: they chose their own name.
- A **loopback** warning when the answer goes to the person's own computer: a loopback or unspecified
  address (`127.0.0.0/8`, `::1`, `0.0.0.0`, `::`), a `.localhost` name, or a private-use scheme. It does
  not reassure: any program on that computer can listen on the address, so the text asks the person to
  continue only when they just started the flow from an application there. It shows whenever the answer
  goes to this computer, including every case where a remembered consent is not enough for a public
  client, so "approved before" never appears without it (a confidential client with a loopback redirect
  also gets the warning, but its remembered consent skips the page).
- An **approved before** notice when a remembered consent already covers the request but the page is
  shown anyway because the client's identity cannot be assured: the person is asked to continue only if
  they started this themselves.
- Who is signed in, the list of permissions (the scope descriptions from your configuration), and
  "Stay connected until you revoke it." only when a refresh token will really be issued (the
  `refreshTokens` mode allows it and the client may use the `refresh_token` grant).
- Two buttons: Allow and Deny.

Logos are not shown. A logo is a tracking and spoofing risk and the pages do not need one.

## The connections page

Shown at `/oauth/connections` to signed-in people. Anonymous visitors are sent to your login first.

- A table of connected applications: name (or host), the resource, the permissions, when it was
  connected and when it was last used, and a Revoke button. A dynamically registered client carries
  the unverified notice.
- The personal access tokens section: list, revoke, and a form to create one. See
  [personal tokens](personal-tokens.md).

The permissions of a connection are its grant: the scopes of its live refresh token that was not
rotated yet. A refresh keeps the grant on the new refresh token and may narrow only the new access
token (a client that asks for less, a person with fewer rights today), so the access token can show
less than the connection holds; the next refresh can ask for the rest again. A connection without a
refresh token (`refreshTokens` set to `offline_access` and not asked for) shows its access token's
scopes. `Connection::$scopes` follows the same rule.

Revoking a connection revokes its whole token family, deletes the person's authorization codes for that
client that were not exchanged yet (for every resource, not only the connection's), and forgets the
consent, so the next authorization asks again.

## Replacing the pages

Each page has a renderer interface. Write a class, pass it to the `AuthorizationServer` constructor
and the built-in page is not used. A renderer returns an HTML string. The handler adds the status and
the headers above.

```php
$server = new AuthorizationServer(
    $config, $storage, $users, $users, $factory, $factory,
    consentRenderer: new MyConsentRenderer(),
    connectionsRenderer: new MyConnectionsRenderer(),
    errorPageRenderer: new MyErrorRenderer(),
);
```

Escape everything you print (`htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`):
client names, descriptions, display names and error texts come from outside.

### `ConsentRendererInterface`

```php
interface ConsentRendererInterface
{
    public function render(ConsentView $view): string;
}
```

`ConsentView` properties and helpers:

| Member | Meaning |
| --- | --- |
| `client` | The `Client` |
| `owner` | The signed-in `ResourceOwner` |
| `resource` | The `ProtectedResource` (use `->name`) |
| `scopes` | `scope => description` of what will be granted |
| `offlineAccess` | Whether the client will stay connected (a refresh token will be issued) |
| `redirectUri` | Where the answer goes |
| `formAction` | The path the form must post to |
| `fields` | Hidden fields to post back, as `name => value`. They carry the signed `consent_token`; the constructor parameter is a `#[\SensitiveParameter]` |
| `clientHost()` | The host that names the client: the `client_id` host of a metadata document, the host the answer goes to for a self-registered client (empty for a private-use scheme), the first redirect URI host for an administrator's client |
| `clientLabel()` | What the title and heading call the client: its name for an administrator's client, a host for the others. Empty for a self-registered client that redirects to a private-use scheme: show a fixed text then (the built-in pages use the `client.local` message) |
| `declaredName()` | The name a self-registered client declared, to show as a quoted unverified line, or `null`. Always set for a private-use redirect, otherwise only when it differs from the host |
| `redirectHost()` | The host of the redirect URI; for a private-use URI, the scheme with its colon (`com.example.app:`), so a scheme such as `claude.ai:` never reads as a host. The same rule as `RedirectNoticeView::redirectHost()` |
| `isUnverified()` | `true` for a dynamically registered client |
| `isLoopbackOnly()` | `true` when the answer goes to this computer (loopback or unspecified address, `.localhost` name, private-use scheme) |
| `approvedBefore` | `true` when a remembered consent covers the request but the page is shown again (public loopback or private-scheme client) |

Your page must send a `POST` to `$view->formAction` with:

- every entry of `$view->fields` as a hidden field. They are the authorization parameters and
  `consent_token`, the signed token bound to the request, the shown scopes and the person. Without it,
  or after 15 minutes, the answer is `invalid_request`;
- `decision`: `approve` or `deny`. Anything else counts as a denial.

```php
final class MyConsentRenderer implements ConsentRendererInterface
{
    public function render(ConsentView $view): string
    {
        $e = fn (string $text): string => htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $hidden = '';
        foreach ($view->fields as $name => $value) {
            $hidden .= '<input type="hidden" name="' . $e($name) . '" value="' . $e($value) . '">';
        }
        $items = implode('', array_map(fn (string $d): string => '<li>' . $e($d) . '</li>', $view->scopes));

        // clientLabel() is '' for a self-registered client that redirects to a private-use scheme.
        $label = $view->clientLabel() !== '' ? $view->clientLabel() : 'An application on this computer';

        return '<h1>' . $e($label) . ' wants access to ' . $e($view->resource->name) . '</h1>'
            . '<ul>' . $items . '</ul>'
            . '<form method="post" action="' . $e($view->formAction) . '">' . $hidden
            . '<button name="decision" value="approve">Allow</button>'
            . '<button name="decision" value="deny">Deny</button></form>';
    }
}
```

Keep the safety messages in your page: say where the answer goes (`redirectHost()`), and show the
unverified, loopback and approved before notices. For a client that registered itself, `$view->client->name`
and the registered redirect URIs are chosen by the client: name it with `clientLabel()` and show
`declaredName()` only as a clearly quoted, unverified line (put the escaped name in its own element, such
as `<q>`, never between quote characters of your own text).

### `ConnectionsRendererInterface`

```php
interface ConnectionsRendererInterface
{
    public function render(ConnectionsView $view): string;
}
```

`ConnectionsView` properties:

| Member | Meaning |
| --- | --- |
| `owner` | The signed-in `ResourceOwner` |
| `connections` | `list<Connection>`: `familyId`, `client`, `resource`, `scopes` (the grant, see [the connections page](#the-connections-page)), `connectedAt`, `lastUsedAt` |
| `personalTokens` | `list<Token>`: `id`, `name`, `resource`, `scopes`, `expiresAt` |
| `creatable` | `resource => ['name' => ..., 'scopes' => [scope => description]]` the person may put in a new token |
| `resourceNames` | `identifier => name`, and `resourceName($identifier)` |
| `formAction` | The path the forms post to |
| `formToken` | The signed token every form must post |
| `maxDays` | The longest life of a new personal token, in days |
| `personalTokensEnabled` | Whether creating personal tokens is offered. Show the section anyway when `personalTokens` is not empty, so people can revoke what is left |
| `newToken` | A token just created. Show it once, with a copy warning |
| `error` | A message about the last action (for example a failed creation) |

Every form posts to `$view->formAction` with `form_token` and an `action`:

| `action` | Other fields |
| --- | --- |
| `revoke_connection` | `family_id` |
| `revoke_token` | `token_id` |
| `create_token` | `name` (1 to 100 characters), `resource`, `days` (1 to `maxDays`), and one `scope:<name>` field with the value `1` for every chosen scope, for example `scope:content:read=1` (a checkbox named `scope:content:read`) |

### `ErrorPageRendererInterface`

```php
interface ErrorPageRendererInterface
{
    public function render(OAuthException $error): string;
}
```

Shown when an authorization request cannot go back to its client (unknown client, bad redirect URI,
expired form and so on) and for connection page errors. `$error->error` is the code,
`$error->getMessage()` the description and `$error->status` the HTTP status.

### `RedirectNoticeRendererInterface`

```php
interface RedirectNoticeRendererInterface
{
    public function renderRedirectNotice(RedirectNoticeView $view): string;
}
```

Optional, on the same class as your `ErrorPageRendererInterface`. It renders the page shown instead
of an automatic redirect when a request fails and its redirect URI is not trusted (a dynamically
registered or metadata document client the signed-in person never approved; see
[endpoints](endpoints.md#get-start)). The built-in error page implements it. If your error renderer
does not, that case shows your plain error page, without the link: safe, but the person cannot go
back to the client.

`RedirectNoticeView` members:

| Member | Meaning |
| --- | --- |
| `error` | The `OAuthException` |
| `client` | The `Client`, or null |
| `redirectUri` | The client's redirect URI |
| `continueUrl` | The redirect URI with the error parameters: the link that continues |
| `redirectHost()` | The host the person would be sent to; for a private-use URI, the scheme with its colon (`com.example.app:`) |

Show the error and the destination host, and offer `continueUrl` as a plain link. Never follow it by
yourself: no script, no `<meta http-equiv="refresh">`.

## Translating with `Messages`

The texts of the built-in pages are in `Messages::DEFAULTS`, in English. Pass overrides to reword or
translate them. You only list the keys you change:

```php
use CakeDC\OAuth\Server\View\Messages;

$server = new AuthorizationServer(
    $config, $storage, $users, $users, $factory, $factory,
    messages: new Messages([
        'consent.approve' => 'Permitir',
        'consent.deny' => 'Denegar',
        'consent.heading' => '{client} quiere acceder a {resource}',
    ]),
);
```

`{name}` placeholders are replaced by the page. Keep the placeholders your text needs. An unknown key
returns the key itself.

Every key, with its default text:

| Key | Default text | Placeholders |
| --- | --- | --- |
| `consent.title` | Authorize {client} | `{client}` |
| `consent.heading` | {client} wants to access {resource} | `{client}`, `{resource}` |
| `consent.from` | The request comes from {host}. Your answer is sent to {redirect}. | `{host}`, `{redirect}` |
| `client.local` | An application on this computer |  |
| `consent.fromLocal` | The request comes from an application on this computer. Your answer is sent to {redirect}. | `{redirect}` (used instead of `consent.from` for a self-registered client with a private-use redirect) |
| `connections.hostsAndLocal` | {hosts} and an application on this computer | `{hosts}` |
| `consent.declaredName` | It calls itself {name}. Anyone can choose that name. | `{name}` (the page puts the escaped name in a `<q>` element; a text without `{name}` gets the name appended in one) |
| `consent.unverified` | This application registered itself; its name is not verified. |  |
| `consent.loopback` | Only continue if you just started this from an application on this computer: any program on this computer can use this address. |  |
| `consent.approvedBefore` | You approved this application before. It is asked again because its identity cannot be confirmed: only continue if you started this yourself. |  |
| `consent.user` | Signed in as {user}. | `{user}` |
| `consent.scopes` | It will be able to: |  |
| `consent.offline` | Stay connected until you revoke it. |  |
| `consent.approve` | Allow |  |
| `consent.deny` | Deny |  |
| `error.title` | Authorization failed |  |
| `error.intro` | The application sent a request that cannot be completed. |  |
| `error.untrusted` | The application asked to send this answer to {host}. This server cannot confirm that {host} belongs to it: only continue if you trust it. | `{host}` |
| `error.continue` | Continue to {host} | `{host}` |
| `connections.title` | Connected applications |  |
| `connections.empty` | No application is connected. |  |
| `connections.client` | Application |  |
| `connections.resource` | Access to |  |
| `connections.scopes` | Permissions |  |
| `connections.connected` | Connected |  |
| `connections.lastUsed` | Last used |  |
| `connections.never` | Never |  |
| `connections.revoke` | Revoke |  |
| `connections.unverified` | Unverified: this application registered itself. |  |
| `tokens.title` | Personal access tokens |  |
| `tokens.empty` | You have no personal access tokens. |  |
| `tokens.name` | Name |  |
| `tokens.resource` | Resource |  |
| `tokens.scopes` | Permissions |  |
| `tokens.expires` | Expires |  |
| `tokens.days` | Expires in (days, up to {max}) | `{max}` |
| `tokens.create` | Create token |  |
| `tokens.created` | Copy your new token now. It will not be shown again: |  |
| `tokens.revoke` | Revoke |  |

The `<html lang>` of the built-in pages is `en`. If you translate fully, supply your own renderers.
