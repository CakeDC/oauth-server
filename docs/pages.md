# Pages

The server renders three pages: the consent page, the connections page and an error page. They are
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

Shown at `/oauth/authorize` when the person has not yet accepted what the client asks for. It shows:

- A heading: "{client} wants to access {resource}". A metadata document client is named by the host
  of its `client_id` URL, because its own name is self-asserted. Other clients are named by
  `Client::$name`.
- Where the request comes from and where the answer goes: "The request comes from {host}. Your answer
  is sent to {redirect}." The host is the client's display host (the `client_id` host for a metadata
  document, otherwise the host of its first redirect URI), so the person can spot a client
  pretending to be something else.
- An **unverified** notice for dynamically registered clients: they chose their own name.
- A **loopback** notice when every redirect URI points to the person's own computer.
- Who is signed in, the list of permissions (the scope descriptions from your configuration), and
  "Stay connected until you revoke it." when a refresh token will be issued.
- Two buttons: Allow and Deny.

Logos are not shown. A logo is a tracking and spoofing risk and the pages do not need one.

## The connections page

Shown at `/oauth/connections` to signed-in people. Anonymous visitors are sent to your login first.

- A table of connected applications: name (or host), the resource, the permissions, when it was
  connected and when it was last used, and a Revoke button. A dynamically registered client carries
  the unverified notice.
- The personal access tokens section: list, revoke, and a form to create one. See
  [personal tokens](personal-tokens.md).

Revoking a connection revokes its whole token family and forgets the consent, so the next
authorization asks again.

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
| `fields` | Hidden fields to post back, as `name => value` |
| `clientHost()` | The host that names the client |
| `redirectHost()` | The host of the redirect URI |
| `isUnverified()` | `true` for a dynamically registered client |
| `isLoopbackOnly()` | `true` when the client only redirects to this computer |

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

        return '<h1>' . $e($view->clientHost()) . ' wants access to ' . $e($view->resource->name) . '</h1>'
            . '<ul>' . $items . '</ul>'
            . '<form method="post" action="' . $e($view->formAction) . '">' . $hidden
            . '<button name="decision" value="approve">Allow</button>'
            . '<button name="decision" value="deny">Deny</button></form>';
    }
}
```

Keep the safety messages in your page: say where the answer goes (`redirectHost()`), and show the
unverified and loopback notices.

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
| `connections` | `list<Connection>`: `familyId`, `client`, `resource`, `scopes`, `connectedAt`, `lastUsedAt` |
| `personalTokens` | `list<Token>`: `id`, `name`, `resource`, `scopes`, `expiresAt` |
| `creatable` | `resource => ['name' => ..., 'scopes' => [scope => description]]` the person may put in a new token |
| `resourceNames` | `identifier => name`, and `resourceName($identifier)` |
| `formAction` | The path the forms post to |
| `formToken` | The signed token every form must post |
| `maxDays` | The longest life of a new personal token, in days |
| `personalTokensEnabled` | Whether to show the personal token section |
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
| `consent.unverified` | This application registered itself; its name is not verified. |  |
| `consent.loopback` | This application runs on your own computer. |  |
| `consent.user` | Signed in as {user}. | `{user}` |
| `consent.scopes` | It will be able to: |  |
| `consent.offline` | Stay connected until you revoke it. |  |
| `consent.approve` | Allow |  |
| `consent.deny` | Deny |  |
| `error.title` | Authorization failed |  |
| `error.intro` | The application sent a request that cannot be completed. |  |
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
