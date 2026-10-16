# Events

The server announces what happens through PSR-14 events. Use them for an audit log, for alerts and
for metrics. By default events are dropped (`NullEventDispatcher`). Pass your own dispatcher to the
`AuthorizationServer` constructor to receive them.

All events live in `CakeDC\OAuth\Server\Event`. They are read-only objects. Token values, client
secrets and codes never appear in an event.

| Event | Fires when |
| --- | --- |
| `TokenIssued` | A token is stored: an access, refresh or personal token |
| `TokenRevoked` | One or more tokens were revoked |
| `ConsentGranted` | A person approved a client |
| `ClientRegistered` | A client was registered, dynamically or by hand |
| `RefreshTokenReused` | A rotated refresh token was presented again outside the grace window |
| `AuthorizationDenied` | An authorization request was refused |

## `TokenIssued`

Fires once for every token stored, so a code exchange with a refresh token fires twice (access, then
refresh). It also fires for personal tokens.

| Property | Type | Meaning |
| --- | --- | --- |
| `token` | `Token` | The stored token (id, type, subject, resource, scopes, expiry). Not its value |
| `client` | `Client` or `null` | The client. `null` for personal tokens |

## `TokenRevoked`

| Property | Type | Meaning |
| --- | --- | --- |
| `reason` | string | Why. See the table below |
| `count` | int | How many tokens this revocation changed (only tokens not revoked before are counted) |
| `token` | `Token` or `null` | The token named in the request, when there is one |
| `familyId` | string or `null` | The family, when a whole family was revoked |
| `subject` | string or `null` | The subject, when all of a person's tokens were revoked |
| `clientInternalId` | string or `null` | The client, when all of a client's tokens were revoked |

The event fires only when `count` is greater than zero. The `reason` values:

| Reason | Meaning |
| --- | --- |
| `client` | The client called `/revoke` (an access token alone, or a refresh token with its family) |
| `connection` | The person revoked a connection on the connections page |
| `personal` | The person revoked a personal token |
| `code_reuse` | An authorization code was used twice, so everything issued from it was revoked. Also fires when two requests race for one code and one loses |
| `refresh_reuse` | A rotated refresh token was replayed, so its family was revoked. Fires together with `RefreshTokenReused` |
| `grace` | A retry inside the grace window received a new pair, and the tokens of the first rotation were revoked |
| `rotation_revoked` | A refresh was revoked while its new pair was being issued, so the new pair was revoked at once |
| `subject` | `TokenRevoker::revokeAllForSubject()` was called |
| `client_revoked` | `TokenRevoker::revokeAllForClient()` was called |
| `issue_failed` | A code exchange failed while storing tokens, so what had been stored was revoked |

You can also call `TokenRevoker::revokeTokens()` with your own reason string (see
[operations](operations.md#revoking-a-leaked-token)).

## `ConsentGranted`

Fires each time a person approves, even when the consent already existed and only scopes were added.

| Property | Type | Meaning |
| --- | --- | --- |
| `consent` | `Consent` | The stored consent: subject, client, resource, scopes |
| `owner` | `ResourceOwner` | Who approved |
| `client` | `Client` | The client |

## `ClientRegistered`

Fires after `POST /oauth/register` and after `ClientRegistrar::create()`. Metadata document clients
are created on first use and do not fire it.

| Property | Type | Meaning |
| --- | --- | --- |
| `client` | `Client` | The new client |

## `RefreshTokenReused`

A refresh token that was already rotated was presented again after the grace window, or while its
family is still live. Its whole family was revoked (a `TokenRevoked` with `refresh_reuse` comes too).

| Property | Type | Meaning |
| --- | --- | --- |
| `token` | `Token` | The reused refresh token |
| `client` | `Client` | The client that presented it |

This is a signal, not proof of theft. A client that refreshes the same token from two processes, or
retries badly after a timeout, causes the same event. Alert on a rising rate rather than on single
events. See [security](security.md#the-refresh-grace-window).

## `AuthorizationDenied`

| Property | Type | Meaning |
| --- | --- | --- |
| `client` | `Client` | The client |
| `owner` | `ResourceOwner` | The signed-in person |
| `reason` | string | `not_allowed` (`canAuthorize()` returned `false`) or `user_denied` (the person pressed Deny, or sent anything but `approve`) |

## Wiring a dispatcher

Any PSR-14 dispatcher works (Symfony's, League's, your framework's). Pass it as `$events`. A small
one that needs no package:

```php
use Psr\EventDispatcher\EventDispatcherInterface;

final class SimpleDispatcher implements EventDispatcherInterface
{
    /** @var array<class-string, list<callable>> */
    private array $listeners = [];

    public function listen(string $event, callable $listener): void
    {
        $this->listeners[$event][] = $listener;
    }

    public function dispatch(object $event): object
    {
        foreach ($this->listeners[$event::class] ?? [] as $listener) {
            $listener($event);
        }

        return $event;
    }
}

$events = new SimpleDispatcher();

$server = new AuthorizationServer(
    $config, $storage, $users, $users, $factory, $factory,
    events: $events,
);
```

Listeners run inside the request. Keep them fast, and catch your own exceptions: an exception from a
listener can fail the request that fired it.

## An audit log example

Write the security-relevant events to a PSR-3 logger (`$logger` is any `Psr\Log\LoggerInterface`):

```php
use CakeDC\OAuth\Server\Event\AuthorizationDenied;
use CakeDC\OAuth\Server\Event\ClientRegistered;
use CakeDC\OAuth\Server\Event\ConsentGranted;
use CakeDC\OAuth\Server\Event\RefreshTokenReused;
use CakeDC\OAuth\Server\Event\TokenIssued;
use CakeDC\OAuth\Server\Event\TokenRevoked;

$audit = function (string $message, array $context) use ($logger): void {
    try {
        $logger->info($message, $context);
    } catch (Throwable) {
        // Never let logging break authorization.
    }
};

$events->listen(ConsentGranted::class, fn (ConsentGranted $e) => $audit('oauth.consent', [
    'subject' => $e->owner->subject,
    'client' => $e->client->clientId,
    'resource' => $e->consent->resource,
    'scopes' => $e->consent->scopes,
]));

$events->listen(TokenIssued::class, fn (TokenIssued $e) => $audit('oauth.token_issued', [
    'type' => $e->token->type->value,
    'subject' => $e->token->subject,
    'client' => $e->client?->clientId,
    'resource' => $e->token->resource,
    'expires' => $e->token->expiresAt?->format(DATE_ATOM),
]));

$events->listen(TokenRevoked::class, fn (TokenRevoked $e) => $audit('oauth.token_revoked', [
    'reason' => $e->reason,
    'count' => $e->count,
    'family' => $e->familyId,
    'subject' => $e->subject,
]));

$events->listen(RefreshTokenReused::class, fn (RefreshTokenReused $e) => $audit('oauth.refresh_reused', [
    'client' => $e->client->clientId,
    'subject' => $e->token->subject,
]));

$events->listen(AuthorizationDenied::class, fn (AuthorizationDenied $e) => $audit('oauth.denied', [
    'reason' => $e->reason,
    'subject' => $e->owner->subject,
    'client' => $e->client->clientId,
]));

$events->listen(ClientRegistered::class, fn (ClientRegistered $e) => $audit('oauth.client_registered', [
    'client' => $e->client->clientId,
    'type' => $e->client->type->value,
    'name' => $e->client->name,
]));
```

Do not log request bodies, `Authorization` headers or form values next to these events.
