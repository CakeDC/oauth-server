<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Event;

use CakeDC\OAuth\Server\Client\Client;

/**
 * A client was registered, dynamically or by hand.
 */
final class ClientRegistered
{
    /**
     * @param \CakeDC\OAuth\Server\Client\Client $client The new client.
     */
    public function __construct(public readonly Client $client)
    {
    }
}
