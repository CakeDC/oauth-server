<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Event;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Grant\Consent;
use CakeDC\OAuth\Server\Owner\ResourceOwner;

/**
 * An owner approved a client.
 */
final class ConsentGranted
{
    /**
     * @param \CakeDC\OAuth\Server\Grant\Consent $consent The stored consent.
     * @param \CakeDC\OAuth\Server\Owner\ResourceOwner $owner Who approved.
     * @param \CakeDC\OAuth\Server\Client\Client $client The client.
     */
    public function __construct(
        public readonly Consent $consent,
        public readonly ResourceOwner $owner,
        public readonly Client $client,
    ) {
    }
}
