<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Owner;

/**
 * Whom a token acts for: a person of the application, or the identity a client acts as.
 */
final class ResourceOwner
{
    /**
     * @param string $subject Stable identifier, stored with grants and tokens (`sub`).
     * @param string $displayName Shown on the consent and connections pages.
     * @param mixed $identity The application's own object for this owner; opaque to the server.
     * @param \CakeDC\OAuth\Server\Owner\SubjectType $type User or client.
     */
    public function __construct(
        public readonly string $subject,
        public readonly string $displayName,
        public readonly mixed $identity = null,
        public readonly SubjectType $type = SubjectType::User,
    ) {
    }
}
