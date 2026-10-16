<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Event;

use CakeDC\OAuth\Server\Token\Token;

/**
 * Tokens were revoked.
 */
final class TokenRevoked
{
    /**
     * @param string $reason `client`, `connection`, `personal`, `code_reuse`, `refresh_reuse`, `grace`,
     *   `rotation_revoked`,
     *   `subject`, `client_revoked`, `issue_failed`.
     * @param int $count How many tokens.
     * @param \CakeDC\OAuth\Server\Token\Token|null $token The token named in the request, if any.
     * @param string|null $familyId The family, when a whole family was revoked.
     * @param string|null $subject The subject, when all of a subject's tokens were revoked.
     * @param string|null $clientInternalId The client, when all of a client's tokens were revoked.
     */
    public function __construct(
        public readonly string $reason,
        public readonly int $count,
        public readonly ?Token $token = null,
        public readonly ?string $familyId = null,
        public readonly ?string $subject = null,
        public readonly ?string $clientInternalId = null,
    ) {
    }
}
