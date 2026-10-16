<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Security;

use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use SensitiveParameter;

/**
 * Signed, expiring tokens that bind a form to what was shown and to whom. They protect the consent
 * and connections forms even in applications without their own CSRF protection.
 */
final class FormToken
{
    /**
     * @param string $secret Signing key, at least 32 characters.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param int $ttl Seconds a token stays valid.
     */
    public function __construct(
        #[SensitiveParameter]
        private readonly string $secret,
        private readonly ClockInterface $clock,
        private readonly int $ttl = 900,
    ) {
        if (strlen($secret) < 32) {
            throw new InvalidArgumentException('The form token secret must be at least 32 bytes.');
        }
    }

    /**
     * A token for $context and $subject.
     */
    public function issue(string $context, string $subject): string
    {
        $expires = $this->clock->now()->getTimestamp() + $this->ttl;

        return $expires . '.' . $this->mac($context, $subject, $expires);
    }

    /**
     * Whether $token was issued for $context and $subject and has not expired.
     */
    public function verify(#[SensitiveParameter] string $token, string $context, string $subject): bool
    {
        if (preg_match('/^([1-9]\d{0,11})\.([a-f0-9]{64})\z/', $token, $matches) !== 1) {
            return false;
        }
        $expires = (int)$matches[1];
        if ($expires <= $this->clock->now()->getTimestamp()) {
            return false;
        }

        return hash_equals($this->mac($context, $subject, $expires), $matches[2]);
    }

    /**
     * The signature.
     */
    private function mac(string $context, string $subject, int $expires): string
    {
        return hash_hmac(
            'sha256',
            'oauth-form-token-v1|' . strlen($context) . ':' . $context . '|' . strlen($subject) . ':' . $subject
                . '|' . $expires,
            $this->secret,
        );
    }
}
