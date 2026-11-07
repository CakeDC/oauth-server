<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use SensitiveParameter;

/**
 * Encrypts the pair a rotation issued with the refresh token that was rotated.
 *
 * Only the token values are needed to answer a concurrent caller with the same pair, and storage keeps
 * hashes only. The seal is the two values XORed with a keystream derived (HKDF-SHA256) from the rotated
 * refresh token, the server secret and a random nonce. Opening it needs the plaintext of the rotated token,
 * which storage never holds, so the seal alone gives nothing away. Integrity comes from the caller: the
 * values it opens are only used when their hashes match the stored tokens.
 *
 * @internal Used by the RefreshTokenRotator; not part of the public API, it may change in any 1.x release.
 */
final class RotationSeal
{
    private const INFO = 'cakedc/oauth-server rotation seal v1';

    private const NONCE_BYTES = 16;

    /**
     * @param string $secret The server secret.
     */
    public function __construct(
        #[SensitiveParameter]
        private readonly string $secret,
    ) {
    }

    /**
     * Seals the values of a pair with the refresh token that was rotated.
     */
    public function seal(
        #[SensitiveParameter]
        string $rotated,
        #[SensitiveParameter]
        string $accessToken,
        #[SensitiveParameter]
        string $refreshToken,
    ): string {
        $plain = pack('n', strlen($accessToken)) . $accessToken . $refreshToken;
        $nonce = random_bytes(self::NONCE_BYTES);

        return base64_encode($nonce . ($plain ^ $this->keystream($rotated, $nonce, strlen($plain))));
    }

    /**
     * The access and refresh token values of a seal, or null when it cannot be read.
     *
     * A wrong rotated token yields garbage, not null: the caller checks the values against the stored hashes.
     *
     * @return array{0: string, 1: string}|null
     */
    public function open(
        #[SensitiveParameter]
        string $rotated,
        string $seal,
    ): ?array {
        $bytes = base64_decode($seal, true);
        if ($bytes === false || strlen($bytes) < self::NONCE_BYTES + 3) {
            return null;
        }
        $nonce = substr($bytes, 0, self::NONCE_BYTES);
        $cipher = substr($bytes, self::NONCE_BYTES);
        $plain = $cipher ^ $this->keystream($rotated, $nonce, strlen($cipher));
        $length = unpack('n', substr($plain, 0, 2));
        $accessLength = is_array($length) ? (int)$length[1] : 0;
        if ($accessLength < 1 || $accessLength >= strlen($plain) - 2) {
            return null;
        }

        return [substr($plain, 2, $accessLength), substr($plain, 2 + $accessLength)];
    }

    /**
     * $length bytes of keystream for one seal.
     */
    private function keystream(
        #[SensitiveParameter]
        string $rotated,
        string $nonce,
        int $length,
    ): string {
        return hash_hkdf('sha256', $rotated, max(0, $length), self::INFO, $this->secret . $nonce);
    }
}
