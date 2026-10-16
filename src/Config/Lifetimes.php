<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Config;

use InvalidArgumentException;

/**
 * How long codes and tokens live, in seconds.
 */
final class Lifetimes
{
    /**
     * @param int $code Authorization code.
     * @param int $access Access token.
     * @param int $refresh Refresh token, renewed by each rotation.
     * @param int $family Maximum life of a chain of refresh tokens.
     * @param int $personalMax Longest a personal token may live.
     * @param int $refreshReuseGrace Seconds in which a just-rotated refresh token may be presented again; 0 disables.
     * @throws \InvalidArgumentException
     */
    public function __construct(
        public readonly int $code = 60,
        public readonly int $access = 3600,
        public readonly int $refresh = 2592000,
        public readonly int $family = 31536000,
        public readonly int $personalMax = 7776000,
        public readonly int $refreshReuseGrace = 30,
    ) {
        $positive = [
            'code' => $code,
            'access' => $access,
            'refresh' => $refresh,
            'family' => $family,
            'personalMax' => $personalMax,
        ];
        foreach ($positive as $name => $value) {
            if ($value < 1) {
                throw new InvalidArgumentException(sprintf('The "%s" lifetime must be at least one second.', $name));
            }
        }
        if ($refreshReuseGrace < 0) {
            throw new InvalidArgumentException('"refreshReuseGrace" cannot be negative.');
        }
    }

    /**
     * Builds lifetimes from settings with the property names as keys. A list is refused.
     *
     * @param array<mixed> $values Settings, as read from a configuration file.
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $values): self
    {
        if ($values !== [] && array_is_list($values)) {
            throw new InvalidArgumentException('"lifetimes" must map lifetime names to seconds, not a list.');
        }
        $known = ['code', 'access', 'refresh', 'family', 'personalMax', 'refreshReuseGrace'];
        $unknown = array_diff(array_keys($values), $known);
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf('Unknown lifetime "%s".', implode('", "', $unknown)));
        }
        foreach ($values as $name => $value) {
            if (!is_int($value)) {
                throw new InvalidArgumentException(sprintf('"lifetimes.%s" must be an integer (seconds).', $name));
            }
        }

        /** @var array<string, int> $values */
        return new self(...$values);
    }
}
