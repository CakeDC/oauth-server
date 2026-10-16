<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http;

use SensitiveParameter;

/**
 * Strict parsing of query strings and form bodies: OAuth parameters must not be repeated, and PHP's
 * own parsing would silently keep the last value.
 *
 * @internal Not part of the public API: it may change in any 1.x release.
 */
final class Params
{
    /**
     * The first value of each parameter, and the names given more than once.
     *
     * @return array{0: array<string, string>, 1: list<string>}
     */
    public static function parse(#[SensitiveParameter] string $raw): array
    {
        $values = [];
        $repeated = [];
        foreach (explode('&', $raw) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $name = urldecode($name);
            if (array_key_exists($name, $values)) {
                if (!in_array($name, $repeated, true)) {
                    $repeated[] = $name;
                }

                continue;
            }
            $values[$name] = urldecode($value);
        }

        return [$values, $repeated];
    }
}
