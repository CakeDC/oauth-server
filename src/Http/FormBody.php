<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Reads form-encoded request bodies.
 */
final class FormBody
{
    /**
     * The form parameters: from the raw body when it can be read (so repeated names are detected),
     * otherwise from the body the framework already parsed. Non-string values are dropped.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return array{0: array<string, string>, 1: list<string>}
     */
    public static function read(ServerRequestInterface $request): array
    {
        $body = $request->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }
        $raw = $body->getContents();
        if ($raw !== '') {
            return Params::parse($raw);
        }
        $parsed = $request->getParsedBody();
        $values = [];
        if (is_array($parsed)) {
            foreach ($parsed as $name => $value) {
                if (is_string($value)) {
                    $values[(string)$name] = $value;
                }
            }
        }

        return [$values, []];
    }

    /**
     * Whether the request declares a form-encoded body.
     */
    public static function isForm(ServerRequestInterface $request): bool
    {
        $type = strtolower($request->getHeaderLine('Content-Type'));

        return str_starts_with($type, 'application/x-www-form-urlencoded');
    }
}
