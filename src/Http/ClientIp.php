<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * The address a request came from, for rate limiting. Behind a proxy, pass a resolver that trusts
 * your proxy's forwarding header instead.
 */
final class ClientIp
{
    /**
     * `REMOTE_ADDR` of the request.
     */
    public static function fromServerParams(ServerRequestInterface $request): string
    {
        $address = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        return is_string($address) && $address !== '' ? $address : 'unknown';
    }
}
