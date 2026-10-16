<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

/**
 * Grant types this server implements. Clients may list others (CIMD documents do); they are ignored.
 */
final class GrantType
{
    public const AUTHORIZATION_CODE = 'authorization_code';
    public const REFRESH_TOKEN = 'refresh_token';
    public const CLIENT_CREDENTIALS = 'client_credentials';
}
