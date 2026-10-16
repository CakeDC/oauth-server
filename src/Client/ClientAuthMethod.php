<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

/**
 * `token_endpoint_auth_method` of a client.
 */
enum ClientAuthMethod: string
{
    case None = 'none';
    case SecretBasic = 'client_secret_basic';
    case SecretPost = 'client_secret_post';
}
