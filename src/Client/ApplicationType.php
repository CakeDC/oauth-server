<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

/**
 * `application_type` of a client (OpenID Connect Registration, required by MCP 2026-07-28 for DCR).
 */
enum ApplicationType: string
{
    case Web = 'web';
    case Native = 'native';
}
