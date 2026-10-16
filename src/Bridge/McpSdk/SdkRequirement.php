<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Bridge\McpSdk;

use LogicException;

/**
 * Checks that the installed mcp/sdk is one the bridge works with: 0.9 or newer. mcp/sdk 0.8 has the
 * validator interface but no `AccessToken`, and its `AuthorizationResult::allow()` takes an array, so the
 * bridge would build fine and then fail with a TypeError on every valid token.
 *
 * @internal Called by AuthorizationServer::mcpTokenValidator() and the bridge's constructor.
 */
final class SdkRequirement
{
    public const VALIDATOR_INTERFACE = 'Mcp\\Server\\Transport\\Http\\OAuth\\AuthorizationTokenValidatorInterface';
    public const ACCESS_TOKEN = 'Mcp\\Server\\Authorization\\AccessToken';

    /**
     * The access token class checked by default. A test seam only: tests point it at a class that does not
     * exist to see the server refuse an older SDK.
     */
    public static string $accessTokenClass = self::ACCESS_TOKEN;

    /**
     * Fails unless both classes exist.
     *
     * @param string $validatorInterface The SDK's token validator interface.
     * @param string|null $accessTokenClass The SDK's access token class, new in 0.9; null for
     *   `$accessTokenClass`.
     * @throws \LogicException When mcp/sdk is missing or older than 0.9.
     */
    public static function assertSupported(
        string $validatorInterface = self::VALIDATOR_INTERFACE,
        ?string $accessTokenClass = null,
    ): void {
        $accessTokenClass ??= self::$accessTokenClass;
        if (!interface_exists($validatorInterface)) {
            throw new LogicException('The MCP SDK bridge requires mcp/sdk 0.9 or newer: composer require mcp/sdk.');
        }
        if (!class_exists($accessTokenClass)) {
            throw new LogicException(
                'The MCP SDK bridge requires mcp/sdk 0.9 or newer; the installed version has no '
                . $accessTokenClass . '. Upgrade mcp/sdk.',
            );
        }
    }
}
