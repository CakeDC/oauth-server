<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Bridge\McpSdk;

use CakeDC\OAuth\Server\Bridge\McpSdk\SdkRequirement;
use CakeDC\OAuth\Server\Bridge\McpSdk\TokenValidator;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use LogicException;
use PHPUnit\Framework\TestCase;

/**
 * The bridge needs mcp/sdk 0.9 or newer: 0.8 has the validator interface but no `AccessToken`, and its
 * `AuthorizationResult::allow()` takes an array, so every valid token would end in a TypeError.
 */
class SdkRequirementTest extends TestCase
{
    public function testTheInstalledSdkIsSupported(): void
    {
        SdkRequirement::assertSupported();

        $this->assertInstanceOf(
            TokenValidator::class,
            (new ServerHarness())->server->mcpTokenValidator(Fixtures::MCP),
        );
    }

    public function testAnSdkWithoutAccessTokenIsRefusedWithTheMinimumVersion(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('mcp/sdk 0.9');

        SdkRequirement::assertSupported(accessTokenClass: 'Mcp\\Server\\Authorization\\NoSuchAccessToken');
    }

    /**
     * The server and the bridge's constructor run the check: with mcp/sdk 0.8 (no AccessToken class) the
     * validator is never built.
     */
    public function testTheServerRefusesToBuildTheBridgeOnAnOlderSdk(): void
    {
        $harness = new ServerHarness();
        SdkRequirement::$accessTokenClass = 'Mcp\\Server\\Authorization\\NoSuchAccessToken';
        try {
            foreach (
                [
                    fn() => $harness->server->mcpTokenValidator(Fixtures::MCP),
                    fn() => new TokenValidator($harness->server->tokenValidator(), Fixtures::MCP),
                ] as $build
            ) {
                try {
                    $build();
                    $this->fail('The bridge was built on an SDK without AccessToken.');
                } catch (LogicException $e) {
                    $this->assertStringContainsString('mcp/sdk 0.9 or newer', $e->getMessage());
                }
            }
        } finally {
            SdkRequirement::$accessTokenClass = SdkRequirement::ACCESS_TOKEN;
        }
    }

    public function testAMissingSdkIsRefusedWithTheMinimumVersion(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('mcp/sdk 0.9');

        SdkRequirement::assertSupported(validatorInterface: 'Mcp\\Server\\NoSuchValidatorInterface');
    }
}
