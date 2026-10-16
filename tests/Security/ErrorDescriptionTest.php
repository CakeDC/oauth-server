<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\ValidationFailure;
use InvalidArgumentException;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * RFC 6749 sections 4.1.2.1 and 5.2, and RFC 6750 section 3: `error_description` may only contain
 * %x20-21 / %x23-5B / %x5D-7E. No double quote, no backslash, nothing outside printable ASCII, whatever
 * the request contained.
 */
class ErrorDescriptionTest extends TestCase
{
    private const ALLOWED = '/\A[\x20\x21\x23-\x5B\x5D-\x7E]*\z/';

    /**
     * Calls whose argument at the given position is an error description.
     */
    private const DESCRIPTION_ARGUMENT = [
        'OAuthException::' => 0,
        'new OAuthException' => 1,
        'new self' => 1,
        'new ValidationFailure' => 0,
        '->challenge' => 2,
    ];

    /**
     * Every string literal of the description argument of every OAuth error the library builds.
     *
     * @return array<string, array{string}>
     */
    public static function literalDescriptions(): array
    {
        $found = [];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__, 2) . '/src'));
        foreach ($files as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }
            $tokens = token_get_all((string)file_get_contents($file->getPathname()));
            $relative = substr($file->getPathname(), strlen(dirname(__DIR__, 2)) + 1);
            foreach (self::descriptionLiterals($tokens) as [$line, $literal]) {
                $found[$relative . ':' . $line . ' ' . substr($literal, 0, 40)] = [$literal];
            }
        }

        return $found;
    }

    /**
     * @param list<mixed> $tokens
     * @return list<array{int, string}>
     */
    private static function descriptionLiterals(array $tokens): array
    {
        $literals = [];
        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            $position = self::callAt($tokens, $i);
            if ($position === null) {
                continue;
            }
            [$open, $argument] = $position;
            $depth = 0;
            $current = 0;
            for ($j = $open; $j < $count; $j++) {
                $token = $tokens[$j];
                if ($token === '(' || $token === '[') {
                    $depth++;
                } elseif ($token === ')' || $token === ']') {
                    $depth--;
                    if ($depth === 0) {
                        break;
                    }
                } elseif ($token === ',' && $depth === 1) {
                    $current++;
                } elseif (
                    $current === $argument
                    && is_array($token)
                    && $token[0] === T_CONSTANT_ENCAPSED_STRING
                ) {
                    $literals[] = [$token[2], self::decode($token[1])];
                }
            }
        }

        return $literals;
    }

    /**
     * The opening parenthesis and the description argument of a call starting at $i, or null.
     *
     * @param list<mixed> $tokens
     * @return array{int, int}|null
     */
    private static function callAt(array $tokens, int $i): ?array
    {
        $text = fn(int $k): string => is_array($tokens[$k] ?? null) ? $tokens[$k][1] : (string)($tokens[$k] ?? '');
        $next = function (int $k) use ($tokens): int {
            do {
                $k++;
            } while (is_array($tokens[$k] ?? null) && $tokens[$k][0] === T_WHITESPACE);

            return $k;
        };
        if ($text($i) === 'OAuthException' && $text($next($i)) === '::') {
            $open = $next($next($next($i)));

            return $text($open) === '(' && $text($next($open)) !== '...' ? [$open, 0] : null;
        }
        if (is_array($tokens[$i]) && $tokens[$i][0] === T_NEW) {
            $class = $next($i);
            $key = 'new ' . $text($class);
            $open = $next($class);
            if (isset(self::DESCRIPTION_ARGUMENT[$key]) && $text($open) === '(') {
                return [$open, self::DESCRIPTION_ARGUMENT[$key]];
            }
        }
        if ($text($i) === '->' && $text($next($i)) === 'challenge') {
            $open = $next($next($i));

            return $text($open) === '(' ? [$open, self::DESCRIPTION_ARGUMENT['->challenge']] : null;
        }

        return null;
    }

    private static function decode(string $literal): string
    {
        $body = substr($literal, 1, -1);

        return $literal[0] === "'" ? str_replace(["\\'", '\\\\'], ["'", '\\'], $body) : stripcslashes($body);
    }

    public function testTheScanFindsTheLibrarysMessages(): void
    {
        $literals = array_column(self::literalDescriptions(), 0);

        $this->assertGreaterThan(80, count($literals));
        $this->assertContains('The authorization code expired.', $literals);
        $this->assertContains('A bearer token is required.', $literals);
        $this->assertContains('The access token is invalid.', $literals);
        $this->assertContains('A valid initial access token is required.', $literals);
    }

    #[DataProvider('literalDescriptions')]
    public function testEveryLiteralDescriptionIsInTheRfcCharacterSet(string $literal): void
    {
        $this->assertMatchesRegularExpression(self::ALLOWED, $literal);
    }

    public function testValidationFailureRefusesAnInvalidDescription(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ValidationFailure('The "token" is bad.');
    }

    /**
     * Values from the request that end up in a description (a grant type, a parameter name, a scope) are
     * made printable, so the endpoints never fail on them and never echo a forbidden character.
     */
    public function testHostileRequestValuesNeverBreakTheCharacterSet(): void
    {
        $hostile = "x\"y\\z\u{00E9}\n";
        $harness = new ServerHarness();
        $client = $harness->registeredClient();
        $tokens = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));
        $token = 'https://example.com/oauth/token';
        $harness->users->clientIdentity = new ResourceOwner('service:import', 'Import', null, SubjectType::Client);
        $responses = [
            'grant type' => $harness->server->tokenHandler()->handle(
                $harness->form($token, ['grant_type' => $hostile, 'client_id' => $client->clientId]),
            ),
            'repeated name' => $harness->server->tokenHandler()->handle($harness->request(
                'POST',
                $token,
                ['Content-Type' => 'application/x-www-form-urlencoded'],
                'x%22%5C%C3%A9=1&x%22%5C%C3%A9=2',
            )),
            'refresh scope' => $harness->server->tokenHandler()->handle($harness->form($token, [
                'grant_type' => 'refresh_token',
                'refresh_token' => $tokens['refresh_token'],
                'client_id' => $client->clientId,
                'scope' => $hostile,
            ])),
            'revoke repeated name' => $harness->server->revokeHandler()->handle($harness->request(
                'POST',
                'https://example.com/oauth/revoke',
                ['Content-Type' => 'application/x-www-form-urlencoded'],
                'a%22b=1&a%22b=2',
            )),
            'client_credentials scope' => $harness->server->tokenHandler()->handle($harness->form($token, [
                'grant_type' => 'client_credentials',
                'client_id' => $harness->confidentialClient('s3cret', ['grantTypes' => ['client_credentials']])->clientId,
                'client_secret' => 's3cret',
                'scope' => $hostile,
            ])),
        ];
        $registrations = [
            'grant_types' => ['redirect_uris' => ['https://app.example.com/cb'], 'grant_types' => [$hostile]],
            'scope' => ['redirect_uris' => ['https://app.example.com/cb'], 'scope' => $hostile],
            'application_type' => ['redirect_uris' => ['https://app.example.com/cb'], 'application_type' => $hostile],
            'auth method' => ['redirect_uris' => ['https://app.example.com/cb'], 'token_endpoint_auth_method' => 'x'],
            'response_types' => ['redirect_uris' => ['https://app.example.com/cb'], 'response_types' => ['token']],
            'web loopback' => ['redirect_uris' => ['http://127.0.0.1/cb'], 'application_type' => 'web'],
            'redirect uri' => ['redirect_uris' => [$hostile]],
        ];
        foreach ($registrations as $name => $metadata) {
            $responses['register ' . $name] = $harness->server->registerHandler()->handle($harness->request(
                'POST',
                'https://example.com/oauth/register',
                ['Content-Type' => 'application/json'],
                (string)json_encode($metadata),
            ));
        }
        $harness->signIn();
        $authorizations = [
            'scope' => ['scope' => 'content:read ' . $hostile],
            'unknown scope' => ['scope' => 'content:nothing'],
            'response_type' => ['response_type' => 'token'],
            'challenge' => ['code_challenge' => null],
            'challenge method' => ['code_challenge_method' => 'plain'],
            'resource' => ['resource' => 'https://elsewhere.example/'],
        ];
        foreach ($authorizations as $name => $params) {
            $responses['authorize ' . $name] = $harness->server->authorizeHandler()->handle(
                $harness->request('GET', $harness->authorizeUrl($client, $params)),
            );
        }
        $next = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200);
            }
        };
        foreach (['Bearer a"b', 'Bearer ' . $tokens['refresh_token'], 'Bearer ' . $tokens['access_token']] as $header) {
            $responses['bearer ' . $header] = $harness->server->bearerMiddleware(Fixtures::MCP, null, ['content:publish'])
                ->process($harness->request('GET', Fixtures::MCP, ['Authorization' => $header]), $next);
        }

        $described = 0;
        foreach ($responses as $name => $response) {
            $this->assertLessThan(500, $response->getStatusCode(), $name);
            foreach ($this->descriptions($response) as $description) {
                $described++;
                $this->assertMatchesRegularExpression(self::ALLOWED, $description, $name);
            }
        }
        $this->assertGreaterThanOrEqual(count($responses), $described);
    }

    public function testAPersonalTokenScopeFromTheFormIsMadePrintable(): void
    {
        $harness = new ServerHarness();

        try {
            $harness->server->connectionService()->createPersonalToken(
                $harness->users->users['42'],
                'Deploy',
                Fixtures::MCP,
                ["x\"\u{00E9}"],
                7,
            );
            $this->fail('An unknown scope was granted.');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_scope', $e->error);
            $this->assertMatchesRegularExpression(self::ALLOWED, $e->getMessage());
        }
    }

    /**
     * Every error_description of a response: JSON body, redirect query and WWW-Authenticate challenge.
     *
     * @return list<string>
     */
    private function descriptions(ResponseInterface $response): array
    {
        $found = [];
        $json = json_decode((string)$response->getBody(), true);
        if (is_array($json) && isset($json['error_description'])) {
            $found[] = (string)$json['error_description'];
        }
        $location = $response->getHeaderLine('Location');
        if ($location !== '') {
            $params = ServerHarness::redirectParams($response);
            if (isset($params['error_description'])) {
                $found[] = $params['error_description'];
            }
        }
        $challenge = $response->getHeaderLine('WWW-Authenticate');
        if (preg_match('/error_description="((?:[^"\\\\]|\\\\.)*)"/', $challenge, $matches) === 1) {
            $found[] = (string)preg_replace('/\\\\(.)/', '$1', $matches[1]);
        }
        $html = (string)$response->getBody();
        if ($found === [] && str_contains($response->getHeaderLine('Content-Type'), 'text/html')) {
            // The error page of an untrusted redirect carries the redirect URL in its link.
            if (preg_match('/href="([^"]+)"/', $html, $matches) === 1) {
                parse_str((string)parse_url(html_entity_decode($matches[1]), PHP_URL_QUERY), $params);
                if (isset($params['error_description']) && is_string($params['error_description'])) {
                    $found[] = $params['error_description'];
                }
            }
        }

        return $found;
    }
}
