<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Resource;

use CakeDC\OAuth\Server\Scope\Scopes;
use InvalidArgumentException;

/**
 * Something tokens are issued for: an MCP endpoint, an API. Tokens are bound to exactly one.
 */
final class ProtectedResource
{
    /**
     * @param string $identifier Canonical URL (see ResourceIdentifier::canonicalize()).
     * @param string $name Shown on the consent and connections pages.
     * @param array<string, string> $scopes Scope name => description shown at consent.
     * @param array<string, list<string>> $implies A granted scope also grants the listed ones.
     * @param list<string> $defaultScopes Granted when a client asks for no scope.
     * @throws \InvalidArgumentException
     */
    public function __construct(
        public readonly string $identifier,
        public readonly string $name,
        public readonly array $scopes,
        public readonly array $implies = [],
        public readonly array $defaultScopes = [],
    ) {
        $canonical = ResourceIdentifier::canonicalize($identifier);
        if ($canonical !== $identifier) {
            throw new InvalidArgumentException(sprintf(
                'The resource "%s" is not canonical; use "%s".',
                $identifier,
                $canonical,
            ));
        }
        ResourceIdentifier::assertSecure($identifier, 'resource');
        if ($scopes === []) {
            throw new InvalidArgumentException(sprintf('The resource "%s" declares no scopes.', $identifier));
        }
        foreach (array_keys($scopes) as $scope) {
            $scope = (string)$scope;
            if (!Scopes::isValid($scope) || $scope === Scopes::OFFLINE_ACCESS) {
                throw new InvalidArgumentException(sprintf('"%s" is not a valid resource scope.', $scope));
            }
        }
        foreach ($implies as $scope => $implied) {
            $this->assertKnown((string)$scope);
            foreach ($implied as $one) {
                $this->assertKnown($one);
            }
        }
        foreach ($defaultScopes as $scope) {
            $this->assertKnown($scope);
        }
    }

    /**
     * Builds a resource from settings: `name`, `scopes`, `implies`, `defaultScopes`. The settings, `scopes`
     * and `implies` are maps: a list given for one of them is refused, naming it (a list of scopes would
     * declare the scopes "0", "1", ...).
     *
     * @param string $identifier The resource URL, in any spelling.
     * @param array<mixed> $config Settings, as read from a configuration file.
     * @throws \InvalidArgumentException
     */
    public static function fromArray(string $identifier, array $config): self
    {
        $identifier = ResourceIdentifier::canonicalize($identifier);
        if ($config !== [] && array_is_list($config)) {
            throw new InvalidArgumentException(sprintf(
                'The settings of the resource "%s" must map setting names to values, not a list.',
                $identifier,
            ));
        }
        $unknown = array_diff(array_keys($config), ['name', 'scopes', 'implies', 'defaultScopes']);
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf(
                'Unknown setting "%s" for the resource "%s".',
                implode('", "', $unknown),
                $identifier,
            ));
        }
        $name = $config['name'] ?? (string)parse_url($identifier, PHP_URL_HOST);
        if (!is_string($name)) {
            throw new InvalidArgumentException(sprintf('"name" of the resource "%s" must be a string.', $identifier));
        }
        $settings = ['scopes' => $config['scopes'] ?? [], 'implies' => $config['implies'] ?? []];
        $settings['defaultScopes'] = $config['defaultScopes'] ?? [];
        foreach ($settings as $key => $value) {
            if (!is_array($value)) {
                throw new InvalidArgumentException(
                    sprintf('"%s" of the resource "%s" must be an array.', $key, $identifier),
                );
            }
        }
        // A list would declare the scopes "0", "1", ...
        $maps = ['scopes' => 'scope names to descriptions', 'implies' => 'scopes to lists of scopes'];
        foreach ($maps as $key => $shape) {
            if ($settings[$key] !== [] && array_is_list($settings[$key])) {
                throw new InvalidArgumentException(
                    sprintf('"%s" of the resource "%s" must map %s, not a list.', $key, $identifier, $shape),
                );
            }
        }

        return new self(
            $identifier,
            $name,
            self::stringMap($settings['scopes'], $identifier),
            self::listMap($settings['implies'], $identifier),
            self::stringList($settings['defaultScopes'], $identifier, 'defaultScopes'),
        );
    }

    /**
     * The scope names, in declaration order.
     *
     * @return list<string>
     */
    public function scopeNames(): array
    {
        return array_map('strval', array_keys($this->scopes));
    }

    /**
     * Whether the resource declares $scope.
     */
    public function hasScope(string $scope): bool
    {
        return isset($this->scopes[$scope]);
    }

    /**
     * $scopes plus every scope they imply, transitively, without duplicates.
     *
     * @param list<string> $scopes Scopes.
     * @return list<string>
     */
    public function expand(array $scopes): array
    {
        $result = [];
        $queue = $scopes;
        while ($queue !== []) {
            $scope = array_shift($queue);
            if (in_array($scope, $result, true)) {
                continue;
            }
            $result[] = $scope;
            foreach ($this->implies[$scope] ?? [] as $implied) {
                $queue[] = $implied;
            }
        }

        return $result;
    }

    /**
     * Fails for a scope the resource does not declare.
     *
     * @param string $scope Scope.
     * @throws \InvalidArgumentException
     */
    private function assertKnown(string $scope): void
    {
        if (!$this->hasScope($scope)) {
            throw new InvalidArgumentException(sprintf(
                'The resource "%s" refers to the unknown scope "%s".',
                $this->identifier,
                $scope,
            ));
        }
    }

    /**
     * Validates a `scope => description` map.
     *
     * @param array<mixed> $value Value.
     * @param string $identifier Resource, for messages.
     * @return array<string, string>
     * @throws \InvalidArgumentException
     */
    private static function stringMap(array $value, string $identifier): array
    {
        $map = [];
        foreach ($value as $key => $description) {
            if (!is_string($description)) {
                throw new InvalidArgumentException(sprintf(
                    '"scopes" of the resource "%s" must map scope names to descriptions (strings).',
                    $identifier,
                ));
            }
            $map[(string)$key] = $description;
        }

        return $map;
    }

    /**
     * Validates a `scope => list of scopes` map.
     *
     * @param array<mixed> $value Value.
     * @param string $identifier Resource, for messages.
     * @return array<string, list<string>>
     * @throws \InvalidArgumentException
     */
    private static function listMap(array $value, string $identifier): array
    {
        $map = [];
        foreach ($value as $key => $list) {
            if (!is_array($list)) {
                throw new InvalidArgumentException(
                    sprintf('"implies" of the resource "%s" must map scopes to lists of scopes.', $identifier),
                );
            }
            $map[(string)$key] = self::stringList($list, $identifier, 'implies');
        }

        return $map;
    }

    /**
     * Validates a list of strings.
     *
     * @param array<mixed> $value Value.
     * @param string $identifier Resource, for messages.
     * @param string $setting The setting, for messages.
     * @return list<string>
     * @throws \InvalidArgumentException
     */
    private static function stringList(array $value, string $identifier, string $setting): array
    {
        $list = [];
        foreach ($value as $item) {
            if (!is_string($item)) {
                throw new InvalidArgumentException(
                    sprintf('"%s" of the resource "%s" must list scope names (strings).', $setting, $identifier),
                );
            }
            $list[] = $item;
        }

        return $list;
    }
}
