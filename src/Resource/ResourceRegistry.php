<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Resource;

use InvalidArgumentException;

/**
 * The resources this server issues tokens for.
 */
final class ResourceRegistry
{
    /**
     * @var array<string, \CakeDC\OAuth\Server\Resource\ProtectedResource>
     */
    private array $resources = [];

    private string $default;

    /**
     * @param list<\CakeDC\OAuth\Server\Resource\ProtectedResource> $resources At least one.
     * @param string|null $default Identifier of the resource used when a client names none; the first by default.
     * @throws \InvalidArgumentException
     */
    public function __construct(array $resources, ?string $default = null)
    {
        if ($resources === []) {
            throw new InvalidArgumentException('Declare at least one resource.');
        }
        foreach ($resources as $resource) {
            if (isset($this->resources[$resource->identifier])) {
                throw new InvalidArgumentException(
                    sprintf('The resource "%s" is declared twice.', $resource->identifier),
                );
            }
            $this->resources[$resource->identifier] = $resource;
        }
        $default = $default === null ? $resources[0]->identifier : ResourceIdentifier::canonicalize($default);
        if (!isset($this->resources[$default])) {
            throw new InvalidArgumentException(sprintf('The default resource "%s" is not declared.', $default));
        }
        $this->default = $default;
    }

    /**
     * Builds the registry from `identifier => settings` (see ProtectedResource::fromArray()). Settings that
     * are not an array (a resource given as a name, or a list of URLs) are refused by resource.
     *
     * @param array<mixed> $config Resources.
     * @param string|null $default Default resource identifier.
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $config, ?string $default = null): self
    {
        $resources = [];
        foreach ($config as $identifier => $settings) {
            if (!is_array($settings)) {
                throw new InvalidArgumentException(sprintf(
                    'The settings of the resource "%s" must be an array like [\'name\' => ..., \'scopes\' => [...]];'
                        . ' got %s. Resources map each resource URL to its settings.',
                    $identifier,
                    get_debug_type($settings),
                ));
            }
            /** @var array<string, mixed> $settings */
            $resources[] = ProtectedResource::fromArray((string)$identifier, $settings);
        }

        return new self($resources, $default);
    }

    /**
     * The resource for $identifier in any spelling, or null.
     *
     * @param string $identifier The resource URL.
     */
    public function get(string $identifier): ?ProtectedResource
    {
        try {
            $canonical = ResourceIdentifier::canonicalize($identifier);
        } catch (InvalidArgumentException) {
            return null;
        }

        return $this->resources[$canonical] ?? null;
    }

    /**
     * The resource used when a client names none.
     */
    public function defaultResource(): ProtectedResource
    {
        return $this->resources[$this->default];
    }

    /**
     * Every resource, in declaration order.
     *
     * @return list<\CakeDC\OAuth\Server\Resource\ProtectedResource>
     */
    public function all(): array
    {
        return array_values($this->resources);
    }

    /**
     * Every scope of every resource, without duplicates.
     *
     * @return list<string>
     */
    public function allScopeNames(): array
    {
        $names = [];
        foreach ($this->resources as $resource) {
            foreach ($resource->scopeNames() as $name) {
                if (!in_array($name, $names, true)) {
                    $names[] = $name;
                }
            }
        }

        return $names;
    }
}
