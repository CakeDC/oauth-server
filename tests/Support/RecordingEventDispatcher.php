<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use Psr\EventDispatcher\EventDispatcherInterface;

class RecordingEventDispatcher implements EventDispatcherInterface
{
    /**
     * @var list<object>
     */
    public array $events = [];

    /**
     * @inheritDoc
     */
    public function dispatch(object $event): object
    {
        $this->events[] = $event;

        return $event;
    }

    /**
     * @template T of object
     * @param class-string<T> $class
     * @return list<T>
     */
    public function ofType(string $class): array
    {
        return array_values(array_filter($this->events, fn(object $e): bool => $e instanceof $class));
    }
}
