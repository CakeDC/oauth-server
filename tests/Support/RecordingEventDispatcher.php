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
     * Called with every event before it is recorded; lets a test interleave another request.
     *
     * @var (callable(object): void)|null
     */
    public $hook = null;

    /**
     * @inheritDoc
     */
    public function dispatch(object $event): object
    {
        $this->events[] = $event;
        if ($this->hook !== null) {
            ($this->hook)($event);
        }

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
