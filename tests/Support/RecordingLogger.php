<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use LogicException;
use Psr\Log\AbstractLogger;
use Stringable;
use Throwable;

class RecordingLogger extends AbstractLogger
{
    /**
     * @var list<array{0: mixed, 1: string, 2: array<mixed>}>
     */
    public array $records = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = [$level, (string)$message, $context];
    }

    /**
     * Everything logged, messages and context, as one string to search.
     */
    public function text(): string
    {
        return (string)json_encode(array_map(
            fn(array $r): array => [$r[1], array_map($this->render(...), $r[2])],
            $this->records,
        ));
    }

    /**
     * A Throwable renders as its class and message; any other object is a bug (it could carry a request,
     * a token or a secret into a log), so it fails the test loudly.
     */
    private function render(mixed $value): mixed
    {
        if ($value instanceof Throwable) {
            return $value::class . ': ' . $value->getMessage();
        }
        if (is_object($value)) {
            throw new LogicException('An object of ' . $value::class . ' was logged.');
        }
        if (is_array($value)) {
            return array_map($this->render(...), $value);
        }

        return $value;
    }
}
