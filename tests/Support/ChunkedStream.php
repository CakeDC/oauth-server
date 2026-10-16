<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * A non-seekable stream that hands out at most 100 bytes per read.
 */
final class ChunkedStream implements StreamInterface
{
    private int $position = 0;

    /**
     * @param string $data The content.
     */
    public function __construct(private readonly string $data)
    {
    }

    /**
     * @inheritDoc
     */
    public function __toString(): string
    {
        return substr($this->data, $this->position);
    }

    /**
     * @inheritDoc
     */
    public function close(): void
    {
    }

    /**
     * @inheritDoc
     */
    public function detach()
    {
        return null;
    }

    /**
     * @inheritDoc
     */
    public function getSize(): ?int
    {
        return null;
    }

    /**
     * @inheritDoc
     */
    public function tell(): int
    {
        return $this->position;
    }

    /**
     * @inheritDoc
     */
    public function eof(): bool
    {
        return $this->position >= strlen($this->data);
    }

    /**
     * @inheritDoc
     */
    public function isSeekable(): bool
    {
        return false;
    }

    /**
     * @inheritDoc
     */
    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new RuntimeException('Not seekable.');
    }

    /**
     * @inheritDoc
     */
    public function rewind(): void
    {
        throw new RuntimeException('Not seekable.');
    }

    /**
     * @inheritDoc
     */
    public function isWritable(): bool
    {
        return false;
    }

    /**
     * @inheritDoc
     */
    public function write(string $string): int
    {
        throw new RuntimeException('Not writable.');
    }

    /**
     * @inheritDoc
     */
    public function isReadable(): bool
    {
        return true;
    }

    /**
     * @inheritDoc
     */
    public function read(int $length): string
    {
        $chunk = substr($this->data, $this->position, min($length, 100));
        $this->position += strlen($chunk);

        return $chunk;
    }

    /**
     * @inheritDoc
     */
    public function getContents(): string
    {
        return $this->__toString();
    }

    /**
     * @inheritDoc
     */
    public function getMetadata(?string $key = null)
    {
        return $key === null ? [] : null;
    }
}
