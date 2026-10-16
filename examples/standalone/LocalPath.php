<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Example;

/**
 * Keeps a post-login redirect on this site.
 */
final class LocalPath
{
    /**
     * The path when it is a plain local one, otherwise "/".
     *
     * A single leading slash, no "//" or "/\" start, and no control character or backslash anywhere
     * (browsers drop tabs and newlines, so "/<TAB>/host" would become "//host").
     */
    public static function orHome(string $path): string
    {
        return preg_match('#\A/(?![/\\\\])[^\x00-\x1F\x7F\\\\]*\z#', $path) === 1 ? $path : '/';
    }
}
