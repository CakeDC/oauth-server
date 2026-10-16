<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View\Html;

/**
 * Helpers of the built-in HTML pages.
 */
final class Html
{
    private const STYLE = 'body{font-family:system-ui,sans-serif;background:#f6f7f9;color:#1d2330;margin:0}'
        . 'main{max-width:42rem;margin:3rem auto;background:#fff;padding:2rem;border-radius:12px;'
        . 'box-shadow:0 1px 4px rgba(0,0,0,.08)}h1{font-size:1.4rem}.warning{background:#fff4e5;'
        . 'padding:.6rem .8rem;border-radius:8px}.muted{color:#5b6475}button{font-size:1rem;'
        . 'padding:.6rem 1.2rem;border-radius:8px;border:0;background:#1d4ed8;color:#fff;cursor:pointer}'
        . 'button.secondary{background:#e5e7eb;color:#1d2330}table{width:100%;border-collapse:collapse}'
        . 'td,th{text-align:left;padding:.4rem;border-bottom:1px solid #eee}code{word-break:break-all}'
        . 'label{display:block;margin:.4rem 0}input[type=text],input[type=number],select{padding:.4rem}';

    /**
     * Escapes text for HTML content and attributes.
     */
    public static function e(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * A whole page; $body must already be escaped.
     */
    public static function page(string $title, string $body): string
    {
        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>' . self::e($title) . '</title><style>' . self::STYLE . '</style></head>'
            . '<body><main>' . $body . '</main></body></html>';
    }
}
