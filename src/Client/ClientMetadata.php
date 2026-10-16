<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

use CakeDC\OAuth\Server\Support\HostName;

/**
 * Checks of the display fields of client metadata (names and URLs), shared by every way a client is created.
 *
 * @internal Not part of the public API: it may change in any 1.x release.
 */
final class ClientMetadata
{
    /**
     * Characters that draw nothing or alter nothing visible, which a name could use to look different
     * from what it is: the combining grapheme joiner, Hangul and Khmer fillers, Mongolian free variation
     * selectors (including U+180F), the braille blank, the halfwidth Hangul filler, the object replacement
     * character, the musical null notehead, and the unassigned default-ignorable code points
     * (U+2065, U+FFF0 to U+FFF8, U+E0000, U+E0002 to U+E001F, U+E0080 to U+E0FFF).
     */
    /**
     * The three RGI emoji tag sequences (subdivision flags): U+1F3F4, the tag characters spelling `gbeng`,
     * `gbsct` or `gbwls`, and the cancel tag U+E007F (England, Scotland, Wales). They are the only sequences
     * that keep tag characters: any other one, however short, can spell a hidden text.
     */
    private const RGI_FLAG = '/(\x{1F3F4})\x{E0067}\x{E0062}'
        . '(?:\x{E0065}\x{E006E}\x{E0067}|\x{E0073}\x{E0063}\x{E0074}|\x{E0077}\x{E006C}\x{E0073})\x{E007F}/u';

    private const INVISIBLE = '/[\x{034F}\x{115F}\x{1160}\x{17B4}\x{17B5}\x{180B}-\x{180F}\x{2065}\x{2800}'
        . '\x{3164}\x{FFA0}\x{FFF0}-\x{FFF8}\x{FFFC}\x{1D159}\x{E0000}\x{E0002}-\x{E001F}'
        . '\x{E0080}-\x{E0FFF}]/u';

    /**
     * Whether $name is usable as a display name. It must be valid UTF-8 and contain a letter, number,
     * punctuation or symbol. It must not contain control characters, line or paragraph separators, bidirectional
     * controls or any other format character (`Cf`), nor characters that draw nothing (fillers, a lone
     * combining grapheme joiner, the object replacement character, unassigned default-ignorable code points)
     * or runs of more than four combining marks (format characters between the marks do not break a run).
     * Allowed although they are format characters: the soft hyphen, the tag characters of the three RGI
     * subdivision flags (England, Scotland, Wales; every other tag character is refused, because a tag
     * sequence spells ASCII invisibly), and U+200C and U+200D between two visible characters (Persian, Indic
     * scripts, emoji sequences). Variation selectors are allowed after a letter, number, punctuation or
     * symbol.
     */
    public static function isUsableName(string $name): bool
    {
        // Tag characters are an ASCII-smuggling carrier: only the three RGI flags keep them.
        $work = preg_replace(self::RGI_FLAG, '$1', $name);
        if ($work === null || preg_match('/\p{Cc}|\p{Zl}|\p{Zp}/u', $work) !== 0) {
            return false;
        }
        // Every format character except the soft hyphen and the joiners checked below.
        if (preg_match('/(?![\x{00AD}\x{200C}\x{200D}])\p{Cf}/u', $work) !== 0) {
            return false;
        }
        if (preg_match(self::INVISIBLE, $work) !== 0) {
            return false;
        }
        $rest = preg_replace(
            [
                '/(?<=[^\p{Z}\p{C}])[\x{200C}\x{200D}](?=[^\p{Z}\p{C}])/u',
                '/(?<=[\p{L}\p{N}\p{P}\p{S}])[\x{FE00}-\x{FE0F}]/u',
            ],
            '',
            $work,
        );
        if ($rest === null || preg_match('/[\x{200C}\x{200D}\x{FE00}-\x{FE0F}]/u', $rest) !== 0) {
            return false;
        }
        $drawn = preg_replace('/\p{Cf}/u', '', $work);

        return $drawn !== null
            && preg_match('/\p{M}{5,}/u', $drawn) === 0
            && preg_match('/[\p{L}\p{N}\p{P}\p{S}]/u', $work) === 1;
    }

    /**
     * The length of $name in characters, not bytes; a string that is not valid UTF-8 is infinitely long.
     */
    public static function characterLength(string $name): int
    {
        $length = preg_match_all('/./su', $name);

        return $length === false ? PHP_INT_MAX : $length;
    }

    /**
     * Whether $url is a plain https URL: RFC 3986 characters only, no user information, a strict host name or
     * IP literal. This is a syntax check for display: the server never fetches these URLs, and renderers
     * must still escape them.
     */
    public static function isDisplayableHttpsUrl(string $url): bool
    {
        if (strlen($url) > 2000 || preg_match(RedirectUriMatcher::URI_CHARACTERS, $url) !== 1) {
            return false;
        }
        $parts = parse_url($url);
        if (!is_array($parts) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        $host = $parts['host'] ?? '';

        return strtolower($parts['scheme'] ?? '') === 'https' && HostName::isValid($host);
    }
}
