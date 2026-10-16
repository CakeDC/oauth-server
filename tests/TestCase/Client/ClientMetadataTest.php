<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client;

use CakeDC\OAuth\Server\Client\ClientMetadata;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ClientMetadataTest extends TestCase
{
    /**
     * @return array<string, array{string, bool}>
     */
    public static function names(): array
    {
        return [
            'plain' => ['Claude Code (work)', true],
            'host-like' => ['Node.js client', true],
            'japanese' => ["\u{3042}\u{3044}\u{3046}", true],
            'accented' => ["Cafe\u{0301}", true],
            'persian with a zero width non-joiner' => ["\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}", true],
            'devanagari with a zero width joiner' => ["\u{0915}\u{094D}\u{200D}\u{0937}", true],
            'emoji zwj sequence' => ["\u{1F469}\u{200D}\u{1F4BB} dev", true],
            'emoji with a variation selector' => ["\u{2764}\u{FE0F} app", true],
            'keycap' => ["1\u{FE0F}\u{20E3}", true],
            'subdivision flag' => ["\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}", true],
            'soft hyphen' => ["Auto\u{00AD}mation", true],
            'four combining marks' => ["a\u{0301}\u{0302}\u{0303}\u{0304}", true],
            'only a symbol' => ["\u{1F680}", true],
            'empty' => ['', false],
            'spaces' => ['   ', false],
            'newline' => ["a\nb", false],
            'invalid utf-8' => ["a\xff", false],
            'no-break space only' => ["\u{00A0}", false],
            'zero width space' => ["Cla\u{200B}ude", false],
            'word joiner' => ["Cla\u{2060}ude", false],
            'bom' => ["\u{FEFF}Claude", false],
            'left-to-right mark' => ["Claude\u{200E}", false],
            'right-to-left mark' => ["Claude\u{200F}", false],
            'arabic letter mark' => ["Claude\u{061C}", false],
            'embedding' => ["a\u{202A}b", false],
            'override' => ["a\u{202E}b", false],
            'isolate' => ["a\u{2066}b", false],
            'pop isolate' => ["a\u{2069}b", false],
            'line separator' => ["a\u{2028}b", false],
            'paragraph separator' => ["a\u{2029}b", false],
            'joiner at the start' => ["\u{200D}Claude", false],
            'joiner at the end' => ["Claude\u{200C}", false],
            'joiner next to a space' => ["Claude \u{200D}App", false],
            'two joiners' => ["a\u{200D}\u{200D}b", false],
            'combining grapheme joiner' => ["Cla\u{034F}ude", false],
            'only combining marks' => ["\u{0301}", false],
            'only a variation selector' => ["\u{FE0F}", false],
            'only an object replacement character' => ["\u{FFFC}", false],
            'only a musical null notehead' => ["\u{1D159}", false],
            'hangul filler' => ["Cla\u{3164}ude", false],
            'braille blank' => ["Claude\u{2800}", false],
            'variation selector after a space' => [" \u{FE0F}a", false],
            'five combining marks' => ["a\u{0301}\u{0302}\u{0303}\u{0304}\u{0305}", false],
            'zalgo' => ['Z' . str_repeat("\u{0301}\u{0316}", 20), false],
            'supplementary variation selector' => ["a\u{E0100}", false],
        ];
    }

    #[DataProvider('names')]
    public function testUsableNames(string $name, bool $usable): void
    {
        $this->assertSame($usable, ClientMetadata::isUsableName($name), bin2hex($name));
    }

    public function testLengthIsCountedInCharacters(): void
    {
        $this->assertSame(3, ClientMetadata::characterLength("\u{3042}\u{1F680}a"));
        $this->assertSame(PHP_INT_MAX, ClientMetadata::characterLength("a\xff"));
    }
}
