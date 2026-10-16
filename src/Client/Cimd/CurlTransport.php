<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

use CakeDC\OAuth\Server\Support\HostName;
use Closure;
use RuntimeException;

/**
 * Fetches over https with curl, pinned to an address that was already checked.
 */
final class CurlTransport implements HttpTransportInterface
{
    /**
     * @inheritDoc
     */
    public function get(string $url, string $ip, int $timeout, int $maxBytes): FetchedResponse
    {
        $options = $this->options($url, $ip, $timeout);
        $handle = curl_init();
        if ($handle === false) {
            throw new RuntimeException('curl could not start.');
        }
        $body = '';
        $headers = [];
        $tooLarge = false;
        $options[CURLOPT_WRITEFUNCTION] = self::writer($maxBytes, $body, $tooLarge);
        $options[CURLOPT_HEADERFUNCTION] = static function ($curl, string $line) use (&$headers): int {
            if (str_contains($line, ':')) {
                [$name, $value] = explode(':', $line, 2);
                $headers[strtolower(trim($name))] = trim($value);
            }

            return strlen($line);
        };
        if (!curl_setopt_array($handle, $options)) {
            throw new RuntimeException('curl could not be configured.');
        }
        $result = curl_exec($handle);
        $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        $primary = (string)curl_getinfo($handle, CURLINFO_PRIMARY_IP);
        unset($handle);
        if ($tooLarge) {
            throw new RuntimeException(sprintf('The document is larger than %d bytes.', $maxBytes));
        }
        if ($result === false) {
            throw new RuntimeException($error !== '' ? $error : 'The request failed.');
        }
        if (!self::sameAddress($primary, $ip)) {
            throw new RuntimeException('The connection did not go to the validated address.');
        }

        return new FetchedResponse($status, $headers, $body);
    }

    /**
     * The curl options for fetching $url pinned to $ip (without the callbacks).
     *
     * @internal
     * @return array<int, mixed>
     * @throws \RuntimeException When $url is not a clean https URL.
     */
    public function options(string $url, string $ip, int $timeout): array
    {
        $parts = preg_match(MetadataDocumentFetcher::URL_CHARACTERS, $url) === 1 ? parse_url($url) : false;
        if (
            !is_array($parts)
            || isset($parts['user'])
            || isset($parts['pass'])
            || strtolower($parts['scheme'] ?? '') !== 'https'
            || !isset($parts['host'])
            || !HostName::isValid($parts['host'])
            || filter_var($ip, FILTER_VALIDATE_IP) === false
        ) {
            throw new RuntimeException('Only https URLs are fetched.');
        }
        $host = trim($parts['host'], '[]');
        $port = $parts['port'] ?? 443;
        $pinned = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;

        return [
            CURLOPT_URL => $url,
            CURLOPT_RESOLVE => [sprintf('%s:%d:%s', $host, $port, $pinned)],
            CURLOPT_CONNECT_TO => [sprintf('::%s:%d', $pinned, $port)],
            CURLOPT_PROXY => '',
            CURLOPT_NOPROXY => '*',
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_USERAGENT => 'cakedc-oauth-server',
        ];
    }

    /**
     * A write callback collecting into $body and refusing (returning 0) beyond $maxBytes.
     *
     * @internal
     */
    public static function writer(int $maxBytes, string &$body, bool &$tooLarge): Closure
    {
        return static function ($curl, string $chunk) use (&$body, &$tooLarge, $maxBytes): int {
            if (strlen($body) + strlen($chunk) > $maxBytes) {
                $tooLarge = true;

                return 0;
            }
            $body .= $chunk;

            return strlen($chunk);
        };
    }

    /**
     * Whether two textual IP addresses are the same address.
     */
    private static function sameAddress(string $a, string $b): bool
    {
        $a = inet_pton($a);
        $b = inet_pton($b);

        return $a !== false && $b !== false && $a === $b;
    }
}
