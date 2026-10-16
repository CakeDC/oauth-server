<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

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
        $parts = preg_match(MetadataDocumentFetcher::URL_CHARACTERS, $url) === 1 ? parse_url($url) : false;
        if (
            !is_array($parts)
            || isset($parts['user'])
            || isset($parts['pass'])
            || strtolower($parts['scheme'] ?? '') !== 'https'
            || !isset($parts['host'])
        ) {
            throw new RuntimeException('Only https URLs are fetched.');
        }
        $handle = curl_init();
        if ($handle === false) {
            throw new RuntimeException('curl could not start.');
        }
        $host = trim($parts['host'], '[]');
        $pinned = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        $body = '';
        $headers = [];
        $tooLarge = false;
        curl_setopt_array($handle, [
            CURLOPT_URL => $url,
            CURLOPT_RESOLVE => [sprintf('%s:%d:%s', $host, $parts['port'] ?? 443, $pinned)],
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_USERAGENT => 'cakedc-oauth-server',
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$headers): int {
                if (str_contains($line, ':')) {
                    [$name, $value] = explode(':', $line, 2);
                    $headers[strtolower(trim($name))] = trim($value);
                }

                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body, &$tooLarge, $maxBytes): int {
                if (strlen($body) + strlen($chunk) > $maxBytes) {
                    $tooLarge = true;

                    return 0;
                }
                $body .= $chunk;

                return strlen($chunk);
            },
        ]);
        $result = curl_exec($handle);
        $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        unset($handle);
        if ($tooLarge) {
            throw new RuntimeException(sprintf('The document is larger than %d bytes.', $maxBytes));
        }
        if ($result === false) {
            throw new RuntimeException($error !== '' ? $error : 'The request failed.');
        }

        return new FetchedResponse($status, $headers, $body);
    }
}
