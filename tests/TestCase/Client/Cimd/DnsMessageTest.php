<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client\Cimd;

use CakeDC\OAuth\Server\Client\Cimd\DnsMessage;
use CakeDC\OAuth\Server\Client\Cimd\DnsReply;
use CakeDC\OAuth\Server\Test\Support\DnsPackets;
use PHPUnit\Framework\TestCase;

class DnsMessageTest extends TestCase
{
    public function testAQueryAsksOneQuestionWithRecursion(): void
    {
        $query = DnsMessage::query(0x1234, 'client.example', DnsPackets::AAAA);

        $this->assertSame(
            pack('nnnnnn', 0x1234, 0x0100, 1, 0, 0, 0) . DnsPackets::name('client.example') . pack('nn', 28, 1),
            $query,
        );
    }

    public function testReadsTheAddressesOfTheAnswer(): void
    {
        $packet = DnsPackets::response(7, 'client.example', DnsPackets::A, [
            ['client.example', DnsPackets::A, '93.184.216.34'],
            ['client.example', DnsPackets::A, '93.184.216.35'],
        ]);

        $reply = DnsMessage::read($packet, 7, 'client.example', DnsPackets::A);

        $this->assertSame(DnsReply::ANSWER, $reply->status);
        $this->assertSame(['93.184.216.34', '93.184.216.35'], $reply->addresses);
    }

    public function testFollowsACnameChainInTheAnswer(): void
    {
        $packet = DnsPackets::response(7, 'client.example', DnsPackets::AAAA, [
            ['edge.cdn.example', DnsPackets::AAAA, '2606:2800:220:1::1'],
            ['client.example', DnsPackets::CNAME, 'www.client.example'],
            ['www.client.example', DnsPackets::CNAME, 'edge.cdn.example'],
        ]);

        $reply = DnsMessage::read($packet, 7, 'client.example', DnsPackets::AAAA);

        $this->assertSame(['2606:2800:220:1::1'], $reply->addresses);
    }

    public function testIgnoresRecordsOutsideTheChainAndOfOtherTypes(): void
    {
        $packet = DnsPackets::response(7, 'client.example', DnsPackets::A, [
            ['other.example', DnsPackets::A, '10.0.0.1'],
            ['client.example', DnsPackets::AAAA, '2606:2800:220:1::1'],
            ['client.example', DnsPackets::A, '93.184.216.34'],
        ]);

        $this->assertSame(['93.184.216.34'], DnsMessage::read($packet, 7, 'client.example', DnsPackets::A)->addresses);
    }

    public function testANameWithoutRecordsIsAnEmptyAnswer(): void
    {
        $reply = DnsMessage::read(DnsPackets::response(7, 'client.example', DnsPackets::A), 7, 'client.example', DnsPackets::A);

        $this->assertSame(DnsReply::ANSWER, $reply->status);
        $this->assertSame([], $reply->addresses);
    }

    public function testNxdomainSaysTheNameDoesNotExist(): void
    {
        $packet = DnsPackets::response(7, 'client.example', DnsPackets::A, [], 3);

        $this->assertSame(DnsReply::NO_NAME, DnsMessage::read($packet, 7, 'client.example', DnsPackets::A)->status);
    }

    public function testOtherResponseCodesAreFailures(): void
    {
        foreach ([1, 2, 4, 5] as $rcode) {
            $packet = DnsPackets::response(7, 'client.example', DnsPackets::A, [], $rcode);

            $this->assertSame(DnsReply::FAILED, DnsMessage::read($packet, 7, 'client.example', DnsPackets::A)->status);
        }
    }

    public function testATruncatedAnswerAsksForTcp(): void
    {
        $packet = DnsPackets::response(7, 'client.example', DnsPackets::A, [], 0, true);

        $this->assertSame(DnsReply::TRUNCATED, DnsMessage::read($packet, 7, 'client.example', DnsPackets::A)->status);
    }

    /**
     * A packet that does not answer this query (another id, another question, a query instead of a
     * response) is ignored: it may be a late answer or a spoofing attempt.
     */
    public function testIgnoresPacketsThatDoNotAnswerTheQuery(): void
    {
        $answer = [['client.example', DnsPackets::A, '93.184.216.34']];
        $foreign = [
            DnsPackets::response(8, 'client.example', DnsPackets::A, $answer),
            DnsPackets::response(7, 'other.example', DnsPackets::A, [['other.example', DnsPackets::A, '93.184.216.34']]),
            DnsPackets::response(7, 'client.example', DnsPackets::AAAA),
            DnsMessage::query(7, 'client.example', DnsPackets::A),
            'short',
        ];

        foreach ($foreign as $packet) {
            $this->assertSame(DnsReply::IGNORED, DnsMessage::read($packet, 7, 'client.example', DnsPackets::A)->status);
        }
    }

    public function testTheQuestionIsMatchedCaseInsensitively(): void
    {
        $packet = DnsPackets::response(7, 'Client.EXAMPLE', DnsPackets::A, [['Client.EXAMPLE', DnsPackets::A, '93.184.216.34']]);

        $this->assertSame(['93.184.216.34'], DnsMessage::read($packet, 7, 'client.example', DnsPackets::A)->addresses);
    }

    public function testMalformedAnswersAreFailures(): void
    {
        $valid = DnsPackets::response(7, 'client.example', DnsPackets::A, [['client.example', DnsPackets::A, '93.184.216.34']]);
        $header = substr($valid, 0, 12);
        $question = DnsPackets::name('client.example') . pack('nn', 1, 1);
        $malformed = [
            'cut in the record' => substr($valid, 0, -2),
            'pointer loop' => $header . $question . "\xC0\x20" . pack('nnNn', 1, 1, 300, 4) . "\x5d\xb8\xd8\x22",
            'pointer beyond the packet' => $header . $question . "\xC1\xFF" . pack('nnNn', 1, 1, 300, 4) . "\x5d\xb8\xd8\x22",
            'A record of 5 bytes' => $header . $question . "\xC0\x0C" . pack('nnNn', 1, 1, 300, 5) . "\x5d\xb8\xd8\x22\x00",
        ];

        foreach ($malformed as $case => $packet) {
            $this->assertSame(DnsReply::FAILED, DnsMessage::read($packet, 7, 'client.example', DnsPackets::A)->status, $case);
        }
    }
}
