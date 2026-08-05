<?php

declare(strict_types=1);

namespace App\Network;

use RuntimeException;

/**
 * DNS 客户端：通过 UDP 直连指定 DNS 服务器，构造/解析 DNS 报文。
 * 对应 Go 版 webtest/dns.go（基于 miekg/dns），返回结构一致：
 *   { domain, record[], ttl, duration }
 */
final class DnsClient
{
    public const TYPE_MAP = [
        'A'    => 1,
        'NS'   => 2,
        'CNAME'=> 5,
        'PTR'  => 12,
        'MX'   => 15,
        'TXT'  => 16,
        'AAAA' => 28,
        'SRV'  => 33,
        'CAA'  => 257,
    ];

    private string $serverIp;
    private int $serverPort;
    private float $timeout;

    public function __construct(string $server = '119.28.28.28:53', float $timeout = 3.0)
    {
        $parts = explode(':', $server, 2);
        $this->serverIp = trim($parts[0], '[]');
        $this->serverPort = isset($parts[1]) ? (int) $parts[1] : 53;
        $this->timeout = $timeout;
    }

    /**
     * 查询指定记录类型。
     *
     * @return array{domain: string, record: string[], ttl: int, duration: float}
     */
    public function query(string $domain, string $type): array
    {
        $qtype = self::TYPE_MAP[strtoupper($type)] ?? null;
        if ($qtype === null) {
            throw new RuntimeException("unsupported record type: {$type}");
        }
        if ($qtype === self::TYPE_MAP['PTR']) {
            $original = $domain;
            $domain = self::reverseAddr($domain);
            if ($domain === '') {
                throw new RuntimeException("invalid IP address: {$original}");
            }
        }

        $start = microtime(true);
        $packet = $this->buildQuery($domain, $qtype);
        $response = $this->exchange($packet);
        $duration = round((microtime(true) - $start) * 1000, 3);

        [$record, $ttl] = $this->parseResponse($response, $qtype, $domain);

        return [
            'domain'   => $domain,
            'record'   => $record,
            'ttl'      => $ttl,
            'duration' => $duration,
        ];
    }

    /**
     * 解析主机名所有地址（A + AAAA 合并），供 SSRF 校验使用。
     *
     * @return string[]
     */
    public function resolveAll(string $host): array
    {
        $ips = [];
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }
        foreach (['A', 'AAAA'] as $type) {
            try {
                $r = $this->query($host, $type);
                foreach ($r['record'] as $ip) {
                    $ips[] = $ip;
                }
            } catch (RuntimeException) {
                // 某协议族解析失败不影响另一个
            }
        }
        return $ips;
    }

    /**
     * 构造 DNS 查询报文。
     */
    private function buildQuery(string $domain, int $qtype): string
    {
        $id = random_int(0, 0xFFFF);
        $header = pack('n6', $id, 0x0100, 1, 0, 0, 0);
        $name = $this->encodeName($domain);
        $question = $name . pack('n2', $qtype, 1);
        return $header . $question;
    }

    /**
     * 编码域名（labels + 终止 0）。
     */
    private function encodeName(string $domain): string
    {
        $domain = rtrim($domain, '.');
        if ($domain === '' || strlen($domain) > 253) {
            throw new RuntimeException('invalid domain name');
        }
        $out = '';
        foreach (explode('.', $domain) as $label) {
            $len = strlen($label);
            if ($len === 0 || $len > 63) {
                throw new RuntimeException('invalid domain label');
            }
            $out .= chr($len) . $label;
        }
        return $out . "\x00";
    }

    /**
     * 发送 UDP 报文并接收响应。
     */
    private function exchange(string $packet): string
    {
        $sock = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($sock === false) {
            throw new RuntimeException('failed to create UDP socket: ' . socket_strerror(socket_last_error()));
        }

        $sec = (int) floor($this->timeout);
        $usec = (int) (($this->timeout - $sec) * 1_000_000);
        @socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, ['sec' => $sec, 'usec' => $usec]);
        @socket_set_option($sock, SOL_SOCKET, SO_SNDTIMEO, ['sec' => $sec, 'usec' => $usec]);

        if (!@socket_connect($sock, $this->serverIp, $this->serverPort)) {
            $err = socket_strerror(socket_last_error($sock));
            socket_close($sock);
            throw new RuntimeException("DNS connect failed: {$err}");
        }

        if (@socket_write($sock, $packet) === false) {
            $err = socket_strerror(socket_last_error($sock));
            socket_close($sock);
            throw new RuntimeException("DNS send failed: {$err}");
        }

        $buf = '';
        $n = @socket_recv($sock, $buf, 4096, 0);
        socket_close($sock);
        if ($n === false || $n < 12) {
            throw new RuntimeException('DNS query timed out');
        }

        return $buf;
    }

    /**
     * 解析 DNS 响应，返回 [records, ttl]。
     *
     * @return array{0: string[], 1: int}
     */
    private function parseResponse(string $msg, int $qtype, string $domain): array
    {
        // Header: ID(2) Flags(2) QD(2) AN(2) NS(2) AR(2)
        $flags = unpack('n', substr($msg, 2, 2))[1];
        $rcode = $flags & 0x0F;
        if ($rcode !== 0) {
            throw new RuntimeException("DNS query failed with Rcode {$rcode}");
        }
        $qdCount = unpack('n', substr($msg, 4, 2))[1];
        $anCount = unpack('n', substr($msg, 6, 2))[1];

        $offset = 12;
        // 跳过 Question 段
        for ($i = 0; $i < $qdCount; $i++) {
            $offset = $this->skipName($msg, $offset);
            $offset += 4; // QTYPE + QCLASS
        }

        $records = [];
        $ttl = 0;
        for ($i = 0; $i < $anCount; $i++) {
            $offset = $this->skipName($msg, $offset);
            if ($offset + 10 > strlen($msg)) {
                break;
            }
            $fields = unpack('ntype/nclass/Nttl/nrdlen', substr($msg, $offset, 10));
            $offset += 10;
            $type = $fields['type'];
            $rdlen = $fields['rdlen'];
            if ($offset + $rdlen > strlen($msg)) {
                break;
            }
            $rdata = substr($msg, $offset, $rdlen);
            $offset += $rdlen;

            if ($type !== $qtype) {
                continue;
            }
            if ($ttl === 0) {
                $ttl = $fields['ttl'];
            }
            $rdataOffset = $offset - $rdlen; // RDATA 在整条消息中的绝对偏移
            $value = $this->parseRdata($msg, $type, $rdata, $rdataOffset);
            if ($value !== null) {
                $records[] = $value;
            }
        }

        return [$records, $ttl];
    }

    /**
     * 解析单条 RDATA，返回记录值字符串；不适用时返回 null。
     *
     * @param string $rdata       RDATA 字节
     * @param int    $rdataOffset RDATA 在消息中的绝对偏移（含指针的名字需要它）
     */
    private function parseRdata(string $msg, int $type, string $rdata, int $rdataOffset): ?string
    {
        switch ($type) {
            case 1:  // A
                return strlen($rdata) === 4 ? inet_ntop($rdata) : null;
            case 28: // AAAA
                return strlen($rdata) === 16 ? inet_ntop($rdata) : null;
            case 2:  // NS
            case 5:  // CNAME
            case 12: // PTR
                $rel = $rdataOffset;
                return $this->decodeName($msg, $rel);
            case 15: // MX: preference(2) + exchange
                $rel = $rdataOffset + 2;
                return $this->decodeName($msg, $rel);
            case 16: // TXT: 多个 length-prefixed 字符串
                $out = [];
                $pos = 0;
                $len = strlen($rdata);
                while ($pos < $len) {
                    $l = ord($rdata[$pos]);
                    $pos++;
                    if ($pos + $l <= $len) {
                        $out[] = substr($rdata, $pos, $l);
                        $pos += $l;
                    } else {
                        break;
                    }
                }
                return $out === [] ? null : implode('', $out);
            case 33: // SRV: priority(2) weight(2) port(2) + target
                $rel = $rdataOffset + 6;
                return $this->decodeName($msg, $rel);
            case 257: // CAA: flags(1) taglen(1) tag + value
                if (strlen($rdata) < 2) {
                    return null;
                }
                $tagLen = ord($rdata[1]);
                return substr($rdata, 2 + $tagLen);
            default:
                return null;
        }
    }

    /**
     * 跳过名字（跳过起始偏移，返回下一个偏移）。指针处理。
     */
    private function skipName(string $msg, int $offset): int
    {
        $len = strlen($msg);
        $hops = 0;
        while ($offset < $len) {
            $b = ord($msg[$offset]);
            if ($b === 0) {
                return $offset + 1;
            }
            if (($b & 0xC0) === 0xC0) {
                return $offset + 2;
            }
            if (($b & 0xC0) !== 0) {
                break; // 保留位，异常
            }
            $offset += 1 + $b;
            $hops++;
            if ($hops > 128) {
                break;
            }
        }
        return $offset;
    }

    /**
     * 从消息中解码名字（支持压缩指针）。$offset 为引用，读取后前移。
     * 指针的跳转位置以 12 字节 header 为基址计算（DNS 压缩规范）。
     */
    private function decodeName(string $msg, int &$offset): string
    {
        $labels = [];
        $len = strlen($msg);
        $hops = 0;
        $pos = $offset;
        $jumped = false;

        while ($pos < $len) {
            $b = ord($msg[$pos]);
            if ($b === 0) {
                $pos++;
                break;
            }
            if (($b & 0xC0) === 0xC0) {
                if ($pos + 1 >= $len) {
                    break;
                }
                $pointer = (($b & 0x3F) << 8) | ord($msg[$pos + 1]);
                if (!$jumped) {
                    $offset = $pos + 2; // 记录游标前移（消费掉指针本身）
                    $jumped = true;
                }
                $pos = $pointer;
                $hops++;
                if ($hops > 128) {
                    return implode('.', $labels);
                }
                continue;
            }
            if (($b & 0xC0) !== 0) {
                break;
            }
            $pos++;
            if ($pos + $b > $len) {
                break;
            }
            $labels[] = substr($msg, $pos, $b);
            $pos += $b;
        }

        if (!$jumped) {
            $offset = $pos;
        }
        return implode('.', $labels);
    }

    /**
     * IP → PTR 反向域名（对应 Go 版 dns.ReverseAddr）。
     */
    public static function reverseAddr(string $ip): string
    {
        $filtered = filter_var($ip, FILTER_VALIDATE_IP);
        if ($filtered === false) {
            return '';
        }
        $parts = explode(':', $ip);
        if (count($parts) > 1) {
            $expanded = inet_pton($ip);
            $hex = bin2hex($expanded);
            return implode('.', array_reverse(str_split($hex))) . '.ip6.arpa.';
        }
        $octets = array_reverse(explode('.', $ip));
        return implode('.', $octets) . '.in-addr.arpa.';
    }
}
