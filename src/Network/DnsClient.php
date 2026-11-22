<?php

declare(strict_types=1);

namespace App\Network;

use RuntimeException;

/**
 * DNS 客户端：构造/解析 DNS 报文，向指定服务器查询。
 * 对应 Go 版 webtest/dns.go（基于 miekg/dns），返回结构一致：
 *   { domain, record[], ttl, duration }
 *
 * 服务器列表支持主从 failover：每项为 "ip:port"（UDP，IPv6 写 [addr]:port）
 * 或 http(s):// DoH URL（RFC 8484 POST）；前一台失败自动切换下一台。
 */
final class DnsClient
{
    public const TYPE_MAP = [
        'A'      => 1,
        'NS'     => 2,
        'CNAME'  => 5,
        'PTR'    => 12,
        'MX'     => 15,
        'TXT'    => 16,
        'AAAA'   => 28,
        'SRV'    => 33,
        'DS'     => 43,
        'RRSIG'  => 46,
        'DNSKEY' => 48,
        'CAA'    => 257,
    ];

    private const DEFAULT_SERVER = '119.28.28.28:53';

    /** @var string[] 服务器列表（ip:port 或 DoH URL），按主从顺序尝试 */
    private array $servers;
    private float $timeout;

    /**
     * @param string|string[] $servers 逗号分隔串或已切分的列表；
     *                                 每项为 "ip:port"（UDP，IPv6 写 [addr]:port）或 http(s):// DoH URL。
     *                                 非法项丢弃，全非法时回退默认服务器（对齐 Go 版 validServers 语义）。
     */
    public function __construct(string|array $servers = self::DEFAULT_SERVER, float $timeout = 3.0)
    {
        $raw = is_array($servers) ? $servers : explode(',', $servers);
        $valid = [];
        foreach ($raw as $item) {
            $item = trim((string) $item);
            if ($item !== '' && ReqResolve::validServerAddr($item)) {
                $valid[] = $item;
            }
        }
        $this->servers = $valid === [] ? [self::DEFAULT_SERVER] : $valid;
        $this->timeout = $timeout;
    }

    /**
     * 当前生效的服务器列表（主从顺序）。
     *
     * @return string[]
     */
    public function servers(): array
    {
        return $this->servers;
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
     * 原始查询（DNSSEC 专用）：带 EDNS0 DO 位，返回所有 answer 记录的原始字节，
     * 供 DnssecVerifier 解析 DNSKEY/RRSIG/DS 并重建签名数据流。
     *
     * @return array{rcode: int, answers: array<int, array{type: int, rdata: string, rdataOffset: int}>, msg: string, duration: float}
     */
    public function queryRaw(string $domain, int $qtype): array
    {
        $start = microtime(true);
        $packet = $this->buildQueryEdns($domain, $qtype);
        $response = $this->exchange($packet);
        $duration = round((microtime(true) - $start) * 1000, 3);

        $flags = unpack('n', substr($response, 2, 2))[1];
        $rcode = $flags & 0x0F;

        return [
            'rcode'    => $rcode,
            'answers'  => $this->parseRawAnswers($response),
            'msg'      => $response,
            'duration' => $duration,
        ];
    }

    /**
     * 构造带 EDNS0 OPT（DO 位）的查询报文。
     */
    private function buildQueryEdns(string $domain, int $qtype): string
    {
        $id = random_int(0, 0xFFFF);
        // ARCOUNT=1：附加 OPT 伪记录
        $header = pack('n6', $id, 0x0100, 1, 0, 0, 1);
        $question = $this->encodeName($domain) . pack('n2', $qtype, 1);
        // NAME=root(0x00), TYPE=OPT(41), CLASS=payload(4096), TTL: DO bit=0x8000, RDLEN=0
        $opt = "\x00" . pack('n', 41) . pack('n', 4096) . pack('N', 0x8000) . pack('n', 0);
        return $header . $question . $opt;
    }

    /**
     * 解析响应中的所有 answer 记录（保留原始 rdata 字节与偏移，供压缩指针解码）。
     *
     * @return array<int, array{type: int, rdata: string, rdataOffset: int}>
     */
    private function parseRawAnswers(string $msg): array
    {
        $qdCount = unpack('n', substr($msg, 4, 2))[1];
        $anCount = unpack('n', substr($msg, 6, 2))[1];

        $offset = 12;
        for ($i = 0; $i < $qdCount; $i++) {
            $offset = $this->skipName($msg, $offset);
            $offset += 4;
        }

        $answers = [];
        for ($i = 0; $i < $anCount; $i++) {
            $offset = $this->skipName($msg, $offset);
            if ($offset + 10 > strlen($msg)) {
                break;
            }
            $fields = unpack('ntype/nclass/Nttl/nrdlen', substr($msg, $offset, 10));
            $offset += 10;
            $rdlen = $fields['rdlen'];
            if ($offset + $rdlen > strlen($msg)) {
                break;
            }
            $answers[] = [
                'type'        => $fields['type'],
                'rdata'       => substr($msg, $offset, $rdlen),
                'rdataOffset' => $offset,
            ];
            $offset += $rdlen;
        }

        return $answers;
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
     * 发送报文并接收响应：按主从顺序尝试，前一台失败自动切换下一台
     * （对应 Go 版 queryWithServers）。
     */
    private function exchange(string $packet): string
    {
        $lastError = 'DNS query failed';
        foreach ($this->servers as $server) {
            try {
                return $this->exchangeOne($packet, $server);
            } catch (RuntimeException $e) {
                $lastError = $e->getMessage();
            }
        }
        throw new RuntimeException($lastError);
    }

    /**
     * 向单台服务器查询：DoH URL 走 HTTP POST，其余走 UDP。
     */
    private function exchangeOne(string $packet, string $server): string
    {
        if (str_starts_with($server, 'http://') || str_starts_with($server, 'https://')) {
            return $this->exchangeDoH($packet, $server);
        }
        return $this->exchangeUdp($packet, $server);
    }

    /**
     * DoH（RFC 8484，POST application/dns-message）。
     *
     * 刻意不做私网/回环拦截：endpoint 可来自 dns-server 配置或请求级 dns=，
     * 节点上自建内网 DoH（127.0.0.1 / 10.x）是合理部署，堵私网会直接打死功能
     * （与 Go 版 queryDoHMsg 的取舍一致）。
     */
    private function exchangeDoH(string $packet, string $endpoint): string
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $endpoint,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $packet,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/dns-message',
                'Accept: application/dns-message',
            ],
        ]);
        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($errno !== 0) {
            throw new RuntimeException('DoH request failed: ' . ($error !== '' ? $error : "curl error {$errno}"));
        }
        if ($status !== 200) {
            throw new RuntimeException("DoH API returned status {$status}");
        }
        if (!is_string($body) || strlen($body) < 12) {
            throw new RuntimeException('DoH response too short');
        }

        return $body;
    }

    /**
     * UDP 查询单台服务器（支持 IPv4 / IPv6；IPv6 服务器须写成 [addr]:port）。
     */
    private function exchangeUdp(string $packet, string $server): string
    {
        $endpoint = ReqResolve::splitHostPort($server);
        if ($endpoint === null) {
            throw new RuntimeException("invalid DNS server: {$server}");
        }
        [$host, $port] = $endpoint;

        $isV6 = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            // 主机名形式：先解析成 IP（Go 的 net.Dial 会做同样的事）
            $resolved = gethostbyname($host);
            if ($resolved === $host) {
                throw new RuntimeException("cannot resolve DNS server {$host}");
            }
            $host = $resolved;
            $isV6 = false;
        }

        $sock = @socket_create($isV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($sock === false) {
            throw new RuntimeException('failed to create UDP socket: ' . socket_strerror(socket_last_error()));
        }

        $sec = (int) floor($this->timeout);
        $usec = (int) (($this->timeout - $sec) * 1_000_000);
        @socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, ['sec' => $sec, 'usec' => $usec]);
        @socket_set_option($sock, SOL_SOCKET, SO_SNDTIMEO, ['sec' => $sec, 'usec' => $usec]);

        if (!@socket_connect($sock, $host, $port)) {
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
    public function decodeName(string $msg, int &$offset): string
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
