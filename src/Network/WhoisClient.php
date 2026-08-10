<?php

declare(strict_types=1);

namespace App\Network;

use App\Config;
use App\Security\Ssrf;
use RuntimeException;

/**
 * WHOIS 协议客户端：对应 Go 版 webtest/whois.go 的查询链路。
 *
 * 流程：
 *  1. 按 TLD 从内置映射找 whois 服务器，未命中则查 IANA（whois.iana.org）发现；
 *  2. TCP 43 端口发送 "domain\r\n" 读取原始响应；
 *  3. 主查询失败 → 用 DnsClient 解析服务器 IP（v4/v6，SSRF 私网过滤）逐个尝试；
 *  4. 响应含 "Registrar WHOIS Server" 且指向其他服务器时做一次 referral 跟随。
 */
final class WhoisClient
{
    private const PORT = 43;
    private const TIMEOUT = 10; // 秒，对齐 Go whoisConnectTimeout

    /** 内置 TLD → WHOIS 服务器（对齐 Go tldWhoisServers） */
    private const TLD_SERVERS = [
        'com'    => 'whois.verisign-grs.com',
        'net'    => 'whois.verisign-grs.com',
        'org'    => 'whois.pir.org',
        'info'   => 'whois.afilias.net',
        'biz'    => 'whois.neulevel.biz',
        'name'   => 'whois.nic.name',
        'pro'    => 'whois.registrypro.pro',
        'io'     => 'whois.nic.io',
        'co'     => 'whois.nic.co',
        'me'     => 'whois.nic.me',
        'cc'     => 'whois.nic.cc',
        'tv'     => 'whois.nic.tv',
        'top'    => 'whois.nic.top',
        'xyz'    => 'whois.nic.xyz',
        'club'   => 'whois.nic.club',
        'online' => 'whois.nic.online',
        'site'   => 'whois.nic.site',
        'store'  => 'whois.nic.store',
        'shop'   => 'whois.nic.shop',
        'app'    => 'whois.nic.google',
        'dev'    => 'whois.nic.google',
        'tech'   => 'whois.nic.tech',
        'cn'     => 'whois.cnnic.cn',
        'wang'   => 'whois.gtld.knet.cn',
        'ren'    => 'whois.renren.us',
    ];

    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * 查询域名的 WHOIS 原始数据。
     *
     * @return array{raw: string, server: string, error: string}
     */
    public function query(string $domain): array
    {
        $server = '';
        try {
            $server = $this->resolveWhoisServer($domain);
            $raw = $this->rawQuery($server, $domain);
        } catch (RuntimeException $e) {
            // 主查询失败 → 手动解析 IP fallback
            try {
                $server = $this->resolveWhoisServer($domain);
                $raw = $this->fallbackQuery($server, $domain);
            } catch (RuntimeException $e2) {
                return ['raw' => '', 'server' => $server, 'error' => $e2->getMessage()];
            }
        }

        // Referral 跟随（增强，超出 Go 单次查询）：仅当响应数据不足
        // （无 Name Server 且无 Domain Status，常见于注册局对注册商数据的"拒绝式"精简响应）
        // 才向 Registrar WHOIS Server 二次查询；数据完整的响应不跟随。
        $referral = self::extractReferralServer($raw);
        if ($referral !== null && strcasecmp($referral, $server) !== 0 && !self::hasEnoughData($raw)) {
            try {
                $followed = $this->rawQuery($referral, $domain);
                if (self::hasEnoughData($followed)) {
                    $raw = $followed;
                    $server = $referral;
                }
            } catch (RuntimeException) {
                // 跟随失败保留首次响应
            }
        }

        return ['raw' => $raw, 'server' => $server, 'error' => ''];
    }

    /**
     * 解析域名对应的 whois 服务器（内置映射 → IANA 发现）。
     */
    private function resolveWhoisServer(string $domain): string
    {
        $ext = self::getExtension($domain);
        if (isset(self::TLD_SERVERS[$ext]) && self::TLD_SERVERS[$ext] !== '') {
            return self::TLD_SERVERS[$ext];
        }

        // IANA 发现：查询 whois.iana.org 的 ".ext"
        $iana = $this->rawQuery('whois.iana.org', '.' . $ext);
        $server = self::extractWhoisServer($iana);
        if ($server === '') {
            throw new RuntimeException("no whois server found in IANA response for .{$ext}");
        }
        return $server;
    }

    /**
     * TCP 43 查询（直连服务器域名，系统解析）。
     */
    private function rawQuery(string $server, string $domain): string
    {
        $fp = @stream_socket_client("tcp://{$server}:" . self::PORT, $errno, $errstr, self::TIMEOUT);
        if ($fp === false) {
            throw new RuntimeException("whois connect to {$server} failed: " . ($errstr !== '' ? $errstr : 'timeout'));
        }
        stream_set_timeout($fp, self::TIMEOUT);
        @fwrite($fp, $domain . "\r\n");

        $raw = '';
        while (!feof($fp)) {
            $chunk = @fread($fp, 8192);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $raw .= $chunk;
            if (strlen($raw) >= 65536) {
                break;
            }
        }
        fclose($fp);
        return $raw;
    }

    /**
     * 主查询失败后的 fallback：DnsClient 解析服务器 IP（v4/v6，SSRF 过滤）逐个尝试。
     */
    private function fallbackQuery(string $server, string $domain): string
    {
        $dns = new DnsClient($this->config->dnsServer);
        $ips = array_values(array_filter(
            $dns->resolveAll($server),
            static fn (string $ip): bool => !Ssrf::enabled() || !Ssrf::isPrivateIp($ip)
        ));
        if ($ips === []) {
            throw new RuntimeException("no reachable public IPs for {$server} after SSRF filter");
        }

        $lastErr = '';
        // v4/v6 交错尝试，最多 4 个（对齐 Go Happy Eyeballs 的取优语义）
        $candidates = [];
        $v4 = array_values(array_filter($ips, static fn (string $ip): bool => !str_contains($ip, ':')));
        $v6 = array_values(array_filter($ips, static fn (string $ip): bool => str_contains($ip, ':')));
        for ($i = 0; $i < max(count($v4), count($v6)); $i++) {
            if (isset($v4[$i])) {
                $candidates[] = $v4[$i];
            }
            if (isset($v6[$i])) {
                $candidates[] = $v6[$i];
            }
        }

        foreach (array_slice($candidates, 0, 4) as $ip) {
            try {
                $fp = @stream_socket_client("tcp://{$ip}:" . self::PORT, $errno, $errstr, self::TIMEOUT);
                if ($fp === false) {
                    $lastErr = $errstr !== '' ? $errstr : 'timeout';
                    continue;
                }
                stream_set_timeout($fp, self::TIMEOUT);
                @fwrite($fp, $domain . "\r\n");
                $raw = '';
                while (!feof($fp)) {
                    $chunk = @fread($fp, 8192);
                    if ($chunk === false || $chunk === '') {
                        break;
                    }
                    $raw .= $chunk;
                    if (strlen($raw) >= 65536) {
                        break;
                    }
                }
                fclose($fp);
                if ($raw !== '') {
                    return $raw;
                }
                $lastErr = 'empty response';
            } catch (RuntimeException $e) {
                $lastErr = $e->getMessage();
            }
        }

        throw new RuntimeException($lastErr !== '' ? $lastErr : 'all WHOIS connection attempts failed');
    }

    /**
     * 提取域名后缀。
     */
    public static function getExtension(string $domain): string
    {
        $parts = explode('.', $domain);
        if (count($parts) >= 2) {
            return strtolower(end($parts));
        }
        return strtolower($domain);
    }

    /**
     * 从 IANA 响应中提取 whois 服务器地址（对齐 Go extractWhoisServer）。
     */
    public static function extractWhoisServer(string $data): string
    {
        foreach (['whois: ', 'Whois: '] as $token) {
            $idx = strpos($data, $token);
            if ($idx !== false) {
                $start = $idx + strlen($token);
                $end = strpos($data, "\n", $start);
                if ($end === false) {
                    $end = strlen($data);
                }
                $server = trim(substr($data, $start, $end - $start));
                $server = preg_replace('#^https?://#i', '', $server) ?? $server;
                $server = preg_replace('#^whois://#i', '', $server) ?? $server;
                return rtrim($server, '/');
            }
        }
        return '';
    }

    /**
     * 从原始响应中提取 Referral WHOIS 服务器。
     */
    private static function extractReferralServer(string $raw): ?string
    {
        foreach (explode("\n", $raw) as $line) {
            $line = trim($line);
            if (preg_match('/^Registrar\s+WHOIS\s+Server\s*:\s*(\S+)\s*$/i', $line, $m) === 1) {
                $server = trim($m[1], '.');
                return $server !== '' ? $server : null;
            }
        }
        return null;
    }

    /**
     * 判断响应是否包含足够的 WHOIS 数据（有 Name Server 或 Domain Status 视为完整）。
     */
    private static function hasEnoughData(string $raw): bool
    {
        $hasNs = preg_match('/^Name\s+Server\s*:/im', $raw) === 1;
        $hasStatus = preg_match('/^Domain\s+Status\s*:/im', $raw) === 1;
        return $hasNs || $hasStatus;
    }
}
