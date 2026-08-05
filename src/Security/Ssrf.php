<?php

declare(strict_types=1);

namespace App\Security;

use App\Network\DnsClient;
use RuntimeException;

/**
 * SSRF 防护：完整移植 Go 版 ssrf 包的逻辑。
 *  1. scheme 白名单（仅 http/https）
 *  2. 主机名 DNS 解析（指定 DNS 服务器）
 *  3. 私有/内网 IP 拦截（RFC1918/回环/链路本地/未指定）
 *  4. 重定向链逐跳校验
 */
final class Ssrf
{
    private static bool $enabled = true;
    private static ?DnsClient $dns = null;

    public static function setEnabled(bool $enabled): void
    {
        self::$enabled = $enabled;
    }

    public static function enabled(): bool
    {
        return self::$enabled;
    }

    public static function setDnsClient(DnsClient $dns): void
    {
        self::$dns = $dns;
    }

    /**
     * 判断 IP 是否属于私有/内部地址段。
     */
    public static function isPrivateIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        return filter_var($ip, FILTER_VALIDATE_IP, $flags) === false;
    }

    /**
     * 判断主机名是否解析到任何私有 IP（对应 Go 版 HasLocalOrPrivateIP）。
     * 解析失败时返回 false（与 Go 版 net.LookupIP err 时返回 false 一致）。
     */
    public static function hasLocalOrPrivateIp(string $host): bool
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return self::isPrivateIp($host);
        }
        foreach (self::resolveHost($host) as $ip) {
            if (self::isPrivateIp($ip)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 出站目标校验：scheme 白名单 + DNS 解析 + 私有 IP 拦截。
     * 校验失败抛出异常（对应 Go 版 ValidateOutboundTarget 返回 error）。
     */
    public static function assertSafeUrl(string $url): void
    {
        if (!self::$enabled) {
            return;
        }
        $parts = parse_url($url);
        if ($parts === false || empty($parts['host'])) {
            throw new RuntimeException('empty host');
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new RuntimeException("invalid scheme: {$scheme}");
        }
        $host = $parts['host'];
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            if (self::isPrivateIp($host)) {
                throw new RuntimeException('request to private/internal address is not allowed');
            }
            return;
        }
        foreach (self::resolveHost($host) as $ip) {
            if (self::isPrivateIp($ip)) {
                throw new RuntimeException('request to private/internal address is not allowed');
            }
        }
    }

    /**
     * 重定向目标校验（对应 Go 版 SecureCheckRedirect）。
     */
    public static function assertSafeRedirectTarget(string $url): void
    {
        self::assertSafeUrl($url);
    }

    /**
     * 解析主机名所有 IP（A + AAAA）。解析全部失败时返回空数组。
     *
     * @return string[]
     */
    private static function resolveHost(string $host): array
    {
        if (self::$dns === null) {
            self::$dns = new DnsClient();
        }
        return self::$dns->resolveAll($host);
    }
}
