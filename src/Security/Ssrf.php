<?php

declare(strict_types=1);

namespace App\Security;

use App\Network\DnsClient;
use App\Network\ReqResolve;
use RuntimeException;

/**
 * SSRF 防护：完整移植 Go 版 ssrf 包的逻辑。
 *  1. scheme 白名单（仅 http/https）
 *  2. 主机名 DNS 解析（请求级 dns* 优先，其次默认服务器）
 *  3. 私有/内网 IP 拦截（RFC1918/回环/链路本地/未指定）
 *  4. 重定向链逐跳校验
 *
 * 请求级配置（dns* / resolve*）由 ApiController 在每次请求开始时注入，
 * 保证预检校验的是「拨号真正会连的地址」——对应 Go 版 InstallSSRFResolver
 * 把 webtest 的解析器接进 ssrf 的动机（预检与拨号同源）。
 */
final class Ssrf
{
    private static bool $enabled = true;
    /** 配置侧 dns-server（逗号分隔，支持 DoH） */
    private static string $defaultServers = '119.28.28.28:53';
    /** 本次请求的解析配置；null = 无覆盖 */
    private static ?ReqResolve $reqResolve = null;

    public static function setEnabled(bool $enabled): void
    {
        self::$enabled = $enabled;
    }

    public static function enabled(): bool
    {
        return self::$enabled;
    }

    /**
     * 设置默认 DNS 服务器（配置 dns-server）。
     */
    public static function setDefaultServers(string $servers): void
    {
        self::$defaultServers = $servers;
    }

    /**
     * 注入本次请求的解析配置（空配置 = 无覆盖）。
     */
    public static function setRequestResolve(ReqResolve $req): void
    {
        self::$reqResolve = $req;
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
        $clean = trim($host, '[]');
        if (filter_var($clean, FILTER_VALIDATE_IP) !== false) {
            return self::isPrivateIp($clean);
        }
        foreach (self::resolveHost($clean) as $ip) {
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
        $host = trim((string) $parts['host'], '[]');
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
     * 解析主机名所有 IP（A + AAAA），带请求级解析配置。
     *
     * 与 Go 版 InstallSSRFResolver 一致：A / AAAA 都查（任一命中私网即拦）；
     * 「是否私网」的判定必须落在 resolve* 改写后的目标上。
     * 解析全部失败返回空数组（原版语义：不因此直接拦截，交由拨号阶段暴露）。
     *
     * @return string[]
     */
    private static function resolveHost(string $host): array
    {
        $req = self::$reqResolve ?? ReqResolve::none();
        $ips = [];

        foreach ([false, true] as $wantV6) {
            $name = $host;
            $target = $req->override($name, $wantV6);
            if ($target !== '') {
                $name = trim($target, '[]');
            }
            if (filter_var($name, FILTER_VALIDATE_IP) !== false) {
                $ips[] = $name;
                continue;
            }

            $servers = $req->servers($wantV6 ? 'ipv6' : 'ipv4');
            $dns = new DnsClient($servers !== [] ? $servers : self::$defaultServers);
            try {
                $result = $dns->query($name, $wantV6 ? 'AAAA' : 'A');
                foreach ($result['record'] as $ip) {
                    if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                        $ips[] = $ip;
                    }
                }
            } catch (RuntimeException) {
                // 某协议族解析失败不影响另一个
            }
        }

        return $ips;
    }
}
