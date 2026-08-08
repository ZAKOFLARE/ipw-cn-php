<?php

declare(strict_types=1);

namespace App\Service;

use App\Cache\InFlightGuard;
use App\Config;
use App\Network\DnsClient;
use App\Network\HttpProbe;
use App\Security\Ssrf;
use App\Support\UrlHelper;
use App\Analytics\Counter;
use RuntimeException;

/**
 * 网站可达性检测：对应 Go 版 checkWebsiteHandler。
 * 输出 WebsiteCheckResult { ipv4, ipv6 }，字段与 Go 版 json tag 完全一致。
 */
final class WebsiteCheckService
{
    public const CACHE_TTL = 300; // 5 分钟
    private const FAIL_CACHE_TTL = 30; // 不可达结果短缓存（对齐 Go 版 30s 后删）

    public function __construct(private Config $config)
    {
    }

    /**
     * @param string $counterPage 统计端点标识（非空时仅"非缓存命中"的真实探测计数）
     */
    public function check(string $url, string $counterPage = ''): array
    {
        $cacheKey = 'detail:' . $url;
        return InFlightGuard::run($cacheKey, self::CACHE_TTL, function () use ($url, $cacheKey) {
            $result = $this->doCheck($url);
            if ($this->anyUnreachable($result)) {
                (new \App\Cache\FileCache())->set($cacheKey, $result, self::FAIL_CACHE_TTL);
            }
            return $result;
        }, $counterPage !== '' ? static fn () => Counter::queue($counterPage) : null);
    }

    private function doCheck(string $url): array
    {
        $host = UrlHelper::hostname($url);
        if ($host !== '' && Ssrf::hasLocalOrPrivateIp($host)) {
            return ['ipv4' => self::fakePerfect($url), 'ipv6' => self::fakePerfect($url)];
        }

        switch ($this->config->singleStack) {
            case 'ipv4':
                return [
                    'ipv4' => $this->checkOne($url, 'v4'),
                    'ipv6' => ['host_record' => 'Skipped due to SINGLE_STACK=ipv4', 'is_reachable' => false],
                ];
            case 'ipv6':
                return [
                    'ipv4' => ['host_record' => 'Skipped due to SINGLE_STACK=ipv6', 'is_reachable' => false],
                    'ipv6' => $this->checkOne($url, 'v6'),
                ];
            default:
                return [
                    'ipv4' => $this->checkOne($url, 'v4'),
                    'ipv6' => $this->checkOne($url, 'v6'),
                ];
        }
    }

    /**
     * @return array{host_record: string, http_status_code: int, https_status_code: int,
     *               dns_lookup_time: float, tcp_connect_time: float, http_connect_time: float,
     *               first_byte_time: float, total_time: float, page_size: int,
     *               download_speed: float, is_reachable: bool}
     */
    private function checkOne(string $url, string $version): array
    {
        try {
            $probe = new HttpProbe(new DnsClient($this->config->dnsServer), $version);
            $r = $probe->probe($url);
            return [
                'host_record'       => $r->hostRecord,
                'http_status_code'  => $r->httpStatusCode,
                'https_status_code' => $r->httpsStatusCode,
                'dns_lookup_time'   => $r->dnsLookupTime,
                'tcp_connect_time'  => $r->tcpConnectTime,
                'http_connect_time' => $r->httpConnectTime,
                'first_byte_time'   => $r->firstByteTime,
                'total_time'        => $r->totalTime,
                'page_size'         => $r->pageSize,
                'download_speed'    => $r->downloadSpeed,
                'is_reachable'      => $r->isReachable,
            ];
        } catch (RuntimeException $e) {
            // 对齐 Go 版失败占位（零值字段全部输出）
            return [
                'host_record'       => 'Error: ' . $e->getMessage(),
                'http_status_code'  => 0,
                'https_status_code' => 0,
                'dns_lookup_time'   => 0.0,
                'tcp_connect_time'  => 0.0,
                'http_connect_time' => 0.0,
                'first_byte_time'   => 0.0,
                'total_time'        => 0.0,
                'page_size'         => 0,
                'download_speed'    => 0.0,
                'is_reachable'      => false,
            ];
        }
    }

    private function anyUnreachable(array $result): bool
    {
        return (isset($result['ipv4']) && !$result['ipv4']['is_reachable'])
            || (isset($result['ipv6']) && !$result['ipv6']['is_reachable']);
    }

    /**
     * 私有 IP 目标返回的"完美"假结果（对应 Go 版 fakePerfectWebsiteResult）。
     */
    private static function fakePerfect(string $url): array
    {
        $cleanHost = str_replace(['https://', 'http://'], '', $url);
        return [
            'host_record'       => $cleanHost,
            'http_status_code'  => 200,
            'https_status_code' => 200,
            'dns_lookup_time'   => 0.5,
            'tcp_connect_time'  => 1.0,
            'http_connect_time' => 1.5,
            'first_byte_time'   => 2.0,
            'total_time'        => 100.0,
            'page_size'         => 52428,
            'download_speed'    => 512.0,
            'is_reachable'      => true,
        ];
    }
}
