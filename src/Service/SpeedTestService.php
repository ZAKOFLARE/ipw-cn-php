<?php

declare(strict_types=1);

namespace App\Service;

use App\Cache\InFlightGuard;
use App\Config;
use App\Network\DnsClient;
use App\Network\HttpProbe;
use App\Analytics\Counter;
use RuntimeException;

/**
 * 网站测速：对应 Go 版 websiteSpeedTestHandler / websiteSpeed。
 * 输出 WebsiteSpeedTestResult（含原始响应头）。
 */
final class SpeedTestService
{
    public const CACHE_TTL = 60; // 1 分钟

    public function __construct(private Config $config)
    {
    }

    /**
     * @param string $counterPage 统计端点标识（非空时仅"非缓存命中"的真实探测计数）
     */
    public function test(string $url, string $version, string $counterPage = ''): array
    {
        $cacheKey = 'speed:' . $url . ':' . $version;
        return InFlightGuard::run(
            $cacheKey,
            self::CACHE_TTL,
            fn () => $this->doTest($url, $version),
            $counterPage !== '' ? static fn () => Counter::queue($counterPage) : null
        );
    }

    private function doTest(string $url, string $version): array
    {
        try {
            $probe = new HttpProbe(new DnsClient($this->config->dnsServer), $version);
            $r = $probe->probe($url);
            return [
                'version'           => $version,
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
                'message'           => '',
                'headers'           => $r->headers,
                'is_reachable'      => $r->isReachable,
            ];
        } catch (RuntimeException $e) {
            return [
                'version'           => $version,
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
                'message'           => '',
                'headers'           => '',
                'is_reachable'      => false,
            ];
        }
    }
}
