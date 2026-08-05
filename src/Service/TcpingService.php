<?php

declare(strict_types=1);

namespace App\Service;

use App\Cache\InFlightGuard;
use App\Config;
use App\Network\TcpPinger;

/**
 * TCPing：对应 Go 版 pingHandler。
 * 输出 TCPingResult { ipv4, ipv6 }（均为 TCPingStats）。
 */
final class TcpingService
{
    public const CACHE_TTL = 60; // 1 分钟

    public function __construct(private Config $config)
    {
    }

    public function ping(string $host, int $port, int $count): array
    {
        $cacheKey = 'tcping:' . $host . ':' . $port . ':' . $count;
        return InFlightGuard::run($cacheKey, self::CACHE_TTL, fn () => $this->doPing($host, $port, $count));
    }

    private function doPing(string $host, int $port, int $count): array
    {
        $pinger = new TcpPinger();
        $portStr = (string) $port;

        switch ($this->config->singleStack) {
            case 'ipv4':
                return [
                    'ipv4' => $pinger->run($host, $portStr, $count, 'v4'),
                    'ipv6' => self::skippedStats('SINGLE_STACK=ipv4'),
                ];
            case 'ipv6':
                return [
                    'ipv4' => self::skippedStats('SINGLE_STACK=ipv6'),
                    'ipv6' => $pinger->run($host, $portStr, $count, 'v6'),
                ];
            default:
                return [
                    'ipv4' => $pinger->run($host, $portStr, $count, 'v4'),
                    'ipv6' => $pinger->run($host, $portStr, $count, 'v6'),
                ];
        }
    }

    /**
     * 单栈模式下被跳过的协议占位（对应 Go 版 "Skipped due to SINGLE_STACK=..."）。
     */
    private static function skippedStats(string $reason): array
    {
        return [
            'ip'        => 'Skipped due to ' . $reason,
            'port'      => '',
            'sent'      => 0,
            'success'   => 0,
            'loss_rate' => 0.0,
            'max_rtt'   => 0.0,
            'min_rtt'   => 0.0,
            'avg_rtt'   => 0.0,
            'results'   => null,
        ];
    }
}
