<?php

declare(strict_types=1);

namespace App\Network;

use App\Security\Ssrf;
use RuntimeException;

/**
 * TCPing：对应 Go 版 webtest/tcping.go。
 * 使用非阻塞 socket + socket_select 实现带超时的连接计时。
 * 返回结构与 Go 版 TCPingStats / TCPingResult 一致。
 */
final class TcpPinger
{
    private float $timeoutMs;
    private float $intervalMs;

    public function __construct(float $timeoutMs = 10_000, float $intervalMs = 100)
    {
        $this->timeoutMs = $timeoutMs;
        $this->intervalMs = $intervalMs;
    }

    /**
     * 解析主机为指定协议族的 IP（v4 → A 记录，v6 → AAAA 记录），并做 SSRF 校验。
     */
    private function resolveHost(string $host, string $version): string
    {
        $clean = trim($host, '[]');
        if (filter_var($clean, FILTER_VALIDATE_IP) !== false) {
            $ip = $clean;
            if ($version === 'v4' && str_contains($ip, ':')) {
                throw new RuntimeException("host {$host} is not a v4 address");
            }
            if ($version === 'v6' && !str_contains($ip, ':')) {
                throw new RuntimeException("host {$host} is not a v6 address");
            }
        } else {
            $dns = new DnsClient();
            $type = $version === 'v6' ? 'AAAA' : 'A';
            $result = $dns->query($host, $type);
            if ($result['record'] === []) {
                throw new RuntimeException("no {$version} address found for {$host}");
            }
            $ip = $result['record'][0];
        }

        if (Ssrf::enabled() && Ssrf::isPrivateIp($ip)) {
            throw new RuntimeException("connection to private/internal address {$ip} is not allowed");
        }

        return $ip;
    }

    /**
     * 单次 TCP 连接测试。
     *
     * @return array{ip: string, port: string, success: bool, rtt: float, error: string, timestamp: string}
     */
    public function ping(string $host, string $port, string $version): array
    {
        $timestamp = date('c');
        try {
            $ip = $this->resolveHost($host, $version);
        } catch (RuntimeException $e) {
            return [
                'ip'        => 'Error: ' . $e->getMessage(),
                'port'      => $port,
                'success'   => false,
                'rtt'       => -1,
                'error'     => $e->getMessage(),
                'timestamp' => $timestamp,
            ];
        }

        $domain = AF_INET;
        if ($version === 'v6') {
            $domain = AF_INET6;
        }

        $sock = @socket_create($domain, SOCK_STREAM, SOL_TCP);
        if ($sock === false) {
            return $this->errorResult($ip, $port, $timestamp, 'socket create failed');
        }
        @socket_set_nonblock($sock);

        $start = microtime(true);
        $ok = @socket_connect($sock, $ip, (int) $port);
        $rtt = -1.0;
        $error = '';
        $success = false;

        if ($ok) {
            $success = true;
            $rtt = round((microtime(true) - $start) * 1000, 3);
        } else {
            $errno = socket_last_error($sock);
            // 非阻塞 connect 立即返回 false + WSAEWOULDBLOCK(Windows)/EINPROGRESS(Unix)，等待可写
            if (in_array($errno, [SOCKET_EINPROGRESS, SOCKET_EALREADY, SOCKET_EINVAL, SOCKET_EWOULDBLOCK], true)) {
                $w = [$sock];
                $r = null;
                $e = null;
                $sec = (int) floor($this->timeoutMs / 1000);
                $usec = (int) (($this->timeoutMs - $sec * 1000) * 1000);
                $sel = @socket_select($r, $w, $e, $sec, $usec);
                if ($sel === 1) {
                    $soError = @socket_get_option($sock, SOL_SOCKET, SO_ERROR);
                    if ($soError === 0) {
                        // 连接成功
                        $success = true;
                        $rtt = round((microtime(true) - $start) * 1000, 3);
                    } elseif ($soError === false) {
                        // Windows: SO_ERROR 查询不可用，用"二次 connect"判定：
                        // 已连接的 socket 再 connect 会返回 WSAEISCONN（10056）
                        $retry = @socket_connect($sock, $ip, (int) $port);
                        $err2 = socket_last_error($sock);
                        if ($retry === true || $err2 === SOCKET_EISCONN) {
                            $success = true;
                            $rtt = round((microtime(true) - $start) * 1000, 3);
                        } else {
                            $error = socket_strerror($err2);
                        }
                    } else {
                        $error = socket_strerror($soError);
                    }
                } else {
                    $error = 'connect timed out';
                }
            } else {
                $error = socket_strerror($errno);
            }
        }

        socket_close($sock);

        return [
            'ip'        => $ip,
            'port'      => $port,
            'success'   => $success,
            'rtt'       => $rtt,
            'error'     => $error,
            'timestamp' => $timestamp,
        ];
    }

    /**
     * 多次连接测试并统计。
     *
     * @return array{ip: string, port: string, sent: int, success: int, loss_rate: float,
     *               max_rtt: float, min_rtt: float, avg_rtt: float, results: array[]}
     */
    public function run(string $host, string $port, int $count, string $version): array
    {
        try {
            $ip = $this->resolveHost($host, $version);
        } catch (RuntimeException $e) {
            return [
                'ip'        => 'Error: ' . $e->getMessage(),
                'port'      => $port,
                'sent'      => $count,
                'success'   => 0,
                'loss_rate' => 100.0,
                'max_rtt'   => -1.0,
                'min_rtt'   => -1.0,
                'avg_rtt'   => -1.0,
                'results'   => null,
            ];
        }

        $stats = [
            'ip'        => $ip,
            'port'      => $port,
            'sent'      => $count,
            'success'   => 0,
            'loss_rate' => 0.0,
            'max_rtt'   => -1.0,
            'min_rtt'   => -1.0,
            'avg_rtt'   => -1.0,
            'results'   => [],
        ];

        $successCount = 0;
        $totalRtt = 0.0;

        for ($i = 0; $i < $count; $i++) {
            $r = $this->ping($host, $port, $version);
            $stats['results'][] = $r;
            if ($r['success']) {
                $successCount++;
                $totalRtt += $r['rtt'];
                if ($r['rtt'] > $stats['max_rtt']) {
                    $stats['max_rtt'] = $r['rtt'];
                }
                if ($stats['min_rtt'] < 0 || $r['rtt'] < $stats['min_rtt']) {
                    $stats['min_rtt'] = $r['rtt'];
                }
            }
            if ($i < $count - 1 && $this->intervalMs > 0) {
                usleep((int) ($this->intervalMs * 1000));
            }
        }

        $stats['success'] = $successCount;
        $stats['loss_rate'] = round(($count - $successCount) * 10000 / $count) / 100;
        if ($successCount > 0) {
            $stats['avg_rtt'] = round($totalRtt * 100 / $successCount) / 100;
            $stats['max_rtt'] = round($stats['max_rtt'], 3);
            $stats['min_rtt'] = round($stats['min_rtt'], 3);
        } else {
            $stats['max_rtt'] = -1.0;
            $stats['min_rtt'] = -1.0;
            $stats['avg_rtt'] = -1.0;
        }

        return $stats;
    }

    /**
     * @return array{ip: string, port: string, success: bool, rtt: float, error: string, timestamp: string}
     */
    private function errorResult(string $ip, string $port, string $timestamp, string $error): array
    {
        return [
            'ip'        => $ip,
            'port'      => $port,
            'success'   => false,
            'rtt'       => -1,
            'error'     => $error,
            'timestamp' => $timestamp,
        ];
    }
}
