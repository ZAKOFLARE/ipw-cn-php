<?php

declare(strict_types=1);

namespace App\Analytics;

/**
 * 统计计数模块（异步、非阻塞、可熔断）。
 *
 * 设计要点：
 *  1. 仅"真实业务数据"（非缓存命中）才计数——由 InFlightGuard 的 onProduced 回调触发；
 *  2. FPM 环境下用 fastcgi_finish_request() 先把响应发给客户端，再执行计数请求，
 *     计数失败/超时完全不影响主流程返回；
 *  3. 计数请求 3 秒内无响应（或 HTTP 非 2xx/3xx）视为失败，写入熔断标记，
 *     之后 1 小时内跳过所有计数尝试（对应"跳过计数环节一小时"）。
 */
final class Counter
{
    private const FUSE_FILE = 'counter_fuse.json';
    private const FUSE_SECONDS = 3600;   // 熔断时长：1 小时
    private const TIMEOUT = 3;           // 计数请求超时：3 秒

    /** @var array<string, true> 本请求内待计数的端点（键去重） */
    private static array $queue = [];
    private static string $baseUrl = '';
    private static bool $ready = false;

    /**
     * 配置计数接口地址（为空则关闭计数）。
     */
    public static function configure(string $baseUrl): void
    {
        self::$baseUrl = $baseUrl;
        self::$ready = $baseUrl !== '';
    }

    public static function enabled(): bool
    {
        return self::$ready;
    }

    /**
     * 入队一次计数（不立即发送，等响应输出后统一 flush）。
     * 同一请求内同一端点只计一次。
     */
    public static function queue(string $page = ''): void
    {
        if (!self::$ready) {
            return;
        }
        self::$queue[$page] = true;
    }

    /**
     * 响应已输出后调用：结束请求（FPM）→ 逐个发送计数 → 失败则熔断。
     * 任何异常都吞掉，绝不抛向主流程。
     */
    public static function flush(): void
    {
        if (!self::$ready || self::$queue === []) {
            return;
        }
        $pages = array_keys(self::$queue);
        self::$queue = [];

        try {
            // FPM：先把已输出的响应交给客户端，后续计数不阻塞用户
            if (function_exists('fastcgi_finish_request')) {
                @fastcgi_finish_request();
            }

            if (self::isFused()) {
                return;
            }

            foreach ($pages as $page) {
                if (!self::send($page)) {
                    // 计数接口 3 秒内无响应/异常 → 熔断 1 小时，后续全部跳过
                    self::fuse();
                    break;
                }
            }
        } catch (\Throwable) {
            // 统计环节绝不影响主流程
        }
    }

    /**
     * 发送单次计数请求。成功（2xx/3xx 且无传输错误）返回 true。
     */
    private static function send(string $page): bool
    {
        $url = self::$baseUrl;
        if ($page !== '') {
            $sep = str_contains($url, '?') ? '&' : '?';
            $url .= $sep . 'page=' . rawurlencode($page);
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT      => 'LemonIPW-Counter/1.0',
        ]);
        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return $errno === 0 && $status >= 200 && $status < 400;
    }

    /**
     * 写入熔断标记：直到 now + 1h 前都不再尝试计数。
     */
    private static function fuse(): void
    {
        $dir = dirname(__DIR__, 2) . '/storage/cache';
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        $file = $dir . '/' . self::FUSE_FILE;
        $tmp = $file . '.tmp';
        if (@file_put_contents($tmp, json_encode(['until' => time() + self::FUSE_SECONDS])) !== false) {
            @rename($tmp, $file);
        }
    }

    private static function isFused(): bool
    {
        $file = dirname(__DIR__, 2) . '/storage/cache/' . self::FUSE_FILE;
        if (!is_file($file)) {
            return false;
        }
        $raw = @file_get_contents($file);
        if ($raw === false) {
            return false;
        }
        $data = json_decode($raw, true);
        return is_array($data) && isset($data['until']) && time() < (int) $data['until'];
    }
}
