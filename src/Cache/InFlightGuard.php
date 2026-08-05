<?php

declare(strict_types=1);

namespace App\Cache;

/**
 * 跨进程并发去重：对应 Go 版 singleflight.Group 的 FPM 近似实现。
 *
 * 策略：
 *  1. 先查缓存，命中直接返回；
 *  2. 用 flock 文件锁抢执行权：抢到者执行探测并写缓存；
 *  3. 未抢到者短轮询缓存（最多等待 $waitSeconds），等到即返回；
 *  4. 超时兜底：自行执行探测（不拿锁，保证请求不挂死）。
 */
final class InFlightGuard
{
    public static function run(string $cacheKey, int $ttl, callable $producer, float $waitSeconds = 5.0): mixed
    {
        $cache = new FileCache();

        if (($hit = $cache->get($cacheKey)) !== null) {
            return $hit;
        }

        $lockFile = self::lockPath($cacheKey);
        $fp = @fopen($lockFile, 'c');
        if ($fp === false) {
            // 无法建锁文件：直接执行
            $value = $producer();
            $cache->set($cacheKey, $value, $ttl);
            return $value;
        }

        if (flock($fp, LOCK_EX | LOCK_NB)) {
            try {
                // 二次检查缓存（避免持锁期间其他人已写入）
                if (($hit = $cache->get($cacheKey)) !== null) {
                    return $hit;
                }
                $value = $producer();
                $cache->set($cacheKey, $value, $ttl);
                return $value;
            } finally {
                flock($fp, LOCK_UN);
                fclose($fp);
            }
        }

        fclose($fp);

        // 未抢到锁：轮询等待执行者写入
        $deadline = microtime(true) + $waitSeconds;
        while (microtime(true) < $deadline) {
            usleep(50_000);
            if (($value = $cache->get($cacheKey)) !== null) {
                return $value;
            }
        }

        // 超时兜底：自行执行
        $value = $producer();
        $cache->set($cacheKey, $value, $ttl);
        return $value;
    }

    private static function lockPath(string $cacheKey): string
    {
        $dir = dirname(__DIR__, 2) . '/storage/cache';
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        return $dir . '/' . sha1($cacheKey) . '.lock';
    }
}
