<?php

declare(strict_types=1);

namespace App\Cache;

/**
 * TTL 文件缓存：对应 Go 版 sync.Map + TTL 语义。
 * FPM 无常驻内存，用磁盘文件承载（虚拟主机可写目录即可）。
 */
final class FileCache
{
    public const DEFAULT_TTL = 300; // 5 分钟，与 Go 版 detail/ssl 缓存一致

    private string $dir;

    public function __construct(?string $dir = null)
    {
        $this->dir = $dir ?? (dirname(__DIR__, 2) . '/storage/cache');
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0755, true);
        }
    }

    /**
     * 读取缓存，未命中或已过期返回 null。
     */
    public function get(string $key): mixed
    {
        $file = $this->path($key);
        if (!is_file($file)) {
            return null;
        }
        $raw = @file_get_contents($file);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || !array_key_exists('expires_at', $data)) {
            return null;
        }
        if (time() > $data['expires_at']) {
            @unlink($file);
            return null;
        }
        return $data['value'];
    }

    /**
     * 写入缓存。
     */
    public function set(string $key, mixed $value, int $ttl = self::DEFAULT_TTL): void
    {
        $data = json_encode([
            'expires_at' => time() + $ttl,
            'value'      => $value,
        ], JSON_UNESCAPED_SLASHES);
        $file = $this->path($key);
        $tmp = $file . '.tmp';
        if (@file_put_contents($tmp, $data) !== false) {
            @rename($tmp, $file);
        }
    }

    public function delete(string $key): void
    {
        @unlink($this->path($key));
    }

    private function path(string $key): string
    {
        return $this->dir . '/' . sha1($key) . '.json';
    }
}
