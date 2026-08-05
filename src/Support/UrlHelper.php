<?php

declare(strict_types=1);

namespace App\Support;

/**
 * URL 工具：对应 Go 版 main.go 中的 normalizeURL / cleanHostRecord / parseURL。
 */
final class UrlHelper
{
    /**
     * 规范化输入 URL，确保带有 http/https scheme。
     */
    public static function normalizeUrl(string $input): string
    {
        $input = trim($input);
        $input = ltrim($input, '/');
        if (str_starts_with($input, 'http://') || str_starts_with($input, 'https://')) {
            return $input;
        }
        if (str_starts_with($input, '//')) {
            return 'https:' . $input;
        }
        return 'https://' . $input;
    }

    /**
     * 清理 Host 记录：去掉 [::1]:80 的方括号与端口。
     * 对应 Go 版 cleanHostRecord。
     */
    public static function cleanHostRecord(string $addr): string
    {
        // IPv6 字面量 [::1]:80
        if (str_starts_with($addr, '[')) {
            $right = strpos($addr, ']');
            if ($right !== false) {
                return substr($addr, 1, $right - 1);
            }
        }

        $colonCount = substr_count($addr, ':');
        $idx = strrpos($addr, ':');
        if ($idx !== false && $colonCount >= 1) {
            return substr($addr, 0, $idx);
        }

        return $addr;
    }

    /**
     * 规范化并解析 URL，返回 parse_url 数组（含 scheme/host/port 等）。
     *
     * @return array<string, string|int>|null
     */
    public static function parse(string $input): ?array
    {
        $normalized = self::normalizeUrl($input);
        $parts = parse_url($normalized);
        if ($parts === false || empty($parts['host'])) {
            return null;
        }
        return $parts;
    }

    /**
     * 从 URL 提取主机名（不含端口）。
     */
    public static function hostname(string $url): string
    {
        $parts = self::parse($url);
        return $parts['host'] ?? '';
    }

    /**
     * 解析 URL 的端口，缺省时按 scheme 推断。
     */
    public static function port(string $url): int
    {
        $parts = self::parse($url);
        if ($parts === null) {
            return 443;
        }
        if (isset($parts['port'])) {
            return (int) $parts['port'];
        }
        return strtolower((string) ($parts['scheme'] ?? '')) === 'https' ? 443 : 80;
    }

    /**
     * 将相对/绝对 Location 头合并为绝对 URL。
     */
    public static function resolveRedirect(string $baseUrl, string $location): string
    {
        if (str_starts_with($location, 'http://') || str_starts_with($location, 'https://')) {
            return $location;
        }
        $parts = parse_url($baseUrl);
        if ($parts === false || empty($parts['host'])) {
            return $location;
        }
        $scheme = $parts['scheme'] ?? 'https';
        $host = $parts['host'];
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        if (str_starts_with($location, '//')) {
            return $scheme . ':' . $location;
        }
        if (str_starts_with($location, '/')) {
            return $scheme . '://' . $host . $port . $location;
        }
        $base = rtrim((string) ($parts['path'] ?? ''), '/');
        $dir = substr($base, 0, (int) strrpos($base, '/') + 1);
        return $scheme . '://' . $host . $port . $dir . $location;
    }
}
