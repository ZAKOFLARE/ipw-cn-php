<?php

declare(strict_types=1);

namespace App\Http;

/**
 * 轻量请求封装。
 */
final class Request
{
    /**
     * 当前请求路径（不含 query，已解码）。
     */
    public static function path(): string
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $path = parse_url($uri, PHP_URL_PATH);
        return rawurldecode($path !== false && $path !== null ? $path : '/');
    }

    public static function method(): string
    {
        return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    }

    public static function query(string $key, ?string $default = null): ?string
    {
        $value = $_GET[$key] ?? null;
        return $value === null ? $default : (string) $value;
    }

    /**
     * 读取 Authorization 头（Bearer token 原样）。
     * 兼容 FPM/CGI 下 Authorization 头被吞的情况：
     * HTTP_AUTHORIZATION → REDIRECT_HTTP_AUTHORIZATION → getallheaders()。
     */
    public static function bearerToken(): string
    {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if ($auth === '' && function_exists('getallheaders')) {
            foreach (getallheaders() as $name => $value) {
                if (strcasecmp((string) $name, 'Authorization') === 0) {
                    $auth = (string) $value;
                    break;
                }
            }
        }
        return $auth;
    }
}
