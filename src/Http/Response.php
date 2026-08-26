<?php

declare(strict_types=1);

namespace App\Http;

/**
 * JSON 响应辅助。
 * json_encode 保持默认的非 ASCII 转义（与 Go encoding/json 的 \uXXXX 行为一致），
 * 但不对斜杠转义（对齐 Go json.Marshal）。
 */
final class Response
{
    /** @var array<string,string> 自定义错误页（状态码字符串 → 重定向 URL 或响应内容），由 setErrorPages 注入 */
    private static array $errorPages = [];

    public static function json(mixed $data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_SLASHES);
    }

    /**
     * 注入自定义错误页（状态码 → 重定向 URL 或内容）。未配置的键走默认 JSON。
     *
     * @param array<string,string> $pages
     */
    public static function setErrorPages(array $pages): void
    {
        self::$errorPages = $pages;
    }

    /**
     * 统一错误输出：
     *  - 命中自定义错误页且值为 URL（http(s)://、//、/ 开头）→ 302 重定向；
     *  - 值为内容 → 输出自定义内容（自动嗅探 Content-Type）；
     *  - 204 无响应体，仅支持 URL 重定向（内容形式回退 JSON）；
     *  - 未配置/空值 → 回退默认 JSON {"error": ...}。
     */
    public static function error(int $status, string $defaultMessage): void
    {
        $key = (string) $status;
        $target = trim(self::$errorPages[$key] ?? '');
        if ($target === '') {
            self::json(['error' => $defaultMessage], $status);
            return;
        }
        if (self::isRedirectUrl($target)) {
            http_response_code(302);
            header('Location: ' . $target);
            return;
        }
        if ($status === 204) {
            self::json(['error' => $defaultMessage], $status);
            return;
        }
        http_response_code($status);
        header('Content-Type: ' . self::detectContentType($target));
        echo $target;
    }

    /**
     * 判断错误页值是否为重定向目标（URL / 路径形式）。
     */
    private static function isRedirectUrl(string $s): bool
    {
        return str_starts_with($s, 'http://')
            || str_starts_with($s, 'https://')
            || str_starts_with($s, '//')
            || str_starts_with($s, '/');
    }

    /**
     * 根据内容嗅探 Content-Type：HTML / JSON / 纯文本。
     */
    private static function detectContentType(string $body): string
    {
        $trim = ltrim($body);
        $lower = strtolower($trim);
        if (str_starts_with($lower, '<!doctype') || str_starts_with($lower, '<html') || str_starts_with($lower, '<body')) {
            return 'text/html; charset=utf-8';
        }
        if ($trim !== '' && $trim[0] === '{' && json_decode($body) !== null) {
            return 'application/json; charset=utf-8';
        }
        return 'text/plain; charset=utf-8';
    }
}
