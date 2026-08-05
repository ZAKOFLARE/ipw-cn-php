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
    public static function json(mixed $data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_SLASHES);
    }
}
