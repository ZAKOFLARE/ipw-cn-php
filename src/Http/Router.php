<?php

declare(strict_types=1);

namespace App\Http;

/**
 * 极简路由：正则匹配 + 命名捕获组提取参数。
 */
final class Router
{
    /** @var array<int, array{pattern: string, handler: callable}> */
    private array $routes = [];

    public function get(string $pattern, callable $handler): void
    {
        $this->routes[] = ['pattern' => $pattern, 'handler' => $handler];
    }

    /**
     * 匹配路径，命中则调用 handler 并返回其结果；未命中返回 null。
     */
    public function dispatch(string $path): mixed
    {
        foreach ($this->routes as $route) {
            if (preg_match($route['pattern'], $path, $matches)) {
                // 仅保留命名捕获组
                $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
                return call_user_func($route['handler'], $params);
            }
        }
        return null;
    }
}
