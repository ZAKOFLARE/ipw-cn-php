<?php

declare(strict_types=1);

use App\Config;
use App\Controller\ApiController;
use App\Http\Request;
use App\Http\Response;
use App\Http\Router;
use App\Network\DnsClient;
use App\Security\Ssrf;
use App\Analytics\Counter;

/**
 * Lemon IPW PHP 后端入口（FPM / php -S 通用）。
 * nginx 配置示例：
 *   location / { try_files $uri /index.php$is_args$args; }
 */

$root = dirname(__DIR__);

// 自动加载：优先 composer，缺失时退化为 PSR-4 手写注册（虚拟主机免 composer 也可运行）
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        if (!str_starts_with($class, 'App\\')) {
            return;
        }
        $file = $root . '/src/' . str_replace('\\', '/', substr($class, 4)) . '.php';
        if (is_file($file)) {
            require $file;
        }
    });
}

$config = Config::load($root);

// 初始化安全与网络基础组件
Ssrf::setEnabled($config->blockPrivateIps);
Ssrf::setDnsClient(new DnsClient($config->dnsServer));

// 统计计数（配置 counter-url 后启用）
Counter::configure($config->counterUrl);

// CORS（对齐 Go 版 gin-contrib/cors 的 AllowAllOrigins 或白名单模式）
handleCors($config);

$router = new Router();
$api = new ApiController($config);

$router->get('~^/$~', static fn (): array => ['status' => 'ok']);
$router->get('~^/v1/detail/(?<url>.+)$~', static fn (array $p): array => $api->detail($p['url']));
$router->get('~^/v1/ssl/(?<url>.+)$~', static fn (array $p): array => $api->ssl($p['url']));
$router->get('~^/v1/tcping/(?<ip>[^/]+)$~', static fn (array $p): array => $api->tcping($p['ip']));
$router->get('~^/v1/dns/(?<type>[^/]+)/(?<domain>.+)$~', static fn (array $p): array => $api->dns($p['type'], $p['domain']));
$router->get('~^/v1/speed/(?<version>[^/]+)/(?<url>.+)$~', static fn (array $p): array => $api->speed($p['version'], $p['url']));

try {
    $result = $router->dispatch(Request::path());
    if ($result === null) {
        Response::json(['error' => 'Not Found'], 404);
    } else {
        Response::json($result);
    }
} catch (Throwable $e) {
    Response::json(['error' => $e->getMessage()], 500);
}

// 响应已输出：异步执行真实业务数据的计数（失败/超时不影响主流程，异常内部吞掉）
Counter::flush();

/**
 * CORS 处理。
 */
function handleCors(Config $config): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    if ($config->acceptDomains === []) {
        header('Access-Control-Allow-Origin: *');
    } elseif ($origin !== '' && in_array($origin, $config->acceptDomains, true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Vary: Origin');
    }

    header('Access-Control-Allow-Methods: GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');

    if (Request::method() === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}
