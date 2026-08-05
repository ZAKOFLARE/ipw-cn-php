<?php

declare(strict_types=1);

namespace App\Controller;

use App\Config;
use App\Http\Request;
use App\Http\Response;
use App\Network\DnsClient;
use App\Service\SslCheckService;
use App\Service\SpeedTestService;
use App\Service\TcpingService;
use App\Service\WebsiteCheckService;
use App\Support\UrlHelper;
use RuntimeException;

/**
 * API 控制器：对应 Go 版 main.go 的各业务 handler。
 */
final class ApiController
{
    public function __construct(private Config $config)
    {
    }

    public function detail(string $url): array
    {
        $url = UrlHelper::normalizeUrl($url);
        return (new WebsiteCheckService($this->config))->check($url);
    }

    public function ssl(string $url): array
    {
        $url = UrlHelper::normalizeUrl($url);
        return (new SslCheckService($this->config))->check($url);
    }

    public function speed(string $version, string $url): array
    {
        $url = UrlHelper::normalizeUrl($url);

        // 校验请求版本与 SINGLE_STACK 配置匹配（对齐 Go 版）
        switch ($this->config->singleStack) {
            case 'ipv4':
                if ($version !== 'v4') {
                    Response::json([
                        'version'     => 'v4',
                        'host_record' => 'Skipped due to SINGLE_STACK=ipv4',
                    ], 400);
                    exit;
                }
                break;
            case 'ipv6':
                if ($version !== 'v6') {
                    Response::json([
                        'version'     => 'v6',
                        'host_record' => 'Skipped due to SINGLE_STACK=ipv6',
                    ], 400);
                    exit;
                }
                break;
        }

        if ($version !== 'v4' && $version !== 'v6') {
            Response::json(['error' => 'Invalid version'], 400);
            exit;
        }

        return (new SpeedTestService($this->config))->test($url, $version);
    }

    public function tcping(string $ip): array
    {
        $port = (int) (Request::query('port', '80'));
        if ($port < 1 || $port > 65535) {
            Response::json(['error' => 'Invalid port number'], 400);
            exit;
        }

        $count = 4;
        $countStr = Request::query('count', '');
        if ($countStr !== '') {
            $n = (int) $countStr;
            if ($n < 1 || $n > 20) {
                Response::json(['error' => 'count must be an integer between 1 and 20'], 400);
                exit;
            }
            $count = $n;
        }

        return (new TcpingService($this->config))->ping($ip, $port, $count);
    }

    public function dns(string $type, string $domain): array
    {
        $parsed = UrlHelper::parse($domain);
        if ($parsed === null) {
            Response::json(['error' => 'Invalid domain'], 400);
            exit;
        }
        $host = (string) $parsed['host'];

        $typeUpper = strtoupper($type);
        if (!isset(DnsClient::TYPE_MAP[$typeUpper])) {
            Response::json(['error' => 'Invalid record type'], 400);
            exit;
        }

        try {
            $client = new DnsClient($this->config->dnsServer);
            return $client->query($host, $typeUpper);
        } catch (RuntimeException $e) {
            Response::json(['error' => $e->getMessage()], 500);
            exit;
        }
    }
}
