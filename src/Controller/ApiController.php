<?php

declare(strict_types=1);

namespace App\Controller;

use App\Config;
use App\Http\Request;
use App\Http\Response;
use App\Network\DnsClient;
use App\Network\ReqResolve;
use App\Security\Ssrf;
use App\Service\DnssecService;
use App\Service\SslCheckService;
use App\Service\SpeedTestService;
use App\Service\TcpingService;
use App\Service\WebsiteCheckService;
use App\Service\WhoisService;
use App\Support\UrlHelper;
use App\Analytics\Counter;
use InvalidArgumentException;
use RuntimeException;

/**
 * API 控制器：对应 Go 版 main.go 的各业务 handler。
 */
final class ApiController
{
    public function __construct(private Config $config)
    {
    }

    /**
     * 解析请求级解析参数（dns/dns4/dns6、resolve/resolve4/resolve6），并把配置注入 SSRF 预检，
     * 使预检与真正拨号读同一份解析配置（对应 Go 版 ParseReqResolve + InstallSSRFResolver）。
     *
     * 参数存在但全部非法时返回 400，避免「看起来指定了、实际按默认跑」。
     */
    private function requestResolve(): ReqResolve
    {
        try {
            $req = ReqResolve::fromQuery(static fn (string $key): ?string => Request::query($key));
        } catch (InvalidArgumentException $e) {
            Response::json(['error' => $e->getMessage()], 400);
            exit;
        }
        Ssrf::setRequestResolve($req);
        return $req;
    }

    public function detail(string $url): array
    {
        $req = $this->requestResolve();
        $url = UrlHelper::normalizeUrl($url);
        return (new WebsiteCheckService($this->config, $req))->check($url, 'detail');
    }

    public function ssl(string $url): array
    {
        $req = $this->requestResolve();
        $url = UrlHelper::normalizeUrl($url);
        return (new SslCheckService($this->config, $req))->check($url, 'ssl');
    }

    public function speed(string $version, string $url): array
    {
        $req = $this->requestResolve();
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

        return (new SpeedTestService($this->config, $req))->test($url, $version, 'speed');
    }

    public function tcping(string $ip): array
    {
        $req = $this->requestResolve();
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

        return (new TcpingService($this->config, $req))->ping($ip, $port, $count, 'tcping');
    }

    public function dns(string $type, string $domain): array
    {
        // dns 拨测只接 dns*（问的就是真实解析结果，resolve* 会自相矛盾）
        $req = $this->requestResolve();
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

        // 按 qtype 选栈：a→dns4|dns，aaaa→dns6|dns，其余→dns
        $stack = $typeUpper === 'A' ? 'ipv4' : ($typeUpper === 'AAAA' ? 'ipv6' : '');
        $servers = $req->servers($stack);

        try {
            $client = new DnsClient($servers !== [] ? $servers : $this->config->dnsServer);
            $result = $client->query($host, $typeUpper);
            // DNS 无缓存，每次查询都是真实数据 → 直接计数
            Counter::queue('dns');
            return $result;
        } catch (RuntimeException $e) {
            Response::error(500, $e->getMessage());
            exit;
        }
    }

    public function dnssec(string $domain): array
    {
        if ($domain === '') {
            Response::json(['error' => 'Domain parameter is required'], 400);
            exit;
        }
        // Go 版 ResolveDNSSEC 不返回 error（失败写入 validation 字段），总是 200 结果
        $result = (new DnssecService($this->config))->check($domain);
        Counter::queue('dnssec');
        return $result;
    }

    public function whois(string $domain): array
    {
        if ($domain === '') {
            Response::json(['error' => 'Domain parameter is required'], 400);
            exit;
        }
        // Go 版 QueryWhois 不返回 error（失败写入结果 error 字段），总是 200 结果
        return (new WhoisService($this->config))->check($domain);
    }
}
