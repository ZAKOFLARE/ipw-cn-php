<?php

declare(strict_types=1);

namespace App\Network;

use App\Security\Ssrf;
use App\Support\UrlHelper;
use RuntimeException;

/**
 * HTTP 探测客户端：对应 Go 版 main.go 的 checkWebsite / websiteSpeed / checkSSL 共用连接层。
 *
 * 关键设计：
 *  - 先用 DnsClient 按协议族（v4→A / v6→AAAA）解析域名，记录 DNS 耗时；
 *  - 再用 CURLOPT_RESOLVE 把 host 强制绑定到解析出的 IP，确保协议族与 DNS 服务器可控；
 *  - 关闭 curl 自动重定向，手动逐跳跟随并做 SSRF 校验（对齐 Go 版 SecureCheckRedirect）；
 *  - https 传输失败时 fallback 到 http（对齐 Go 版 fallbackToHTTP 逻辑）。
 */
final class HttpProbe
{
    private const MAX_REDIRECTS = 10;
    private const TIMEOUT = 10; // 秒，对齐 Go 版 resty 10s 超时

    private DnsClient $dns;
    private string $version;

    public function __construct(DnsClient $dns, string $version)
    {
        $this->dns = $dns;
        $this->version = $version;
    }

    /**
     * 发起探测（含 https→http fallback）。
     *
     * @throws RuntimeException 传输层失败
     */
    public function probe(string $url): ProbeResult
    {
        try {
            return $this->probeChain($url);
        } catch (RuntimeException $e) {
            if (str_starts_with($url, 'https://')) {
                $replaced = 0;
                $result = $this->probeChain(str_replace('https://', 'http://', $url, $replaced));
                $result->httpsStatusCode = 0; // 对齐 Go 版 fallbackToHTTP
                $result->fallbackToHttp = true;
                return $result;
            }
            throw $e;
        }
    }

    /**
     * 沿重定向链逐跳探测（每跳 SSRF 校验），分阶段耗时累加，状态取最后一跳。
     */
    private function probeChain(string $url): ProbeResult
    {
        $currentUrl = $url;
        $merged = new ProbeResult();
        $startTotal = microtime(true);

        for ($hop = 0; $hop < self::MAX_REDIRECTS; $hop++) {
            Ssrf::assertSafeUrl($currentUrl); // 每跳都做 SSRF 校验

            $r = $this->probeOnce($currentUrl);

            // 分阶段耗时累加（对齐 resty TraceInfo 跨重定向累加语义）
            $merged->dnsLookupTime += $r->dnsLookupTime;
            $merged->tcpConnectTime += $r->tcpConnectTime;
            $merged->httpConnectTime += $r->httpConnectTime;
            $merged->firstByteTime += $r->firstByteTime;
            $merged->pageSize = $r->pageSize;
            $merged->downloadSpeed = $r->downloadSpeed;
            $merged->isReachable = $r->isReachable;

            // 状态与信息取最后一跳
            $merged->hostRecord = $r->hostRecord;
            $merged->httpStatusCode = $r->httpStatusCode;
            $merged->httpsStatusCode = $r->httpsStatusCode;
            $merged->headers = $r->headers;
            $merged->httpVersion = $r->httpVersion;
            $merged->certInfo = $r->certInfo;

            if ($r->location !== null && $r->httpStatusCode >= 300 && $r->httpStatusCode < 400) {
                $currentUrl = UrlHelper::resolveRedirect($currentUrl, $r->location);
                continue;
            }
            break;
        }

        $merged->totalTime = round((microtime(true) - $startTotal) * 1000, 3);
        $merged->dnsLookupTime = round($merged->dnsLookupTime, 3);
        $merged->tcpConnectTime = round($merged->tcpConnectTime, 3);
        $merged->httpConnectTime = round($merged->httpConnectTime, 3);
        $merged->firstByteTime = round($merged->firstByteTime, 3);
        if ($merged->totalTime > 0) {
            $merged->downloadSpeed = round($merged->pageSize / 1024.0 / ($merged->totalTime / 1000.0), 3);
        }
        return $merged;
    }

    /**
     * 单跳探测。
     */
    private function probeOnce(string $url): ProbeResult
    {
        $result = new ProbeResult();

        $parts = UrlHelper::parse($url);
        if ($parts === null) {
            throw new RuntimeException('invalid URL');
        }
        $host = strtolower((string) $parts['host']);
        $port = UrlHelper::port($url);
        $scheme = strtolower((string) ($parts['scheme'] ?? 'https'));

        // 1. DNS 解析（按协议族），耗时独立记录
        $dnsType = $this->version === 'v6' ? 'AAAA' : 'A';
        $dnsStart = microtime(true);
        $dnsResult = $this->dns->query($host, $dnsType);
        $result->dnsLookupTime = round((microtime(true) - $dnsStart) * 1000, 3);

        if ($dnsResult['record'] === []) {
            throw new RuntimeException("no {$this->version} address found for {$host}");
        }
        $ip = $dnsResult['record'][0];
        if (Ssrf::enabled() && Ssrf::isPrivateIp($ip)) {
            throw new RuntimeException('request to private/internal address is not allowed');
        }

        // 2. curl 请求（RESOLVE 强制 host→IP）
        $rawHeaders = '';
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL              => $url,
            CURLOPT_RETURNTRANSFER   => true,
            CURLOPT_TIMEOUT          => self::TIMEOUT,
            CURLOPT_CONNECTTIMEOUT   => self::TIMEOUT,
            CURLOPT_FOLLOWLOCATION   => false, // 手动跟随重定向
            CURLOPT_SSL_VERIFYPEER   => false, // 对齐 Go 版 InsecureSkipVerify
            CURLOPT_SSL_VERIFYHOST   => 0,
            CURLOPT_IPRESOLVE        => $this->version === 'v6' ? CURL_IPRESOLVE_V6 : CURL_IPRESOLVE_V4,
            CURLOPT_RESOLVE          => ["{$host}:{$port}:{$ip}"],
            CURLOPT_CERTINFO         => true,
            CURLOPT_ENCODING         => '',
            CURLOPT_HEADERFUNCTION   => static function ($ch, string $header) use (&$rawHeaders): int {
                $rawHeaders .= $header;
                return strlen($header);
            },
        ]);

        $startReq = microtime(true);
        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $info = curl_getinfo($ch);
        $elapsed = (microtime(true) - $startReq) * 1000;

        if ($errno !== 0) {
            curl_close($ch);
            throw new RuntimeException($error !== '' ? $error : "curl error {$errno}");
        }
        if (!is_string($body)) {
            $body = '';
        }

        $status = (int) $info['http_code'];
        $connectTime = (float) ($info['connect_time'] ?? 0);
        $appConnectTime = (float) ($info['appconnect_time'] ?? 0);
        $startTransfer = (float) ($info['starttransfer_time'] ?? 0);

        $result->tcpConnectTime = round($connectTime * 1000, 3);
        $result->httpConnectTime = round(($appConnectTime > 0 ? $appConnectTime : $connectTime) * 1000, 3);
        $result->firstByteTime = round($startTransfer * 1000, 3);
        $result->totalTime = round($elapsed, 3);
        $result->pageSize = strlen($body);
        $result->downloadSpeed = $result->totalTime > 0
            ? round(strlen($body) / 1024.0 / ($result->totalTime / 1000.0), 3)
            : 0.0;
        $result->hostRecord = UrlHelper::cleanHostRecord((string) ($info['primary_ip'] ?? $ip) . ':' . $port);
        $result->httpVersion = self::httpVersionName((int) ($info['http_version'] ?? 0));
        $result->httpStatusCode = $status;
        $result->httpsStatusCode = $scheme === 'https' ? $status : 0;
        $result->isReachable = true;
        $result->headers = $rawHeaders;
        $result->certInfo = (array) curl_getinfo($ch, CURLINFO_CERTINFO);

        // 重定向 Location
        if ($status >= 300 && $status < 400) {
            $location = self::extractHeader($rawHeaders, 'location');
            if ($location !== null) {
                $result->location = trim($location);
            }
        }

        curl_close($ch);
        return $result;
    }

    private static function httpVersionName(int $code): string
    {
        return match ($code) {
            1       => 'HTTP/1.0',
            2       => 'HTTP/1.1',
            3, 4    => 'HTTP/2',
            5       => 'HTTP/3',
            default => '',
        };
    }

    /**
     * 从原始响应头中提取指定 header 的值（大小写不敏感，取第一个）。
     */
    private static function extractHeader(string $rawHeaders, string $name): ?string
    {
        foreach (explode("\r\n", $rawHeaders) as $line) {
            $colon = strpos($line, ':');
            if ($colon === false) {
                continue;
            }
            if (strcasecmp(substr($line, 0, $colon), $name) === 0) {
                return trim(substr($line, $colon + 1));
            }
        }
        return null;
    }
}
