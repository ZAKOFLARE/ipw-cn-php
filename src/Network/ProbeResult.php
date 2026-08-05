<?php

declare(strict_types=1);

namespace App\Network;

use App\Support\UrlHelper;

/**
 * HTTP 探测结果（内部结构，Service 层再组装为对外 JSON）。
 */
final class ProbeResult
{
    public string $hostRecord = '';
    public int $httpStatusCode = 0;
    public int $httpsStatusCode = 0;
    public float $dnsLookupTime = 0.0;
    public float $tcpConnectTime = 0.0;
    public float $httpConnectTime = 0.0;
    public float $firstByteTime = 0.0;
    public float $totalTime = 0.0;
    public int $pageSize = 0;
    public float $downloadSpeed = 0.0;
    public bool $isReachable = false;
    public string $headers = '';
    public string $httpVersion = '';
    /** @var array<int, array<string, string>> CURLINFO_CERTINFO */
    public array $certInfo = [];
    public ?string $location = null;
    public bool $fallbackToHttp = false;
}
