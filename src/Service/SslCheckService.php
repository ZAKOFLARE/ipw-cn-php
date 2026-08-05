<?php

declare(strict_types=1);

namespace App\Service;

use App\Cache\InFlightGuard;
use App\Config;
use App\Network\DnsClient;
use App\Network\HttpProbe;
use App\Security\Ssrf;
use App\Support\UrlHelper;
use RuntimeException;

/**
 * SSL 证书检查：对应 Go 版 sslCheckHandler / checkSSL。
 * 输出 SSLCheckResult { ipv4, ipv6 }。
 */
final class SslCheckService
{
    public const CACHE_TTL = 300;
    private const FAIL_CACHE_TTL = 30;
    private const GO_ZERO_TIME = '0001-01-01T00:00:00Z'; // 对齐 Go time.Time{} 的 JSON

    public function __construct(private Config $config)
    {
    }

    public function check(string $url): array
    {
        $cacheKey = 'ssl:' . $url;
        return InFlightGuard::run($cacheKey, self::CACHE_TTL, function () use ($url, $cacheKey) {
            $result = $this->doCheck($url);
            if ($this->anyUnreachable($result)) {
                (new \App\Cache\FileCache())->set($cacheKey, $result, self::FAIL_CACHE_TTL);
            }
            return $result;
        });
    }

    private function doCheck(string $url): array
    {
        $host = UrlHelper::hostname($url);
        if ($host !== '' && Ssrf::hasLocalOrPrivateIp($host)) {
            return ['ipv4' => self::fakeInvalid($host), 'ipv6' => self::fakeInvalid($host)];
        }

        switch ($this->config->singleStack) {
            case 'ipv4':
                return [
                    'ipv4' => $this->checkOne($url, 'v4'),
                    'ipv6' => self::skippedDetail('SINGLE_STACK=ipv4'),
                ];
            case 'ipv6':
                return [
                    'ipv4' => self::skippedDetail('SINGLE_STACK=ipv6'),
                    'ipv6' => $this->checkOne($url, 'v6'),
                ];
            default:
                return [
                    'ipv4' => $this->checkOne($url, 'v4'),
                    'ipv6' => $this->checkOne($url, 'v6'),
                ];
        }
    }

    /**
     * @return array{cert_validity_days: int, cert_start_time: string, cert_end_time: string,
     *               http_version: string, host_record: string, https_status_code: int,
     *               total_time: float, download_speed: float, domain: string,
     *               issuer_organization: string[], issuer_common_name: string,
     *               subject_common_name: string, is_expired: bool, is_reachable: bool}
     */
    private function checkOne(string $url, string $version): array
    {
        try {
            $probe = new HttpProbe(new DnsClient($this->config->dnsServer), $version);
            $r = $probe->probe($url);

            $certPem = $r->certInfo[0]['Cert'] ?? null;
            if ($certPem === null) {
                throw new RuntimeException('no SSL certificate found');
            }
            $parsed = openssl_x509_parse($certPem);
            if ($parsed === false) {
                throw new RuntimeException('failed to parse certificate');
            }

            $now = time();
            $validFrom = (int) ($parsed['validFrom_time_t'] ?? 0);
            $validTo = (int) ($parsed['validTo_time_t'] ?? 0);
            $remainingDays = (int) floor(($validTo - $now) / 86400);
            $isExpired = $now > $validTo || $now < $validFrom;

            $subjectCn = (string) ($parsed['subject']['CN'] ?? '');
            $issuerCn = (string) ($parsed['issuer']['CN'] ?? '');
            $issuerOrg = $parsed['issuer']['O'] ?? null;

            return [
                'cert_validity_days'   => $remainingDays,
                'cert_start_time'      => $validFrom > 0 ? date('c', $validFrom) : self::GO_ZERO_TIME,
                'cert_end_time'        => $validTo > 0 ? date('c', $validTo) : self::GO_ZERO_TIME,
                'http_version'         => $r->httpVersion,
                'host_record'          => $r->hostRecord,
                'https_status_code'    => $r->httpsStatusCode,
                'total_time'           => $r->totalTime,
                'download_speed'       => $r->downloadSpeed,
                'domain'               => UrlHelper::cleanHostRecord($subjectCn),
                'issuer_organization'  => $issuerOrg === null ? [] : (is_array($issuerOrg) ? array_values($issuerOrg) : [$issuerOrg]),
                'issuer_common_name'   => $issuerCn,
                'subject_common_name'  => $subjectCn,
                'is_expired'           => $isExpired,
                'is_reachable'         => true,
            ];
        } catch (RuntimeException $e) {
            return self::errorDetail($e->getMessage());
        }
    }

    private function anyUnreachable(array $result): bool
    {
        return (isset($result['ipv4']) && !$result['ipv4']['is_reachable'])
            || (isset($result['ipv6']) && !$result['ipv6']['is_reachable']);
    }

    private static function skippedDetail(string $reason): array
    {
        return self::baseDetail() + [
            'host_record'  => "Skipped due to {$reason}",
            'is_expired'   => true,
            'is_reachable' => false,
        ];
    }

    private static function errorDetail(string $message): array
    {
        return self::baseDetail() + [
            'host_record'  => 'Error: ' . $message,
            'is_expired'   => true,
            'is_reachable' => false,
        ];
    }

    private static function baseDetail(): array
    {
        return [
            'cert_validity_days'  => 0,
            'cert_start_time'     => self::GO_ZERO_TIME,
            'cert_end_time'       => self::GO_ZERO_TIME,
            'http_version'        => '',
            'host_record'         => '',
            'https_status_code'   => 0,
            'total_time'          => 0.0,
            'download_speed'      => 0.0,
            'domain'              => '',
            'issuer_organization' => [],
            'issuer_common_name'  => '',
            'subject_common_name' => '',
            'is_expired'          => true,
            'is_reachable'        => false,
        ];
    }

    /**
     * 私有 IP 目标返回的无效证书假结果（对应 Go 版 fakeInvalidSSLResult）。
     */
    private static function fakeInvalid(string $host): array
    {
        return self::baseDetail() + [
            'host_record'         => $host,
            'issuer_common_name'  => 'Invalid Certificate',
            'subject_common_name' => $host,
            'domain'              => $host,
        ];
    }
}
