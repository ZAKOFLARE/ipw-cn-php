<?php

declare(strict_types=1);

namespace App\Service;

use App\Cache\InFlightGuard;
use App\Config;
use App\Analytics\Counter;
use App\Network\WhoisClient;

/**
 * WHOIS 查询：对应 Go 版 webtest/whois.go 的 QueryWhois + parseWhoisResult。
 * 输出与 Go 版 WhoisResult json tag 完全一致（含 error 字段，接口总是 200）。
 */
final class WhoisService
{
    public const CACHE_TTL = 300; // 5 分钟，对齐 Go whoisCache

    public function __construct(private Config $config)
    {
    }

    public function check(string $domain): array
    {
        $cacheKey = 'whois:' . strtolower($domain);
        return InFlightGuard::run($cacheKey, self::CACHE_TTL, function () use ($domain) {
            return $this->doCheck($domain);
        }, static fn () => Counter::queue('whois'));
    }

    private function doCheck(string $domain): array
    {
        $result = [
            'domain'       => strtoupper($domain),
            'status'       => [],
            'registrar'    => ['name' => '', 'ianaId' => ''],
            'registrant'   => self::emptyContact(),
            'technical'    => self::emptyContact(),
            'abuseContact' => self::emptyContact(),
            'dates'        => ['registration' => '', 'expiration' => '', 'lastChanged' => ''],
            'nameservers'  => [],
            'whoisServer'  => '',
            'raw'          => '',
            'error'        => '',
        ];

        $client = new WhoisClient($this->config);
        $data = $client->query($domain);

        $result['raw'] = $data['raw'];
        if ($data['server'] !== '') {
            $result['whoisServer'] = $data['server'];
        }
        if ($data['error'] !== '') {
            $result['error'] = $data['error'];
            return $result;
        }

        $this->parseRaw($data['raw'], $result);
        return $result;
    }

    /**
     * 解析原始 WHOIS 文本为结构化字段。
     */
    private function parseRaw(string $raw, array &$result): void
    {
        $abuse = ['email' => '', 'phone' => ''];
        $registrarIanaId = '';

        foreach (explode("\n", $raw) as $line) {
            $line = rtrim($line, "\r");
            $trimmed = trim($line);

            if ($trimmed === '' || str_starts_with($trimmed, '%') || str_starts_with($trimmed, '#')) {
                continue;
            }

            $colon = strpos($trimmed, ':');
            if ($colon === false) {
                continue;
            }
            $key = self::normalizeKey(substr($trimmed, 0, $colon));
            $value = trim(substr($trimmed, $colon + 1));
            if ($value === '') {
                continue;
            }

            // Abuse 联系（照抄 Go abusePatterns）
            if (preg_match('/^(?:registrar\s+abuse\s+contact\s+email|abuse\s+(?:contact\s+)?email)$/', $key) === 1) {
                $abuse['email'] = $value;
                continue;
            }
            if (preg_match('/^(?:registrar\s+abuse\s+contact\s+phone|abuse\s+(?:contact\s+)?phone)$/', $key) === 1) {
                $abuse['phone'] = $value;
                continue;
            }
            // IANA ID（照抄 Go ianaIdPattern）
            if (preg_match('/^registrar\s+iana\s+id$/', $key) === 1) {
                $registrarIanaId = $value;
                continue;
            }

            // 联系人前缀字段（RIR 格式：Registrant Name / Tech Email / Admin Phone ...）
            if (preg_match('/^(registrant|tech|technical|admin|administrative)\s+(.+)$/', $key, $m) === 1) {
                // Go 版仅映射 registrant/technical；admin 不映射（Abuse 单独从 raw 提取）
                $contactKey = $m[1] === 'tech' ? 'technical' : $m[1];
                if ($contactKey === 'registrant' || $contactKey === 'technical') {
                    self::applyContactField($result[$contactKey], $m[2], $value);
                }
                continue;
            }
            // CNNIC 格式：Registrant 单行 = 注册人名称
            if ($key === 'registrant') {
                if ($result['registrant']['name'] === '') {
                    $result['registrant']['name'] = $value;
                }
                continue;
            }

            switch ($key) {
                case 'name server':
                case 'nserver':
                    $result['nameservers'][] = rtrim($value, '.');
                    break;
                case 'domain status':
                case 'status':
                    $result['status'][] = $value;
                    break;
                case 'creation date':
                case 'created on':
                case 'registered on':
                case 'created':
                case 'registration time':
                    if ($result['dates']['registration'] === '') {
                        $result['dates']['registration'] = $value;
                    }
                    break;
                case 'registry expiry date':
                case 'expiration date':
                case 'expires on':
                case 'expiry date':
                case 'paid-till':
                case 'expiration time':
                    if ($result['dates']['expiration'] === '') {
                        $result['dates']['expiration'] = $value;
                    }
                    break;
                case 'updated date':
                case 'last updated':
                case 'last modified':
                    if ($result['dates']['lastChanged'] === '') {
                        $result['dates']['lastChanged'] = $value;
                    }
                    break;
                case 'registrar whois server':
                case 'whois server':
                    if ($result['whoisServer'] === '') {
                        $result['whoisServer'] = $value;
                    }
                    break;
                case 'registrar':
                case 'sponsoring registrar':
                    // 仅当值不是 "WHOIS Server: xxx" 这类复合行时取注册商名
                    if (!str_contains($value, ':') && $result['registrar']['name'] === '') {
                        $result['registrar']['name'] = $value;
                    }
                    break;
            }
        }

        if ($registrarIanaId !== '') {
            $result['registrar']['ianaId'] = $registrarIanaId;
        }
        if ($abuse['email'] !== '' || $abuse['phone'] !== '') {
            $result['abuseContact']['email'] = $abuse['email'];
            $result['abuseContact']['phone'] = $abuse['phone'];
        }

        $result['nameservers'] = array_values(array_unique($result['nameservers']));
        $result['status'] = array_values(array_unique($result['status']));
    }

    private static function applyContactField(array &$contact, string $field, string $value): void
    {
        switch ($field) {
            case 'name':
                $contact['name'] = $value;
                break;
            case 'organization':
                $contact['org'] = $value;
                break;
            case 'phone':
                $contact['phone'] = $value;
                break;
            case 'email':
            case 'contact email':
                $contact['email'] = $value;
                break;
            case 'state/province':
            case 'province':
                $contact['province'] = $value;
                break;
            case 'referral url':
                $contact['contactUri'] = $value;
                break;
        }
    }

    /**
     * key 规范化：小写、"-" 转空格、压缩连续空格。
     */
    private static function normalizeKey(string $key): string
    {
        $key = strtolower(trim($key));
        $key = str_replace('-', ' ', $key);
        return preg_replace('/\s+/', ' ', $key) ?? $key;
    }

    /**
     * @return array{name: string, org: string, phone: string, email: string, province: string, contactUri: string}
     */
    private static function emptyContact(): array
    {
        return ['name' => '', 'org' => '', 'phone' => '', 'email' => '', 'province' => '', 'contactUri' => ''];
    }
}
