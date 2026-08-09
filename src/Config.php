<?php

declare(strict_types=1);

namespace App;

/**
 * 应用配置：读取 config/setting.json，环境变量优先，未配置则使用默认值。
 * 与原 Go 版 readConfig() 行为对齐。
 */
final class Config
{
    public string $port;
    public string $ghProxy;
    public string $singleStack;
    public string $dnsServer;
    public bool $blockPrivateIps;
    /** @var string[] */
    public array $acceptDomains = [];
    public string $counterUrl = '';
    public string $dnssecServer = '';

    public static function load(string $rootDir): self
    {
        $config = new self();
        $file = $rootDir . '/config/setting.json';
        $values = [];
        if (is_file($file)) {
            $decoded = json_decode((string) file_get_contents($file), true);
            if (is_array($decoded)) {
                $values = $decoded;
            }
        }

        // 环境变量优先，其次配置文件，最后默认值
        $port = getenv('PORT') ?: ($values['port'] ?? '');
        $config->port = $port !== '' ? (string) $port : '8080';

        $config->ghProxy = getenv('GH_PROXY') ?: ($values['gh-proxy'] ?? '');
        $config->singleStack = strtolower(trim(getenv('SINGLE_STACK') ?: ($values['single-stack'] ?? '')));
        $config->dnsServer = getenv('DNS_SERVER') ?: ($values['dns-server'] ?? '');
        if ($config->dnsServer === '') {
            $config->dnsServer = '119.28.28.28:53';
        }

        $blockEnv = getenv('BLOCK_PRIVATE_IPS');
        $config->blockPrivateIps = $blockEnv !== false
            ? !in_array(strtolower($blockEnv), ['false', '0', ''], true)
            : (($values['block-private-ips'] ?? true) === true);

        $cors = getenv('CORS') ?: ($values['cors'] ?? '');
        if ($cors !== '') {
            $config->acceptDomains = array_values(array_filter(array_map('trim', explode(',', $cors))));
        }

        $config->counterUrl = getenv('COUNTER_URL') ?: ($values['counter-url'] ?? '');

        $config->dnssecServer = getenv('DNSSEC_SERVER') ?: ($values['dnssec-server'] ?? '');

        return $config;
    }
}
