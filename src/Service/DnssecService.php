<?php

declare(strict_types=1);

namespace App\Service;

use App\Config;
use App\Network\DnsClient;
use App\Network\DnssecVerifier;
use RuntimeException;

/**
 * DNSSEC 查询：对应 Go 版 webtest/dnssec.go 的 ResolveDNSSEC。
 * 输出与 Go 版 DNSSECResult json tag 完全一致。
 *
 * 注意：Go 版该函数几乎不返回 error（查询失败都写入 validation 字段并返回结果），
 * 因此本服务同样不抛异常，任何失败都组装为 200 结果返回。
 */
final class DnssecService
{
    /** 默认 DNSSEC 专用 DNS 列表（国内公共 DNS 的 53 端口不响应 DO 位，需独立配置） */
    private const DEFAULT_SERVERS = ['8.8.8.8:53', '9.9.9.9:53'];

    public function __construct(private Config $config)
    {
    }

    public function check(string $domain): array
    {
        $result = [
            'domain'      => $domain,
            'enabled'     => false,
            'valid'       => false,
            'has_rrsig'   => false,
            'has_dnskey'  => false,
            'has_ds'      => false,
            'algorithm'   => 0,
            'key_tag'     => 0,
            'signer_name' => '',
            'validation'  => '',
            'duration'    => 0.0,
        ];

        // 解析 DNSSEC 专用 DNS 列表（逗号分隔，支持端口），网络层失败时自动轮询下一个
        $servers = $this->config->dnssecServer !== ''
            ? array_values(array_filter(array_map('trim', explode(',', $this->config->dnssecServer))))
            : self::DEFAULT_SERVERS;
        if ($servers === []) {
            $servers = self::DEFAULT_SERVERS;
        }

        // 1. 查询 DNSKEY（带 EDNS0 DO）：轮询服务器直到网络层成功
        $dns = null;
        $lastErr = '';
        foreach ($servers as $server) {
            try {
                $dns = new DnsClient($server);
                $raw = $dns->queryRaw($domain, DnsClient::TYPE_MAP['DNSKEY']);
                break;
            } catch (RuntimeException $e) {
                $lastErr = $e->getMessage();
            }
        }

        if ($dns === null) {
            $result['validation'] = 'DNSKEY query failed: ' . $lastErr;
            return $result;
        }

        $result['duration'] = $raw['duration'];

        if ($raw['rcode'] !== 0) {
            $result['validation'] = 'DNSKEY query failed with Rcode ' . $raw['rcode'];
            return $result;
        }

        $dnskeyList = [];
        foreach ($raw['answers'] as $ans) {
            if ($ans['type'] !== DnsClient::TYPE_MAP['DNSKEY']) {
                continue;
            }
            $dnskey = self::parseDnsKey($ans['rdata']);
            if ($dnskey !== null) {
                $dnskeyList[] = $dnskey;
                $result['has_dnskey'] = true;
            }
        }

        if ($dnskeyList !== []) {
            $result['key_tag'] = self::dnsKeyTag($dnskeyList[0]);
            $result['algorithm'] = $dnskeyList[0]['algorithm'];
        }

        // 2. 查询 A 记录（带 EDNS0 DO），收集 A RRset 与 RRSIG
        try {
            $rawA = $dns->queryRaw($domain, DnsClient::TYPE_MAP['A']);
        } catch (RuntimeException) {
            $rawA = ['rcode' => -1, 'answers' => []];
        }

        if ($rawA['rcode'] === 0) {
            $aRrset = [];
            $rrsigList = [];
            foreach ($rawA['answers'] as $ans) {
                if ($ans['type'] === DnsClient::TYPE_MAP['A']) {
                    $aRrset[] = ['type' => 1, 'rdata' => $ans['rdata']];
                } elseif ($ans['type'] === DnsClient::TYPE_MAP['RRSIG']) {
                    $sig = self::parseRrsig($rawA['msg'], $ans);
                    if ($sig !== null) {
                        $rrsigList[] = $sig;
                        $result['has_rrsig'] = true;
                    }
                }
            }

            // 3. 用 DNSKEY 逐条验证 RRSIG
            foreach ($rrsigList as $rrsig) {
                foreach ($dnskeyList as $dnskey) {
                    if (DnssecVerifier::verify($rrsig, $dnskey, $aRrset, strtolower($domain))) {
                        $result['enabled'] = true;
                        $result['valid'] = true;
                        $result['algorithm'] = $dnskey['algorithm'];
                        $result['key_tag'] = self::dnsKeyTag($dnskey);
                        $result['signer_name'] = $rrsig['signer_name'];
                        $result['validation'] = sprintf(
                            'DNSSEC 验证通过 (算法: %d, KeyTag: %d)',
                            $dnskey['algorithm'],
                            self::dnsKeyTag($dnskey)
                        );
                        return $result;
                    }
                }
            }

            if ($rrsigList !== [] && $dnskeyList !== []) {
                $result['enabled'] = true;
                $result['valid'] = false;
                $result['validation'] = sprintf(
                    'RRSIG 验证失败: %d 条 RRSIG, %d 个 DNSKEY，无匹配签名',
                    count($rrsigList),
                    count($dnskeyList)
                );
                return $result;
            }
        }

        // 4. 查询 DS 记录
        try {
            $rawDS = $dns->queryRaw($domain, DnsClient::TYPE_MAP['DS']);
            if ($rawDS['rcode'] === 0) {
                foreach ($rawDS['answers'] as $ans) {
                    if ($ans['type'] === DnsClient::TYPE_MAP['DS']) {
                        $result['has_ds'] = true;
                        break;
                    }
                }
            }
        } catch (RuntimeException) {
            // DS 查询失败忽略（对齐 Go 版 _,_）
        }

        // 5. 兜底分类
        if ($result['has_rrsig'] && $result['has_dnskey']) {
            $result['enabled'] = true;
            $result['valid'] = false;
            $result['validation'] = '存在 RRSIG 和 DNSKEY，但签名验证未通过';
        } elseif ($result['has_rrsig']) {
            $result['enabled'] = true;
            $result['valid'] = false;
            $result['validation'] = '存在 RRSIG，但缺少 DNSKEY';
        } elseif ($result['has_dnskey']) {
            $result['enabled'] = false;
            $result['valid'] = false;
            $result['validation'] = '存在 DNSKEY，但缺少 RRSIG';
        } else {
            $result['enabled'] = false;
            $result['valid'] = false;
            $result['validation'] = '未检测到 DNSSEC 记录';
        }

        return $result;
    }

    /**
     * 解析 DNSKEY RDATA：Flags(2) + Protocol(1) + Algorithm(1) + PublicKey。
     *
     * @return array{flags: int, protocol: int, algorithm: int, public_key: string}|null
     */
    private static function parseDnsKey(string $rdata): ?array
    {
        if (strlen($rdata) < 4) {
            return null;
        }
        $fields = unpack('nflags/Cprotocol/Calgorithm', substr($rdata, 0, 4));
        if ($fields === false) {
            return null;
        }
        return [
            'flags'      => $fields['flags'],
            'protocol'   => $fields['protocol'],
            'algorithm'  => $fields['algorithm'],
            'public_key' => substr($rdata, 4),
        ];
    }

    /**
     * 解析 RRSIG RDATA（RDATA 在消息中的绝对偏移，Signer Name 可能为压缩指针）。
     *
     * @param array{type: int, rdata: string, rdataOffset: int} $ans
     * @return array{type_covered: int, algorithm: int, labels: int, orig_ttl: int,
     *               expiration: int, inception: int, key_tag: int, signer_name: string,
     *               signature: string}|null
     */
    private static function parseRrsig(string $msg, array $ans): ?array
    {
        $rdata = $ans['rdata'];
        if (strlen($rdata) < 18) {
            return null;
        }
        $fields = unpack(
            'ntype_covered/Calgorithm/Clabels/Norig_ttl/Nexpiration/Ninception/nkey_tag',
            substr($rdata, 0, 18)
        );
        if ($fields === false) {
            return null;
        }

        // Signer Name：从 rdataOffset+18 开始（可能含压缩指针，需要整条 msg）
        $offset = $ans['rdataOffset'] + 18;
        $signerName = (new DnsClient())->decodeName($msg, $offset);

        $signature = substr($rdata, $offset - $ans['rdataOffset']);

        return [
            'type_covered' => $fields['type_covered'],
            'algorithm'    => $fields['algorithm'],
            'labels'       => $fields['labels'],
            'orig_ttl'     => $fields['orig_ttl'],
            'expiration'   => $fields['expiration'],
            'inception'    => $fields['inception'],
            'key_tag'      => $fields['key_tag'],
            'signer_name'  => $signerName,
            'signature'    => $signature,
        ];
    }

    /**
     * DNSKEY KeyTag（RFC 4034 Appendix B）：
     * 对完整 RDATA（Flags+Protocol+Algorithm+PublicKey）按 16-bit 大端字累加。
     */
    private static function dnsKeyTag(array $dnskey): int
    {
        $rdata = pack('nCC', $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'])
            . $dnskey['public_key'];
        $ac = 0;
        $len = strlen($rdata);
        for ($i = 0; $i < $len; $i++) {
            $ac += ($i % 2 === 0) ? (ord($rdata[$i]) << 8) : ord($rdata[$i]);
        }
        $ac += ($ac >> 16) & 0xFFFF;
        return $ac & 0xFFFF;
    }
}
