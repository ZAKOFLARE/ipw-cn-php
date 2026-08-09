<?php

declare(strict_types=1);

namespace App\Network;

use RuntimeException;

/**
 * DNSSEC 签名验证器：对应 Go 版 miekg/dns 的 RRSIG.Verify(dnskey, rrset)。
 *
 * 流程（RFC 4034 §3.1.8.1）：
 *   1. 重建 signature input = RRSIG_RDATA(不含 Signature) + 规范化编码的 RRset；
 *   2. 将 DNSKEY 裸公钥编码为 SPKI/DER（RSA / ECDSA / ED25519）；
 *   3. 用 openssl_verify 验证。
 *
 * 仅支持主流算法：RSA(SHA1/256/512)、ECDSAP256SHA256、ED25519；
 * 其他算法（DSA/GOST/ED448 等）返回 false（与 Go 版存在合理差异）。
 */
final class DnssecVerifier
{
    // DNSSEC 算法编号（RFC 4034 / 4035 / 6605 / 8080）
    public const ALGO_RSASHA1          = 5;
    public const ALGO_RSASHA1_NSEC3    = 7;
    public const ALGO_RSASHA256        = 8;
    public const ALGO_RSASHA512        = 10;
    public const ALGO_ECDSAP256SHA256  = 13;
    public const ALGO_ED25519          = 15;

    /**
     * 验证一条 RRSIG 对 RRset 的签名。
     *
     * @param array $rrsig   解析后的 RRSIG 字段：
     *                       type_covered, algorithm, labels, orig_ttl, expiration, inception,
     *                       key_tag, signer_name, signature(原始字节)
     * @param array $dnskey  解析后的 DNSKEY 字段：flags, protocol, algorithm, public_key(原始字节)
     * @param array $rrset   RRset 记录数组，每项：type(2字节值), rdata(原始字节)
     * @param string $owner  被签名 RRset 的 owner 名（小写）
     */
    public static function verify(array $rrsig, array $dnskey, array $rrset, string $owner): bool
    {
        if ($rrset === []) {
            return false;
        }
        $algorithm = (int) $rrsig['algorithm'];
        if ($dnskey['algorithm'] != $algorithm) {
            return false;
        }

        try {
            $keyPem = self::dnsKeyToSpkiPem((string) $dnskey['public_key'], $algorithm);
            $signature = (string) $rrsig['signature'];
            $data = self::buildSignatureInput($rrsig, $rrset, $owner);

            return match ($algorithm) {
                self::ALGO_RSASHA1, self::ALGO_RSASHA1_NSEC3 =>
                    openssl_verify($data, $signature, $keyPem, OPENSSL_ALGO_SHA1) === 1,
                self::ALGO_RSASHA256 =>
                    openssl_verify($data, $signature, $keyPem, OPENSSL_ALGO_SHA256) === 1,
                self::ALGO_RSASHA512 =>
                    openssl_verify($data, $signature, $keyPem, OPENSSL_ALGO_SHA512) === 1,
                self::ALGO_ECDSAP256SHA256 =>
                    openssl_verify($data, self::ecdsaRawToDer($signature), $keyPem, OPENSSL_ALGO_SHA256) === 1,
                self::ALGO_ED25519 =>
                    openssl_verify($data, $signature, $keyPem) === 1,
                default => false,
            };
        } catch (RuntimeException) {
            return false;
        }
    }

    /**
     * 重建签名数据流（RFC 4034 §3.1.8.1）。
     * signature input = RRSIG_RDATA(从 Type Covered 到 Signer Name，不含 Signature) + 规范化的 RRset。
     *
     * @param array $rrsig  解析后的 RRSIG 字段
     * @param array $rrset  RRset 记录：每项含 type / rdata
     * @param string $owner 小写 owner 名
     */
    private static function buildSignatureInput(array $rrsig, array $rrset, string $owner): string
    {
        // RRSIG 固定头（TypeCovered/Algorithm/Labels/OrigTTL/Expiration/Inception/KeyTag）
        $input = pack(
            'nCCNNNn',
            (int) $rrsig['type_covered'],
            (int) $rrsig['algorithm'],
            (int) $rrsig['labels'],
            (int) $rrsig['orig_ttl'],
            (int) $rrsig['expiration'],
            (int) $rrsig['inception'],
            (int) $rrsig['key_tag']
        );
        // Signer Name（canonical：小写、非压缩）
        $input .= self::encodeCanonicalName(strtolower((string) $rrsig['signer_name']));

        // RRset：按 canonical rdata 排序后逐条编码（owner 小写、TTL 用 RRSIG 的 OrigTTL）
        $records = [];
        foreach ($rrset as $rr) {
            $records[] = $rr['rdata'];
        }
        usort($records, 'strcmp');

        foreach ($records as $rdata) {
            $input .= self::encodeCanonicalName($owner);
            $input .= pack('n2', (int) $rrset[0]['type'], 1);          // TYPE + CLASS(IN)
            $input .= pack('N', (int) $rrsig['orig_ttl']);             // TTL = RRSIG OrigTTL
            $input .= pack('n', strlen($rdata)) . $rdata;              // RDLENGTH + RDATA
        }

        return $input;
    }

    /**
     * DNSKEY 裸公钥 → SPKI PEM（RSA / ECDSA P-256 / ED25519）。
     */
    private static function dnsKeyToSpkiPem(string $publicKey, int $algorithm): string
    {
        switch ($algorithm) {
            case self::ALGO_RSASHA1:
            case self::ALGO_RSASHA1_NSEC3:
            case self::ALGO_RSASHA256:
            case self::ALGO_RSASHA512:
                $der = self::rsaSpki($publicKey);
                break;
            case self::ALGO_ECDSAP256SHA256:
                $der = self::ecdsaSpki($publicKey);
                break;
            case self::ALGO_ED25519:
                $der = self::ed25519Spki($publicKey);
                break;
            default:
                throw new RuntimeException("unsupported DNSSEC algorithm: {$algorithm}");
        }

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----";
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new RuntimeException('failed to parse DNSKEY public key');
        }
        return $pem;
    }

    /**
     * RSA：DNSKEY 裸公钥（len(1) + e + n）→ DER SPKI。
     */
    private static function rsaSpki(string $publicKey): string
    {
        $eLen = ord($publicKey[0]);
        $e = substr($publicKey, 1, $eLen);
        $n = substr($publicKey, 1 + $eLen);
        if ($n === false || $n === '' || $e === false || $e === '') {
            throw new RuntimeException('invalid RSA DNSKEY');
        }

        $rsaPub = self::derSequence(self::derInteger($n) . self::derInteger($e));
        $algoId = self::derSequence(self::derOid("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") . "\x05\x00");
        return self::derSequence($algoId . self::derBitString($rsaPub));
    }

    /**
     * ECDSA P-256：DNSKEY 裸公钥 → DER SPKI。
     * 兼容两种 wire 形式：65 字节（0x04||X||Y，RFC 6605）与 64 字节（X||Y，部分权威实际如此）。
     */
    private static function ecdsaSpki(string $publicKey): string
    {
        if (strlen($publicKey) === 65 && $publicKey[0] === "\x04") {
            // 已是未压缩点
        } elseif (strlen($publicKey) === 64) {
            $publicKey = "\x04" . $publicKey;
        } else {
            throw new RuntimeException('invalid ECDSA DNSKEY');
        }
        $algoId = self::derSequence(
            self::derOid("\x2a\x86\x48\xce\x3d\x02\x01")            // id-ecPublicKey
            . self::derOid("\x2a\x86\x48\xce\x3d\x03\x01\x07")       // prime256v1
        );
        return self::derSequence($algoId . self::derBitString($publicKey));
    }

    /**
     * ED25519：DNSKEY 裸公钥（32 字节）→ DER SPKI。
     */
    private static function ed25519Spki(string $publicKey): string
    {
        if (strlen($publicKey) !== 32) {
            throw new RuntimeException('invalid ED25519 DNSKEY');
        }
        $algoId = self::derSequence(self::derOid("\x2b\x65\x70"));  // 1.3.101.112 Ed25519
        return self::derSequence($algoId . self::derBitString($publicKey));
    }

    /**
     * ECDSA 原始签名 r||s（64 字节）→ DER ECDSA-Sig-Value。
     */
    private static function ecdsaRawToDer(string $signature): string
    {
        if (strlen($signature) !== 64) {
            throw new RuntimeException('invalid ECDSA signature length');
        }
        $r = ltrim(substr($signature, 0, 32), "\x00");
        $s = ltrim(substr($signature, 32, 32), "\x00");
        if ($r === '' || $s === '') {
            throw new RuntimeException('invalid ECDSA signature');
        }
        return self::derSequence(self::derInteger($r) . self::derInteger($s));
    }

    /**
     * 域名 canonical 编码：label 序列 + 终止 0（小写、无压缩）。
     */
    private static function encodeCanonicalName(string $name): string
    {
        $name = rtrim($name, '.');
        if ($name === '') {
            return "\x00";
        }
        $out = '';
        foreach (explode('.', $name) as $label) {
            $out .= chr(strlen($label)) . $label;
        }
        return $out . "\x00";
    }

    // ---------- DER 编码原语 ----------

    private static function derLength(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xFF) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function derSequence(string $content): string
    {
        return "\x30" . self::derLength(strlen($content)) . $content;
    }

    private static function derInteger(string $bytes): string
    {
        // 正整数编码：高位为 1 时补 0x00
        if ($bytes !== '' && (ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    private static function derBitString(string $bytes): string
    {
        return "\x03" . self::derLength(strlen($bytes) + 1) . "\x00" . $bytes;
    }

    private static function derOid(string $bytes): string
    {
        return "\x06" . self::derLength(strlen($bytes)) . $bytes;
    }
}
