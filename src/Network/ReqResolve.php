<?php

declare(strict_types=1);

namespace App\Network;

use InvalidArgumentException;

/**
 * 请求级解析配置：dns / dns4 / dns6 与 resolve / resolve4 / resolve6。
 * 对应 Go 版 webtest/dns.go 的 ReqResolve。
 *
 *	dns=1.1.1.1:53                      两栈都用这个服务器（换服务器去问）
 *	dns4=1.1.1.1:53,dns6=[2400::1]:53   按栈覆盖（优先于 dns=）
 *	resolve=example.com:1.2.3.4         两栈都把 example.com 解析成 1.2.3.4（直接改答案）
 *	resolve4=example.com:1.2.3.4        只 IPv4 侧生效（优先于 resolve=）
 *	resolve6=example.com:[::1]          只 IPv6 侧生效（优先于 resolve=）
 *	resolve=www.example.com:origin.net  目标是域名时把它当作新的 host 再解析
 *
 * 只在「域名 → IP」这一步生效：detail / ssl / speed / tcping、SSRF 预检；
 * whois 与 dns 拨测不接 resolve*（前者只做归属查询，后者问的就是真实解析）。
 */
final class ReqResolve
{
    /** @var string[] dns= */
    private array $dns = [];
    /** @var string[] dns4= */
    private array $dns4 = [];
    /** @var string[] dns6= */
    private array $dns6 = [];
    /** @var array<string,string> resolve=：域名 → IP 或另一域名 */
    private array $resolve = [];
    /** @var array<string,string> resolve4= */
    private array $resolve4 = [];
    /** @var array<string,string> resolve6= */
    private array $resolve6 = [];

    /** 零值：没有任何请求级覆盖。 */
    public static function none(): self
    {
        return new self();
    }

    /**
     * 从 query 解析全部 6 个参数。
     * 参数存在但**全部项非法**时报错（上层返 400），避免「看起来指定了、实际被静默忽略」；
     * 缺省/为空则视为不覆盖。
     *
     * @param callable(string):?string $get
     * @throws InvalidArgumentException
     */
    public static function fromQuery(callable $get): self
    {
        $out = new self();

        foreach (['dns', 'dns4', 'dns6'] as $key) {
            $raw = trim((string) $get($key));
            if ($raw === '') {
                continue;
            }
            $list = self::normalizeServers($raw);
            if ($list === []) {
                throw new InvalidArgumentException(
                    "{$key} must be a comma-separated list of ip:port or DoH URLs"
                );
            }
            $out->{$key} = $list;
        }

        foreach (['resolve', 'resolve4', 'resolve6'] as $key) {
            $raw = trim((string) $get($key));
            if ($raw === '') {
                continue;
            }
            $map = self::parseResolveMap($raw);
            if ($map === []) {
                throw new InvalidArgumentException(
                    "{$key} must be a comma-separated list of host:ip or host:cname"
                );
            }
            $out->{$key} = $map;
        }

        return $out;
    }

    /**
     * 无任何请求级覆盖（此时才允许走共享缓存）。
     */
    public function empty(): bool
    {
        return $this->dns === [] && $this->dns4 === [] && $this->dns6 === []
            && $this->resolve === [] && $this->resolve4 === [] && $this->resolve6 === [];
    }

    /**
     * 按栈名取本次生效的 DNS 服务器：stack 为 "ipv4"/"ipv6" 时优先取对应覆盖，
     * 其余（含空串）取 dns= 默认；返回空数组表示用配置 dns-server。
     *
     * @return string[]
     */
    public function servers(string $stack = ''): array
    {
        if ($stack === 'ipv4' && $this->dns4 !== []) {
            return $this->dns4;
        }
        if ($stack === 'ipv6' && $this->dns6 !== []) {
            return $this->dns6;
        }
        return $this->dns;
    }

    /**
     * 返回该域名在指定族下的强制解析目标；"" 表示未命中（照常走 DNS）。
     * 优先级与 dns* 对称：resolve4/resolve6 非空时覆盖 resolve。
     * 目标是 IP 还是域名由调用方判断——IP 直连、域名当作新 host 再解析。
     */
    public function override(string $host, bool $wantV6): string
    {
        $map = $this->resolve;
        if ($wantV6 && $this->resolve6 !== []) {
            $map = $this->resolve6;
        } elseif (!$wantV6 && $this->resolve4 !== []) {
            $map = $this->resolve4;
        }
        return $map[self::canonicalHost($host)] ?? '';
    }

    /**
     * 请求级配置的规范化片段，拼在探测缓存键末尾。
     * 零值返回空串（缓存键与「没有任何请求级参数」时完全一致）；
     * 否则形如 ";dns=1.1.1.1:53,8.8.8.8:53;resolve6=example.com:[::1]"。
     *
     * 字段顺序固定、映射按键排序，避免参数书写顺序把同一个请求拆成两条缓存。
     */
    public function cacheKey(): string
    {
        $out = '';
        $serverFields = [['dns', $this->dns], ['dns4', $this->dns4], ['dns6', $this->dns6]];
        foreach ($serverFields as [$name, $values]) {
            if ($values === []) {
                continue;
            }
            $out .= ';' . $name . '=' . implode(',', $values);
        }

        $resolveFields = [
            ['resolve', $this->resolve],
            ['resolve4', $this->resolve4],
            ['resolve6', $this->resolve6],
        ];
        foreach ($resolveFields as [$name, $map]) {
            if ($map === []) {
                continue;
            }
            // map 顺序无关：必须按键排序，否则同一请求每次拼出的键都不同，缓存永远命不中
            $keys = array_keys($map);
            sort($keys, SORT_STRING);
            $pairs = [];
            foreach ($keys as $key) {
                $pairs[] = $key . ':' . $map[$key];
            }
            $out .= ';' . $name . '=' . implode(',', $pairs);
        }

        return $out;
    }

    /**
     * 解析「逗号分隔的 DNS 服务器」字符串并做格式校验，规则与配置侧一致：
     * 每项为 "ip:port"（UDP）或 http(s):// DoH URL；非法项丢弃。全非法时返回空数组。
     *
     * @return string[]
     */
    public static function normalizeServers(string $raw): array
    {
        $out = [];
        foreach (explode(',', $raw) as $item) {
            $item = trim($item);
            if ($item !== '' && self::validServerAddr($item)) {
                $out[] = $item;
            }
        }
        return $out;
    }

    /**
     * 校验单个 DNS 服务器地址的格式：
     *  - DoH URL：必须是 http/https 且 host 非空（不限制私网——节点自建内网 DoH 是合理部署）；
     *  - UDP：必须是 host:port 且端口合法（IPv6 必须写成 [addr]:port）。
     */
    public static function validServerAddr(string $server): bool
    {
        if (str_starts_with($server, 'http://') || str_starts_with($server, 'https://')) {
            $parts = parse_url($server);
            return is_array($parts) && ($parts['host'] ?? '') !== '';
        }
        return self::splitHostPort($server) !== null;
    }

    /**
     * 拆分 host:port（支持 [IPv6]:port）。格式非法返回 null。
     *
     * @return array{0: string, 1: int}|null
     */
    public static function splitHostPort(string $server): ?array
    {
        if (preg_match('/^\[([^\]]+)\]:(\d{1,5})$/', $server, $matches) === 1) {
            $port = (int) $matches[2];
            return ($port >= 1 && $port <= 65535) ? [$matches[1], $port] : null;
        }

        $pos = strrpos($server, ':');
        if ($pos === false || $pos === 0 || $pos === strlen($server) - 1) {
            return null;
        }
        $host = substr($server, 0, $pos);
        $portStr = substr($server, $pos + 1);
        // 裸 IPv6（未加方括号）会被误拆，必须拒绝
        if ($host === '' || str_contains($host, ':') || !ctype_digit($portStr)) {
            return null;
        }
        $port = (int) $portStr;
        if ($port < 1 || $port > 65535) {
            return null;
        }
        return [$host, $port];
    }

    /**
     * 把「域名:目标,域名:目标」切成映射表，非法项丢弃。
     * 每组按**第一个冒号**切：域名不含冒号，IPv6 目标可带或不带方括号。
     *
     * @return array<string,string>
     */
    private static function parseResolveMap(string $raw): array
    {
        $out = [];
        foreach (explode(',', $raw) as $item) {
            $item = trim($item);
            $idx = strpos($item, ':');
            if ($idx === false || $idx === 0 || $idx === strlen($item) - 1) {
                continue;
            }
            $host = self::canonicalHost(substr($item, 0, $idx));
            $target = trim(substr($item, $idx + 1));
            if ($host === '' || preg_match('#[ /\\\\]#', $host) === 1 || !self::validResolveTarget($target)) {
                continue;
            }
            $out[$host] = $target;
        }
        return $out;
    }

    /**
     * 归一化主机名：去首尾空白、转小写、去结尾的点，便于与查询域名匹配。
     */
    private static function canonicalHost(string $host): string
    {
        return strtolower(rtrim(trim($host), '.'));
    }

    /**
     * 目标必须是 IP 或形如域名的字符串（含点、无空格、无端口）。
     */
    private static function validResolveTarget(string $target): bool
    {
        $trimmed = trim($target, '[]');
        if (filter_var($trimmed, FILTER_VALIDATE_IP) !== false) {
            return true;
        }
        // 非 IP 却含冒号：视为「带端口」的误用，丢弃（映射不需要端口）
        if (str_contains($trimmed, ':') || !str_contains($trimmed, '.') || preg_match('#[ /\\\\]#', $trimmed) === 1) {
            return false;
        }
        return preg_match('/^[A-Za-z0-9._*-]+$/', $trimmed) === 1;
    }
}
