# LEMIPW-PHP-V3 部署教程

LemonIPW的PHP后端替代。覆盖kangle虚拟主机与nginx两种部署方式

## 一、环境要求

| 项目 | 要求 |
|------|------|
| PHP | **≥ 8.0**（建议 8.2+，代码使用 `str_starts_with` / `match` / 属性提升等 8.0 语法） |
| 扩展 | curl、sockets、openssl、json（虚拟主机一般自带） |
| 目录权限 | `storage/cache/` 必须可写（缓存 + 计数熔断标记都存这里） |

## 二、目录结构

上传并解压后，站点目录应该是这样的（`public/` 是唯一 Web 入口）：

```
站点根/
├── public/                 ← Web 根目录（面板绑定/nginx root 指向这里）
│   └── index.php
├── src/                    ← 业务代码
├── config/
│   └── setting.json
├── deploy/
│   └── kangle.rewrite      ← kangle 伪静态模板
└── storage/
    └── cache/              ← 需可写
```

## 三、方式一：kangle 虚拟主机（已验证可行）

### 步骤

1. 上传 zip 解压到站点目录，确认 `public/index.php` 存在；
2. kangle 面板把**网站根目录**指向 `public/`（能看到 index.php 的那一层）；
3. 确认站点的 **PHP 版本 ≥ 8.0**（kangle 老主机常见 5.x/7.x，不够会报函数错误）；
4. 把 `deploy/kangle.rewrite` 复制到 **`public/` 目录下**（与 index.php 同级），文件名保持 `.rewrite`；
5. 重启站点（kangle 面板重启按钮）；
6. 验证（见下）。

### .rewrite 内容

```
location / {
    try_files $uri $uri/ /index.php?$query_string;
}
```

面板备选写法（kangle 面板 → 虚拟主机 → rewrite）：

```
rewrite ^/v1/.* /index.php last;
rewrite ^/$ /index.php last;
```

### 验证

```bash
curl https://example.com/v1/dns/a/example.com
```

- 返回 `{"domain":"example.com","record":[...]}` → 成功；
- 返回 `{"error":"Not Found"}`（JSON）→ rewrite 把 REQUEST_URI 改写了，换上面 `.rewrite` 的 try_files 写法；
- 返回 kangle 的 HTML 404 → `.rewrite` 没生效（检查文件名/位置/是否重启）。

## 四、方式二：nginx

```nginx
server {
    listen 80;
    server_name example.com;
    root /www/wwwroot/example.com/public;      # 指向 public
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/tmp/php-cgi-82.sock;   # 按实际 PHP 版本
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
}
```

宝塔等面板：网站 → 设置 → **伪静态**，选择 ThinkPHP 规则（效果同上）。

## 五、setting.json 配置项

```json
{
    "port": 80,
    "gh-proxy": "",
    "single-stack": "",
    "dns-server": "119.28.28.28:53",
    "block-private-ips": true,
    "cors": "",
    "counter-url": "https://api.2409178.xyz/data/zakoflare/web.php?add=1",
    "dnssec-server": "8.8.8.8:53,9.9.9.9:53",
    "access-token": "",
    "node-id": "",
    "error-pages": {}
}
```

| 配置项 | 取值 | 留空/默认行为 |
|--------|------|--------------|
| `port` | 数字 | 默认 8080（仅参考，实际端口由服务器决定） |
| `gh-proxy` | URL 前缀 | 已无实际用途（IP 库下载砍掉了），保留兼容 |
| `single-stack` | `""` / `ipv4` / `ipv6` | 空 = 双栈；其他值按双栈处理 |
| `dns-server` | 逗号分隔的 `IP:PORT` 或 `http(s)://` DoH URL | 默认 `119.28.28.28:53`（国内可达）。第一个为主，查询失败自动切换下一个；IPv6 服务器写 `[addr]:port` |
| `block-private-ips` | **布尔** `true`/`false` | 默认 true（SSRF 防护）。**必须写 JSON 布尔**，写字符串 `"false"` 会关闭防护 |
| `cors` | 逗号分隔的 Origin | 空 = 允许所有来源 |
| `counter-url` | 统计接口 URL | 空 = 关闭计数 |
| `dnssec-server` | 逗号分隔的 DNS | 默认 `8.8.8.8:53,9.9.9.9:53`。DNSSEC 查询专用（国内公共 DNS 的 53 端口不响应 DNSSEC 的 DO 位），网络失败自动轮询 |
| `access-token` | 字符串 | 空 = 关闭鉴权；非空时 `/v1/*` 接口要求请求头 `Authorization: Bearer <access-token>`，否则 418（对齐 Go 版 tokenCheck，健康检查 `/` 不受影响） |
| `node-id` | 字符串 | 节点身份标识。非空时随计数请求追加 `node=<node-id>` 参数，供统计端区分节点；留空不上报 |
| `error-pages` | 对象 `{状态码: URL 或内容}` | 空对象/未配置 = 默认 JSON 错误。键支持 `401`/`403`/`404`/`418`/`500`/`204`。值以 `http(s)://`、`//`、`/` 开头 → **302 重定向**到该地址；否则作为响应体输出（自动嗅探 Content-Type：HTML/JSON/纯文本）。`204` 无响应体，只支持 URL 重定向。空值视为未自定义 |

环境变量优先级高于配置文件：`PORT` / `SINGLE_STACK` / `DNS_SERVER` / `BLOCK_PRIVATE_IPS` / `CORS` / `COUNTER_URL` / `DNSSEC_SERVER` / `ACCESS_TOKEN` / `NODE_ID` / `ERROR_PAGES`（JSON 字符串）。

## 六、接口清单

| 端点 | 说明 |
|------|------|
| `GET /` | 健康检查 `{"status":"ok"}` |
| `GET /v1/detail/*url` | 网站可达性检测（分阶段计时） |
| `GET /v1/ssl/*url` | SSL 证书检查 |
| `GET /v1/dns/:type/*domain` | DNS 解析（a/aaaa/cname/mx/ns/ptr/srv/txt/caa） |
| `GET /v1/dnssec/:domain` | DNSSEC 验证 |
| `GET /v1/tcping/:ip` | TCPing（`?port=&count=`） |
| `GET /v1/speed/:version/*url` | 网站测速（v4/v6） |
| `GET /v1/whois/:domain` | WHOIS 查询 |

### 请求级解析参数（自定义 DNS / 自定义解析）

`/v1/detail`、`/v1/ssl`、`/v1/speed`、`/v1/tcping`、`/v1/dns` 额外接受一组 query 参数，用于按次覆盖解析行为（与 Go 版一致）：

| 参数 | 取值 | 说明 |
|------|------|------|
| `dns` | 逗号分隔的 `ip:port` 或 `http(s)://` DoH URL | 本次查询改用指定 DNS 服务器，取代配置的 `dns-server` |
| `dns4` | 同上 | 只覆盖 IPv4 族解析，**优先于 `dns`** |
| `dns6` | 同上 | 只覆盖 IPv6 族解析，**优先于 `dns`** |
| `resolve` | 逗号分隔的 `域名:目标`，目标为 IP 或域名 | 强制改写某域名的解析结果（两栈通用） |
| `resolve4` | 同上 | 只影响 IPv4 侧；非空时 IPv4 侧**只用这张表** |
| `resolve6` | 同上 | 只影响 IPv6 侧；非空时 IPv6 侧**只用这张表** |

- `dns*`（换服务器去问）与 `resolve*`（直接改答案）正交，可同时使用。
- `resolve*` 目标是 IP → 拨号直接连该 IP（仍做私网校验）；目标是域名 → 当作新 host 继续解析。
- 参数存在但**所有项都非法**时返回 `400`，不会静默忽略；非法项在混写时被丢弃。
- `dns` 拨测只取 `dns*`（问的就是真实解析结果，改写会自相矛盾）；`whois` / `dnssec` 不接受这些参数。
- 带覆盖的请求按独立缓存键缓存，不同服务器/映射的结果不会互相串味。

```bash
# 换服务器解析
curl "https://example.com/v1/detail/https://www.example.com?dns=1.1.1.1:53"
# DoH 服务器
curl "https://example.com/v1/dns/a/example.com?dns=https://doh.pub/dns-query"
# 强制把域名解析到指定 IP
curl "https://example.com/v1/tcping/example.com?port=443&resolve4=example.com:93.184.216.34"
```

## 七、常见问题

| 现象 | 原因 |
|------|------|
| kangle 的 "No such file or directory" 404 | 伪静态没配 → 见方式一步骤 4 |
| 访问 `/` 返回 204 | 旧版 CORS bug，已修复 → 确认 `public/index.php` 是最新代码 |
| 报 `str_starts_with()` 未定义 | PHP < 8.0 → 换 PHP 版本 |
| detail/dns 端点全报 DNS 超时 | `dns-server` 配了国内不可达的地址（如 1.1.1.1）→ 改 `119.28.28.28:53` |
| `storage/cache/counter_fuse.json` 出现 | 计数接口不可达触发熔断（1 小时后自动恢复），可删文件立即恢复 |
