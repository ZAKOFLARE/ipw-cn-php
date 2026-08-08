原始README.MD请前往 https://github.com/nomdn/ipw-cn 查看
本篇仅介绍其在虚拟主机中部署的重要注意事项.

1,域名的根绑定文件夹为/public

2,默认仅支持PHP8.1+

3,伪静态规则配置:
选择规则 ThinkPHP/Laravel
填入:

location / {
    try_files $uri $uri/ /index.php?$query_string;
}

可解决/返回404/204的绝大多数问题

4,若有CDN,优先推荐以http回源,cors处填写加速域名,如https://www.zakoflare.com

5,祝您使用愉快

6, "counter-url" 参数为统计数据收集接口,可以使用上一个发行版本[RC6.1]来减去填写和收集的步骤,我们需要收集一些调用量数据,所以我们不推荐您更改它,以免出现一些意料之外的错误
