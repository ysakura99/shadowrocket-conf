# shadowrocket-conf

- [global-public-dns.conf](https://raw.githubusercontent.com/ysakura99/shadowrocket-conf/main/dist/global-public-dns.conf)
- [global-home-dns.conf](https://raw.githubusercontent.com/ysakura99/shadowrocket-conf/main/dist/global-home-dns.conf)
- [china-public-dns.conf](https://raw.githubusercontent.com/ysakura99/shadowrocket-conf/main/dist/china-public-dns.conf)
- [china-home-dns.conf](https://raw.githubusercontent.com/ysakura99/shadowrocket-conf/main/dist/china-home-dns.conf)

Action 每周一重建 `dist/` 推回 main,以上链接即最新;手动更新 `uv run build.py`;宏(内网段/内网 DNS)在 `build.py` 顶部。小火箭「配置」里直接添加上面的 URL 即可。

| 配置 | 路由(块顺序见各 conf `[Rule]` 开头目录) | DNS |
|---|---|---|
| `global-public-dns` | • lan<br>• cn(geosite+geoip)DIRECT<br>• FINAL,PROXY | cloudflare-dns.com/dns.google DoH `#proxy`(域名由代理侧解析);bootstrap/fallback = dns.alidns.com + doh.pub DoH,`[Host]` 钉 223.5.5.5 / 1.12.12.12;DIRECT 域名走系统 DNS |
| `global-home-dns` | 同上 | `192.168.8.2#proxy`(始终走代理回家,单一路径);proxy-dns-server = alidns+doh.pub(节点域名 bootstrap 防死锁) |
| `china-public-dns` | • lan<br>• ai DIRECT<br>• gfw DIRECT<br>• bigco(11 家 geosite+geoip)DIRECT<br>• cn(geosite+geoip)PROXY<br>• FINAL,DIRECT | cloudflare-dns.com/dns.google DoH 直连(人在国外,本地即国外出),`[Host]` 钉 1.1.1.1 / 8.8.4.4;proxy-dns-server = cloudflare |
| `china-home-dns` | 同上 | 同 global-home-dns,但 proxy-dns-server = cloudflare |

拓扑前提:出国回国的 PROXY 都指向同一个家里端点(国内);最终出口由 8.2 的 mihomo 决定。所以 192.168.8.2 经 PROXY 永远可达,home-dns 两个方向都能用;global 的 DoH `#proxy` 是"到家 → 家里 mihomo 再出国"双跳,仍从国外出。

设计要点:

- 全内联零外链:GitHub raw 国内不可达,避免鸡生蛋;13 万行 hash/trie 匹配无性能问题
- geoip cn 内联,省掉自定义 mmdb
- 域名规则在前、IP 规则带 no-resolve;china 的 geoip cn 例外,让漏网 CN 域名按 IP 兜底
- `+.foo` → DOMAIN-SUFFIX、裸域名 → DOMAIN、CIDR → IP-CIDR,不认识的行 WARN 跳过
- ipv6=false 但 v6 规则保留
