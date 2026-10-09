# XG2010G 下一轮实机测试

适用于本仓库 r16 和 `mwan4-pbr-compat` 0.2.0，配套 mossdef PBR 1.2.3。
先确认对应提交的 QEMU 集成通过，再重新编译/安装固件；旧固件不能验证新适配器。
配置步骤见 [PBR_COMPAT.md](PBR_COMPAT.md)。测试优先规则使用实际逻辑 WAN
名字，例如 `mwan4_strategy_unicom_prefer`，不是设备名 `lan3`。

## 目前就能测的项目

电信 PON PPPoE + 联通 DHCP、现有 1GbE 客户端足以完成以下功能测试：

| 项目 | 操作 | 应看到的结果 |
|---|---|---|
| 单 WAN 优先 | 给一台客户端建立源地址 + 测试端口的联通优先 PBR 规则；建立多个新 IPv4 连接 | 命中 PBR 规则的连接使用联通；普通连接仍按 MWAN4 配置分配 |
| 全局均衡 | 把同一测试规则目标改为 `mwan4_strategy_balanced` | 同层 member 按 weight 分配新连接；单个连接不要求跨两条 WAN |
| 联通断线 | 在连续测试中断开联通 WAN，记录时间、MWAN4 状态和新连接出口 | 达到探测失败阈值后，新连接转电信；原 NAT 会话可能重连 |
| 联通恢复 | 恢复联通并继续创建新连接 | 健康恢复后，联通优先规则重新走联通，目标名字不变 |
| fw4 重载 | 测试期间执行 `/etc/init.d/firewall reload`，随后创建新连接 | PBR goto 链存在，分流继续正常，无重复路由规则 |
| MWAN4 重载 | 执行 `/etc/init.d/mwan4 reload`，检查返回值和 PBR reload 日志 | 无启动错误；PBR 策略和健康路由恢复，LAN 管理连接可用 |
| 域名规则 | 给实际能访问的测试域名建 PBR 规则，客户端使用路由器 DNS，再重新连接 | dnsmasq nft set 加入解析地址，实际连接使用选定出口 |

域名测试需检查 IPv4；浏览器优先 IPv6 或客户端绕过路由器 DNS 会影响结果。
通过域名/端口命中后，再开 PPE/offload 复测出口和计数。fw4/服务重载及断线
会影响活跃连接，记录恢复时间即可，不能要求已有 TCP/NAT 会话完全无损迁移。

每个阶段采集下列只读信息，并标注测试规则名、客户端 IP、开始/恢复时间：

```sh
date
/usr/libexec/mwan4-pbr-compat status
ip -4 rule show
ip -4 route show table all
nft list ruleset
logread -e mwan4
logread -e pbr
cat /var/etc/mwan4-pbr.json
cat /var/etc/mwan4-pbr/reload.log
```

规则计数、外网出口地址及 WAN 收发计数要相互核对；仅 `ip route get ... mark ...`
能证明路由选择，不能证明应用流量已命中 PBR。测试目标需允许从两条 WAN 访问。
回传日志前可遮盖公网地址和域名，保留接口、mark、表号、计数及时间对应关系。

## 有条件后再测

- **吞吐叠加**：使用已链路协商至少 2.5Gbps 的客户端及交换链路，两个独立
  下载源/多连接测速同时跑，记录两条 WAN 的速率、PPE 计数、逐核心 CPU。
  现有 1GbE 客户端和 115 单一下载源不足以判断双 WAN 最高总吞吐。
- **双 PPPoE 重拨**：联通正式切 PPPoE 后，验证真实 L3 设备变化、策略目标
  保持、探测表及恢复出口。DHCP 断线通过不能替代 PPPoE 重拨验证。
- **IPv6**：两条线都取得地址/PD/网关后再收集 IPv6 路由和前缀信息。本轮
  adapter 仅支持 IPv4，当前只有电信 IPv6 属预期，不纳入双 IPv6 均衡验收。

不需要先购买新网卡，先完成现有设备能做的分流、切换、重载和 PPE 功能测试。
