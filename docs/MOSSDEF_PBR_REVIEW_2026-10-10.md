# mossdef PBR 1.2.3 对照与本次修正

核对：[仓库](https://github.com/mossdef-org/pbr)、
[1.2.3 README](https://github.com/mossdef-org/pbr/blob/1.2.3/README.md)、
[官方文档](https://docs.mossdef.org/pbr/)及实际源码。
1.2.3 分支当前为 `d462378320e5ae88dfe475964faa16f80f5f70cd`，与我们的
QEMU 固定版本相同。主分支说明 1.2.2 为稳定版、1.2.3 为开发版。

## 已确认的接口与职责

- 1.2.3 README 仍称 shell 实现，但实际消费 API 的代码在 `platform.uc`、
  `pbr.uc`；使用 ucode。链接文档声明适用 1.2.2，不能替代源码核对。
- PBR 从 `require('mwan4')` 取得接口 mark/chain 和 strategy；策略生成 goto，
  不另建策略路由表。因此 PBR 匹配流量，Rust MWAN4 决定出口与健康回退。
- 外部 WAN_prefer 的回退语义由 MWAN4 决定；PBR strict_enforcement 不会把
  该目标改为严格断路。普通 VPN 目标仍由 PBR 管理，需要单独验证失效行为。
- DNS 动态域名集合使用 `dnsmasq.nftset` 及实际带 nftset 功能的 dnsmasq。
  此固定版本的 resolver 检测没有为任意 smartdns/unbound set 模式提供通用
  支持，不能仅依据主分支 Highlights 就承诺它们与适配器自动兼容。
- IPv6 是 PBR 自身能力；我们的策略适配层仍限 IPv4。DNS 重定向策略与
  流量出口策略是不同配置项，不能把改 DNS 服务器当作改 WAN。

## 本次实际修正

1. 统一 ucode 开关解析，接受 PBR 的 `yes/on/true` 及正数形式。之前仅
   检查 `ipv6_enabled=1` 会漏掉 `true`；启用 PBR 的 `true` 也会被误拒绝。
2. netifd_enabled 开启时拒绝策略模式，即使扩展文件暂未存在，避免后续
   PBR 安装/升级把 netifd 扩展重新激活。现有扩展文件检查继续保留。
3. consumer API 与诊断支持常用布尔拼写；init 对 `enabled=true` 也会
   生成 PBR mark 排除掩码，保留外部 VPN/普通 PBR 规则优先级关系。
4. 修正诊断中的 strict 说明，补 DNS/QUIC、规则顺序及 output/prerouting
   配置说明。core/LuCI 升 r18，adapter 升 0.2.2。

回归包含 ucode 开关矩阵、consumer API、诊断脚本及 QEMU 真实配置：
IPv6/netifd 为 true 时拒绝 reload；PBR enabled=true 能启动，且原生策略
同时排除 `0xff0000` 与 `0x3f00`。保留之前 WAN 回退、fw4 重载和清理测试。

## 实机验证要点

先验证源 IP + TCP/UDP 端口规则，再测域名集合实际加入地址、规则计数和 WAN
出口。域名测试让客户端使用路由器 DNS，区分缓存、DoH、IPv6 和 QUIC。
启用 PPE 后再复测命中与失败恢复；VM 成功不表示域名全链路或 PPE 已通过。
完整配置见 [PBR_COMPAT.md](PBR_COMPAT.md)，硬件步骤见
[XG2010G_PBR_TEST_PLAN_2026-10-10.md](XG2010G_PBR_TEST_PLAN_2026-10-10.md)。
