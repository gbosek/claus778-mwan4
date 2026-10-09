# 多 WAN / PBR 方案对照与本次改进

## 是否必须安装 PBR

不必须。我们的 MWAN4 已负责线路探测、按 metric 分层、按 weight 分配
ECMP、故障恢复和来源/目的地址策略。需要按域名、端口、协议、MAC 或 VPN
匹配时，再使用独立 PBR 包。PBR 是匹配条件的提供者，MWAN4 是健康状态和
多 WAN 出口的管理者。

## 参考实现

| 实现 | 已核对的设计 | 我们采用的做法 |
|---|---|---|
| [OpenWrt mwan3](https://github.com/openwrt/packages/blob/master/net/mwan3/files/lib/mwan3/mwan3.sh) | 低 metric 优先，同层 weight 均衡；独立表、mark、sticky 和 last_resort | 保持 metric 语义；明确说明异层是主备；隔离 mark/规则所有权 |
| [mossdef mwan4](https://github.com/mossdef-org/mwan4/tree/28b384183bdf7ab43bef52d3d8ae648ba2565610) | ucode/nft 负责接口与 strategy 链；暴露 consumer API | 实现兼容 consumer API，由 Rust 管理出口和健康；PBR 负责匹配 |
| [mossdef PBR 1.2.3](https://github.com/mossdef-org/pbr/tree/d462378320e5ae88dfe475964faa16f80f5f70cd) | 读取接口 mark/chain；策略目标生成 goto；外部目标不创建 PBR 路由表 | 增加 balanced、逻辑 WAN 和 WAN_prefer 目标；固定源码提交用于 VM 回归 |
| [mini-mwan](https://github.com/alex-schwartzman/mini-mwan/blob/main/HIGH_LEVEL_DESIGN.md) | 配置与实时状态分离，直接管理核心路由，支持主备/多出口 | 保持内核 ECMP；显式处理逻辑接口到实时 L3 设备的映射 |

这些实现不能同时接管同一套路由。适配层不复制 mossdef 的 ucode 多 WAN
守护进程，也不替换我们已验证的 Rust/ECMP 路径。

## 本次实现

- 默认 `pbr_mode=standalone`；可选 addon 安装后才可启用 mossdef consumer 模式。
- PBR 的域名、端口等匹配可指向全局均衡或某条优先 WAN。
- 优先 WAN 不可用/降级时，保留 mark 规则并回退到当前 main 表，避免误落入
  原生来源策略。WAN 恢复后自动回到其独立表。
- 查询 WAN 默认路由前先保留 main 的具体路由，保护 LAN、直连和 VPN 路由。
- 使用 `0x3f00`，保留其他 mark 位；拒绝与 PBR netifd 扩展及危险清理区间冲突。
- fw4 重载使用幂等 nft 批次；MWAN4 启动发布接口后重载已启用的 PBR。
- 停止服务按 protocol 77 和保留优先级清理自有 mark 规则；保持 PBR 链引用有效。
- LuCI 增加可选 PBR 集成模式，更新安装配置说明，核心/LuCI release 升至 r16。

## 验证范围

本地：Rust 单元测试、clippy、ucode renderer/consumer API、真实隔离 netns
路由优先级与回退、真实 nft 数据包 mark、幂等重载、init 回归、JS/Python 语法。
CI 新增固定版本 PBR 1.2.3 的实际 OpenWrt/ImmortalWrt 集成回归：策略 goto
规则加载、fw4 重载、DHCP WAN 离线/恢复、停止清理。

尚不支持任意成员子集策略、严格 WAN-only 断路、跨连接的客户端 sticky 策略。
集成策略暂限 IPv4；独立 IPv6 健康、IPv6 源前缀选择仍需另外实现和验证。
PPE/offload、实际域名/端口命中、既有 NAT 会话恢复必须在 XG2010G 验证。

## 对当前实机测试的解释

- 联通 DHCP 没有 IPv6，暂时只有电信 IPv6 符合当前线路条件。不能用开启
  `accept_ra` 就断言获得 IPv6；正式双 PPPoE 后再核对地址、PD、网关和路由。
- metric 不同是主备语义；现在已补说明和警告，均衡需使用同一最低 metric。
- 115 网盘和 1GbE 客户端都有可能限制吞吐。现有日志未建立真实双线叠加上限。
- 先更新源码/固件并安装匹配的 addon/PBR；当前旧固件不具有本次 consumer API。

配置与回退步骤见 [PBR_COMPAT.md](PBR_COMPAT.md)。
