# VLESS REALITY v2：有界的目标握手记录镜像

状态：待实施。基线：meow-rs `48dd9555`；上游参考：xtls/reality `9234c772ba8f`、Xray-core `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。本规格补充 `listener-vless.md` 的 REALITY 入站契约；未改变的行为仍以 v1 规格为准。`vless-reality-design-test.md` 中的出站节点证据不替代本规格的入站门禁。

## 1. 决策、适用范围与保真承诺

- 默认 `dial-first`：在分类同一入站连接的同时，向固定配置目标 `dest` 建立一个 TCP 连接。认证通过且目标模板可用时，以本地 TLS 密钥生成与**本次目标探测冻结前缀**形状匹配的记录；提交前不兼容时，在允许回落且有配额的前提下复用同一目标 socket 进入 cover。任何模式都不得静默地从 v2 切换到 v1 本地握手。
- 显式 `off` 保留 v1 路径：REALITY 认证成功时不解析、不拨号、不依赖 `dest`；普通 cover 仍由监听器按 v1 规则拨号。标准 TLS、REALITY 出站、VLESS 用户校验、`IN-USER`、Vision END/DIRECT 和 XUDP 数据面不变。
- 镜像比较对象是 TCP 重组后的 TLS 记录：一条 ServerHello（SH）记录、零或一条合规伪 CCS、连续的 N 条完整 `0x17` 记录。SH 保留 legacy version、协商版本、cipher、session-id echo、压缩字段、扩展线序与长度及记录头；只替换 random 和完整 key-share 值。CCS（如有）逐字节相等。逐条比较加密记录的五字节头，**不**比较密文或 tag。
- 常见 FoxIO JA4S 的 `a` 部分包含传输标记、TLS 版本、扩展计数和 ALPN 摘要；`b` 是所选 cipher；`c` 是按线序的扩展类型列表的摘要。本规格允许的 TLS 1.3 SH 不含 ALPN；位于加密 EE 内的 ALPN 对被动观察者不可见，该项通常为 `00`。JA4S 不覆盖扩展值或长度、random、key-share 值、CCS、加密记录长度或 TCP 行为，只作派生诊断，不能替代字段比较。
- 不承诺识别真实目标完整首飞行的终点，也不承诺跨 CH 或跨连接指纹相等、TCP 分段或合包、发送时刻、拥塞窗口、FIN/RST 时刻、应用层行为或不可区分性。减少 syscall 不等于控制分段。对于无法解密的目标响应，不能判定每条 `0x17` 记录的语义。
- v2.0 镜像支持非 HRR、非 PSK 的 TLS 1.3，组为 `X25519`（`0x001d`）和 `X25519+ML-KEM-768`（`0x11ec`），套件见 §4.2。使用目标实际选择且客户端实际提供的组，不改写 CH、不降组、不重新拨号。其他组及不兼容模板按提交前规则进入 cover。无本地 0-RTT、客户端证书、ALPN 协商、NST、ECH 接受、后台探针、模板缓存、连接池或可变目标。
- 真实目标可能在收到客户端 Finished 前发送 NST：RFC 8446 §4.6.1 允许在不请求客户端证书时预计算 transcript，pinned 上游也有该路径。其密文在冻结前只作为候选记录桶；准备期间出现的新增字节按 §6 处理，提交后按 §7 处理。不得向目标发送本地生成或从客户端收到的 Finished 来探测 NST。

**时序非目标。** 对同一 CH、同一受控目标及相同拨号条件，cover 可以在目标首字节就绪时转发；镜像必须收齐合格前缀、等待完整静默窗口 `q`，再完成本地准备。镜像路径因此新增等待，可能形成可观测的时延分布差，不设置“消除双峰”门禁。虚拟时间硬门禁：在无背压、无后续目标字节且未到硬截止时，设首字节到达时间为 `t_first`、完整可行前缀最后一字节到达时间为 `t_last`；cover 在 `t_first` 就绪后不等待 `q`，镜像不得在 `t_last+q` 前开始写，并在该时刻驱动就绪分支及本地准备后不得再人为等待一个窗口。硬截止先于或等于该时刻时不得命中。

实际 TTFB 仅作诊断。同一测试客户端用同一合成 CH，在相同目标脚本和拨号配置下交替运行正常镜像和仅在测试中强制的普通 cover。以客户端单调时钟测量“CH 最后一字节交给 socket 至读到响应首字节”，报告成功数、失败和超时数、两组 p50/p95/p99，以及配对 `ΔTTFB = TTFB_mimic − TTFB_cover` 的分布。不以 Docker 或真实网络上的固定毫秒差作为 CI 门禁。

## 2. 架构与配置

### 2.1 职责与依赖

| 所有者 | 职责 |
|---|---|
| `meow-transport` | CH 预读与认证、字节模板验证、切桶、TLS transcript 和 key schedule、seal、Finished reader、既有 `RealityTlsStream`；提供接收已连接 stream 的双前缀 cover relay。无 DNS、拨号、路由、监听器配额或配置依赖。 |
| `meow-listener` | 每个 named listener 的配额、拨号、状态机、截止时间、commit/cover 权限、双端 socket 生命周期和 VLESS 移交。 |
| `meow-common` | 提供现有解析与受保护直连能力；本 PR 不新增 resolver、作业池或 `meow-transport` 到其他 workspace crate 的依赖。 |
| `meow-config` / `meow-app` / `meow-api` | 有类型的配置、统一静态校验、启动转换、重启语义及脱敏测试。 |

遵循 ADR-0001 的传输边界和 `meow-transport` 的叶子约束。传输层导出不透明的 `VerifiedHello`、`PreparedFlight` 或等价状态，不导出私钥、AuthKey 或可绕过认证的生产构造器。共用 TLS key schedule、AEAD、证书生成和 Vision 流；v2 扩展的是握手阶段 API 和带 padding 的 seal。**不新增 TLS 后端、不引入第三方 REALITY 栈、不新增重型依赖。** 保留现有 BoringSSL 原语和 rustls 测试夹具。

### 2.2 `reality-config.mimic`

```yaml
# 放在现有 type: vless 的 reality-config 下。
# dest、private-key、short-id 和 server-names 继续遵循 v1。
mimic:
  probe-timeout-ms: 3000
  quiescence-min-ms: 15
  quiescence-max-ms: 40
  max-concurrent-probes: 64
```

| 字段 | 默认与范围 |
|---|---|
| `mode` | 默认 `dial-first`；`off` 为显式退出选项。按字面匹配，只接受这两个值。 |
| `probe-timeout-ms` | 默认 `3000`，整数 `[500,15000]`。CH 已认证且符合镜像入口条件、目标已连接、P 获取成功后，在首次写目标 CH 前起钟。包含完整上传、采样和本地准备，不含此前的拨号、读 CH 或认证；仍受连接总截止限制。 |
| `quiescence-min-ms` | 默认 `15`，整数 `[5,200]`。 |
| `quiescence-max-ms` | 默认 `40`，整数 `[10,500]`；要求 `min <= max < probe-timeout-ms`。 |
| `max-concurrent-probes` | 默认 `64`，整数 `[1,256]`。限制已认证且获准探测的会话从 `UploadHello` 到客户端 Finished 的并发；不限制早拨或普通 cover。同一 named listener 的所有 bind 地址共享。 |

缺省或 `{}` 取默认；拒绝显式 `null`、非 map、未知或重复键、非整数及越界值。即使 `mode: off` 也校验显式字段。仅 REALITY 子块接受 `mimic`；不得接受标准 TLS 下的同名配置、`short-ids` 别名或以 `proxy` 覆盖目标。原始 YAML 与 typed runtime 使用同一套范围与默认定义；`-t`、启动及 `PUT /configs`（包括 force）不得分歧。此配置校验不执行 DNS、socket bind 或目标健康检查。

`GET /listeners` 保持 v1 端点投影，不回显 `mimic` 或安全身份。归一化后的 mimic 纳入 typed listener 比较与持久化；缺省、`{}` 和显式等价配置不产生变更提示。有效配置变更提示重启，不影响活跃 listener、配额、socket 或正在进行的握手。

**发布决策（2026-11-27）。** Driver 批准默认 `dial-first`，接受升级后既有配置的认证连接依赖 `dest` 的可达性、首个安全候选地址、目标兼容性及准入配额。这与上游 REALITY 常开镜像依赖目标的可用性语义一致，不表示两者实现或可观测行为完全相同。升级说明必须说明这项变化及 §8.2 的早拨影响。`mode: off` 用于灰度回退与基准对比；它在握手前选定 v1 路径，不是 v2 错误回退。任何模式均不做静默 v2→v1 本地握手降级。

## 3. 认证与原始字节

保留 v1 的 CH 入口界限：最多 65,536 **wire** 字节（含每条五字节记录头）、32 条记录，每条明文 body 为 `1..=16384`。读完包含首条完整逻辑 CH 的记录时，不预读下一条记录。对能够有界分类的普通 TLS、结构不符、SNI 不允许或认证失败，返回已读 wire prefix；客户端超限、I/O 错误、截断或到达总截止则关闭。最后一条 CH 记录若含尾随逻辑消息，不进入本地握手，已读字节原样交给 cover。

保留三种视图，不要求三份分配：

1. `ch_wire`：精确的预读 TCP 前缀，含记录头，供目标上传或 cover；不得从解析树重建。
2. `ch_message`：复原后的 `01 || uint24(body_len) || body`，内含线上 32 字节 session-id 密文与 tag；用于 TLS transcript，结果不受记录分片影响。
3. `aad`：从 `ch_message` 得到，唯一改动是将经长度校验的 session-id 数据 `[39,71)` 置零，保留长度字节。可在同步段内暂时清零逻辑区并在所有退出路径恢复；只有恢复后的字节能进入 transcript，`ch_wire` 始终不改。

按 v1 验证 CH 结构、扩展唯一性、TLS 1.3、允许的 SNI 和 32 字节 session-id。用于**静态认证**的 peer 公钥优先取独立 X25519 share；仅缺该 share 时取合规混合 share 的 X25519 后缀。无可用 share 或静态 ECDH 全零则认证失败。

```text
auth_dh = X25519(config_static_private, auth_peer_public)
AuthKey = HKDF-SHA256(IKM=auth_dh, salt=CH.random[0:20], info="REALITY", L=32)
auth_plain = AES-256-GCM-Open(AuthKey, CH.random[20:32], aad,
                             session_id[0:16], session_id[16:32])
```

`auth_plain` 严格为 16 字节：版本 3、保留位 1、Unix 秒 `u32be`、short-id 8。版本与保留位按 v1 解析，不新增拒绝策略。沿用 v1 协议时钟和双向时间窗口，边界含等号，零关闭时间校验。对所有已配置 short-id 做定长恒定时间比较并汇总，不在首次命中时退出。GCM 验证失败不使用明文。

认证通过不等于可镜像。CH 须实际携带至少一份允许组、结构正确的 share，并在 `supported_groups` 声明对应组；选中组的公钥可用性在模板验证时检查。最多保留独立 X25519 候选 32 字节和混合候选 1216 字节，不复制其他 share。**TLS 临时交换独立取目标 SH 所选组对应的 share**：两个候选的 X25519 公钥可以不同，不复用静态认证 ECDH 结果。

不因 CH 的 `signature_algorithms` 或 `signature_algorithms_cert` 未列出 `0x0807` 而拒绝已通过 REALITY 认证的连接。继续使用 v1 Ed25519 REALITY 证书和真实的 Ed25519 `CertificateVerify`。这是 REALITY 兼容例外，不是标准 TLS 的签名算法选择规则；pinned Xray 的 Chrome 预设线上广告不等于 uTLS 的实际验证能力。真正不支持 Ed25519 的客户端不能完成握手，不更换签名算法，也不在提交后回落。

不接管带 `early_data` 或 `pre_shared_key` 的 CH；单独存在 `psk_key_exchange_modes` 不拒绝。`record_size_limit` 仅允许缺省或合法值 `16385`，以免沿用的应用记录层违反更小的限制。允许 GREASE ECH；不解密 inner CH，不声称从普通 SH 即可判定目标是否给出了 ECH 接受确认。镜像以已认证的 outer CH 建立本地 transcript，不生成 ECH 确认，不复制目标 random。上述镜像入口限制均不施加给 `off`。

## 4. 模板、密钥与连续流

### 4.1 模板

第一条记录必须为 `16 03 03 <len>`，恰含一条完整 SH；不镜像跨记录 SH。验证：

- 握手类型 `02`、各层长度精确闭合、`legacy_version=0303`、压缩字段 `00`。
- random 不是 RFC 8446 §4.1.3 的 HRR 常量，尾部不带与本模板不符的降级标记。
- `legacy_session_id_echo` 恰为 `ch_message` 中的 32 字节**密文** session-id。
- cipher 是 §4.2 允许的三套之一，且原 CH 确实提供。
- 扩展恰含一份 `supported_versions(002b)=0304` 与一份 `key_share(0033)`，线序不限，无重复、未知扩展或 PSK。`key_share` 为 `group:u16 || exchange_len:u16 || exchange`，长度精确闭合，并对应原 CH 已声明且实际提供的可用 share。组不匹配、错长、无效公钥编码或低阶 X25519 均在提交前按模板不兼容处理。目标 share 的 X25519 部分也须通过低阶检查；目标 KEM ciphertext 只检查长度，不解封。

| 目标选中组 | 对应客户端 share | 本地替换的完整服务器 share | 输入 TLS HKDF 的 `tls_dh` | SH 逻辑长度 / wire 长度 |
|---|---|---|---|---|
| `0x001d` | X25519 public（32） | 本地临时 X25519 public（32） | X25519 secret（32） | `122 / 127` |
| `0x11ec` | ML-KEM-768 encapsulation key（1184）∥ X25519 public（32） | 新 ML-KEM-768 ciphertext（1088）∥ 本地临时 X25519 public（32） | ML-KEM secret（32）∥ X25519 secret（32） | `1210 / 1215` |

复用 v1 `encapsulate_server_share` 的交换机制、字节布局和现有 BoringSSL ML-KEM-768，**不复用 v1 的选组偏好**。只为最终选中组生成一次本地临时 X25519 密钥；混合组再向客户端有效的 ML-KEM encapsulation key 封装一次。拒绝全零 X25519 结果。对端输入无效是提交前模板不兼容；输入有效后的本地密码学内部故障按 §6 关闭。目标 share 不参与本地秘密派生。

在私有输出中按 parser 给出的范围原位替换**完整** 32 或 1120 字节 share；范围随扩展线序计算，不使用固定偏移，也不能只替换混合 share 的末 32 字节。另替换 random `[6,38)`（偏移含握手头）：用 CSPRNG 生成，不复用目标 random，不得等于 HRR 常量或以 `DOWNGRD\x00` / `DOWNGRD\x01` 结尾。重采样有固定次数上限，失败记本地密码学错误。其余字节，包括组、全部长度和 SID echo，一字不改。

SH 后允许最多一条严格等于 `14 03 03 00 01 01` 的伪 CCS，且只能位于第一条 `0x17` 前。随后每条候选头必须是 `17 03 03 <u16be L>`，`18 <= L <= 16401`。逐条保留五字节头和范围，不能以第一条的版本代替后续校验。初始 CH 的 legacy record version 例外不适用于目标输出；即使客户端接收端容忍，也不镜像非 `0303` 的目标记录。明文 Alert、额外 CCS、非预期类型、版本或长度按提交前规则回落；已读的坏头仍属于原始 prefix。

### 4.2 本地 flight 与 key schedule

| 套件 | 哈希 / `h` 字节 | AEAD key 字节 | IV / tag 字节 |
|---|---|---|---|
| `1301 TLS_AES_128_GCM_SHA256` | SHA-256 / 32 | 16 | 12 / 16 |
| `1302 TLS_AES_256_GCM_SHA384` | SHA-384 / 48 | 32 | 12 / 16 |
| `1303 TLS_CHACHA20_POLY1305_SHA256` | SHA-256 / 32 | 32 | 12 / 16 |

`tls_dh` 以所选组规定的 32 或 64 个原始字节进入 `Extract`，不预哈希、不颠倒两半、不按套件哈希长度截断。组只改变 SH 和 `tls_dh`；哈希、AEAD 与 Finished 长度由套件决定，逻辑加密 flight 的 `M` 不因组改变。`T0` 使用带线上密文 SID 的原始逻辑 CH 和实际发出的、已替换完整 share 的 SH，不使用目标原 SH。

以下 `H` 表示套件哈希。`Extract` 参数顺序为 `(salt, IKM)`；`ExpandLabel` 按 RFC 8446 编码 `uint16(output_len)`、带 `"tls13 "` 前缀的长度前缀 label 和长度前缀 context。`DS(secret,label,messages) = ExpandLabel(secret,label,H(messages),h)`；空 transcript 对应 `H(empty)`，不是空 context。无 PSK 的派生顺序：

```text
Z         = zero[h]
early     = Extract(Z, Z)
handshake = Extract(DS(early, "derived", empty), tls_dh)
T0        = ch_message || patched_sh_message
c_hs      = DS(handshake, "c hs traffic", T0)
s_hs      = DS(handshake, "s hs traffic", T0)
master    = Extract(DS(handshake, "derived", empty), Z)

T1        = T0 || EE || Certificate
signature = Ed25519_sign(0x20 * 64 || "TLS 1.3, server CertificateVerify"
                         || 0x00 || H(T1))
CV        = handshake_message(0x0f, uint16be(0x0807) || uint16be(64) || signature)
T2        = T1 || CV
Fin(k,T)  = HMAC-H(ExpandLabel(k,"finished",empty,h), H(T))
sFin      = handshake_message(0x14, Fin(s_hs,T2))
T3        = T2 || sFin
c_ap      = DS(master, "c ap traffic", T3)
s_ap      = DS(master, "s ap traffic", T3)
expected_client_finished_body = Fin(c_hs,T3)
```

`EE` 为握手头加两字节零扩展向量长度，共 6 字节，**不是空消息**。`Certificate` 为 v1 单张本地 Ed25519 leaf，使用空 request context 和空 per-entry extensions。外层 X.509 签名值为 `HMAC-SHA512(AuthKey, raw_ed25519_public_key)`，这是 REALITY 认证约定，不是普通 PKIX 签名；`CertificateVerify` 则使用真实 Ed25519 签名。不得复制目标证书、ALPN、密文或密钥。

`M = len(EE || Certificate || CV || sFin)`。按 v1 的 174 字节 DER，SHA-256 为 301 字节、SHA-384 为 317 字节。探测阶段所用长度须由同一个序列化布局得出；准备阶段核对实际序列化结果，不用估计值作门槛。仅在模板冻结后构造及签名一次。

Transcript 包含握手类型和 `uint24` 长度，不包含记录头、CCS、inner type、padding 或 tag。应用流量秘密的 transcript 快照在**服务端** Finished 后；客户端 Finished 用 `c_hs` 和同一 `T3` 校验，验证成功后才移交应用流。可预计算 SHA-256 和 SHA-384 的哈希**状态**以提前释放逻辑 CH；不得把 `H(CH)` 摘要当作 CH 字节再哈希。

每方向、每 epoch 独立派生 `key = ExpandLabel(traffic_secret,"key",empty,key_len)`、`iv = ExpandLabel(traffic_secret,"iv",empty,12)`。AEAD nonce 为 `iv XOR (zero[4] || uint64be(seq))`，没有线上显式 nonce。AAD 为该条最终五字节外层头，其长度含 tag、不含头。每条加密记录消耗该方向、该 epoch 的一个序号；SH 和 CCS 不消耗。握手和应用 epoch 分别从零开始，禁止回绕，错误路径不得用同一密钥和序号重新封装。复用 v1 记录层的 AEAD；镜像逻辑不进入既有出站或应用记录路径。

### 4.3 切桶

对已验证的 N 条记录，`C[i]=L[i]-17`：扣除一字节 inner type 和 16 字节 tag。RFC 8446 §5.4 的上限为**含类型**的 16385 字节，故 `content+padding <= 16384`；不能把 TLSCiphertext 的通用上限当作这三套 AEAD 的合规发送上限。给定符合 §4.1 和 §6 的桶，存在全部为正 payload 的分配，当且仅当 `N >= 1`、各 `C[i]` 属于 `[1,16384]`，且 `N <= M <= sum(C)`。

```text
plan(M, heads):
    validate all record headers, counts and budgets
    compute C with checked arithmetic
    reject if N == 0 or M < N or M > checked_sum(C)
    offset = 0
    for i in 0..N:
        suffix_count = N - i - 1
        remaining = M - offset
        take = min(C[i], remaining - suffix_count)
        append (head[i], offset..offset+take, pad=C[i]-take)
        offset += take
    require offset == M
    return plan
```

证明：每桶允许 `[1,C[i]]`，因此上下和界必要。归纳假设本步剩余长度介于剩余桶数和剩余总容量之间。若取 `C[i]`，剩余长度不超过后缀容量，且至少为后缀桶数；否则恰好给每个后缀桶留一字节，而每桶容量至少为一。故每步 `take >= 1`，最后恰好耗尽 `M`，上下和界也充分。允许切在握手消息头内部；所有分片同属服务端握手 epoch，不能插入别的 inner type。服务端 Finished 恰好结束于最后一条记录的逻辑 content 边界。

逐条封装 `flight[range] || 0x16 || zeros(pad)`，得到 `L` 字节的 `ciphertext || tag`。inner type 位于 padding **之前**。将 plaintext 直接置入私有输出的对应记录区并原位 seal，或采用同等容量的实现，不另分配满长记录 scratch。完整 flight 在首次写客户端前均已 seal。验收覆盖桶长 `[25,3217,281,69]`：首桶容量 8，可放 6 字节 EE 和后续两字节，但不得把首桶与 EE 绑定。

## 5. 拨号、准入与截止时间

以下为 `dial-first` 的编排；`off` 保持 v1 本地握手及 cover 路径。

- `H=256`：派生连接任务前 `try_acquire`，覆盖早拨、CH、认证及本地 TLS 完成。无 H 不派生、不解析、不拨号。外层 `max-connections` 生命周期限制不变；零不取消 H/P/C。三类配额均按 named listener 的所有 bind 共享，不排队等待内部许可。
- `P=max-concurrent-probes`：仅在 CH 认证通过、满足入口 profile、目标已连且 CH 前缀完全处于上传限速豁免内时，于 `UploadHello` 前 `try_acquire`。持有至目标关闭、cover 交接或终止。无 P 则以 `probe_saturated` 尝试 cover，不写本地 TLS。未认证或原本不满足镜像入口条件的连接不尝试获取 P。
- `C=64`：沿用 cover 配额。先 `try_acquire C`，再交接同一目标 socket 及前缀；释放 H 和可能持有的 P 后开始 relay。无 C 则关闭。外层 TLS 完成时先关闭目标，再释放 P/H，然后继续 VLESS 请求；外层生命周期槽不提前释放。
- 使用现有 `resolve_host_all`、活跃监听端点自环排除及 `connect_tcp(SocketAddr)`，保留现有保护、绑定和 mark。按既有地址顺序选择首个未被自环过滤的地址。每次 `dial-first` 至多一次解析调用和一次 TCP connect 调用；失败不尝试其他地址、不重解析、不改拨其他目标。无安全候选按解析阶段失败处理。普通 cover 同样复用早拨 socket；**不存在饱和后另拨一次的路径**。`off` 的 v1 多地址 cover 不变。不得由客户端 SNI、ALPN 或 VLESS 请求选择探测目标，不为探测增加重定向、PROXY header 或代理链。
- 父连接任务固定 `read_preflight(client)` 和 `dial(dest)` 两个 future，在同一驱动循环中用 `select!` 或等价机制持续 poll。保存先完成的结果，只继续 poll 未完成的分支，不重建进行中的 future。先得到可 cover 的 CH 时，仍在 H 与原拨号截止内等同一次拨号；目标先就绪时只持 socket，不发送 CH、不读目标。致命错误、截止或父任务取消直接 drop 两边的 future、已取得 socket 和许可证。不派生每连接后台 TCP 任务。已开始的系统解析工作不保证可抢占，不能持有连接 socket 或许可；取消后即使解析返回，也绝不能触发 connect。本 PR 不新增 DNS 工作配额或起拨令牌桶。
- `d_hs=admitted_at+15s`：自连接与握手准入起计，覆盖调度、解析/拨号、CH、认证、探测、发送、Finished 和首个 VLESS 请求。`d_dial=min(d_hs,dial_begin+3s)`，`dial_begin` 为首次 poll 解析/拨号分支的时刻。取得 P 后、首次写目标 CH 前记录 `probe_start`，`d_probe=min(d_hs,probe_start+probe-timeout)`。`d_emit=min(d_hs,commit_at+3s)`，`d_finish=min(d_hs,emit_done+5s)`。均为绝对截止，持续字节、部分写或 CCS 不延长期限。进入 cover 前仍须满足 `d_hs`；交接后的 relay 使用 v1 独立时钟。
- 对选中的数值地址，在第一次实际 poll connect 前记录 `tcp_start`，connect 成功返回当下记录 `tcp_ready`。差值是**应用层观测建连耗时**，含连接 poll 的调度与平台开销，不含之前的 DNS 或等待另一分支的时间，不称为内核 TCP RTT。静默窗口 `q=clamp(floor_ms((tcp_ready-tcp_start)/2), q_min, q_max)` 仅用于静默判定。

## 6. 提交前状态机

字节和 socket 均有唯一所有者。可用 enum 或消费型 API 表达以下转移。提交前唯一允许发送给客户端的内容，是**已选择 cover 后**的原始目标流。不得提前发送本地 SH、CCS、Alert 或应用字节。

| 状态 | 转移 |
|---|---|
| `ReadAndDial` | 仅原早拨成功才可继续；致命 preflight 错误、拨号失败或适用截止到期直接关闭。分类为 cover、CH profile 不兼容，或启用了上传限速且完整 `ch_wire` 超出 `after-bytes` 豁免：丢弃认证上下文，将同一 socket 和未上传前缀交给 `CoverPending`。否则尝试 P：失败走 `CoverPending(probe_saturated)`；成功后起 `d_probe` 并进入 `UploadHello`。这些 cover 分支均未上传 CH。 |
| `UploadHello` | 已持有 P。只写原始 `ch_wire`，不读或转发后续客户端字节。完整成功后记 `uploaded=len(ch_wire)`，释放客户端 wire 前缀后才分配目标采样区，进入 `Probe`。写零、I/O 错误或截止直接关闭；不重放部分前缀、不二次拨号。 |
| `Probe` | 增量保留每一个已读字节并按 §4.1 解析。不兼容、预算超限、明文 Alert 或目标读 EOF，若未到 `d_hs`，转 `CoverPending`。独立 `d_probe` 到期且尚不能提交时也转 cover。EOF 连同前缀作为方向终止状态交接；RST 或致命读错关闭，不承诺错误后送达已缓冲字节。 |
| `Prepare` | 冻结后私有构造、校验并 seal 完整 flight，不丢弃目标原始前缀。不成立的切桶计划、无效对端模板、独立探测截止或检查到目标新字节，按相应原因回落；目标 EOF 按半关闭回落。总截止、本地 RNG、签名或 AEAD 内部故障、致命 I/O 错误直接关闭，不在线降级算法。 |
| `Commit` | 确认未到截止、完整 flight 已 seal、仍持同一目标 socket，且通过最终非阻塞检查。消费回落权限、释放 `s2c_raw` 和准备临时区，记录 `commit_at`。**在第一次 poll 客户端写之前**进入不可回落状态；即使首次写为零、失败或仅部分成功，也不能恢复回落权。 |

扫描、冻结与 cover 交接：

1. 目标原始响应 wire 上限 `W=65536`，包含 SH、CCS 和所有记录头；另容纳一个已读溢出哨兵字节，最多 16 条加密记录。读请求受剩余空间限制；头部足够时即判明显不符，完整 body 到达后才计入模板。第 `W+1` 字节保留给 cover，此后不再采样。解析游标不回退，不反复解析同一记录头。
2. 仅在 SH/CCS 合法、至少有一条完整候选记录、当前位置恰在记录边界且切桶可行时允许静默判定，阈值为 `last_byte_observed+q`。新字节重置基准；容量不足或处于半头、半 body 时不得冻结。达到记录数上限不等于成功，仍须观察后续字节、EOF 或完整静默。
3. 硬截止优先于静默命中；不得截短 `q`。同时观察到新字节和静默到期时先处理新字节。监听器保留具体目标 `TcpStream`，提交前执行一次最多一字节的立即 `try_read`，不等待 readiness：`WouldBlock` 才允许继续，读到字节则保留并回落，EOF 按半关闭回落，致命读错关闭。同步签名和 seal 不能由异步 timer 抢占；准备完成后、实际提交前，以单调时钟重新检查 `d_hs` 和 `d_probe`。`d_hs` 到期关闭；仅 `d_probe` 到期且目标可交接时，以 `probe_timeout` 回落。最终检查与对端写入不是内核级原子操作，检查后的竞态按 §7 处理。
4. `CoverPending` 只在 C 成功且总截止未到时启动 cover。移动 client、**唯一已连接的原目标 socket**、未上传的 `c2s_prefix`、已读的 `s2c_prefix` 和目标 EOF 状态。每方向先写自己的 prefix，再复制该方向后续 socket 字节；已上传的前缀绝不重放。进入 relay 后沿用 v1 的每方向 16 KiB 缓冲、半关闭、60s idle 和 600s lifetime。目标 EOF 时先送完下行前缀再 shutdown 客户端写侧；上行可独立结束。复用 v1 上传 limiter，将 `uploaded` 计入已用豁免；下行 prefix 由下行 limiter 从零计费。限速只改变节奏，不改字节。旧 cover 入口使用 `uploaded=0` 和空下行前缀。

## 7. 提交后状态机

`Emit → WaitClientFinished → Established`。从 commit 起，父任务同时驱动客户端写入或读取及同一个目标监控 future。监控只尝试读一字节。**任何**非空目标数据，包括可能的后续握手、加密 Alert、NST 或应用数据，以及目标 EOF、RST 或其他读错，均为终止事件；不转发，也不吞掉一批字节后继续等待。目标保持静默不代表握手成功，不延长本地截止。

`Emit` 写完整个已 seal flight 并 flush；完成后释放发送缓冲，再读取客户端 Finished。每个阶段均使用自己的绝对截止。调度优先级：先处理已到的硬截止，再处理本轮可观察的目标终止事件，最后处理客户端结果；这不声称知道远端事件的物理先后。目标监控期间不得循环重建正在消耗字节的 `read_exact` 或 `write_all`。任何失败和取消关闭两端，不要求再发本地 Alert，无 cover 分支。

Finished reader 逐条精确读客户端的记录头和 body，不预读下一条记录；最多 32 条、65,536 wire 字节。可忽略一条字节精确匹配 §4.1 的兼容 CCS，不消耗握手序号。其余须为长度合规的 `17 03 03`，以 `c_hs` 对应的 AEAD 开封；先验证 tag，再从尾部剥去零 padding 并取首个非零字节作为 inner type。拒绝全零、空握手 content、类型错误、超限、AEAD 失败或错误逻辑消息。仅重组一条 `Finished(0x14)`，声明长度等于 `h`，允许跨记录分片，拒绝同一记录内 Finished 后的握手字节。以定长恒定时间比较 `verify_data`。

验证成功后关闭目标、释放 P/H、清理握手秘密，以原 client stream 构造 v1 `RealityTlsStream`：读 `c_ap`、写 `s_ap`，序号均为零。粘包中的下一条应用记录留在 socket；若等价实现引入 read-ahead，必须把未消费的**原始密文字节**交给 `RealityTlsStream`，不能交给 Vision 明文解析器。首个 VLESS 请求仍受 `d_hs` 约束；只有 UUID 和 flow 通过才可路由或创建 XUDP 状态。

## 8. 资源、指标与安全

### 8.1 资源账

`W=65536` 计目标候选前缀的 wire 字节，含 SH、CCS 和每条记录头；额外最多一字节用于无损回落。16 条满长密文 body 共 262,416 字节，加记录头及对应组的 SH 和可选 CCS 后，`0x001d` 最多为 262,629 字节，`0x11ec` 最多为 263,717 字节。W 下两个组均只能容纳至多三条满长记录。16 条和 W 是同时生效、不可互换的限制。

| 阶段 | 显式 byte arena 上限 |
|---|---|
| `ReadAndDial` / CH 认证 | `Bch=2W+8192+5+G=140517`。原始前缀、逻辑/AAD 共用区、去重 bitset、头，及 `G=32+1216=1248` 字节候选 share；计入候选复制与逻辑区短暂共存的峰值。 |
| `UploadHello` | `Bupload=W+G=66784`。仅 CH wire 前缀和候选 share；不同时分配目标采样区。 |
| `Probe` / `Prepare` | `Bprobe=(W+1)+W+G+4096=136417`。目标原样前缀及哨兵、私有 seal 输出、候选 share 和调用方可见临时区；临时区包含逻辑 flight、临时密钥及交换结果、KEM 输出等。SH 直接按范围复制至输出再 patch，不另留整份 SH。 |
| `Emit` | `Bemit=W`。commit 释放原始前缀和临时区，不保留两套 flight。 |
| `WaitClientFinished` | `Bfin=16401+5+52=16458`。原位解密 body、头和最多 `4+48` 字节逻辑 Finished；释放发送缓冲后分配。 |
| cover | `Bcover=(W+1)+2×16384=98305`。移动已有前缀而非复制，不同时持有满长 CH 和目标前缀；前缀耗尽即释放。 |

按实际容量而非 `Vec::len()` 计账。禁止第三份 CH、整份 transcript 拷贝、复制全部 share 或按对端长度无界扩容。任何时点的 arena 上限为各阶段活跃会话数乘对应上限之和；前五阶段总会话数不超过 H，`UploadHello` 至 `WaitClientFinished` 的总会话数不超过 P，cover 不超过 C。交接可短暂持有两个许可，不得额外分配一份前缀或重复计入一个会话的 arena。忽略更紧的外层生命周期限制，每个 named listener 的保守上界：

```text
H × max(Bch, Bupload, Bprobe, Bemit, Bfin) + C × Bcover
= 256 × 140517 + 64 × 98305
= 42,263,872 B
```

多个 listener 的上界相加。该数只界定显式 arena，不是 RSS。完整峰值须按同一时点合算：arena、会话固定状态（含最多 16 条描述符、future 字段、提交后单字节监控及 crypto 后端对象）、allocator 元数据与保留页、resolver 与运行时共享开销、所有存活 socket 的内核缓冲和对象、已建立数据面及其他进程开销。前两项按阶段验证容量和布局；allocator、系统解析器和 TCP autotuning 需分平台测量。不得从 W 推导全进程内存上界。

每 listener 的目标 TCP socket（含 connect-in-progress）不超过 `H+C=320`；P 是 H 的子集，不计成 `P+C` 或 `H+P+C`。入站握手和 cover 客户端也不超过 `H+C`，另计每 bind 尚未准入的 socket、listener FD 和已建立的数据面连接。继承的 DNS 后端不在该 TCP FD 上界内；不承诺系统 lookup 的硬并发或起拨速率。连接生命周期上限为零时不承诺进程级数据面总量。保留 v1 task-size 回归测试，禁止把阶段大缓冲内联进长连接 future。

### 8.2 指标与安全红线

| 指标 | 记账点 |
|---|---|
| `reality_v2_dial_started_total` | 早拨分支实际开始解析或取得字面地址；每条 dial-first 连接至多一次，与认证结果无关。可另以 `reality_v2_tcp_connect_started_total` 记录真正发起 TCP connect。 |
| `reality_v2_probe_started_total` | 获得 P、记录 `probe_start` 后，第一次上传 CH 前；P 饱和不计。 |
| `reality_v2_committed_total` | 消费回落权时。 |
| `reality_v2_mimic_hit_total` | 验毕客户端 Finished 时；不能用提交或写完服务端 flight 代替。 |
| `reality_v2_cover_total{reason}` | 拿到 C 且正式交接 relay 时；仅决定尝试 cover 不计。 |
| `reality_v2_close_total{phase,reason}` | 外层握手或 cover 失败、取消而终止；正常 cover EOF 完成和已建立 VLESS 生命周期结束不计。 |
| `active_handshakes` / `active_probes` / `active_covers` | 分别按 H/P/C 许可的获取与释放跟踪，不等同累计开始次数。测试可读内部快照，不强制新增公共指标 API。 |

- Cover 原因限定为 `auth_failed, probe_saturated, client_profile, dest_profile, hrr, unsupported_cipher, unsupported_group, unsupported_ext, record_limit, capacity, probe_timeout, dest_alert, dest_eof, late_dest_bytes, upload_shaping`。
- Close 阶段限定为 `admission, read_and_dial, upload, probe, prepare, emit, wait_finished, cover`；原因限定为 `handshake_saturated, cover_saturated, resolve, connect, client_limit, client_io, dest_io, deadline, local_crypto, emit_io, finished_invalid, dest_tail, dest_eof, canceled`。拨号或握手硬超时计 `deadline`，目标 EOF 不是 timeout。`probe_timeout` 仅表示独立探测截止触发了**实际 cover 交接**。P 满且 C 也满时，除已发生的早拨计数外，只记 `close(cover_saturated)`；不记 probe、commit、hit 或 cover。每连接至多一次 commit、hit、实际 cover 分流和终止计数；禁止动态错误文本进入标签。
- v2 自有事件、诊断和测试报告不记录 peer、目标地址或域名、SNI、UUID、用户名、short-id、证书内容、私钥、AuthKey、流量密钥或原始 TLS 字节。拨号和解析错误映射到固定分类，不转印共享 resolver 的原始诊断；继承的通用 resolver 诊断不属于 v2 新增日志接口，也不是脱敏交付证据。安全结构的 `Debug` 不得绕过此规则。不记录认证失败的密钥相关子原因，不生成 key log；测试抓包仅用合成凭据。
- 使用检查过的整数、有界循环和增量扫描；每个字节只扫描或拷贝常数次，不重复哈希全量 CH、不重新签名。完整 flight 和 Finished 的字节、记录数上限约束每连接密码学工作。使用既有后端的定时安全原语，清理可擦除的临时秘密缓冲，不承诺擦除分配器或后端的所有副本。禁止减弱 MAC/tag 检查、共享 nonce 或跨连接缓存握手私钥。
- Dial-first 可能在收到任何 CH 字节前发起 DNS、发 SYN 或产生目标空连接。H、固定目标和绝对截止约束本地连接占用，**不提供每秒起拨上限或 libc 作业硬上限**；未认证扫描仍可耗尽 H，P 不是这道防线。仅将自有或明确授权的地址配置为目标。如需防公网起拨洪峰，应在部署入口限速，或单独评审共享 resolver 与起拨治理。时间窗口不是重放缓存；新鲜临时密钥、Finished、无 0-RTT 和 VLESS 凭据仍是数据面放行边界。

## 9. 验证门禁、证据与实施切分

| 门禁 | 必须能复现的断言 |
|---|---|
| `T1` 确定性切桶与模板 | 穷举小容量和 M，与独立分配枚举对比；覆盖 `M=N`、`M=sum(C)`、N=0、容量不足、`L=17/18/16401/16402`、单桶、多桶及跨握手头的小首桶。两个组各测两种扩展线序、完整 share range、SH 掩码、CCS 和逐条五字节头。负例含未知组、未提供目标所选组、混合 CH share 长 `1215/1217`、混合 SH share 长 `1119/1121`、坏 ML-KEM 公钥、低阶 X25519 后缀、HRR、TLS 1.2、PSK、重复或未知扩展、SID 错误、单条 record version 不符和缩小 RSL。合法匹配的混合组必须通过。 |
| `T2` 独立 Python oracle | 扩展 `generate_reality_independent_vectors.py`，冻结 `0x001d` 三套完整向量、`0x11ec × 0x1302` 完整向量，以及双份 share 和仅混合 share 的认证样本。固定 Python/cryptography 测试依赖，`--check` 在内存生成并比较已提交证据，不向外站拨号。冻结 CH wire 与 AAD、原始及 patched SH、静态/临时输入、AuthKey、leaf DER、T0–T3 哈希、CV、双向 Finished、双向握手和应用 key/IV、至少两条带序号和 padding 的记录及应用 `seq=0` 首记录。混合样本固定 decapsulation seed、独立生成后冻结的 ciphertext 及临时 X25519 输入；Python 从 seed 解封冻结 ciphertext，再与独立计算的 X25519 secret 按规定顺序拼接。`--check` 不调用随机 `encapsulate()` 重生成冻结字节。Rust 消费独立向量并逐字节核对，可用仅测试的固定随机数和封装结果注入；另以生产真实封装完成双向握手。篡改 SID/tag、CH AAD 扩展、使用清零 CH 或目标旧 SH 作 transcript、错记录 AAD/seq、重播旧 Finished、颠倒混合秘密顺序或只替换混合 share 后缀均须失败；合法 CH 重分帧须成功。 |
| `T3` 有界 I/O、调度和回落 | Fake dial/IO 和虚拟时钟证明 CH 未完成时拨号能完成，建连计时不含等 CH，未认证 H 占用不消耗 P；H 满不启动工作，P 满且 C 有或无空位分别验证复用或关闭，均不重拨。验证 `probe_start` 不含早拨或等 CH，硬截止和并列优先级正确，满足 §1 虚拟时间 TTFB 条件。覆盖分片、W 和哨兵、逐字节慢速、可行容量后的半记录、明文 Alert、EOF 半关闭、RST、部分写、上传限速、quiet 与硬截止并列、提交前零本地输出、双向 prefix+suffix 精确且只一次；提交后注入写零、部分写错误、目标非 EOF 尾字节、EOF/RST、半开、坏 Finished 和超限，断言无 cover。涵盖各阶段父任务取消及 resolver 迟到不触发 connect，并核对 socket、H/P/C 和开始、commit、hit、cover、close 分类。不设墙钟毫秒关闭断言。 |
| `T4` 数据面交接 | 一次写入 CCS、分片且带 padding 的客户端 Finished、下一条应用 TLS 记录；精确读后消费首条应用记录并继续 Vision。运行既有 `vless_listener_integration`、`vision_direct_wire`、`vision_server_alloc` 和 `vless_integration`。显式 `off` 在不可达 `dest` 下完成 v1 认证，早拨计数为零；错误 UUID 或 flow 无 VLESS 路由拨号，该计数不是 dial-first 的目标拨号计数。 |
| `T5` 受控目标与 pinned Docker | 保留 `vless_interop_docker` 的镜像 digest、客户端版本检查、`MEOW_REQUIRE_DOCKER=1` 和隔离拓扑。下列矩阵全部实跑，从线上 CH 确认组、cipher 及与预设相符的广告，不以配置名代替断言。缺服务、少跑矩阵或未验证镜像命中均失败，不因缺少目标组而跳过，也不以新增 retry 获绿。 |
| `T6` 配置、依赖与体积 | 运行 `vless_listener_config_test`、app `-t` 和 API force/restart/redaction 测试，覆盖边界、缺省归一化、错误类型、未知/重复键及未启用 feature 的拒绝。复用 `cargo fmt --all -- --check`、默认/all/no-default Clippy；显式运行 `cargo test -p meow-transport --features reality --lib` 和 v2 listener 测试，不能只跑 `tls_server_test`。以 `cargo tree` 核对无新增生产 TLS/C++ 依赖或 transport→workspace 边。保持 aarch64-musl stripped minimal ≤ 8 MiB 等既有门禁；以同工具链、同 profile 报告 full 相对 v1 的 stripped 字节差，不将已有 full 观测值冒称硬阈值。 |

### 9.1 `T5` 靶场与证据

1. **可编程记录目标。** 在隔离内网接收原始 CH、回显 SID，并生成所选组合法长度的 `0304` SH；X25519 部分使用非低阶公钥。混合模板的 KEM ciphertext 和后续 `0x17` body 可为合成内容，因为探针不解密。事先定义确定的头部向量，覆盖单桶、多桶和小首桶。目标写完后静默至被测端完成或测试控制结束，不在标称 flight 后写尾字节或提前关闭。独立观察器记录同次探测的目标输出和客户端实际收到的对应前缀：SH 只遮盖 random 和完整 share 值，另断言 SID echo；CCS、N 和逐条五字节头精确比较。被测 parser 上报的桶表不得作为唯一 oracle。
2. **小型互操作矩阵。**

   | pinned 客户端 | 目标组选定 | 套件 | 短测条数 |
   |---|---|---|---:|
   | Xray 缺省 / `chrome` 预设 | `0x001d` | `0x1301`、`0x1302`、`0x1303` | 3 |
   | mihomo `chrome`，混合关闭 | `0x001d` | `0x1301`、`0x1302`、`0x1303` | 3 |
   | Xray 缺省 / `chrome` 预设 | `0x11ec` | `0x1302` | 1 |
   | mihomo `chrome`，`support-x25519mlkem768: true` | `0x11ec` | `0x1302` | 1 |

   每条断言真实 outer Finished、短双向 TCP echo 和形状匹配。pinned Xray 的缺省/`chrome` 映射到 pinned uTLS Chrome 133；至少一条验证其 CH 广告中确无 `0x0807`，仍成功验证真实 Ed25519 CV，不得换用广告 Ed25519 的预设绕过回归。mihomo 关闭混合时线上无 `0x11ec`，开启时实际提供该组的 share。HRR、PSK、未知组和未提供的 `0x11ec` 用独立负向夹具验证原字节回落、无本地 REALITY/VLESS 建立，不要求合成目标完成普通 TLS。
3. **真实 cover 与完整数据面分别取证。** 保留禁票、使用本地 CA 的真实 TLS 1.3 cover；普通 TLS 客户端验证实际目标证书和 HTTPS body。这不是合成目标的断言，不比较不同 CH 的形状。in-process 为两个 pinned 客户端各跑一个完整 dial-first 组合，至少一条选择 `0x11ec`，验证大于 1 MiB 的双向模式 echo，每连接 DIRECT raw-read/raw-write `+1/+1`，以及 XUDP `21/300/1400` 字节、来源与不切 raw。real-app 保留主动反绕过检查，并至少各验证一条 dial-first TCP 路径和 XUDP 路径，不从外部证据推断内部 DIRECT 计数。cover 目标和 VLESS 内层 echo 使用独立端口与计数器。保留 standard TLS 和 `off` 回归，不要求八条短测逐条重复批量数据面测试。

### 9.2 `T6` 默认模式与升级验证

- 分别以缺省 `mimic` 和 `mimic: {}` 启动真实运行时入口，向有计数的本地目标实测默认 `dial-first`。仅接入客户端且尚未读完 CH 时应已启动早拨；随后发送有效 CH，应上传一次原始前缀并命中镜像，完成客户端 Finished。不能只断言反序列化枚举值。
- 同一运行时入口验证显式 `mode: off`：目标不可达时，既有 v1 认证路径仍成功，针对 cover 目标的 preflight 解析、早拨和 TCP connect 调用计数均为零；普通 cover 的既有拨号语义不变。
- 提交升级说明，明确未修改的旧配置也进入默认 `dial-first`、认证可用性新增哪些依赖、未认证早拨的运维影响，以及如何用显式 `mode: off` 并重启恢复 v1 路径。校验 API 将等价配置视为不变，将有效模式变化标记为需要重启。

### 9.3 实施切分

1. **Transport**：拆分认证与完成阶段，保持 v1 接口；实现两组模板解析、完整 share 替换、切桶和 seal，完成 `T1/T2`。
2. **Listener**：接入固定目标早拨、配额、双前缀 cover、所有权屏障、提交后监控和 Finished 移交，完成 `T3/T4`。复用现有 `meow-common` 接口，不对用户开放未完成路径。
3. **Config / App / API**：接通默认 `dial-first` 和显式 `off`、统一校验、启动快照、重启及脱敏契约，完成 `T6`。更新 v1 文档中“认证连接不拨号”“认证后不回落”的适用条件及升级说明。
4. **测试与发布**：补齐 `T5`、固化矩阵证据和分阶段资源测量；全部门禁通过后才合并。真实节点 smoke 仅手工 opt-in，禁止纳入 CI。任何未来默认模式变更须另做可用性和资源评审。