# 火漆 · Sealing Wax — 线上格式规范 (wire spec)

> 规范版本:2(2026-11 配对 PAKE 化;数据帧格式与 v1 一致,配对帧为
> 破坏性变更,magic `SWX1` 编号沿用)。本文是字节级的互操作规范;实现以
> `app/src/main/cpp/core/` 为准,配对原语以 vendored 的
> `app/src/main/cpp/spake2/` 为准,测试向量见 `docs/vectors.json`。
> 所有整数大端(big-endian)。所有字节串在向量中以 hex 或标准 base64
> (含 `=` 填充、不换行)表示。

## 1. 通用帧头(仅数据帧)

配对帧(v2 起)是**无头 SPAKE2 消息**,不携带下列任何字段。通用头只
存在于数据帧,且仅在解掩后的本地副本中可见(§3):

```
magic   4B  "SWX1"                       常量 53 57 58 31
type    1B  0x03 文本密文  0x04 文件密文
            (0x01 邀请 / 0x02 回复已随裸握手废除,编号保留永不复用)
suite   1B  0x01 = SPAKE2 + HKDF-SHA256 + ChaCha20-Poly1305 (IETF)
```

收到未知 `type` 必须明确拒绝;收到 `suite != 0x01` 必须明确拒绝
(错误码 `SWX_E_UNSUPPORTED`),绝不产出错误明文。0x02 为未来算法迁移
保留编号(见 README_AGENT §8)。

## 2. 配对帧(无头 SPAKE2 消息;邀请 32B,回复 64B)

```
invite:  32B  发起方 SPAKE2 份额(Edwards 点编码;无 magic、无 type、无 suite)
reply:   64B  接收方 SPAKE2 份额(32B) || confirm(32B)
```

- **原语**:平衡 SPAKE2 over curve25519,实现为 vendored 的 BoringSSL
  `spake25519` C 移植(`app/src/main/cpp/spake2/`,来源与许可证见其
  README)。消息结构:`share = ephemeral_point + password_blinded_point`;
  输出 `pake_shared` = SHA-512(有序名字 || 双方份额 || DH 结果 || 暗号哈希)。
- **transcript 名字**:发起方 `"swx-inviter"`,接收方 `"swx-responder"`
  ——角色绑定盲化方向(M/N),份额反射回本端不可能完成配对。
- **暗号永不上线**:识别一帧配对消息的唯一依据是暗号本身;服务器无
  暗号即无判定。每次错误暗号猜测都需要一次完整配对交互(在线猜),
  对截获份额的离线暴力不可行。
- **confirm**:仅回复帧携带,`HKDF-SHA256-Expand(pake_shared, "confirm", 32)`。
  发起方在 finish 时校验——不匹配(暗号不一致)即 `SWX_E_CRYPTO`,
  永不建立会话。失败后发起方会话保持可重试(实现把 SPAKE2 上下文回滚
  到处理回复之前):同一邀请码 + 新回复码可直接再试,邀请码不必重发
  (2026-11 真机 BUG 修复;PAKE 性质保证重试仅能在线逐次猜)。接收方
  无配对期确认路径(两帧下限):由发起方首条可解密消息隐式确认。
- **base64 编码后**:邀请码 44 字符,回复码 88 字符;解码必须严格
  (§7 同款规则)。长度即格式:邀请码 ≠ 32B、回复码 ≠ 64B 为
  `SWX_E_FORMAT`。
- **统计边界(如实记录)**:份额是 Edwards 点编码,随机 32B 可解码为
  合法点的概率 ≈ 1/2——配对帧带有 ≈1 bit/帧的统计结构(单帧似然比
  ~2×,成对 ~4×),远弱于 v1 已废除的确定性 `SWX1` 前缀(base64 恒以
  `U1dYMQ` 开头,100% 确认),但非严格为零。均匀份额需要 Elligator
  映射,无成熟 C 实现可用。

## 3. 数据帧(文本/文件共用)

逻辑字段(掩码前的帧结构):

```
header      6B   (magic + type + suite)
counter     8B   方向内终身单调流水号(见 §6)
nonce       12B  每消息 CSPRNG 纯随机,与流水号解耦
fingerprint 16B  逻辑消息 id(CSPRNG),同一逻辑消息的所有分片相同
chunk_idx   4B   分片序号,从 0 起
chunk_total 4B   总分片数(单片消息 = 1)
ct          n≥16B ChaCha20-Poly1305 密文 || 16B tag
```

**传输掩码(上线字节,2026-11 定案)**:固定头 50B 中除 nonce(偏移
[14,26))外全部掩码——区域 `[0..14) ∪ [26..50)` 共 38B(恰为 §4 AAD
区)与掩码密钥流逐字节 XOR;`ct` 不掩(AEAD 输出本就伪随机):

```
mask_ks = HKDF-SHA256-Expand(session_key, "mask" || nonce, 38)

masked[i] = header[i] XOR mask_ks[i]          (0 ≤ i < 14)
masked[i] = header[i] XOR mask_ks[i - 12]     (26 ≤ i < 50)
```

(`mask_ks[14..38)` 平移 12 对齐到偏移 26;nonce 区原样上线。)

掩码后整帧在计算上与等长随机字节不可区分——信道侧无法把日常流量
识别为火漆(magic / counter / 指纹特征全部消失)。长度与时序仍可见
(长度由 §9 填充缓解)。

收方流程:长度检查(≥66B)→ 读明文 nonce → 派生 `mask_ks` → 解掩
本地 50B 头副本 → 验 magic/type/suite(失败 `SWX_E_FORMAT`,未知
suite `SWX_E_UNSUPPORTED`)→ §6 高水位 → AEAD 解密。错会话、头
篡改、nonce 篡改均表现为 `SWX_E_FORMAT`(魔数解成垃圾)。

帧最小长度 = 50 + 16 = 66B。`chunk_idx >= chunk_total` 为格式错误。

## 4. AAD(38B,不含 nonce)

AAD 绑定除 nonce 与密文外的全部帧字段,防跨消息拼接与调序:

```
aad = magic(4) || type(1) || suite(1) || counter(8) || fingerprint(16)
      || chunk_idx(4) || chunk_total(4)
```

等价于线上字节 `[0..14) || [26..50)`。

## 5. 密钥编排

```
pake_shared = SPAKE2(暗号)                      # 64B;暗号错 ⇒ 输出不一致
session_key = HKDF-SHA256-Expand(pake_shared, "session" || suite, 32)
sas_raw     = HKDF-SHA256-Expand(pake_shared, "sas", 64)
confirm     = HKDF-SHA256-Expand(pake_shared, "confirm", 32)   (回复帧)
msg_key     = HKDF-SHA256-Expand(session_key,
                                  "msg" || dir(1) || counter(8 BE), 32)
mask_ks     = HKDF-SHA256-Expand(session_key, "mask" || nonce(12), 38)
```

`dir`:发起方发送 = 0x01,接收方发送 = 0x02。同一逻辑消息的每个分片
各自派生 `msg_key`(counter 不同),**无棘轮、无钥链推进**。

SAS:从 `sas_raw` 每 4B 读大端 u32,拒绝采样 `v < 4×10⁹`,取
`v mod 10⁹` 得均匀 9 位十进制数(3-3-3 分组是 UI 约定,不属于线上格式)。
16 次采样全拒的概率 ≈ 5×10⁻¹⁹,此时实现必须报错而不是退化。

## 6. 流水号与防重放

- counter 0 保留不使用;首个使用的 counter 为 1。
- 发送方:方向内单调递增,每个数据帧消耗一个。
- 接收方:维护高水位 `recv_hwm`(初始 0);`counter <= recv_hwm` 的帧
  拒收(重放),认证成功后 `recv_hwm = counter`。
- 平台层持久化纪律(预支号段、原子写、崩溃后跳号)见 README_AGENT §4;
  跳号无害,重号不允许。

## 7. 文本信道

- 单片密文的 base64 长度 ≤ 4000 字符 ⇒ 帧二进制 ≤ 3000B ⇒ 明文分片
  ≤ 2934B。
- 超长文本按明文分片上限自动分段,每段独立封帧(独立 counter 与 nonce,
  相同 fingerprint),按 chunk_idx 重组。
- base64:标准字母表、保留 `=`、不换行;解码必须严格(拒绝空白、
  坏字符、中置 `=`)。

## 8. 文件信道(.swx 容器)

`.swx` 是自描述记录序列,每条记录:

```
record = frame_len(4B BE) || frame(数据帧, type 0x04)
```

- 内部分片默认 8MiB/片(纯流式内存粒度,与 IM 文件上限无关)。
- **首片明文**:`meta_len(4B BE) || meta || 文件字节…`;
  `meta` 为 UTF-8 JSON `{"name": "<文件名>", "size": <字节数>}`。
  文件名/大小对信道侧不可见。
- 收方按 meta.size 裁剪末片(兼容发送方填充,见 §9)。
- 记录长度合法域:`66 ≤ frame_len ≤ 8MiB + 82`。
- 截断、乱序(chunk_idx 必须从 0 连续递增)、`chunk_total` 不一致均
  为明确拒绝。
- 账本对账:对整个 `.swx` 字节流(含记录长度前缀)做 BLAKE2b-256,
  与本地账本比对,无需会话密钥。

## 9. 长度混淆(可选,默认关;纯发送侧行为,无需协商)

- 逐会话开关,阈值档位以 base64 字符计:200/364/664/1208/2200/4000
  (等比 r = 20^(1/5) ≈ 1.82,精确命中核心区间端点;2026-11 第六批,
  下限由 500 降至 200,上限 4000 不变)。无默认档:开启必选档;关闭时
  分割 = 单片上限(4000 字符),非混淆。区间内的旧保存值仍合法,仅不再
  出现在 UI 档位中。
- 阈值 T 对应明文分片目标 `T×3/4 − 66` 字节(4000 → 2934 = 分片上限),
  填充后单片 base64 恰为 T 字符。
- 填充格式:`[明文][0x80][0x00⁺]`(标记必带至少一个 0x00)。收方剥离
  规则:仅当尾部存在 ≥1 个 `0x00` 且其前一字节为 `0x80` 时,截去
  `[0x80][0x00*]`——UTF-8 文本不含 `0x00` 字节,而无 `0x00` 尾随的
  `0x80` 永远是明文本体(如"呀" = `E5 91 80`)。
- 恰好填满的分片不携带标记;仅剩 1 字节空间的分片不填充(其 base64
  长度仍恰为阈值,无长度泄漏)。
- 已知权衡:明文自身以 `0x80 0x00…` 结尾会被误剥——UTF-8 文本不含
  `0x00`,实际不可达;文件走 meta.size 裁剪,不受影响。
- 文件:开启时仅末片补齐至整 8MiB 桶(`.swx` 体积只泄露桶位)。

## 10. 保存会话状态 blob(60B,不直接上线;装入 Tink 信封)

```
magic "SWXS"(4) ver(1)=1 role(1) suite(1) flags(1,bit0=填充开)
thresh(2 BE) rsv(2)=0 session_key(32) blake2b-128(16 over前44B)
```

计数器不在此 blob 内(平台层 16B 明文小文件另行持久化)。角色翻转
(`swx_state_flip_role`)翻转 role 字节并重算校验和,用于解密自己
发出的历史帧(消息密钥与方向绑定)。

## 11. 错误语义

| 码 | 名称 | 语义 |
|---|---|---|
| 0 | SWX_OK | 成功 |
| -1 | SWX_E_ARG | 非法参数 |
| -2 | SWX_E_FORMAT | 帧格式损坏(magic/长度) |
| -3 | SWX_E_TYPE | 未知/非预期消息类型 |
| -4 | SWX_E_LEN | 缓冲不足/长度不匹配 |
| -5 | SWX_E_CRYPTO | AEAD 认证失败(绝不产出错误明文) |
| -6 | SWX_E_STATE | 当前状态不允许此操作 |
| -7 | SWX_E_REPLAY | 计数器不高于接收高水位 |
| -8 | SWX_E_UNSUPPORTED | 不支持的套件 |
| -9 | SWX_E_IO | 状态导入损坏 |
| -10 | SWX_E_PARTIAL | 分片已收、逻辑消息未齐 |

## 12. 安全主张边界

本规范覆盖的保证:信道读取、篡改/伪造、重放/延迟、首次配对 MITM
(PAKE 暗号 + confirm;SAS 仪表盘带外核对)、数据帧协议指纹不可识别
(§3 传输掩码)与配对帧不可确定性识别(§2)。如实不承诺:配对帧的
残余统计结构(§2)、长度/时序元数据、解锁态设备被完全掌控、对端背叛。
见 README_AGENT §2。
