# 火漆 · Sealing Wax — 线上格式规范 (wire spec)

> 规范版本:1(对应 App magic `SWX1`)。本文是字节级的互操作规范;实现以
> `app/src/main/cpp/core/` 为准,测试向量见 `docs/vectors.json`。
> 所有整数大端(big-endian)。所有字节串在向量中以 hex 或标准 base64
> (含 `=` 填充、不换行)表示。

## 1. 通用帧头

```
magic   4B  "SWX1"                       常量 53 57 58 31
type    1B  0x01 邀请 0x02 回复 0x03 文本 0x04 文件
suite   1B  0x01 = X25519 + HKDF-SHA256 + ChaCha20-Poly1305 (IETF)
```

收到未知 `type` 必须明确拒绝;收到 `suite != 0x01` 必须明确拒绝
(错误码 `SWX_E_UNSUPPORTED`),绝不产出错误明文。0x02 为未来算法迁移
保留编号(见 README_AGENT §8)。

## 2. 邀请 / 回复帧(54B)

```
header  6B   (magic + type + suite)
pubkey  32B  发起方(type 0x01)/ 接收方(type 0x02)的 X25519 公钥
salt    16B  本端随机盐(CSPRNG)
```

邀请帧由发起方((inviter)生成;接收方粘贴后生成回复帧。两帧布局相同,
仅 `type` 与载荷归属不同。公钥为自身密钥的 `crypto_scalarmult_base`
输出;私钥在配对完成后即被销毁。

邀请/回复帧保持明文可识别(掩握手需要先有共享密钥,鸡生蛋;任何接收
方可用的识别规则,服务器同样能跑)。这是既定交换:配对仪式可识别
(罕见、一次性),日常数据帧不可识别(§3 传输掩码)。明文握手不提供
任何解掩能力——解掩只缺 `session_key`,而它只缺 ECDH 共享秘密,
私钥永不上链路(论证见 README_AGENT §4)。

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
shared      = X25519(sk, peer_pk)                    # 拒绝全零结果
salt        = inviter_salt(16) || responder_salt(16) # 角色定序,两端一致
prk         = HKDF-SHA256-Extract(salt, shared)
session_key = HKDF-SHA256-Expand(prk, "session" || suite, 32)
sas_raw     = HKDF-SHA256-Expand(prk, "sas", 64)
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

- 逐会话开关,阈值以 base64 字符计(500/1000/2000/4000)。
- 阈值 T 对应明文分片目标 `T×3/4 − 66` 字节(4000 → 2934 = 分片上限),
  填充后单片 base64 恰为 T 字符。
- 填充格式:`[明文][0x80][0x00*]`,收方恒剥离:自尾向跳过 0x00,
  前一字节为 0x80 则截去。恰好填满的分片不携带标记。
- 已知权衡:明文自身以 `0x80 0x00…` 结尾会被误剥(聊天文本可忽略;
  文件走 meta.size 裁剪,不受影响)。
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
(SAS 带外核对)、数据帧协议指纹不可识别(§3 传输掩码)。不承诺:
解锁态设备被完全掌控、通信元数据、对端背叛。见 README_AGENT §2。
