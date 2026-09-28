# 协议、错误码与生命周期语义

本文档说明本地化动态客户端注册服务的 HTTP 协议、软件声明格式、错误码、
并发与幂等语义、密钥策略以及客户端生命周期状态机。

## 1. 软件声明（Software Statement）

软件声明是一个 **JWS Compact Serialization（RFC 7515）** 令牌：

```
BASE64URL(UTF8(header)) . BASE64URL(UTF8(payload)) . BASE64URL(HMAC-SHA256)
```

### 1.1 JOSE 头部

| 字段 | 取值 |
| --- | --- |
| `alg` | 固定 `HS256`（其它值一律拒绝，避免算法混淆） |
| `typ` | `client-software-statement+jwt`（缺省亦可） |
| `kid` | 本地密钥标识，如 `local-key-1` |

### 1.2 载荷声明（claims）

| 声明 | 必需 | 说明 |
| --- | --- | --- |
| `iss` | 是 | 签发者，必须等于服务端配置的受信任签发者 |
| `sub` | 否 | 默认为 `software_id` |
| `software_id` | 是 | 软件的稳定唯一标识，注册后成为数据库 UNIQUE 键 |
| `client_id` | 否 | 客户端期望使用的标识；缺省时由服务端随机生成 |
| `jti` | 是 | 声明的唯一标识；**相同 `jti` 的重放被视为幂等重试** |
| `iat` / `exp` | 是 | 签发/过期时间（Unix 秒），`exp` 必须晚于当前时间且晚于 `iat` |
| `metadata` | 是 | 客户端元数据对象，见下节 |

签发工具：

```bash
uv run python -m dcr.cli --software-id sw-123 \
  --metadata '{"redirect_uris":["https://app.example/cb"]}' --ttl 600
```

### 1.3 客户端元数据（metadata）

| 字段 | 默认 | 校验规则 |
| --- | --- | --- |
| `redirect_uris` | — | `authorization_code`/`implicit` 授权时必填；必须为绝对 URI、无 fragment；`https`（或 `localhost`/`127.0.0.1`/`::1`/`*.localhost` 回环 http）；不可重复 |
| `grant_types` | `authorization_code`,`refresh_token` | 仅允许 `authorization_code`、`refresh_token`、`client_credentials`、`implicit`；不可重复 |
| `response_types` | 按 grant 推导 | 允许 `code`/`token`/`id_token`，且与 grant_types 一致 |
| `token_endpoint_auth_method` | `client_secret_basic` | 允许 `client_secret_basic`、`client_secret_post`、`none`；`none` 不可与 `client_credentials` 组合 |
| `scope` | 空 | 空格分隔，每个值必须在服务端允许集合内 |
| `client_name` | 空 | 字符串 |
| `client_uri` | — | 若提供必须为绝对 URI |

`token_endpoint_auth_method` 为 `none` 的公共客户端不签发客户端密钥。

## 2. 接口契约

### 2.1 POST /register

请求体：

```json
{ "software_statement": "<JWS>" }
```

响应：

- `201 Created`：首次注册成功，返回完整客户端记录；机密客户端**仅此一次**
  返回明文 `client_secret` 与 `client_secret_expires_at`。
- `200 OK`：**幂等重放**——完全相同的声明（相同 `jti`）再次提交，返回同一
  客户端记录，不重复签发密钥。
- `409 Conflict`：同一 `software_id` 已注册但提交了不同声明（`jti` 不同），
  或显式 `client_id` 已被其他软件占用，错误码 `duplicate_client`，错误描述中
  给出已存在的 `client_id` 或并发说明。
- `4xx`：声明或元数据校验失败（见错误码表），**不产生任何持久化副作用**。

### 2.2 PUT /clients/{client_id}

请求体除 `software_statement` 外必须带整数 `version`（乐观锁条件）：

```json
{ "software_statement": "<JWS>", "version": 1 }
```

- 声明中的 `software_id` 与 `iss` 必须与在册记录一致（所有权证明）。
- 版本匹配则更新元数据、`version += 1`。
- 版本落后返回 `409 version_conflict`，错误描述中给出当前版本。
- 处于 `revoked`/`deleted` 的客户端拒绝更新（`409 client_revoked`），
  已撤销客户端只能走独立恢复流程。
- 元数据非法时整体校验失败，不会部分写入，既有记录保持不变。

### 2.3 密钥管理

- `POST /clients/{id}/secret/rotate`
  - 仅 `active` 状态的机密客户端可用。
  - 默认策略：旧 `current` 密钥转为 `previous` 并设置短暂的重叠到期时间，
    新密钥成为 `current`；同一时刻最多只有一个 `previous`。
  - `"revoke_previous": true`：所有旧密钥立即转为 `revoked`。
  - 响应返回新明文密钥（只此一次）。
- `POST /clients/{id}/secret/revoke`：撤销该客户端全部未撤销密钥。
- 密钥以 PBKDF2-HMAC-SHA256（随机盐、可配置迭代次数）哈希存储，数据库中
  永不存在明文。
- 认证（服务内部 `authenticate(client_id, secret)`）接受未过期的 `current`
  或 `previous` 密钥；`suspended`/`revoked` 客户端即使密钥正确也拒绝。

### 2.4 生命周期状态转换

`POST /clients/{id}/state/{target_state}`，可带 `version` 做条件转换。
合法转换：

```
                ┌──────────┐
                │  active  │◀──────────────┐
                └──┬───┬───┘               │ (仅独立 /recover 流程)
        suspend   │   │  revoke/delete    │
                   ▼   ▼                    │
              ┌───────────┐   resume        │
              │ suspended │─────────────────┤
              └───┬───┬───┘                  │
        resume   │   │  revoke/delete       │
                   ▼   ▼                      │
                ┌─────────┐  delete   ┌────────┐
                │ revoked │──────────▶│ deleted│ (终态)
                └─────────┘           └────────┘
                   终态（普通转换）
```

| 从 | 允许到 |
| --- | --- |
| `active` | `suspended`, `revoked`, `deleted` |
| `suspended` | `active`, `revoked`, `deleted` |
| `revoked` | `deleted` |
| `deleted` | （无） |

- 非法转换返回 `409 invalid_state_transition`。
- 转换到 `revoked` 时会**连带撤销全部密钥**。
- `revoked → active` 在普通状态接口中**被明确禁止**；唯一入口是
  `POST /clients/{id}/recover`。

#### 独立恢复流程 POST /clients/{id}/recover

刻意区别于普通更新，防止被撤销客户端悄悄复活：

1. 仅 `revoked` 状态可用（其它状态返回 `409 invalid_state_transition`）；
2. 必须提供能证明所有权的新软件声明，且体中显式声明 `"recover": true`；
3. 恢复后签发**全新的密钥**（机密客户端），所有旧密钥保持撤销，旧凭据
   永远不可能随恢复而复活。

### 2.5 GET /clients（列表）

查询参数：

| 参数 | 说明 |
| --- | --- |
| `state` | 按 `active`/`suspended`/`revoked`/`deleted` 过滤；非法值 400 |
| `cursor` | 上一页响应中的 `next_cursor`（不透明 base64） |
| `page_size` | 正整数，默认 50，上限 200 |

响应：

```json
{
  "clients": [ { ...client record... } ],
  "next_cursor": "Bg==" ,
  "total": 23
}
```

- 分页采用**基于插入 `rowid` 的 keyset 方案**：游标指向最后一行的单调
  rowid。翻页期间无论并发注册/更新多少，单次遍历不会重复也不会遗漏
  （后续新提交只会出现在后续新发起的遍历中）。
- `total` 为当前过滤条件下的总数，与游标位置无关。
- 列表/详情响应**绝不包含密钥材料**；明文密钥只在注册/轮换/恢复当次响应中出现。

## 3. 错误码

所有错误响应形如：

```json
{ "error": "<machine_readable_code>", "error_description": "<human text>" }
```

| HTTP | error 码 | 触发场景 |
| --- | --- | --- |
| 400 | `invalid_request` | 体不是 JSON 对象、缺 body、分页参数非法、更新缺 `version`、恢复缺 `recover:true` 等 |
| 400 | `malformed_software_statement` | 令牌不是三段式 JWS、base64/JSON 段损坏 |
| 400 | `invalid_signature` | HMAC 签名不匹配（伪造密钥、篡改签名/载荷） |
| 400 | `invalid_software_statement` | `alg` 非 HS256、`typ` 不支持、`iss/jti/software_id/iat/exp` 缺失或形状错误、`exp<=iat` |
| 400 | `software_statement_expired` | `exp` 已过 |
| 400 | `untrusted_issuer` | `iss` 不是本地受信任签发者 |
| 400 | `invalid_redirect_uris` | 非绝对 URI、含 fragment、非 https（非回环）、重复或缺失 |
| 400 | `invalid_grant_types` | 非法/重复的 grant_type |
| 400 | `invalid_token_endpoint_auth_method` | 非法认证方式或与 grant 冲突 |
| 400 | `invalid_scope` | 出现未被允许的 scope 值 |
| 400 | `invalid_client_metadata` | response_types 等其它元数据字段非法 |
| 403 | `software_statement_mismatch` | 更新/轮换/转换/恢复时声明不拥有该客户端（`software_id` 或 `iss` 不一致） |
| 404 | `client_not_found` | `client_id` 不存在 |
| 409 | `duplicate_client` | 重复注册：software_id/client_id 冲突（含并发竞争的败方） |
| 409 | `version_conflict` | 乐观版本号条件不满足（并发更新败方） |
| 409 | `invalid_state_transition` | 非法生命周期转换；对非 revoked 客户端调用恢复 |
| 409 | `client_revoked` | 已撤销客户端尝试普通更新 |
| 409 | `secret_rotation_rejected` | 非 active、公共客户端等不可轮换的情形 |
| 400 | `invalid_client` | 预留：凭据认证失败 |

## 4. 并发与一致性保证

1. **注册**：服务端 `software_id`、`client_id` 均为数据库 UNIQUE；应用层在
   进程内串行化“检查-插入”窗口，数据库约束兜底跨进程竞争。并发提交同一软件：
   一个 `201`，相同声明的其余请求 `200`，不同声明的其余请求 `409`。
2. **更新/状态转换**：`WHERE client_id=? AND version=?` 的比较并交换，
   影响行数为 0 即 `409 version_conflict`，由客户端基于最新版本重试。
3. **密钥轮换/撤销**：在单写事务中完成旧密钥降级与新密钥插入（部分唯一索引
   保证同一客户端至多一条 `current`），失败整体回滚。
4. **持久化**：SQLite WAL 模式落盘，客户端记录、版本、状态、密钥哈希在
   进程重启后完全保持；重叠窗口的旧密钥到期判断基于存储的 `expires_at`。
