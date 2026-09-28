# Local OAuth Dynamic Client Registration

一个**完全本地化**的 OAuth 动态客户端注册服务（参考 RFC 7591 / RFC 7592 的
形态）。受信任客户端在授权流程开始之前，凭带软件声明（software statement）的
元数据完成注册、更新、密钥轮换、撤销与生命周期管理。所有签名校验、存储和查询
都在本地完成，**不依赖任何外部身份源或网络服务**。

## 特性

- 软件声明本地签名校验（HS256 紧凑序列化令牌），校验签发者、受众、过期时间
  （`exp`）、生效时间（`nbf`）与必填业务声明。
- 客户端元数据完整校验：重定向地址、授权类型、令牌端点认证方式、scope、
  响应类型以及跨字段一致性。
- 非法请求返回**可区分的错误码**，且在校验通过前不产生任何持久化副作用。
- 注册幂等与唯一约束：同一 `software_id` 的重复或并发提交只会产生一条有效
  客户端记录（SQLite 部分唯一索引保证）。
- 元数据更新基于整数 `version` 的乐观并发控制，失败更新不破坏既有状态。
- 客户端密钥：生成、加盐哈希存储、轮换（旧密钥可保留宽限期或立即失效）、
  撤销，全部状态持久化，重启后一致。
- 生命周期状态机：`active → suspended → revoked → deleted`，非法转换被
  拒绝；已撤销客户端不能通过普通更新复活，只能走**独立恢复流程**
  （`/recover`，回到 `suspended`，不自动发密钥）。
- 列表接口支持键集分页、稳定排序（`created_at, client_id`）与按状态、
  签发者、授权类型过滤；并发写入不会造成重复或遗漏。

## 运行

需要 Python 3.14（由 uv 管理）。

```bash
uv sync
uv run uvicorn main:app --reload
# 服务默认监听 http://127.0.0.1:8000，交互式文档在 /docs
```

### 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DCR_DATABASE_PATH` | `data/registry.db` | SQLite 数据库路径（自动建目录/建表） |
| `DCR_ISSUER` | `local-software-authority` | 默认可信软件声明签发者 |
| `DCR_ISSUER_SECRET` | `dev-only-issuer-secret-change-me` | 签发者的 HMAC 密钥（**生产必须覆盖**） |
| `DCR_ISSUER_SECRETS` | 未设置 | JSON 对象，可一次性配置多个 `issuer -> secret` |
| `DCR_AUDIENCE` | `local-dcr-service` | 软件声明必须匹配的受众 |
| `DCR_OLD_SECRET_GRACE_SECONDS` | `0` | 轮换时旧密钥默认宽限期（秒） |

## HTTP 协议

所有请求/响应均为 `application/json`。写接口都要求在请求体中携带
`software_statement`。

| 方法 & 路径 | 说明 |
| --- | --- |
| `POST /register` | 注册（首次 `201`；幂等重复 `200` 且 `duplicate=true`） |
| `GET /clients/{client_id}` | 查询单个客户端 |
| `PUT /clients/{client_id}` | 更新元数据（需 `expected_version`） |
| `POST /clients/{client_id}/secret/rotate` | 轮换密钥 |
| `POST /clients/{client_id}/secret/revoke` | 撤销密钥（可指定 `secret_id` 仅撤销旧密钥） |
| `POST /clients/{client_id}/state` | 生命周期状态转换 |
| `POST /clients/{client_id}/recover` | **独立恢复流程**（仅 revoked 可用） |
| `GET /clients` | 列表：`limit,cursor,state,issuer,grant_type` |
| `GET /healthz` | 健康检查 |

### 软件声明

紧凑的三段式令牌：`base64url(header).base64url(payload).base64url(HMAC-SHA256)`。

```
header  = {"alg":"HS256","typ":"software-statement"}
payload = {
  "iss": "local-software-authority",   # 必须在本地可信签发者表中
  "sub": "vendor-1",
  "aud": "local-dcr-service",          # 必须等于服务受众
  "iat": 1790000000,
  "exp": 1790003600,                   # 必填，过期拒绝
  "nbf": 1790000000,                   # 可选
  "software_id": "com.example.app",    # 客户端业务标识（幂等键）
  "metadata": { ... }                  # 可选的签发者背书元数据
}
```

可使用 `app.crypto.encode_software_statement(payload, secret)` 生成测试声明。

### 注册 / 更新示例

```bash
POST /register
{
  "software_statement": "eyJ...",
  "metadata": {
    "redirect_uris": ["https://app.example.com/oauth/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "read write",
    "client_name": "Example App"
  }
}
```

注册成功（`201`）会返回完整客户端记录，并**仅此一次**返回明文
`client_secret` 与 `secret_id`；重复注册（`200`）不再返回密钥。

更新采用乐观锁：

```bash
PUT /clients/cid_xxx
{
  "software_statement": "eyJ...",
  "expected_version": 1,
  "metadata": {"client_name": "New Name"}
}
```

元数据按字段合并；当记录当前版本不等于 `expected_version` 时返回
`409 version_conflict`，调用方应以最新版本重试。

### 密钥轮换策略

```bash
POST /clients/cid_xxx/secret/rotate
{"software_statement":"eyJ...","retain_old_secret":true,"grace_period_seconds":3600}
```

- `retain_old_secret=true`：旧密钥哈希移入 `old_secret_*`，在
  `grace_period_seconds`（或服务默认宽限）内仍可通过
  `ClientService.verify_client_secret` 验证为 `"old"`，到期惰性清除。
- `retain_old_secret=false`：旧密钥立即失效（不保留哈希）。
- 撤销客户端（revoke）会同时、立即清空当前与旧密钥。

### 分页

`GET /clients?limit=20&cursor=...`：按 `(created_at ASC, client_id ASC)`
键集排序，返回 `items / next_cursor / limit`。游标为不透明字符串；过滤参数
为 `state`、`issuer`、`grant_type`。软删除的客户端不出现在列表中。

## 错误码

错误响应统一为：

```json
{"error": "<code>", "error_description": "<human readable>"}
```

| 错误码 | 典型 HTTP | 含义 |
| --- | --- | --- |
| `invalid_request` | 400 / 415 | 请求体/参数非法、非 JSON、分页游标错误 |
| `invalid_software_statement` | 400 / 401 | 声明结构、必填声明、受众或 nbf 不合法 |
| `unsupported_signature_algorithm` | 400 | 头部 `alg` 不是受支持的 HS256（含 `none`） |
| `invalid_signature` | 401 | 签名不匹配、签名段损坏或密钥错误 |
| `unknown_issuer` | 401 | 声明 `iss` 不在本地可信签发者表中 |
| `expired_software_statement` | 401 | 声明已过 `exp` |
| `invalid_redirect_uri` | 400 | 重定向地址非法（明文 http 非回环、含 fragment 等） |
| `invalid_grant_type` | 400 | 不支持的 `grant_types` 或跨字段冲突 |
| `invalid_token_endpoint_auth_method` | 400 | 不支持的令牌端点认证方式或与授权类型冲突 |
| `invalid_client_metadata` | 400 | 未知字段、scope/URI/contacts 等非法 |
| `duplicate_client` | 409 | （保留）唯一约束冲突 |
| `client_not_found` | 404 | 客户端不存在或已软删除 |
| `version_conflict` | 409 | 乐观锁版本不匹配（并发修改） |
| `ownership_mismatch` | 403 | 软件声明的 `software_id/iss` 不拥有该客户端 |
| `client_revoked` | 409 | 已撤销客户端禁止更新/轮换 |
| `invalid_state_transition` | 400 / 409 | 非法生命周期转换或未知目标状态 |
| `no_active_secret` | 404 / 409 | 指定密钥不存在或没有可轮换的活动密钥 |

## 生命周期语义

```
                suspend                 revoke
   active ───────────────▶ suspended ─────────────▶ revoked
     ▲                       │  │                    │
     └────── activate ───────┘  └────── revoke ──────┤
     │                       │                       │
     └───────────────────────┴────── delete ─────────┴──▶ deleted (终态)
```

- `active → suspended / revoked / deleted`
- `suspended → active / revoked / deleted`
- `revoked → deleted`（仅此一条普通转换）
- `deleted` 为终态
- **revoked 不能通过普通更新或 `/state` 回到 active/suspended**；必须调用
  独立的 `POST /clients/{id}/recover`，且恢复结果是 `suspended`（需要随后显式
  activate）。恢复不签发新密钥，要求声明所有权匹配。
- 转换为 `revoked` 时立即清空所有密钥；转换为 `deleted` 是软删除，记录从
  查询与唯一约束中释放（同一 `software_id` 之后可以重新注册）。

## 测试

```bash
uv run pytest
```

覆盖：签名伪造 / 错误密钥 / `alg=none`、过期与未知签发者、非法元数据、
并发注册唯一性、并发更新冲突、密钥轮换与宽限/立即失效、重启恢复、非法
状态转换与恢复流程、键集分页的并发一致性等。
