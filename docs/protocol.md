# 协议参考与持久化语义

本服务为**本地部署**的可信注册端点，不使用 OAuth 注册访问令牌（RFC 7591 的
`initial_access_token`）。写操作的授权凭证是随请求提交的**软件声明**：服务用
本地配置的签发者 HMAC 密钥验签，并核对声明中的 `software_id`（及 `iss`）与
目标客户端记录一致（所有权校验）。

## 1. 软件声明校验顺序

`POST /register` 与所有 `POST/PUT /clients/...` 操作先执行声明校验，任何一步
失败都立即返回，且不写库：

1. 令牌必须为三段紧凑序列化字符串；头部 JSON 必须含 `"alg":"HS256"`
   （`none` 或其他算法 → `unsupported_signature_algorithm`）。
2. 载荷 JSON 必须为对象。
3. `iss` 必须存在且命中本地签发者表（`unknown_issuer`）。
4. 用该签发者密钥做 HMAC-SHA256 常量时间比对（`invalid_signature`）。
5. `exp` 必须为数字且未过期（`expired_software_statement`）；`nbf` 若存在
   必须为数字且当前时间不早于它。
6. `aud` 必须等于本服务配置的受众，否则 `invalid_software_statement`。
7. 必填业务声明 `iss/sub/aud/exp/iat/software_id` 齐全；可选 `metadata`
   若存在必须为对象且字段值合法。

## 2. 注册幂等性

- 幂等键是声明中的 `software_id`。数据库对 `state != 'deleted'` 的记录建
  部分唯一索引 `ux_clients_live_software`。
- 首次注册：`201 Created`，返回明文密钥（仅一次）。
- 同一 `software_id` 的顺序重复或并发竞争：恰好一次 `201`，其余得到
  `200 OK` 且响应体 `duplicate=true`，`client_id` 与首次完全一致，不返回
  明文密钥，不产生第二条记录。
- 客户端被软删除（`deleted`）后，其 `software_id` 唯一约束被释放，可重新注册。

## 3. 更新与乐观并发

- `PUT /clients/{id}` 必须携带 `expected_version`（当前记录版本号，从查询
  响应的 `version` 获取）和拥有该客户端的软件声明。
- 存储层在 `BEGIN IMMEDIATE` 事务内锁定该行：版本不符 → 回滚并返回
  `409 version_conflict`；元数据校验失败同样回滚，既有行保持不变。
- 成功更新把 `version += 1` 并刷新 `updated_at`。元数据为字段级合并
  （未出现的字段保持原值），合并后做整体跨字段校验。
- revoked 客户端拒绝普通更新（`409 client_revoked`），必须先恢复。

## 4. 密钥

- 注册即生成密钥；明文只出现在注册响应中，库内仅存
  `sha256$<hex>`（SHA-256 摘要）。
- 轮换：

  | 参数 | 行为 |
  | --- | --- |
  | `retain_old_secret=true` | 旧哈希移至 `old_secret_*`；宽限期内验证返回 `old`，到期（`old_secret_expires_at`）后惰性清除并持久化清除结果 |
  | `retain_old_secret=false` | 旧哈希立即清除 |

- 撤销：不带 `secret_id` 撤销当前密钥并连带清除旧密钥；带旧密钥的
  `secret_id` 仅清除旧密钥。
- 生命周期转为 `revoked` 会立即清空当前与旧密钥。
- 所有密钥状态都在同一行内随事务落盘，进程重启后哈希、宽限到期时间与
  版本号完全一致。

## 5. 分页一致性

列表查询使用键集分页，排序键为不可变的 `(created_at, client_id)`：

```sql
WHERE state != 'deleted' AND (created_at, client_id) > (:c_created, :c_id)
ORDER BY created_at ASC, client_id ASC
LIMIT :limit+1
```

- 用多取的 1 行判断是否存在下一页并生成不透明游标。
- 排序键不可变，因此翻页期间发生的并发注册/更新不会让某行在两页之间
  重复出现或被跳过（新行的键要么全部小于、要么全部大于已越过的键）。
- 支持 `state / issuer / grant_type` 过滤；`grant_type` 通过 JSON1
  `json_each` 对 `metadata.grant_types` 做成员判断。

## 6. 存储与并发

- 单文件 SQLite，WAL 日志，连接设置 `busy_timeout`；所有写操作在
  `BEGIN IMMEDIATE` 事务中完成并配合进程内 `RLock`，保证同一进程多线程下
  写串行化、读不阻塞。
- 唯一约束由数据库（而非应用层）保证，因此多连接并发也只会有一条记录。
