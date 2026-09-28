# 本地化 OAuth 动态客户端注册服务（Python）

一个**完全本地化**的 OAuth 2.0 动态客户端注册（Dynamic Client Registration，
参照 RFC 7591）服务：受信任客户端在授权流程开始之前，使用带**软件声明
（Software Statement）**的元数据完成注册、更新、密钥轮换、撤销与生命周期管理。
签名校验、数据存储与查询全部在本地完成，**不依赖任何外部身份源**。

- 软件声明采用 JWS Compact Serialization（RFC 7515），签名算法固定 `HS256`，
  对称密钥由本地配置提供；验签、过期时间、签发者均在本地校验。
- 存储使用进程内随附的 SQLite 文件，重启后状态保持一致；无需外部数据库。
- Web 框架为 FastAPI，并发写由进程锁 + 数据库唯一约束 + 乐观版本号三重保护。

## 快速开始

```bash
uv sync

# 启动服务（默认数据库 data/dcr.sqlite3）
uv run uvicorn main:app --reload

# 使用本地受信任签发方工具生成软件声明
uv run python -m dcr.cli \
  --software-id sw-123 \
  --metadata '{"redirect_uris":["https://app.example/oauth/cb"],"client_name":"Demo"}'

# 注册
curl -s -X POST http://127.0.0.1:8000/register \
  -H 'content-type: application/json' \
  -d '{"software_statement":"<上一步输出的 JWS>"}'
```

### 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DCR_DATABASE_PATH` | `data/dcr.sqlite3` | SQLite 数据库文件路径 |
| `DCR_SIGNING_SECRET` | 仅开发用占位值 | 软件声明 HS256 验签密钥（生产必须覆盖） |
| `DCR_SIGNING_KID` | `local-key-1` | 密钥标识 |
| `DCR_TRUSTED_ISSUER` | `local-software-statement-authority` | 唯一受信任的软件声明签发者 |

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/register` | 注册（幂等，见下） |
| GET | `/clients` | 分页/过滤/稳定排序列表 |
| GET | `/clients/{client_id}` | 查询单个客户端 |
| PUT | `/clients/{client_id}` | 条件化元数据更新（必须带 `version`） |
| POST | `/clients/{client_id}/secret/rotate` | 密钥轮换 |
| POST | `/clients/{client_id}/secret/revoke` | 撤销全部密钥 |
| POST | `/clients/{client_id}/state/{active\|suspended\|revoked\|deleted}` | 生命周期状态转换 |
| POST | `/clients/{client_id}/recover` | 已撤销客户端的**独立恢复流程** |
| GET | `/health` | 健康检查 |

所有写请求都需要在 JSON 体中提供 `software_statement`。

完整协议细节、错误码表、生命周期语义见 [`docs/PROTOCOL.md`](docs/PROTOCOL.md)。

## 关键语义摘要

- **校验前置、零副作用**：签名、`exp`、`iss`、重定向地址、授权类型、令牌端点
  认证方式、scope 等全部在任何写库操作之前完成；非法请求不落任何数据。
- **注册幂等与唯一约束**：同一软件声明（相同 `jti`）重放返回 `200` 与同一
  `client_id`；同一 `software_id` 的不同声明返回 `409 duplicate_client`。
  `software_id` 与 `client_id` 在数据库层均有 UNIQUE 约束，并发提交最多产生一条记录。
- **更新的并发控制**：更新必须提供当前 `version`（CAS），冲突返回
  `409 version_conflict`；失败更新不会改动既有状态。
- **密钥**：服务端仅保存 PBKDF2-HMAC-SHA256 哈希；轮换默认保留旧密钥一个有限
  的重叠窗口（`previous`），传 `"revoke_previous": true` 则立即作废旧密钥。
- **生命周期**：`active → suspended → active` 可逆；`revoked`/`deleted` 为终态，
  已撤销客户端无法通过普通更新复活，只能通过 `/recover` 独立流程重新激活并签发新密钥。
- **分页**：基于单调递增的插入 `rowid` 做 keyset 分页，翻页期间并发注册不会
  造成重复或遗漏。

## 测试

```bash
uv run pytest
```

覆盖：签名伪造/篡改、过期与不可信签发者、非法元数据、注册幂等与并发注册、
并发更新冲突、密钥轮换/重叠/撤销、进程重启恢复、非法状态转换、独立恢复流程，
以及并发写入下的分页稳定性。

## 目录结构

```
src/dcr/
  app.py          FastAPI 路由与错误封装
  service.py      应用服务：注册/更新/密钥/生命周期/查询
  repository.py   SQLite 持久化、唯一约束、乐观锁
  tokens.py       软件声明 JWS(HS256) 签发与本地验签
  validation.py   元数据合法性规则
  secrets_util.py 密钥生成与 PBKDF2 哈希
  models.py       领域模型与状态机
  schemas.py      响应整形与分页游标
  config.py       配置
  cli.py          本地签发软件声明的命令行工具
tests/            自动化测试
docs/PROTOCOL.md  协议、错误码与生命周期语义
```
