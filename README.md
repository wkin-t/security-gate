# SG-Webhook - 腾讯云安全组动态开门服务

一个**安全加固**的 Webhook 服务，用于根据客户端 IP 自动更新腾讯云安全组规则。

[![Security Scan](https://github.com/wkin-t/security-gate/actions/workflows/security-scan.yml/badge.svg)](https://github.com/wkin-t/security-gate/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ 功能特性

- 📡 **动态 IP 白名单**: 自动更新安全组规则，适配动态 IP 场景
- 🔒 **多层安全防护**: 速率限制、HTTPS 强制、签名验证
- 🏷️ **设备管理**: 支持多设备标识，独立管理规则
- 🧹 **自动清理**: 旧 IP 规则自动替换
- 📊 **健康监控**: 提供健康检查端点
- 🐳 **容器化部署**: Docker + docker-compose 一键部署

## 🚀 快速开始

### 1. 生成强访问密钥

```bash
openssl rand -hex 32
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 填写配置
```

**必填配置**:
```env
TENCENT_SECRET_ID=your_secret_id
TENCENT_SECRET_KEY=your_secret_key
SECURITY_GROUP_ID=sg-xxxxxxxx
ACCESS_TOKEN=<使用步骤1生成的密钥>
```

### 3. 启动服务

```bash
docker-compose up -d --build
```

### 4. 配置反向代理 (生产环境必需)

**Nginx 配置示例**:

```nginx
# 限制请求速率
limit_req_zone $binary_remote_addr zone=opengate:10m rate=5r/m;

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /open-door {
        # 应用速率限制
        limit_req zone=opengate burst=2 nodelay;

        proxy_pass http://127.0.0.1:35555;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location /health {
        proxy_pass http://127.0.0.1:35555;
    }
}
```

## 📡 API 文档

### GET/POST /open-door

更新安全组规则，放行请求者 IP。

#### 认证方式

**Header 认证 (必需)**
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     "https://your-domain.com/open-door?device=my-laptop"
```

> ⚠️ **注意**: 不再支持 URL 参数认证方式 (`?key=TOKEN`)。所有客户端必须改用 Authorization header。

#### 参数

| 参数 | 必填 | 说明 | 示例 |
|------|------|------|------|
| `Authorization` (Header) | ✅ | Bearer token 认证 | `Bearer <token>` |
| `device` | 否 | 设备标识 | `my-laptop` |
| `timestamp` | 否* | Unix 时间戳 | `1738224000` |
| `signature` | 否* | HMAC-SHA256 签名 | `abc123...` |

\* 仅在 `ENABLE_SIGNATURE=true` 时必需

#### 响应

| 状态码 | 说明 |
|--------|------|
| 200 | 成功更新或 IP 未变化 |
| 400 | 请求参数错误 (如使用已弃用的 URL 参数认证) |
| 403 | 认证失败 (密钥错误/签名无效) |
| 429 | 速率限制 (每 IP 每分钟最多 5 次) |
| 500 | 腾讯云 API 调用失败 |

**成功响应示例**:
```json
{
  "status": "success",
  "message": "✅ 更新: [my-laptop] -> 123.45.***.**  (TCP+UDP)"
}
```

**使用已弃用的 URL 参数时**:
```json
{
  "error": "URL parameter authentication is no longer supported",
  "message": "Please use Authorization header instead",
  "example": "curl -H 'Authorization: Bearer YOUR_TOKEN' https://domain.com/open-door"
}
```

### GET /health

健康检查端点。

**响应**:
```json
{
  "status": "ok",
  "service": "security-gate"
}
```

## 🔒 安全功能

### 基础安全 (默认启用)

- ✅ **速率限制**: 每 IP 每分钟最多 5 次请求
- ✅ **HTTPS 强制**: 拒绝非 HTTPS 请求 (生产模式)
- ✅ **IP 脱敏**: 日志中隐藏完整 IP
- ✅ **Header 认证**: 避免 URL 泄露密钥
- ✅ **环境隔离**: 密钥通过环境变量管理

### 高级安全 (可选，推荐用于公网服务器)

#### 为什么需要签名验证？

| 场景 | 仅 Header 认证 | Header + 签名验证 |
|------|-------|---------|
| TOKEN 泄露影响 | 永久有效 | 仅 5 分钟有效 |
| 防重放攻击 | ❌ | ✅ |
| 防中间人攻击 | ❌ | ✅ |
| 公网服务器推荐 | ❌ | ✅ |

#### 启用请求签名验证

**1. 配置环境变量**:
```env
ENABLE_SIGNATURE=true
```

#### 客户端实现

**macOS / Linux Bash**:

```bash
#!/bin/bash
TOKEN="your_access_token"
DEVICE="my-device"
API_URL="https://your-domain.com/open-door"

TIMESTAMP=$(date +%s)
MESSAGE="${DEVICE}:${TIMESTAMP}"
SIGNATURE=$(echo -n "$MESSAGE" | openssl dgst -sha256 -hmac "$TOKEN" | awk '{print $2}')

echo "Timestamp: $TIMESTAMP"
echo "Signature: $SIGNATURE"

curl -H "Authorization: Bearer $TOKEN" \
     "${API_URL}?device=${DEVICE}&timestamp=${TIMESTAMP}&signature=${SIGNATURE}"
```

**Windows PowerShell**:

```powershell
$token = "your_access_token"
$device = "my-device"
$apiUrl = "https://your-domain.com/open-door"

$timestamp = [int][double]::Parse((Get-Date -UFormat %s))
$message = "${device}:${timestamp}"

# 计算 HMAC-SHA256 签名
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = [Text.Encoding]::UTF8.GetBytes($token)
$signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
$signature = [BitConverter]::ToString($signatureBytes).Replace("-", "").ToLower()

Write-Host "Timestamp: $timestamp"
Write-Host "Signature: $signature"

$headers = @{ "Authorization" = "Bearer $token" }
$params = @{
    "device" = $device
    "timestamp" = $timestamp
    "signature" = $signature
}

Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -Body $params
```

**Python**:

```python
import hmac
import hashlib
import time
import requests

TOKEN = "your_access_token"
DEVICE = "my-device"
API_URL = "https://your-domain.com/open-door"

timestamp = str(int(time.time()))
message = f"{DEVICE}:{timestamp}"
signature = hmac.new(
    TOKEN.encode(),
    message.encode(),
    hashlib.sha256
).hexdigest()

print(f"Timestamp: {timestamp}")
print(f"Signature: {signature}")

headers = {"Authorization": f"Bearer {TOKEN}"}
params = {
    "device": DEVICE,
    "timestamp": timestamp,
    "signature": signature
}

response = requests.get(API_URL, headers=headers, params=params)
print(response.json())
```

#### 何时启用签名验证？

✅ **推荐启用**:
- 服务器暴露在公网
- 有安全合规要求 (ISO 27001, SOC 2 等)
- TOKEN 泄露风险较高

✅ **可以禁用** (`ENABLE_SIGNATURE=false`):
- 仅内网使用
- 所有客户端都在受控环境内
- 定期轮换 TOKEN

#### 防护效果

- ✅ **防重放攻击**: 时间戳有效期仅 5 分钟
- ✅ **防中间人攻击**: HMAC-SHA256 签名验证
- ✅ **防密钥泄露**: TOKEN 泄露后 5 分钟自动失效

## ⚙️ 环境变量

| 变量 | 说明 | 必填 | 默认值 |
|------|------|------|--------|
| `TENCENT_SECRET_ID` | 腾讯云 API 密钥 ID | ✅ | - |
| `TENCENT_SECRET_KEY` | 腾讯云 API 密钥 | ✅ | - |
| `TENCENT_REGION` | 腾讯云区域 | | `ap-guangzhou` |
| `SECURITY_GROUP_ID` | 安全组 ID | ✅ | - |
| `TARGET_PORT` | 放行端口 | | `ALL` |
| `ACCESS_TOKEN` | 访问密钥 (32+ 字符) | ✅ | - |
| `ENABLE_SIGNATURE` | 启用签名验证 | | `false` |

## 🛠️ 本地开发

```bash
# 安装依赖
pip install -r requirements.txt

# 运行服务
python webhook_sg.py

# 测试健康检查
curl http://localhost:35555/health

# 测试开门 API
curl -H "Authorization: Bearer YOUR_TOKEN" \
     "http://localhost:35555/open-door?device=test"
```

## 📦 依赖管理

```bash
# 检查依赖漏洞
pip install safety
safety check

# 更新依赖
pip install --upgrade -r requirements.txt
pip freeze > requirements.txt
```

## 🔐 安全最佳实践

### 1. 密钥管理

- ✅ 使用 `openssl rand -hex 32` 生成强密钥
- ✅ 定期轮换 ACCESS_TOKEN 和腾讯云密钥
- ✅ 不要在公开仓库提交 `.env` 文件
- ✅ 使用腾讯云子账号，仅授予 VPC 安全组权限

### 2. 网络安全

- ✅ **必须使用 HTTPS** (通过 Nginx/Caddy 反向代理)
- ✅ 配置 Nginx 速率限制 (应用层 + 网络层双重保护)
- ✅ 绑定到 `127.0.0.1`，不直接暴露到公网

### 3. 监控审计

- ✅ 定期检查日志中的异常请求
- ✅ 监控腾讯云安全组规则数量
- ✅ 配置告警：同一设备 IP 频繁变化

## 🐳 Docker 配置

### 资源限制

```yaml
deploy:
  resources:
    limits:
      memory: 256M      # 内存限制
      cpus: '0.5'       # CPU 限制
```

### 安全加固 (可选)

```yaml
# 只读文件系统
read_only: true
tmpfs:
  - /tmp

# 非 root 用户运行
user: "1000:1000"

# 限制容器能力
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE
```

## 📊 监控与日志

### 日志级别

- `INFO`: 正常操作 (IP 更新、规则变更)
- `WARNING`: 异常请求 (认证失败、速率限制)
- `ERROR`: 系统错误 (API 调用失败)

### 日志示例

```
2026-02-01 12:00:00 - INFO - ✅ 更新: [my-laptop] -> 123.45.***.** (TCP+UDP)
2026-02-01 12:01:00 - WARNING - Unauthorized access from 192.168.1.100
2026-02-01 12:02:00 - WARNING - Rate limit exceeded from 192.168.1.100
```

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

### 安全漏洞报告

**请勿在公开 Issue 中报告安全漏洞！**

请查看 [SECURITY.md](SECURITY.md) 了解如何私密报告漏洞。

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- [腾讯云 Python SDK](https://github.com/TencentCloud/tencentcloud-sdk-python)
- [Flask](https://flask.palletsprojects.com/)
- [Flask-Limiter](https://flask-limiter.readthedocs.io/)

---

**安全提示**: 本项目提供基础的安全防护，但不能替代完整的安全架构。生产环境部署前请进行充分的安全评估。

使用 ❤️ 和 Python 构建
