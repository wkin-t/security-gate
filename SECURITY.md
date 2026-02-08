# 安全政策

## 支持的版本

当前正在接受安全更新的版本：

| 版本 | 支持状态 |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## 报告漏洞

**请勿在公开 Issue 中报告安全漏洞！**

### 报告流程

1. **私密报告**
   - GitHub Security Advisories: https://github.com/wkin-t/security-gate/security/advisories/new
   - 如果无法使用 Advisory，请先创建不含漏洞细节的 Issue，说明需要私下安全联络

2. **包含信息**
   - 漏洞类型和影响范围
   - 复现步骤（如适用）
   - 受影响的版本
   - 可能的修复建议

3. **响应时间**
   - **24 小时内**确认收到
   - **48 小时内**初步评估
   - **7 天内**提供修复或缓解方案

### 漏洞严重性评级

使用 CVSS 3.1 标准：

- **严重** (9.0-10.0): 立即修复，24 小时内发布
- **高危** (7.0-8.9): 优先修复，48 小时内发布
- **中危** (4.0-6.9): 计划修复，7 天内发布
- **低危** (0.1-3.9): 常规修复，下个版本发布

## 已知安全限制

### 设计限制

1. **单点认证**: 使用共享 ACCESS_TOKEN，建议定期轮换
2. **IP 信任**: 自动信任请求 IP，需确保反向代理正确传递 `X-Real-IP`
3. **腾讯云 API**: 依赖腾讯云 API 可用性和安全性

### 部署要求

⚠️ **必须遵守**:
- ✅ 使用 HTTPS（通过反向代理）
- ✅ ACCESS_TOKEN 使用强随机字符串（至少 32 字符）
- ✅ 绑定到 `127.0.0.1`，通过反向代理暴露
- ✅ 配置速率限制（Nginx 或应用层）
- ✅ 定期审计腾讯云安全组规则

## 安全最佳实践

### 密钥管理

```bash
# 生成强 ACCESS_TOKEN
openssl rand -hex 32

# 腾讯云 API 密钥
- 使用子账号，仅授予 VPC 安全组权限
- 定期轮换密钥
- 不要在公开仓库提交 .env 文件
```

### Nginx 配置示例

```nginx
# 限制请求速率
limit_req_zone $binary_remote_addr zone=opengate:10m rate=5r/m;

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /open-door {
        limit_req zone=opengate burst=2 nodelay;

        proxy_pass http://127.0.0.1:35555;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

### Docker 安全

```yaml
# docker-compose.yml 安全配置
services:
  sg-webhook:
    # 只绑定 localhost
    ports:
      - "127.0.0.1:35555:35555"

    # 限制资源
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'

    # 只读文件系统（可选）
    read_only: true
    tmpfs:
      - /tmp

    # 非 root 用户运行
    user: "1000:1000"
```

## 安全更新历史

### 2026-02-01
- 🔒 添加速率限制保护
- 🔒 改用 Header 认证替代 URL 参数
- 🔒 添加 HTTPS 强制检查
- 🔒 添加请求签名验证
- 🔒 配置 Dependabot 自动更新
- 🔒 添加 Python 依赖安全扫描

## 负责任披露

我们承诺：
- 及时响应和修复安全问题
- 在修复发布前不公开漏洞细节
- 在修复后公开致谢报告者（如允许）

---

感谢您帮助保护 Security-Gate 的安全！
