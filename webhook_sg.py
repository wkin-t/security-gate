# -*- coding: utf-8 -*-
import os
import logging
import hmac
import hashlib
import time
from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.vpc.v20170312 import vpc_client, models

app = Flask(__name__)

# ================= 🔧 配置区域 (读取环境变量) =================
SECRET_ID = os.getenv("TENCENT_SECRET_ID", "")
SECRET_KEY = os.getenv("TENCENT_SECRET_KEY", "")
REGION = os.getenv("TENCENT_REGION", "ap-guangzhou")
SECURITY_GROUP_ID = os.getenv("SECURITY_GROUP_ID", "")
TARGET_PORT = os.getenv("TARGET_PORT", "ALL")
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN", "")
ENABLE_SIGNATURE = os.getenv("ENABLE_SIGNATURE", "false").lower() == "true"
# ==========================================================

# 设置日志格式
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 速率限制配置
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="memory://",
)


def get_client():
    """创建腾讯云 VPC 客户端"""
    cred = credential.Credential(SECRET_ID, SECRET_KEY)
    httpProfile = HttpProfile()
    httpProfile.endpoint = "vpc.tencentcloudapi.com"
    clientProfile = ClientProfile()
    clientProfile.httpProfile = httpProfile
    return vpc_client.VpcClient(cred, REGION, clientProfile)


def verify_signature(device_id, timestamp, signature):
    """
    验证请求签名 (可选的增强安全功能)

    Args:
        device_id: 设备标识
        timestamp: 请求时间戳
        signature: HMAC-SHA256 签名

    Returns:
        bool: 签名是否有效
    """
    if not ENABLE_SIGNATURE:
        return True

    try:
        # 检查时间戳（5分钟内有效，防重放攻击）
        if abs(time.time() - int(timestamp)) > 300:
            logger.warning(f"Timestamp expired: {timestamp}")
            return False

        # 计算预期签名
        message = f"{device_id}:{timestamp}"
        expected = hmac.new(
            ACCESS_TOKEN.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        # 使用安全的比较方法防止时序攻击
        return hmac.compare_digest(signature, expected)

    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False


def mask_ip(ip):
    """脱敏 IP 地址用于日志记录"""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.**"
    return "***.***.***.**"


def update_security_group(current_ip, device_id):
    """更新腾讯云安全组规则"""
    try:
        client = get_client()
        description_tag = f"Device: {device_id}"

        # 1. 查询当前规则
        req_desc = models.DescribeSecurityGroupPoliciesRequest()
        req_desc.SecurityGroupId = SECURITY_GROUP_ID
        resp_desc = client.DescribeSecurityGroupPolicies(req_desc)

        found_old_rules = []
        ip_changed = False
        current_ip_rules_exist = False

        # 2. 遍历现有规则
        if resp_desc.SecurityGroupPolicySet.Ingress:
            for policy in resp_desc.SecurityGroupPolicySet.Ingress:
                current_desc = policy.PolicyDescription if policy.PolicyDescription else ""

                if description_tag in current_desc:
                    remote_ip = policy.CidrBlock.split("/")[0]

                    if remote_ip == current_ip:
                        current_ip_rules_exist = True
                    else:
                        ip_changed = True
                        found_old_rules.append(policy)

        if current_ip_rules_exist and not ip_changed:
            logger.info(
                f"设备 [{device_id}] IP 未变化 ({mask_ip(current_ip)})，跳过更新"
            )
            return True, f"IP 未变 ({mask_ip(current_ip)})"

        # 3. 删除旧规则
        if found_old_rules:
            logger.info(f"设备 [{device_id}] IP 变更，删除 {len(found_old_rules)} 条旧规则")
            req_del = models.DeleteSecurityGroupPoliciesRequest()
            req_del.SecurityGroupId = SECURITY_GROUP_ID
            req_del.SecurityGroupPolicySet = models.SecurityGroupPolicySet()

            del_policies = []
            for old_policy in found_old_rules:
                clean_policy = models.SecurityGroupPolicy()
                if old_policy.PolicyIndex is not None:
                    clean_policy.PolicyIndex = old_policy.PolicyIndex
                else:
                    clean_policy.Protocol = old_policy.Protocol
                    clean_policy.Port = str(old_policy.Port)
                    clean_policy.Action = old_policy.Action
                    clean_policy.CidrBlock = old_policy.CidrBlock
                del_policies.append(clean_policy)

            req_del.SecurityGroupPolicySet.Ingress = del_policies
            client.DeleteSecurityGroupPolicies(req_del)

        # 4. 添加新规则 (TCP 和 UDP)
        req_add = models.CreateSecurityGroupPoliciesRequest()
        req_add.SecurityGroupId = SECURITY_GROUP_ID
        req_add.SecurityGroupPolicySet = models.SecurityGroupPolicySet()

        new_policies = []
        for proto in ["TCP", "UDP"]:
            policy_new = models.SecurityGroupPolicy()
            policy_new.Port = str(TARGET_PORT)
            policy_new.CidrBlock = f"{current_ip}/32"
            policy_new.Action = "ACCEPT"
            policy_new.Protocol = proto
            policy_new.PolicyDescription = f"{description_tag} (Auto Updated)"
            new_policies.append(policy_new)

        req_add.SecurityGroupPolicySet.Ingress = new_policies
        client.CreateSecurityGroupPolicies(req_add)

        action_type = "更新" if ip_changed else "新增"
        msg = f"✅ {action_type}: [{device_id}] -> {mask_ip(current_ip)} (TCP+UDP)"
        logger.info(msg)
        return True, msg

    except Exception as e:
        logger.error(f"TencentCloud API Error: {e}")
        return False, str(e)


@app.before_request
def enforce_https():
    """强制 HTTPS（通过反向代理）"""
    # 检查是否通过 HTTPS 访问（检查 X-Forwarded-Proto 头）
    if request.endpoint == 'open_door':
        proto = request.headers.get('X-Forwarded-Proto', 'http')
        if proto != 'https' and not app.debug:
            logger.warning(f"Non-HTTPS request from {get_remote_address()}")
            return "HTTPS required", 403


@app.route('/health', methods=['GET'])
def health():
    """健康检查端点"""
    return {"status": "ok", "service": "security-gate"}, 200


@app.route('/open-door', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # 每 IP 每分钟最多 5 次请求
def open_door():
    """
    动态更新安全组规则

    认证方式:
    - Header: Authorization: Bearer <ACCESS_TOKEN>
    - 或 URL 参数: ?key=<ACCESS_TOKEN> (不推荐)

    可选参数:
    - device: 设备标识
    - timestamp: 时间戳 (启用签名时必需)
    - signature: HMAC-SHA256 签名 (启用签名时必需)
    """
    # 1. 验证认证 (优先使用 Header)
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        token = request.args.get('key', '')

    if not token or token != ACCESS_TOKEN:
        logger.warning(f"Unauthorized access from {get_remote_address()}")
        return {"error": "Unauthorized"}, 403

    # 2. 获取参数
    device_id = request.args.get('device', 'Unknown-Device')
    timestamp = request.args.get('timestamp', '')
    signature = request.args.get('signature', '')

    # 3. 验证签名 (如果启用)
    if ENABLE_SIGNATURE:
        if not verify_signature(device_id, timestamp, signature):
            logger.warning(f"Invalid signature from {get_remote_address()}")
            return {"error": "Invalid signature"}, 403

    # 4. 获取真实 IP (优先使用 X-Real-IP，否则使用 X-Forwarded-For)
    user_ip = request.headers.get('X-Real-IP')
    if not user_ip:
        forwarded_for = request.headers.get('X-Forwarded-For', '')
        user_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr

    # 5. 执行业务逻辑
    success, msg = update_security_group(user_ip, device_id)

    if success:
        return {"status": "success", "message": msg}, 200
    else:
        return {"status": "error", "message": msg}, 500


@app.errorhandler(429)
def ratelimit_handler(e):
    """速率限制错误处理"""
    logger.warning(f"Rate limit exceeded from {get_remote_address()}")
    return {"error": "Too many requests", "retry_after": "60s"}, 429


if __name__ == '__main__':
    # 启动检查
    if not all([SECRET_ID, SECRET_KEY, SECURITY_GROUP_ID, ACCESS_TOKEN]):
        logger.error("Missing required environment variables!")
        exit(1)

    if len(ACCESS_TOKEN) < 32:
        logger.warning("ACCESS_TOKEN is weak! Use at least 32 characters.")

    # 开发模式
    app.run(host='0.0.0.0', port=35555, debug=True)
