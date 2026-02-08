# -*- coding: utf-8 -*-
import os
import logging
import hmac
import hashlib
import time
import uuid
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
ENABLE_SIGNATURE = os.getenv("ENABLE_SIGNATURE", "true").lower() == "true"
ENABLE_IP_BLACKLIST = os.getenv("ENABLE_IP_BLACKLIST", "true").lower() == "true"
ENABLE_NONCE = os.getenv("ENABLE_NONCE", "true").lower() == "true"
MAX_AUTH_FAILURES = int(os.getenv("MAX_AUTH_FAILURES", "5"))  # 最大失败次数
BLACKLIST_DURATION = int(os.getenv("BLACKLIST_DURATION", "3600"))  # 封禁时长（秒）
NONCE_CACHE_SIZE = int(os.getenv("NONCE_CACHE_SIZE", "1000"))  # nonce 缓存大小
RUN_DEBUG = os.getenv("RUN_DEBUG", "false").lower() == "true"
RUN_HOST = os.getenv("RUN_HOST", "0.0.0.0")
RUN_PORT = int(os.getenv("RUN_PORT", "35555"))
# =========================================================

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

# IP 黑名单数据结构
# {ip: {'failures': count, 'first_failure': timestamp, 'blacklisted_until': timestamp}}
ip_blacklist = {}

# nonce 缓存 {nonce: timestamp}
nonce_cache = {}


def clean_expired_nonces():
    """清理过期的 nonce（超过 5 分钟）"""
    if not ENABLE_NONCE:
        return

    current_time = time.time()
    expired_nonces = [
        nonce for nonce, timestamp in nonce_cache.items()
        if current_time - timestamp > 300  # 5 分钟
    ]

    for nonce in expired_nonces:
        del nonce_cache[nonce]

    # 如果缓存过大，删除最老的记录
    if len(nonce_cache) > NONCE_CACHE_SIZE:
        sorted_nonces = sorted(nonce_cache.items(), key=lambda x: x[1])
        for nonce, _ in sorted_nonces[:len(nonce_cache) - NONCE_CACHE_SIZE]:
            del nonce_cache[nonce]


def is_nonce_used(nonce):
    """检查 nonce 是否已被使用"""
    if not ENABLE_NONCE or not nonce:
        return False

    clean_expired_nonces()
    return nonce in nonce_cache


def mark_nonce_used(nonce):
    """标记 nonce 已使用"""
    if not ENABLE_NONCE or not nonce:
        return

    nonce_cache[nonce] = time.time()


def clean_expired_blacklist():
    """清理过期的黑名单记录"""
    current_time = time.time()
    expired_ips = []

    for ip, data in ip_blacklist.items():
        # 清理已解除封禁的 IP
        if 'blacklisted_until' in data and current_time > data['blacklisted_until']:
            expired_ips.append(ip)
        # 清理超过 5 分钟的失败记录
        elif 'first_failure' in data and current_time - data['first_failure'] > 300:
            if 'blacklisted_until' not in data:
                expired_ips.append(ip)

    for ip in expired_ips:
        del ip_blacklist[ip]


def is_ip_blacklisted(ip):
    """检查 IP 是否被封禁"""
    if not ENABLE_IP_BLACKLIST:
        return False

    clean_expired_blacklist()

    if ip in ip_blacklist:
        data = ip_blacklist[ip]
        if 'blacklisted_until' in data:
            if time.time() < data['blacklisted_until']:
                return True
            else:
                # 封禁已过期，清除记录
                del ip_blacklist[ip]

    return False


def record_auth_failure(ip):
    """记录认证失败，必要时封禁 IP"""
    if not ENABLE_IP_BLACKLIST:
        return

    current_time = time.time()

    if ip not in ip_blacklist:
        ip_blacklist[ip] = {
            'failures': 1,
            'first_failure': current_time
        }
    else:
        data = ip_blacklist[ip]

        # 如果距离第一次失败超过 5 分钟，重置计数
        if current_time - data.get('first_failure', 0) > 300:
            data['failures'] = 1
            data['first_failure'] = current_time
        else:
            data['failures'] += 1

        # 达到阈值，封禁 IP
        if data['failures'] >= MAX_AUTH_FAILURES:
            data['blacklisted_until'] = current_time + BLACKLIST_DURATION
            logger.warning(
                f"IP {mask_ip(ip)} blacklisted for {BLACKLIST_DURATION}s "
                f"after {data['failures']} failed attempts"
            )


def get_client():
    """创建腾讯云 VPC 客户端"""
    cred = credential.Credential(SECRET_ID, SECRET_KEY)
    httpProfile = HttpProfile()
    httpProfile.endpoint = "vpc.tencentcloudapi.com"
    clientProfile = ClientProfile()
    clientProfile.httpProfile = httpProfile
    return vpc_client.VpcClient(cred, REGION, clientProfile)


def verify_signature(device_id, timestamp, signature, nonce=None):
    """
    验证请求签名 (可选的增强安全功能)

    Args:
        device_id: 设备标识
        timestamp: 请求时间戳
        signature: HMAC-SHA256 签名
        nonce: 一次性随机数 (可选，启用时必需)

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

        # 如果启用 nonce，检查是否已使用
        if ENABLE_NONCE:
            if not nonce:
                logger.warning("Nonce is required but not provided")
                return False

            if is_nonce_used(nonce):
                logger.warning(f"Nonce already used: {nonce[:8]}...")
                return False

        # 计算预期签名
        if ENABLE_NONCE and nonce:
            message = f"{device_id}:{timestamp}:{nonce}"
        else:
            message = f"{device_id}:{timestamp}"

        expected = hmac.new(
            ACCESS_TOKEN.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        # 使用安全的比较方法防止时序攻击
        if hmac.compare_digest(signature, expected):
            # 签名验证成功，标记 nonce 为已使用
            if ENABLE_NONCE and nonce:
                mark_nonce_used(nonce)
            return True

        return False

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

    except Exception:
        logger.exception("TencentCloud API error")
        return False, "internal_error"


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

    必需参数:
    - device: 设备标识 (推荐)
    - timestamp: Unix 时间戳 (启用签名时必需)
    - signature: HMAC-SHA256 签名 (启用签名时必需)
    - nonce: 一次性随机数 (启用 nonce 时必需，防重放)
    """
    # 0. 检查 IP 黑名单
    client_ip = get_remote_address()
    if is_ip_blacklisted(client_ip):
        logger.warning(f"Blacklisted IP {mask_ip(client_ip)} attempted access")
        return {"error": "Access denied", "message": "Too many failed attempts"}, 403

    # 1. 检查是否尝试使用已弃用的 URL 参数认证
    if 'key' in request.args:
        logger.warning(
            f"Deprecated URL parameter authentication attempted from {client_ip}"
        )
        record_auth_failure(client_ip)
        return {
            "error": "URL parameter authentication is no longer supported",
            "message": "Please use Authorization header instead",
            "example": "curl -H 'Authorization: Bearer YOUR_TOKEN' https://domain.com/open-door"
        }, 400

    # 2. 验证 Header 认证
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if not token or token != ACCESS_TOKEN:
        logger.warning(f"Unauthorized access from {client_ip}")
        record_auth_failure(client_ip)
        return {"error": "Unauthorized"}, 403

    # 2. 获取参数
    device_id = request.args.get('device', 'Unknown-Device')
    timestamp = request.args.get('timestamp', '')
    signature = request.args.get('signature', '')
    nonce = request.args.get('nonce', '')  # 一次性随机数

    # 3. 验证签名 (如果启用)
    if ENABLE_SIGNATURE:
        if not verify_signature(device_id, timestamp, signature, nonce):
            logger.warning(f"Invalid signature from {client_ip}")
            record_auth_failure(client_ip)
            return {"error": "Invalid signature"}, 403

    # 4. 获取真实 IP (优先使用 X-Real-IP，否则使用 X-Forwarded-For)
    user_ip = request.headers.get('X-Real-IP')
    if not user_ip:
        forwarded_for = request.headers.get('X-Forwarded-For', '')
        user_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr

    # 5. 执行业务逻辑
    request_id = str(uuid.uuid4())
    success, msg = update_security_group(user_ip, device_id)

    if success:
        logger.info("Request %s succeeded: %s", request_id, msg)
        return {
            "status": "success",
            "message": "Security group rules updated",
            "request_id": request_id
        }, 200
    else:
        logger.error("Request %s failed: %s", request_id, msg)
        return {
            "status": "error",
            "message": "Failed to update security group",
            "request_id": request_id
        }, 500


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

    app.run(host=RUN_HOST, port=RUN_PORT, debug=RUN_DEBUG)
