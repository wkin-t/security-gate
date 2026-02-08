# -*- coding: utf-8 -*-
import os
import sys
import pytest
import hmac
import hashlib
import time
import uuid
from unittest.mock import patch, MagicMock

# 设置环境变量，然后导入 app
os.environ['TENCENT_SECRET_ID'] = 'test-id'
os.environ['TENCENT_SECRET_KEY'] = 'test-key'
os.environ['SECURITY_GROUP_ID'] = 'sg-test'
os.environ['ACCESS_TOKEN'] = 'test-token-1234567890abcdef'

import webhook_sg


@pytest.fixture
def client():
    """创建测试客户端"""
    webhook_sg.app.config['TESTING'] = True
    webhook_sg.app.config['DEBUG'] = True  # 禁用 HTTPS 检查
    webhook_sg.limiter.enabled = False  # 禁用速率限制

    # 清空黑名单和 nonce 缓存
    webhook_sg.ip_blacklist.clear()
    webhook_sg.nonce_cache.clear()

    with webhook_sg.app.test_client() as client:
        yield client


class TestAuthenticationRemoval:
    """测试 URL 参数认证移除"""

    def test_health_check(self, client):
        """健康检查端点应该正常工作"""
        response = client.get('/health')
        assert response.status_code == 200
        assert response.json['status'] == 'ok'

    def test_header_authentication_success(self, client):
        """Header 认证应该正常工作"""
        with patch('webhook_sg.ENABLE_SIGNATURE', False):  # 禁用签名验证以简化测试
            with patch('webhook_sg.update_security_group') as mock_update:
                mock_update.return_value = (True, 'Success')

                response = client.get(
                    '/open-door?device=test-device',
                    headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                )

                assert response.status_code == 200
                assert response.json['status'] == 'success'
                assert response.json['message'] == 'Security group rules updated'
                assert 'request_id' in response.json

    def test_update_failure_does_not_expose_internal_error(self, client):
        """后端错误不应把内部异常细节回传给客户端"""
        with patch('webhook_sg.ENABLE_SIGNATURE', False):
            with patch('webhook_sg.update_security_group') as mock_update:
                mock_update.return_value = (False, "Traceback: secret details")

                response = client.get(
                    '/open-door?device=test-device',
                    headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                )

                assert response.status_code == 500
                assert response.json['status'] == 'error'
                assert response.json['message'] == 'Failed to update security group'
                assert 'request_id' in response.json
                assert 'Traceback' not in response.json['message']

    def test_url_parameter_authentication_rejected(self, client):
        """URL 参数认证应该被拒绝，返回 400 错误"""
        response = client.get('/open-door?key=test-token-1234567890abcdef&device=test-device')

        assert response.status_code == 400
        assert response.json['error'] == 'URL parameter authentication is no longer supported'
        assert 'Authorization header' in response.json['message']
        assert 'example' in response.json

    def test_url_parameter_authentication_with_valid_header(self, client):
        """即使 Header 有效，URL 参数也应该被拒绝"""
        response = client.get(
            '/open-door?key=test-token&device=test-device',
            headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
        )

        assert response.status_code == 400
        assert response.json['error'] == 'URL parameter authentication is no longer supported'

    def test_missing_header_authentication(self, client):
        """缺少 Header 认证应该返回 401 错误"""
        response = client.get('/open-door?device=test-device')

        assert response.status_code == 403
        assert response.json['error'] == 'Unauthorized'

    def test_invalid_header_authentication(self, client):
        """无效的 Header 认证应该返回 401 错误"""
        response = client.get(
            '/open-door?device=test-device',
            headers={'Authorization': 'Bearer invalid-token'}
        )

        assert response.status_code == 403
        assert response.json['error'] == 'Unauthorized'

    def test_error_response_format(self, client):
        """验证错误响应格式包含迁移指南"""
        response = client.get('/open-door?key=test-token&device=test-device')

        data = response.json
        assert 'error' in data
        assert 'message' in data
        assert 'example' in data
        assert 'curl' in data['example'].lower()
        assert 'Authorization' in data['example']


class TestSignatureVerification:
    """测试签名验证功能"""

    @pytest.fixture
    def client(self):
        """创建测试客户端"""
        webhook_sg.app.config['TESTING'] = True
        webhook_sg.app.config['DEBUG'] = True  # 禁用 HTTPS 检查
        webhook_sg.limiter.enabled = False  # 禁用速率限制

        # 清空黑名单和 nonce 缓存
        webhook_sg.ip_blacklist.clear()
        webhook_sg.nonce_cache.clear()

        with webhook_sg.app.test_client() as client:
            yield client

    def _generate_signature(self, device_id, timestamp):
        """生成有效的 HMAC-SHA256 签名"""
        message = f"{device_id}:{timestamp}"
        signature = hmac.new(
            b'test-token-1234567890abcdef',
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def test_signature_disabled_no_signature_required(self, client):
        """签名验证关闭时（默认），不需要签名"""
        with patch('webhook_sg.ENABLE_SIGNATURE', False):
            with patch('webhook_sg.update_security_group') as mock_update:
                mock_update.return_value = (True, 'Success')

                response = client.get(
                    '/open-door?device=test-device',
                    headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                )

                assert response.status_code == 200
                assert response.json['status'] == 'success'

    def test_signature_enabled_valid_signature(self, client):
        """签名验证启用时，有效签名应该通过（不使用 nonce）"""
        with patch('webhook_sg.ENABLE_SIGNATURE', True):
            with patch('webhook_sg.ENABLE_NONCE', False):  # 禁用 nonce 以测试纯签名
                with patch('webhook_sg.update_security_group') as mock_update:
                    mock_update.return_value = (True, 'Success')

                    timestamp = str(int(time.time()))
                    signature = self._generate_signature('test-device', timestamp)

                    response = client.get(
                        f'/open-door?device=test-device&timestamp={timestamp}&signature={signature}',
                        headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                    )

                    assert response.status_code == 200
                    assert response.json['status'] == 'success'

    def test_signature_enabled_no_signature(self, client):
        """签名验证启用时，缺少签名应该返回 403"""
        with patch('webhook_sg.ENABLE_SIGNATURE', True):
            with patch('webhook_sg.ENABLE_NONCE', False):
                response = client.get(
                    '/open-door?device=test-device&timestamp=123456789',
                    headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                )

                assert response.status_code == 403
                assert response.json['error'] == 'Invalid signature'

    def test_signature_enabled_invalid_signature(self, client):
        """签名验证启用时，无效签名应该返回 403"""
        with patch('webhook_sg.ENABLE_SIGNATURE', True):
            with patch('webhook_sg.ENABLE_NONCE', False):
                timestamp = str(int(time.time()))

                response = client.get(
                    f'/open-door?device=test-device&timestamp={timestamp}&signature=invalid_signature_12345',
                    headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                )

                assert response.status_code == 403
                assert response.json['error'] == 'Invalid signature'

    def test_signature_enabled_expired_timestamp(self, client):
        """签名验证启用时，过期的时间戳应该返回 403"""
        with patch('webhook_sg.ENABLE_SIGNATURE', True):
            with patch('webhook_sg.ENABLE_NONCE', False):
                # 使用 6 分钟前的时间戳（超过 5 分钟有效期）
                old_timestamp = str(int(time.time()) - 400)
                signature = self._generate_signature('test-device', old_timestamp)

                response = client.get(
                    f'/open-door?device=test-device&timestamp={old_timestamp}&signature={signature}',
                    headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                )

                assert response.status_code == 403
                assert response.json['error'] == 'Invalid signature'

    def test_signature_enabled_wrong_device_id(self, client):
        """签名验证启用时，错误的设备 ID 应该导致签名验证失败"""
        with patch('webhook_sg.ENABLE_SIGNATURE', True):
            with patch('webhook_sg.ENABLE_NONCE', False):
                timestamp = str(int(time.time()))
                # 为 test-device 生成签名，但请求使用不同的设备 ID
                signature = self._generate_signature('test-device', timestamp)

                response = client.get(
                    f'/open-door?device=wrong-device&timestamp={timestamp}&signature={signature}',
                    headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                )

                assert response.status_code == 403
                assert response.json['error'] == 'Invalid signature'


class TestIPBlacklist:
    """测试 IP 黑名单功能"""

    @pytest.fixture
    def client(self):
        """创建测试客户端"""
        webhook_sg.app.config['TESTING'] = True
        webhook_sg.app.config['DEBUG'] = True
        webhook_sg.limiter.enabled = False

        # 清空黑名单
        webhook_sg.ip_blacklist.clear()

        with webhook_sg.app.test_client() as client:
            yield client

    def test_ip_blacklist_after_failures(self, client):
        """失败次数达到阈值后 IP 被封禁"""
        with patch('webhook_sg.ENABLE_IP_BLACKLIST', True):
            with patch('webhook_sg.MAX_AUTH_FAILURES', 3):
                # 前 2 次失败
                for _ in range(2):
                    response = client.get(
                        '/open-door?device=test',
                        headers={'Authorization': 'Bearer wrong-token'}
                    )
                    assert response.status_code == 403

                # 第 3 次失败，触发封禁
                response = client.get(
                    '/open-door?device=test',
                    headers={'Authorization': 'Bearer wrong-token'}
                )
                assert response.status_code == 403

                # 下次请求应该被黑名单拦截
                response = client.get(
                    '/open-door?device=test',
                    headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                )
                assert response.status_code == 403
                assert response.json['error'] == 'Access denied'

    def test_ip_blacklist_disabled(self, client):
        """禁用黑名单时不应封禁"""
        with patch('webhook_sg.ENABLE_IP_BLACKLIST', False):
            # 多次失败
            for _ in range(10):
                response = client.get(
                    '/open-door?device=test',
                    headers={'Authorization': 'Bearer wrong-token'}
                )
                assert response.status_code == 403
                assert response.json['error'] == 'Unauthorized'


class TestNonceVerification:
    """测试 nonce 防重放功能"""

    @pytest.fixture
    def client(self):
        """创建测试客户端"""
        webhook_sg.app.config['TESTING'] = True
        webhook_sg.app.config['DEBUG'] = True
        webhook_sg.limiter.enabled = False

        # 清空 nonce 缓存
        webhook_sg.nonce_cache.clear()

        with webhook_sg.app.test_client() as client:
            yield client

    def _generate_signature_with_nonce(self, device_id, timestamp, nonce):
        """生成包含 nonce 的签名"""
        message = f"{device_id}:{timestamp}:{nonce}"
        signature = hmac.new(
            b'test-token-1234567890abcdef',
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def test_nonce_enabled_valid_request(self, client):
        """启用 nonce 时，有效的 nonce 应该通过"""
        with patch('webhook_sg.ENABLE_SIGNATURE', True):
            with patch('webhook_sg.ENABLE_NONCE', True):
                with patch('webhook_sg.update_security_group') as mock_update:
                    mock_update.return_value = (True, 'Success')

                    timestamp = str(int(time.time()))
                    nonce = str(uuid.uuid4())
                    signature = self._generate_signature_with_nonce('test-device', timestamp, nonce)

                    response = client.get(
                        f'/open-door?device=test-device&timestamp={timestamp}&nonce={nonce}&signature={signature}',
                        headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                    )

                    assert response.status_code == 200
                    assert response.json['status'] == 'success'

    def test_nonce_enabled_duplicate_nonce(self, client):
        """启用 nonce 时，重复的 nonce 应该被拒绝"""
        with patch('webhook_sg.ENABLE_SIGNATURE', True):
            with patch('webhook_sg.ENABLE_NONCE', True):
                with patch('webhook_sg.update_security_group') as mock_update:
                    mock_update.return_value = (True, 'Success')

                    timestamp = str(int(time.time()))
                    nonce = str(uuid.uuid4())
                    signature = self._generate_signature_with_nonce('test-device', timestamp, nonce)

                    # 第一次请求成功
                    response1 = client.get(
                        f'/open-door?device=test-device&timestamp={timestamp}&nonce={nonce}&signature={signature}',
                        headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                    )
                    assert response1.status_code == 200

                    # 重复相同的 nonce，应该被拒绝
                    response2 = client.get(
                        f'/open-door?device=test-device&timestamp={timestamp}&nonce={nonce}&signature={signature}',
                        headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                    )
                    assert response2.status_code == 403
                    assert response2.json['error'] == 'Invalid signature'

    def test_nonce_enabled_missing_nonce(self, client):
        """启用 nonce 时，缺少 nonce 应该被拒绝"""
        with patch('webhook_sg.ENABLE_SIGNATURE', True):
            with patch('webhook_sg.ENABLE_NONCE', True):
                timestamp = str(int(time.time()))
                # 不包含 nonce 的签名
                message = f"test-device:{timestamp}"
                signature = hmac.new(
                    b'test-token-1234567890abcdef',
                    message.encode(),
                    hashlib.sha256
                ).hexdigest()

                response = client.get(
                    f'/open-door?device=test-device&timestamp={timestamp}&signature={signature}',
                    headers={'Authorization': 'Bearer test-token-1234567890abcdef'}
                )

                assert response.status_code == 403
                assert response.json['error'] == 'Invalid signature'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
