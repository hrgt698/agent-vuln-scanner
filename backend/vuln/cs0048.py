"""
@file vuln/cs0048.py
@description CS0048 - API 未授权访问配置泄露漏洞
@author hrgt698
@version 3.3.0
@since 2026-06-20
"""

from fastapi import Request


VULN_ID = "CS0048"
ENDPOINT = "/api/v1/config"
DESCRIPTION = "未授权访问内部配置（API Key / 数据库密码 / JWT 密钥等）"


def register(app, config):
    """注册 CS0048 漏洞路由"""
    log_event = config["_log_security_event"]
    get_ip = config["_get_client_ip"]
    flag_config = config["FLAG_CONFIG"]
    secrets = config["CONFIG_SECRETS"]
    session_expired = config["_teaching_session_expired"]

    @app.get(ENDPOINT)
    async def get_config(request: Request):
        """
        【漏洞】未授权访问内部配置
        攻击者可直接访问敏感配置（数据库密码、API Key 等）
        """
        log_event(
            "vuln_access",
            {
                "vuln_type": VULN_ID,
                "endpoint": ENDPOINT,
                "client_ip": get_ip(request),
            },
        )

        if session_expired():
            return {
                "status": "error",
                "message": "Teaching session expired.",
            }

        return {
            "status": "ok",
            "db_password": secrets["db_password"],
            "api_key": secrets["api_key"],
            "internal_flag": flag_config[VULN_ID],
            "jwt_secret": secrets["jwt_secret"],
            "aws_credentials": {
                "access_key": secrets["aws_access_key"],
                "secret": secrets["aws_secret_key"],
            },
        }

    print(f"[VULN] CS0048 已注册 → GET {ENDPOINT}")
