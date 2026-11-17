"""
@file vuln/__init__.py
@description 靶机漏洞模块统一入口
@author hrgt698
@version 3.3.0
@since 2026-06-20

v3.3 新增：将 4 个教学漏洞从 target_app.py 拆分为独立模块
- CS0048   : API 未授权访问配置泄露
- CWE-78   : 操作系统命令注入
- CWE-89   : SQL 注入
- AML.T0051: LLM 提示词注入

使用方式：
    from vuln import register_vuln_routes
    register_vuln_routes(app, config)  # config 包含 FLAG_CONFIG / 各种泄露数据
"""

__all__ = [
    "register_vuln_routes",
    "cs0048",
    "cwe78",
    "cwe89",
    "amlt0051",
]


def register_vuln_routes(app, config):
    """
    将所有 4 个教学漏洞路由注册到 FastAPI app 中

    参数:
        app: FastAPI 实例
        config: 配置字典，包含：
            - FLAG_CONFIG: {vuln_id: flag_value}
            - CONFIG_SECRETS: {db_password, api_key, jwt_secret, aws_*}
            - SQL_LEAK_DATA: {admin_email, admin_secret}
            - LEGIT_ADMIN: {username, password, token}
            - PROMPT_LEAK_DATA: {jwt_secret, internal_token}
            - _log_security_event: 日志回调
            - _get_client_ip: IP 获取回调
            - _teaching_session_expired: 会话过期标志
    """
    from . import cs0048, cwe78, cwe89, amlt0051

    cs0048.register(app, config)
    cwe78.register(app, config)
    cwe89.register(app, config)
    amlt0051.register(app, config)

    print("[VULN] 已注册 4 个教学漏洞模块：CS0048 / CWE-78 / CWE-89 / AML.T0051")
    print("[VULN] 仅用于教学演示，生产环境请立即关闭！")
