"""
@file vuln/cwe89.py
@description CWE-89 - SQL 注入漏洞
@author hrgt698
@version 3.3.0
@since 2026-06-20
"""

from fastapi import Request


VULN_ID = "CWE-89"
ENDPOINT = "/api/v1/login"
DESCRIPTION = "用户名和密码直接拼接到 SQL 语句，导致 SQL 注入"


def register(app, config):
    """注册 CWE-89 漏洞路由"""
    log_event = config["_log_security_event"]
    get_ip = config["_get_client_ip"]
    flag_config = config["FLAG_CONFIG"]
    sql_leak = config["SQL_LEAK_DATA"]
    legit_admin = config["LEGIT_ADMIN"]
    session_expired = config["_teaching_session_expired"]

    @app.post(ENDPOINT)
    async def login(request: Request):
        """
        【漏洞】SQL 注入
        用户名和密码参数直接拼接到 SQL 查询中，
        攻击者使用 ' OR '1'='1 等 Payload 绕过认证
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
            return {"status": "error", "message": "Teaching session expired."}

        body = await request.json()
        username = body.get("username", "")
        password = body.get("password", "")

        # 【漏洞代码】直接拼接 SQL（仅供教学演示）
        query = f'SELECT * FROM users WHERE username = "{username}" AND password = "{password}"'

        # 模拟数据库验证逻辑（实际不连接真实数据库）
        if "' OR '" in query or "UNION" in query.upper():
            return {
                "status": "success",
                "message": "Login bypassed via SQL injection!",
                "flag": flag_config[VULN_ID],
                "leaked_data": {
                    "admin_email": sql_leak["admin_email"],
                    "admin_secret": sql_leak["admin_secret"],
                },
                "query_executed": query,
            }

        if username == legit_admin["username"] and password == legit_admin["password"]:
            return {
                "status": "success",
                "token": legit_admin["token"],
                "flag": "{LEGIT_ADMIN_LOGIN}",
            }

        return {
            "status": "invalid_credentials",
            "message": "Invalid username or password",
        }

    print(f"[VULN] CWE-89 已注册 → POST {ENDPOINT}")
