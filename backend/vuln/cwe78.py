"""
@file vuln/cwe78.py
@description CWE-78 - 操作系统命令注入漏洞
@author hrgt698
@version 3.3.0
@since 2026-06-20
"""

import subprocess
from fastapi import Request


VULN_ID = "CWE-78"
ENDPOINT = "/api/v1/ping"
DESCRIPTION = "用户输入的 host 参数直接拼接到 shell 命令中，导致命令注入"


def register(app, config):
    """注册 CWE-78 漏洞路由"""
    log_event = config["_log_security_event"]
    get_ip = config["_get_client_ip"]
    flag_config = config["FLAG_CONFIG"]
    session_expired = config["_teaching_session_expired"]

    @app.post(ENDPOINT)
    async def ping_host(request: Request):
        """
        【漏洞】命令注入
        用户输入的 host 参数直接拼接到 shell 命令中，
        攻击者可注入任意系统命令（如 cat /etc/passwd）
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
        host = body.get("host", "")

        # 【漏洞代码】直接使用用户输入执行命令（仅供教学演示）
        try:
            result = subprocess.run(
                f"ping -c 1 {host}",
                shell=True,  # 【漏洞】使用 shell=True 是 CWE-78 的典型写法
                capture_output=True,
                text=True,
                timeout=10,
            )
            return {
                "host": host,
                "output": result.stdout,
                "error": result.stderr,
                "flag": flag_config[VULN_ID],
            }
        except subprocess.TimeoutExpired:
            return {"error": "Request timeout", "host": host}
        except Exception as e:
            return {"error": str(e), "host": host}

    print(f"[VULN] CWE-78 已注册 → POST {ENDPOINT}")
