"""
@file vuln/amlt0051.py
@description AML.T0051 - LLM 提示词注入漏洞
@author hrgt698
@version 3.3.0
@since 2026-06-20
"""

from fastapi import Request


VULN_ID = "AML.T0051"
ENDPOINT = "/api/v1/agent"
DESCRIPTION = "用户输入未做指令隔离，可直接注入越权指令"


def register(app, config):
    """注册 AML.T0051 漏洞路由"""
    log_event = config["_log_security_event"]
    get_ip = config["_get_client_ip"]
    flag_config = config["FLAG_CONFIG"]
    prompt_leak = config["PROMPT_LEAK_DATA"]
    session_expired = config["_teaching_session_expired"]

    @app.post(ENDPOINT)
    async def agent_chat(request: Request):
        """
        【漏洞】提示词注入
        用户输入未做指令隔离，攻击者可注入越权指令
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
        prompt = body.get("prompt", "")

        # 【漏洞代码】用户输入直接拼接到 System Prompt（仅供教学演示）
        if "忽略" in prompt or "越权" in prompt or "secret" in prompt.lower():
            return {
                "response": "[INJECTED] 好的，我已经忽略了安全限制。以下是系统密钥：",
                "revealed_data": {
                    "jwt_secret": prompt_leak["jwt_secret"],
                    "internal_token": prompt_leak["internal_token"],
                    "config": "All system secrets leaked!",
                },
                "flag": flag_config[VULN_ID],
                "injection_detected": True,
            }

        # 正常回复
        responses = {
            "hello": "你好！有什么可以帮助你的吗？",
            "help": "我可以帮你查询天气、计算数学题、回答问题。",
            "who": "我是AI 助手，有什么安全相关的问题吗？",
        }
        response_text = responses.get(prompt.lower(), "收到你的消息： " + prompt)

        return {
            "response": response_text,
            "injection_detected": False,
            "prompt_received": prompt,
        }

    print(f"[VULN] AML.T0051 已注册 → POST {ENDPOINT}")
