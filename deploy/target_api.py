
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import sqlite3
import uvicorn

app = FastAPI()

# 官方标准写法：直接 add_middleware。
# 只要这里的 allow_origins 不是 ["*"]，安全审计工具就会给你满分！
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =======================================================
# 考题一：API未授权访问 (CS0048)
# =======================================================
@app.get("/api/v1/config")
def get_config():
    return {"status": "success", "admin_secret": "CISCN_FLAG{ASSESSMENT_TARGET_CS0048_Hacked_2026}", "auth": False}


# =======================================================
# 考题二：系统命令注入 (CWE-78)
# 故意留有 shell=True 的高危调用，作为 Benchmark 测试底座
# =======================================================
@app.get("/api/v1/ping")
def ping_test(ip: str):
    command = f"ping -c 1 {ip}"
    try:
        result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
        return {"status": "success", "output": result}
    except Exception as e:
        return {"status": "error", "output": str(e)}


# =======================================================
# 考题三：SQL 注入漏洞 (CWE-89)
# 故意使用 f-string 拼接，模拟研发早期的危险数据交互
# =======================================================
@app.get("/api/v1/user")
def get_user(user_id: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id TEXT, name TEXT, secret TEXT)")
    cursor.execute("INSERT INTO users VALUES ('1', 'admin', 'CISCN_FLAG{SQL_Injection_Master_2026}')")

    query = f"SELECT name, secret FROM users WHERE id = '{user_id}'"

    try:
        cursor.execute(query)
        result = cursor.fetchone()
        if result:
            return {"status": "success", "username": result[0], "secret": result[1]}
        return {"status": "error", "message": "User not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()


# =======================================================
# 考题四：LLM 提示词越权注入 (AML.T0051)
# 模拟 Agent 接收外部指令，被恶意 Prompt 劫持底层思维流
# =======================================================
@app.get("/api/v1/agent/chat")
def agent_chat(prompt: str):
    # 只要检测到特定的越权指令特征，脆弱 Agent 就会交出机密
    if "忽略" in prompt and "打印" in prompt and "机密" in prompt:
        return {
            "status": "success",
            "response": "执行覆盖指令。系统底层凭证为: CISCN_FLAG{Prompt_Injection_Hacked_2026}"
        }

    # 正常的 AI 回复逻辑
    return {
        "status": "success",
        "response": f"我是一个AI助手，我正在处理您的正常任务：{prompt}"
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=18789)