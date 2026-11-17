"""
services.constants — 常量、Prompt 模板、DAG 配置
"""

from scheduler import DAGScheduler, VulnTask


# =====================================================
# 漏洞脚本白名单
# =====================================================
ALLOWED_SCRIPTS = frozenset({
    "exp_cs0048.py", "exp_cwe78.py",
    "exp_sql_injection.py", "exp_prompt_injection.py",
})

# 可用模型列表
AVAILABLE_MODELS = {
    "qwen-turbo": "通义千问-Turbo（轻量快速）",
    "qwen-plus": "通义千问-Plus（均衡性能）",
    "qwen-max": "通义千问-Max（最强能力）",
    "qwen-max-longcontext": "通义千问-Max-长文本",
}


# =====================================================
# CoT System Prompt
# =====================================================
COT_SYSTEM_PROMPT = """你是资深网络安全工程师，请严格按照以下推理链逐步分析漏洞：

**步骤1 - 漏洞定位**：判断漏洞的真实类型和触发条件，确认攻击入口点。
**步骤2 - 深入分析**：分析该漏洞的利用链、前置依赖和后置影响。
**步骤3 - 风险量化**：参照 CVSS 3.1 标准评估严重程度（攻击向量、攻击复杂度、权限要求、用户交互、影响范围、机密性/完整性/可用性影响）。
**步骤4 - 根因追溯**：推断漏洞产生的工程原因（如未做输入校验、使用了危险函数 shell=True、配置不当等）。
**步骤5 - 分级修复**：给出立即修复（热补丁）、短期修复（代码重构）、长期修复（架构优化）三级建议。

最终严格按以下格式输出（不要偏离格式）：

### 一、漏洞概述
（简要描述漏洞情况、触发条件）

### 二、风险分析
（分析该漏洞的风险等级、CVSS 评分、潜在危害）

### 三、根因分析
（分析漏洞产生的工程根因）

### 四、修复建议（分级）
- **立即修复**：...
- **短期修复**：...
- **长期优化**：...
"""


# =====================================================
# Few-shot 示例
# =====================================================
FEW_SHOT_EXAMPLES = [
    {
        "role": "assistant",
        "content": (
            "## 漏洞研判报告\n\n"
            "### 一、基本信息\n"
            "- 漏洞ID: CWE-89\n"
            "- 漏洞名称: SQL注入漏洞\n"
            "- 风险等级: 高危（CVSS 9.8）\n\n"
            "### 二、漏洞分析\n"
            "攻击者通过在用户输入中注入 SQL 片段（' OR '1'='1），"
            "绕过认证逻辑，成功执行任意查询。\n\n"
            "### 三、风险量化（CVSS 3.1）\n"
            "攻击向量: 网络 | 复杂度: 低 | 所需权限: 无 | "
            "用户交互: 无 | 范围: 变更 | 机密性: 高 | 完整性: 高 | 可用性: 高\n"
            "**基础分数: 9.8（严重）**\n\n"
            "### 四、根因追溯\n"
            "后端代码直接拼接用户输入到 SQL 查询语句，未使用参数化查询或 ORM 框架。\n\n"
            "### 五、修复建议\n"
            "1. 使用参数化查询（PreparedStatement）替代字符串拼接\n"
            "2. 启用 ORM 框架的防注入机制（如 SQLAlchemy）\n"
            "3. 遵循最小权限原则，数据库账户不赋予 DBA 权限"
        ),
    },
    {
        "role": "user",
        "content": (
            "【漏洞信息】\n"
            "- 漏洞ID：CWE-78\n"
            "- 漏洞名称：命令注入漏洞\n"
            "- 执行状态：success\n"
            "- 风险等级：严重\n"
            "- 执行日志：; cat /etc/passwd | grep root"
        ),
    },
    {
        "role": "assistant",
        "content": (
            "## 漏洞研判报告\n\n"
            "### 一、基本信息\n"
            "- 漏洞ID: CWE-78\n"
            "- 漏洞名称: 命令注入漏洞\n"
            "- 风险等级: 严重（CVSS 10.0）\n\n"
            "### 二、漏洞分析\n"
            "攻击者通过在 `host` 参数中注入 `; cat /etc/passwd | grep root` 命令，"
            "在服务器上执行任意系统命令，导致根目录信息泄露。\n\n"
            "### 三、风险量化（CVSS 3.1）\n"
            "攻击向量: 网络 | 复杂度: 低 | 所需权限: 无 | "
            "用户交互: 无 | 范围: 变更 | 机密性: 高 | 完整性: 高 | 可用性: 高\n"
            "**基础分数: 10.0（严重）**\n\n"
            "### 四、根因追溯\n"
            "后端代码使用 `shell=True` 或 `os.system()` 直接执行用户输入，"
            "未对特殊字符（; | & $ `）进行过滤。\n\n"
            "### 五、修复建议\n"
            "1. 禁止使用 shell=True，使用列表形式传递参数\n"
            "2. 对用户输入进行严格的字符白名单校验（仅允许字母数字）\n"
            "3. 将命令执行权限隔离到沙箱容器中"
        ),
    },
]


# =====================================================
# DAG 默认任务配置
# =====================================================
SCRIPTS_INFO = [
    ("exp_cs0048.py", "API未授权访问配置泄露", "CS0048", 3, "high"),
    ("exp_cwe78.py",   "系统命令注入漏洞 (RCE)", "CWE-78",  1, "critical", 2),
    ("exp_sql_injection.py", "SQL注入漏洞",       "CWE-89",  2, "high",     2),
    ("exp_prompt_injection.py", "大模型提示词越权注入", "AML.T0051", 4, "high", 1),
]


def build_default_scheduler() -> DAGScheduler:
    """构建含四大漏洞的 DAG 调度器"""
    scheduler = DAGScheduler()
    for info in SCRIPTS_INFO:
        script, name, cve, priority, risk_level = info[0], info[1], info[2], info[3], info[4]
        max_retries = info[5] if len(info) > 5 else 1
        scheduler.add_task(VulnTask(
            script=script, name=name, cve=cve,
            priority=priority, risk_level=risk_level,
            max_retries=max_retries,
        ))
    return scheduler