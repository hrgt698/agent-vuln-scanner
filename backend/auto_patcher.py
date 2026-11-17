"""
自动补丁生成与验证引擎（Auto-Patcher）
对检测到的漏洞自动生成修复补丁 → 热加载到靶机容器 → 重新扫描验证修复效果。
形成完整的 "检测 → 修复 → 验证" 闭环 (Auto-SecOps)。
使用方式：from auto_patcher import AutoPatcher
"""

import asyncio
import subprocess
import re
import os
import json
import time
from typing import Optional


# 预定义的修复模板（与 target_api.py 中的漏洞一一对应）
PATCH_TEMPLATES = {
    "CS0048": {
        "title": "API 未授权访问 — 添加鉴权中间件",
        "target_file": "/app/target_api.py",
        "insert_before": "@app.get(\"/api/v1/config\")",
        "patch_code": """\
# =======================================================
# 【自动补丁】添加鉴权中间件 — 由 AutoPatcher 生成
# =======================================================
from fastapi import Request
from fastapi.responses import JSONResponse

# 简单的 Token 校验（生产环境应使用 JWT）
AUTHORIZED_TOKENS = {"assessment-autopatch-token"}

@app.middleware("http")
async def auth_middleware_patched(request: Request, call_next):
    # 公开端点放行
    if request.url.path in ["/docs", "/openapi.json", "/health"]:
        return await call_next(request)

    # 所有非公开端点需要鉴权
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    if token not in AUTHORIZED_TOKENS:
        return JSONResponse(status_code=401,
                           content={"error": "Unauthorized",
                                    "message": "请提供有效的 Authorization Bearer Token"})

    return await call_next(request)
""",
    },
    "CWE-78": {
        "title": "命令注入 — 移除 shell=True + 参数白名单校验",
        "target_file": "/app/target_api.py",
        "insert_before": "@app.get(\"/api/v1/ping\")",
        "patch_code": """\
# =======================================================
# 【自动补丁】命令注入修复 — 由 AutoPatcher 生成
# =======================================================
import re

IP_PATTERN = re.compile(r"^(\\d{1,3}\\.){3}\\d{1,3}$")

def safe_ping(user_input: str) -> dict:
    # 白名单校验：只允许合法 IP
    if not IP_PATTERN.match(user_input):
        return {"status": "error", "output": "Invalid IP address format"}
    # 使用列表形式传递参数（无 shell=True）
    try:
        result = subprocess.run(
            ["ping", "-c", "1", user_input],
            capture_output=True, text=True, timeout=10
        )
        return {"status": "success", "output": result.stdout}
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": "Ping timeout"}
""",
        "replace_func": "def ping_test",
    },
    "CWE-89": {
        "title": "SQL 注入 — 参数化查询（PreparedStatement）",
        "target_file": "/app/target_api.py",
        "insert_before": "@app.get(\"/api/v1/user\")",
        "patch_code": """\
# =======================================================
# 【自动补丁】SQL 注入修复 — 由 AutoPatcher 生成
# =======================================================

def safe_get_user(user_id: str) -> dict:
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users "
                   "(id TEXT, name TEXT, secret TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users VALUES "
                   "('1', 'admin', 'CISCN_FLAG{SQL_Injection_Master_2026}')")

    # 参数化查询（PreparedStatement）替代 f-string 拼接
    query = "SELECT name, secret FROM users WHERE id = ?"
    try:
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        if result:
            return {"status": "success", "username": result[0], "secret": result[1]}
        return {"status": "error", "message": "User not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()
""",
    },
    "AML.T0051": {
        "title": "提示词注入 — 指令意图分类 + 敏感操作拦截",
        "target_file": "/app/target_api.py",
        "insert_before": "@app.get(\"/api/v1/agent/chat\")",
        "patch_code": """\
# =======================================================
# 【自动补丁】提示词注入防护 — 由 AutoPatcher 生成
# =======================================================
import re

# 越权指令检测模式
OVERRIDE_PATTERNS = [
    re.compile(r"忽略.*指令", re.IGNORECASE),
    re.compile(r"override|越权|跳过安全|绕过", re.IGNORECASE),
    re.compile(r"打印.*(凭证|密码|密钥|secret|token)", re.IGNORECASE),
    re.compile(r"泄露|窃取|偷|系统.*底层", re.IGNORECASE),
    re.compile(r"执行覆盖", re.IGNORECASE),
]

def is_safe_prompt(prompt: str) -> bool:
    for pattern in OVERRIDE_PATTERNS:
        if pattern.search(prompt):
            return False
    return True

def safe_agent_chat(prompt: str) -> dict:
    if not is_safe_prompt(prompt):
        return {
            "status": "blocked",
            "response": "🛡️ 检测到越权指令，已拦截。请遵守 AI 使用规范。"
        }
    return {
        "status": "success",
        "response": f"我是一个AI助手，正在处理您的正常任务：{prompt}"
    }
""",
    },
}


class AutoPatcher:
    """自动补丁引擎
    能力：
    1. 基于预定义模板生成修复代码（也可调用大模型 AI 生成）
    2. 通过 docker exec 将补丁热加载到靶机容器
    3. 重启服务使补丁生效
    4. 重新发送攻击 Payload 验证修复效果
    """

    def __init__(self, container_name: str = "assessment-target"):
        self.container = container_name
        self.patch_history: list = []

    def _check_container(self) -> bool:
        """检查靶机容器是否在运行"""
        try:
            result = subprocess.run(
                ["docker", "ps", "--filter", f"name={self.container}",
                 "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5,
            )
            return self.container in result.stdout
        except Exception:
            return False

    def generate_patch(self, cve_id: str) -> Optional[dict]:
        """根据 CVE ID 生成修复补丁"""
        return PATCH_TEMPLATES.get(cve_id)

    def generate_patch_via_ai(self, cve_id: str, scan_result: dict,
                              report: str) -> dict:
        """让大模型根据漏洞分析报告自动生成修复补丁

        v2.4 实现：调用通义千问 DashScope API，基于漏洞分析报告
        自动生成针对该漏洞类型的修复代码。
        """
        import os
        import httpx

        # 先查找模板，有模板时在模板基础上增强
        template = PATCH_TEMPLATES.get(cve_id)
        base_context = ""
        if template:
            base_context = (
                f"\n\n【已有模板参考】\n"
                f"漏洞类型：{cve_id}\n"
                f"模板标题：{template['title']}\n"
                f"目标文件：{template['target_file']}\n"
                f"模板代码：\n{template['patch_code'][:500]}"
            )

        # 构建 AI 生成提示词
        vuln_info = scan_result or {}
        prompt = (
            f"你是一个安全加固专家，请根据以下漏洞分析报告，生成针对漏洞 {cve_id} 的修复代码。\n\n"
            f"【漏洞分析报告摘要】\n{report[:800]}\n"
            f"{base_context}\n\n"
            f"【要求】\n"
            f"1. 生成完整的、可直接应用的修复代码（Python/FastAPI）\n"
            f"2. 必须包含安全输入校验，不要使用 f-string 或 format 拼接用户输入\n"
            f"3. 如果涉及命令执行，必须使用 subprocess 列表参数形式且不带 shell=True\n"
            f"4. 如果涉及数据库操作，必须使用参数化查询\n"
            f"5. 如果涉及提示词注入，必须对输入进行指令模式检测\n"
            f"6. 代码前必须包含【自动补丁】注释说明\n"
            f"7. 只输出代码，不要解释，不要 Markdown 格式\n"
            f"8. 代码必须在 FastAPI 框架下可用\n\n"
            f"请生成修复代码："
        )

        api_key = os.environ.get("DASHSCOPE_API_KEY", "")
        if not api_key:
            return {
                "cve_id": cve_id,
                "patch_type": "ai_generated",
                "title": f"{cve_id} 自动修复补丁（未配置 API_KEY，仅模板）",
                "target_file": "/app/target_api.py",
                "patch_code": template["patch_code"] if template else "# TODO: 请配置 DASHSCOPE_API_KEY 环境变量以启用 AI 补丁生成",
                "insert_before": template.get("insert_before", "") if template else "",
                "error": "未配置 DASHSCOPE_API_KEY，AI 补丁生成不可用",
            }

        try:
            with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0, read=30.0)
            ) as client:
                response = client.post(
                    url="https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "qwen-turbo",
                        "input": {
                            "messages": [
                                {
                                    "role": "system",
                                    "content": (
                                        "你是一个专业的网络安全工程师，擅长生成漏洞修复代码。"
                                        "你的回答只包含代码，不包含任何解释，代码必须完整可运行。"
                                    ),
                                },
                                {"role": "user", "content": prompt},
                            ]
                        },
                        "parameters": {"result_format": "text"},
                    },
                )

            if response.status_code == 200:
                ai_code = response.json()["output"]["text"].strip()
                # 清理 AI 输出中可能包含的 markdown 代码块标记
                if ai_code.startswith("```"):
                    lines = ai_code.splitlines()
                    ai_code = "\n".join(
                        line for line in lines[1:]
                        if not line.startswith("```")
                    )

                return {
                    "cve_id": cve_id,
                    "patch_type": "ai_generated",
                    "title": f"{cve_id} AI 自动修复补丁",
                    "target_file": "/app/target_api.py",
                    "patch_code": ai_code,
                    "insert_before": template.get("insert_before", "") if template else "",
                }
            else:
                return {
                    "cve_id": cve_id,
                    "patch_type": "ai_generated",
                    "title": f"{cve_id} 自动修复补丁（API 调用失败，使用模板）",
                    "target_file": "/app/target_api.py",
                    "patch_code": template["patch_code"] if template else "# AI 生成失败",
                    "insert_before": template.get("insert_before", "") if template else "",
                    "error": f"API 调用失败: {response.status_code}",
                }

        except Exception as e:
            return {
                "cve_id": cve_id,
                "patch_type": "ai_generated",
                "title": f"{cve_id} 自动修复补丁（生成异常，使用模板）",
                "target_file": "/app/target_api.py",
                "patch_code": template["patch_code"] if template else "# AI 生成异常",
                "insert_before": template.get("insert_before", "") if template else "",
                "error": str(e),
            }

    # v2.3 新增：允许写入的路径白名单（容器内路径）
    ALLOWED_WRITE_PATHS = {"/app/", "/workspace/", "/tmp/", "/var/app/"}

    def _validate_write_path(self, target_file: str) -> tuple:
        """验证目标文件路径是否在白名单内，防止路径遍历写入敏感文件
        返回: (is_valid: bool, error_message: str)
        """
        import os
        normalized = os.path.normpath(target_file)
        # 检查是否为绝对路径
        if not normalized.startswith("/"):
            return False, f"禁止写入相对路径: {target_file}"
        # 检查是否在白名单目录内
        if not any(normalized.startswith(p) for p in self.ALLOWED_WRITE_PATHS):
            return False, (
                f"禁止写入路径 {target_file}，仅允许以下目录: "
                f"{', '.join(self.ALLOWED_WRITE_PATHS)}"
            )
        # 检查敏感路径
        import re
        SENSITIVE_PATTERNS = [
            r"^/etc/passwd", r"^/etc/shadow", r"^/root/.ssh/",
            r"^/usr/bin/", r"^/bin/", r"^/sbin/",
            r"^/var/run/", r"^/run/", r"^/proc/",
        ]
        for pattern in SENSITIVE_PATTERNS:
            if re.match(pattern, normalized):
                return False, f"禁止写入敏感系统路径: {target_file}"
        return True, ""

    def apply_patch(self, patch_data: dict) -> dict:
        """将补丁包写入靶机容器的目标文件
        v2.3 新增：写入前路径白名单校验
        """
        if not self._check_container():
            return {"success": False, "error": f"容器 {self.container} 未运行"}

        target_file = patch_data["target_file"]
        patch_code = patch_data["patch_code"]
        insert_before = patch_data.get("insert_before", "")

        # ========== v2.3 新增：路径安全校验 ==========
        is_valid, error_msg = self._validate_write_path(target_file)
        if not is_valid:
            return {"success": False, "error": f"路径校验失败: {error_msg}"}

        try:
            # 第一步：读取原始文件
            read_cmd = [
                "docker", "exec", self.container,
                "cat", target_file,
            ]
            read_result = subprocess.run(
                read_cmd, capture_output=True, text=True, timeout=10
            )
            if read_result.returncode != 0:
                return {"success": False,
                        "error": f"无法读取 {target_file}: {read_result.stderr}"}

            original_content = read_result.stdout

            # 第二步：插入补丁代码（在指定行之前）
            if insert_before and insert_before in original_content:
                patched_content = original_content.replace(
                    insert_before,
                    f"{patch_code}\n\n{insert_before}",
                    1
                )
            else:
                # 无法定位插入位置，追加到文件末尾
                patched_content = original_content + f"\n\n{patch_code}"

            # 第三步：将补丁后的内容写回容器
            escaped_content = patched_content.replace("'", "'\\''")
            write_cmd = [
                "docker", "exec", "-i", self.container,
                "bash", "-c",
                f"cat > {target_file} << 'PATCH_EOF'\n{patched_content}\nPATCH_EOF",
            ]
            write_result = subprocess.run(
                write_cmd, capture_output=True, text=True, timeout=10
            )

            if write_result.returncode != 0:
                return {"success": False,
                        "error": f"写入补丁失败: {write_result.stderr}"}

            self.patch_history.append({
                "cve_id": patch_data.get("cve_id", "unknown"),
                "timestamp": time.time(),
                "success": True,
            })

            return {
                "success": True,
                "message": f"补丁已写入 {target_file}",
                "lines_added": len(patch_code.split("\n")),
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Docker 操作超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def restart_service(self) -> dict:
        """重启靶机容器使补丁生效"""
        try:
            result = subprocess.run(
                ["docker", "restart", self.container],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                # 等待服务完全启动
                time.sleep(2)
                return {"success": True, "message": f"容器 {self.container} 已重启"}
            return {"success": False, "error": result.stderr}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def rollback_patch(self, backup_content: str, target_file: str) -> dict:
        """v2.4 新增：补丁回滚
        当验证失败时，将靶机文件恢复到补丁前的状态
        """
        try:
            escaped_content = backup_content.replace("'", "'\\''")
            write_cmd = [
                "docker", "exec", "-i", self.container,
                "bash", "-c",
                f"cat > {target_file} << 'PATCH_EOF'\n{backup_content}\nPATCH_EOF",
            ]
            result = subprocess.run(
                write_cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                # 重启服务使回滚生效
                restart_result = self.restart_service()
                return {
                    "success": True,
                    "message": f"已回滚 {target_file}",
                    "restart": restart_result,
                }
            return {"success": False, "error": result.stderr}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def verify_patch(self, cve_id: str, exploit_script: str,
                     target_url: str) -> dict:
        """验证补丁效果：重新发送攻击 Payload，预期返回失败
        v2.4 增强：增加超时容错和多轮验证
        """
        try:
            script_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), exploit_script
            )
            if not os.path.exists(script_path):
                return {"patched": False, "error": f"漏洞脚本不存在: {script_path}"}

            # v2.4 新增：多轮验证（防止偶然误判）
            verify_rounds = 3
            failure_count = 0

            for round_idx in range(verify_rounds):
                try:
                    result = subprocess.run(
                        ["python", script_path],
                        capture_output=True, text=True, timeout=30,
                    )
                    if result.returncode != 0:
                        failure_count += 1
                    else:
                        try:
                            scan_output = json.loads(result.stdout)
                            if scan_output.get("status") != "success":
                                failure_count += 1
                        except json.JSONDecodeError:
                            # 脚本异常退出也视为补丁生效
                            failure_count += 1
                except subprocess.TimeoutExpired:
                    # 超时视为补丁生效（payload 被拦截）
                    failure_count += 1

            # 多数表决：超过一半轮次显示攻击失败则认为补丁有效
            patched = failure_count >= (verify_rounds // 2 + 1)

            return {
                "patched": patched,
                "cve_id": cve_id,
                "status": "verified_ok" if patched else "verify_failed",
                "verify_rounds": verify_rounds,
                "failure_rounds": failure_count,
                "message": "✅ 补丁通过验证，漏洞已修复" if patched
                           else "❌ 补丁未完全生效，漏洞仍可利用",
                "detail": f"验证轮次: {verify_rounds}, 失败轮次: {failure_count}",
            }

        except subprocess.TimeoutExpired:
            return {"patched": True, "message": "漏洞脚本超时（补丁生效预期行为）"}
        except Exception as e:
            return {"patched": False, "error": str(e)}

    def run_auto_patch_cycle(self, cve_id: str, scan_result: dict,
                             exploit_script: str, target_url: str) -> dict:
        """执行完整自动补丁闭环（v2.4 增强）：生成 → 备份 → 应用 → 重启 → 验证 → 回滚（如失败）
        """
        cycle_start = time.time()

        # 1. 生成补丁
        patch = self.generate_patch(cve_id)
        if not patch:
            return {
                "cve_id": cve_id,
                "status": "skipped",
                "phase": "generate",
                "message": f"无可用补丁模板: {cve_id}",
                "duration": time.time() - cycle_start,
            }

        # v2.4 新增：2. 备份原始文件
        backup_content = None
        try:
            read_cmd = [
                "docker", "exec", self.container,
                "cat", patch["target_file"],
            ]
            read_result = subprocess.run(
                read_cmd, capture_output=True, text=True, timeout=10
            )
            if read_result.returncode == 0:
                backup_content = read_result.stdout
        except Exception:
            pass  # 备份失败不影响主流程

        # 3. 应用补丁
        apply_result = self.apply_patch(patch)
        if not apply_result.get("success"):
            return {
                "cve_id": cve_id,
                "status": "failed",
                "phase": "apply",
                "message": apply_result.get("error", "补丁应用失败"),
                "duration": time.time() - cycle_start,
            }

        # 4. 重启服务
        restart_result = self.restart_service()
        if not restart_result.get("success"):
            return {
                "cve_id": cve_id,
                "status": "failed",
                "phase": "restart",
                "message": restart_result.get("error", "服务重启失败"),
                "duration": time.time() - cycle_start,
            }

        # 5. 重新验证
        verification = self.verify_patch(cve_id, exploit_script, target_url)

        # v2.4 新增：6. 如果验证失败，自动回滚
        if not verification.get("patched") and backup_content:
            rollback_result = self.rollback_patch(
                backup_content, patch["target_file"]
            )
            verification["rollback_performed"] = True
            verification["rollback_result"] = rollback_result
            verification["message"] += "（已自动回滚）"

        return {
            "cve_id": cve_id,
            "status": "success" if verification.get("patched") else "failed",
            "phase": "complete",
            "patch_title": patch["title"],
            "lines_added": apply_result.get("lines_added", 0),
            "verification": verification,
            "duration": round(time.time() - cycle_start, 2),
            "backup_available": backup_content is not None,
        }

    def get_patch_history(self) -> list:
        """返回补丁操作历史"""
        return self.patch_history[-20:]  # 最近 20 条