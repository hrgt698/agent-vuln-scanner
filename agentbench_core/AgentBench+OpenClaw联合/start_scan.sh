#!/bin/bash
echo "====== 启动AgentBench自动化漏洞探测 ======"
echo "正在联动OpenClaw漏洞靶机..."
echo ""
python3 simple_test.py
echo ""
echo "====== 探测结束，日志已自动保存 ======"
docker logs openclaw_vuln_target > vuln_access.log
echo "访问日志已保存至 vuln_access.log"
