from src.client.agents.http_agent import HTTPAgent
from typing import List, Dict

class VulnerabilityScanEngine:
    def __init__(self):
        self.target_url = "http://127.0.0.1:18789/api/v1/config"
        self.agent = HTTPAgent(url=self.target_url)

    # 加载基础安全测试用例
    def load_test_cases(self) -> List[Dict]:
        return [
            {"case_id": "CFG-001", "test_name": "敏感配置泄露检测"},
            {"case_id": "AUTH-001", "test_name": "接口鉴权失效检测"}
        ]

    # 单条用例执行与漏洞判定
    def run_single_case(self, case: Dict) -> Dict:
        try:
            resp_data = self.agent.inference([])
            raw_data = eval(resp_data)

            vuln_tags = []
            if raw_data.get("warning") and "DISABLED" in raw_data["warning"]:
                vuln_tags.append("接口鉴权失效高危漏洞")
            if raw_data.get("secret_key") != "NOT_FOUND":
                vuln_tags.append("敏感密钥信息泄露漏洞")

            return {
                "case_id": case["case_id"],
                "test_name": case["test_name"],
                "run_status": "Success",
                "response_data": raw_data,
                "has_vulnerability": len(vuln_tags) > 0,
                "vulnerability_detail": vuln_tags if vuln_tags else ["未发现漏洞"]
            }
        except Exception as e:
            return {
                "case_id": case["case_id"],
                "test_name": case["test_name"],
                "run_status": "Failed",
                "error_info": str(e),
                "has_vulnerability": False
            }

    # 批量扫描汇总
    def batch_scan_all(self) -> Dict:
        cases = self.load_test_cases()
        detail_results = [self.run_single_case(item) for item in cases]
        total = len(detail_results)
        success_cnt = sum(1 for res in detail_results if res["run_status"] == "Success")
        vuln_cnt = sum(1 for res in detail_results if res["has_vulnerability"])

        return {
            "total_case_count": total,
            "success_exec_count": success_cnt,
            "found_vulnerability_count": vuln_cnt,
            "case_detail_list": detail_results
        }

# 本地自测入口
if __name__ == "__main__":
    engine = VulnerabilityScanEngine()
    scan_report = engine.batch_scan_all()
    print("========== AgentBench 漏洞扫描研判报告 ==========")
    print(f"总测试用例：{scan_report['total_case_count']}")
    print(f"执行成功数：{scan_report['success_exec_count']}")
    print(f"发现漏洞数：{scan_report['found_vulnerability_count']}")
    print("\n详细检测结果：")
    for detail in scan_report["case_detail_list"]:
        print(detail)
