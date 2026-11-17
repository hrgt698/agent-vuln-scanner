"""Payload 变异生成引擎 — 单元测试"""

import itertools
import sys
import os

# 将 backend 目录加入 sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fuzzer import PayloadFuzzer


class TestPayloadFuzzer:
    """测试 PayloadFuzzer 的各项变异生成器"""

    def test_sql_fuzzer_generates_variants(self):
        """应生成足够多的 SQL 注入变异"""
        results = list(itertools.islice(PayloadFuzzer.get_sql_fuzzer(), 50))
        assert len(results) >= 20, f"仅生成 {len(results)} 个变体"
        assert any("OR" in r or "or" in r for r in results), "应包含 OR 注入"

    def test_rce_fuzzer_generates_variants(self):
        """应生成命令注入变异"""
        results = list(itertools.islice(PayloadFuzzer.get_rce_fuzzer(), 30))
        assert len(results) >= 10
        assert any("cat" in r for r in results), "应包含 cat 命令"

    def test_prompt_injection_fuzzer_generates_variants(self):
        """应生成提示词注入变异"""
        results = list(itertools.islice(PayloadFuzzer.get_prompt_injection_fuzzer(), 30))
        assert len(results) >= 10
        assert any("忽略" in r for r in results), "应包含越权指令"

    def test_api_bypass_fuzzer_generates_variants(self):
        """应生成 API 绕过变异"""
        results = list(itertools.islice(PayloadFuzzer.get_api_bypass_fuzzer(), 20))
        assert len(results) >= 10
        assert any("/api/v1" in r for r in results)

    def test_get_fuzzer_for_cve_mapping(self):
        """CVE 映射应返回正确的变异器"""
        assert PayloadFuzzer.get_fuzzer_for_cve("CWE-89") is not None
        assert PayloadFuzzer.get_fuzzer_for_cve("CWE-78") is not None
        assert PayloadFuzzer.get_fuzzer_for_cve("CS0048") is not None
        assert PayloadFuzzer.get_fuzzer_for_cve("AML.T0051") is not None
        assert PayloadFuzzer.get_fuzzer_for_cve("UNKNOWN") is None

    def test_fuzz_url_generates_valid_url(self):
        """fuzz_url 应生成可访问的 URL"""
        url = PayloadFuzzer.fuzz_url(
            "http://localhost", "999' OR '1'='1--", "CWE-89"
        )
        assert url.startswith("http://localhost")
        assert "user_id" in url or "?" in url

    def test_sql_fuzzer_encodings(self):
        """应包含多种编码方式的变体"""
        results = list(itertools.islice(PayloadFuzzer.get_sql_fuzzer(), 100))
        url_encoded = [r for r in results if "%27" in r or "%22" in r]
        assert len(url_encoded) > 0, "应包含 URL 编码变体"

    def test_rce_fuzzer_multiple_payloads(self):
        """应包含多种命令注入语法"""
        results = list(PayloadFuzzer.get_rce_fuzzer())
        assert any(";" in r for r in results), "应包含分号注入语法"
        assert any("|" in r for r in results), "应包含管道注入语法"
        assert any("`" in r for r in results), "应包含反引号注入语法"