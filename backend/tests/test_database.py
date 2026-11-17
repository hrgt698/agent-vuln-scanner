"""
数据库模块单元测试
测试 SQLite 存储、扫描记录、补丁记录、对抗记录等功能。
"""

import os
import tempfile
import pytest
from pathlib import Path
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from database import Database, ScanRecord, PatchRecord, AdversarialRecord


@pytest.fixture
def temp_db():
    """创建隔离的临时数据库（每个用例独立实例，避免单例跨用例累积）"""
    Database.reset_instance()
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = Database.get_instance(db_path=db_path, use_orm=True)
    yield db
    Database.reset_instance()
    try:
        os.unlink(db_path)
    except OSError:
        pass



def test_save_scan_record(temp_db):
    """测试保存一条扫描记录"""
    record = ScanRecord(
        target_url="http://127.0.0.1:18789",
        cve_id="CWE-89",
        vuln_name="SQL注入",
        status="success",
        risk_level="high",
        execution_log="SELECT * FROM users WHERE id = '1' OR '1'='1';",
        analysis_report="检测到典型 SQL 注入攻击，风险等级：高",
        timestamp=1000000,
        duration=2.3,
    )
    row_id = temp_db.save_scan_record(record)
    assert row_id > 0


def test_save_batch_scan_records(temp_db):
    """测试批量保存扫描记录"""
    records = [
        ScanRecord(
            target_url="http://127.0.0.1:18789",
            cve_id="CS0048",
            vuln_name="API未授权访问",
            status="success",
            risk_level="high",
            timestamp=1000001,
            duration=1.5,
        ),
        ScanRecord(
            target_url="http://127.0.0.1:18789",
            cve_id="CWE-78",
            vuln_name="命令注入",
            status="failed",
            risk_level="critical",
            timestamp=1000002,
            duration=3.2,
        ),
    ]
    count = temp_db.save_batch_scan_records(records)
    assert count == 2


def test_get_scan_history(temp_db):
    """测试获取扫描历史"""
    # 先插入一些数据
    for i in range(5):
        temp_db.save_scan_record(ScanRecord(
            target_url="http://127.0.0.1:18789",
            cve_id=f"CWE-{i}",
            status="success",
            timestamp=1000000 + i,
            duration=1.0 + i * 0.1,
        ))

    history = temp_db.get_scan_history(limit=3)
    assert len(history) == 3
    # 按时间倒序排列
    assert history[0]["timestamp"] > history[2]["timestamp"]


def test_get_scan_stats(temp_db):
    """测试获取扫描统计信息"""
    for i in range(10):
        status = "success" if i < 7 else "failed"
        temp_db.save_scan_record(ScanRecord(
            target_url="http://127.0.0.1:18789",
            cve_id="CWE-89",
            status=status,
            timestamp=1000000 + i,
            duration=1.0,
        ))

    stats = temp_db.get_scan_stats()
    assert stats["total_scans"] == 10
    assert stats["successful_scans"] == 7
    assert stats["success_rate"] > 0.65


def test_save_patch_record(temp_db):
    """测试保存补丁记录"""
    record = PatchRecord(
        cve_id="CWE-89",
        patch_title="参数化查询修复",
        patch_type="code_fix",
        status="applied",
        lines_added=3,
        verification_result="verified",
        timestamp=1000000,
    )
    row_id = temp_db.save_patch_record(record)
    assert row_id > 0


def test_get_patch_history(temp_db):
    """测试获取补丁历史"""
    for i in range(3):
        temp_db.save_patch_record(PatchRecord(
            cve_id=f"CWE-{i}",
            patch_title=f"修复方案 {i}",
            status="applied",
            timestamp=1000000 + i,
        ))

    history = temp_db.get_patch_history(limit=10)
    assert len(history) == 3


def test_save_adversarial_record(temp_db):
    """测试保存对抗记录"""
    record = AdversarialRecord(
        target_url="http://127.0.0.1:18789",
        max_rounds=3,
        red_score=7,
        blue_score=3,
        winner="red",
        vulnerability_stats='{"CS0048": "success", "CWE-89": "failed"}',
        duration=45.2,
        timestamp=1000000,
    )
    row_id = temp_db.save_adversarial_record(record)
    assert row_id > 0


def test_get_adversarial_history(temp_db):
    """测试获取对抗历史"""
    for i in range(2):
        temp_db.save_adversarial_record(AdversarialRecord(
            target_url="http://127.0.0.1:18789",
            max_rounds=3,
            red_score=i + 5,
            blue_score=i,
            winner="red",
            vulnerability_stats='{"CS0048": "success"}',
            duration=30.0,
            timestamp=1000000 + i,
        ))

    history = temp_db.get_adversarial_history(limit=10)
    assert len(history) == 2


def test_database_singleton():
    """测试数据库单例模式"""
    db1 = Database.get_instance(db_path="./test_singleton.db")
    db2 = Database.get_instance(db_path="./test_singleton.db")
    assert db1 is db2
    try:
        os.unlink("./test_singleton.db")
    except OSError:
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
