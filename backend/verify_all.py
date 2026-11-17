"""一次性测试所有核心模块"""
import os
import sys
import sqlite3
os.chdir(os.path.dirname(os.path.abspath(__file__)))

problems = []

try:
    import config_loader
    c = config_loader.get_config()
    assert c.get('app.version'), "config version missing"
    print("[OK] config_loader  版本=%s" % c.get('app.version'))
except Exception as e:
    print("[FAIL] config_loader: %s" % e)
    problems.append(('config_loader', str(e)))

try:
    from database import Database, ScanRecord
    conn = sqlite3.connect(':memory:')
    # 模拟直接用 sqlite3 测试表结构
    db = Database(db_path=':memory:')
    record = ScanRecord(target_url='http://test', cve_id='CWE-78', vuln_name='RCE',
                        status='success', risk_level='high', execution_log='test',
                        analysis_report='', timestamp=1000, duration=1.0)
    rid = db.save_scan_record(record)
    assert rid, "failed to save scan record"
    stats = db.get_scan_stats()
    print("[OK] database  saved_id=%s, total=%s" % (rid, stats.get('total_scans')))
except Exception as e:
    print("[FAIL] database: %s" % e)
    problems.append(('database', str(e)))

try:
    from scheduler import DAGScheduler, AdaptiveScheduler, VulnTask
    scheduler = DAGScheduler()
    for cve in ['CS0048', 'CWE-89', 'CWE-78', 'AML.T0051']:
        scheduler.add_task(VulnTask(script='exp.py', name=cve, cve=cve))
    order = scheduler.get_execution_order()
    assert len(order) == 4, "wrong task count"
    print("[OK] scheduler  topo=%s" % order)
except Exception as e:
    print("[FAIL] scheduler: %s" % e)
    problems.append(('scheduler', str(e)))

try:
    from attack_graph import AttackGraphAnalyzer
    analyzer = AttackGraphAnalyzer()
    result = analyzer.analyze([
        {'cve_id': 'CWE-78', 'status': 'success'},
        {'cve_id': 'CWE-89', 'status': 'success'},
    ])
    assert 'attack_path' in result and 'overall_risk_score' in result
    print("[OK] attack_graph  path=%s, risk=%s" % (result['attack_path'], result['overall_risk_score']))
except Exception as e:
    print("[FAIL] attack_graph: %s" % e)
    problems.append(('attack_graph', str(e)))

try:
    from fuzzer import PayloadFuzzer
    fuzzer = PayloadFuzzer.get_fuzzer_for_cve('CWE-89')
    variants = list(fuzzer) if fuzzer else []
    assert len(variants) > 0, "no variants"
    url = PayloadFuzzer.fuzz_url('http://target', variants[0], 'CWE-89')
    assert 'user_id' in url
    print("[OK] fuzzer  variants=%d, url=%s" % (len(variants), url[:60]))
except Exception as e:
    print("[FAIL] fuzzer: %s" % e)
    problems.append(('fuzzer', str(e)))

try:
    from rule_based_waf import RuleBasedWAF
    waf = RuleBasedWAF()
    blocked, det = waf.should_block("' OR '1'='1 UNION SELECT * FROM users; --")
    assert blocked, "SQLi should be blocked"
    blocked2, det2 = waf.should_block("正常请求查询产品列表")
    assert not blocked2, "normal request should pass"
    print("[OK] rule_based_waf  sqli_score=%.2f, normal_score=%.2f" % (det.score, det2.score))
except Exception as e:
    print("[FAIL] rule_based_waf: %s" % e)
    problems.append(('rule_based_waf', str(e)))

try:
    from agent_tracer import DecisionTreeTracer
    tracer = DecisionTreeTracer('test-agent')
    root_id = tracer.start_episode('init', 'task desc')
    step1 = tracer.record_step('observed', 'action1', 1.0, thought='thinking1')
    step2 = tracer.record_step('observed', 'action2', 2.0, thought='thinking2', error='')
    tree = tracer.get_tree_data()
    assert tree['total_steps'] == 3
    assert tree['total_reward'] == 3.0
    print("[OK] agent_tracer  steps=%d, reward=%.1f" % (tree['total_steps'], tree['total_reward']))
except Exception as e:
    print("[FAIL] agent_tracer: %s" % e)
    problems.append(('agent_tracer', str(e)))

try:
    from ensemble_judge import EnsembleJudger
    judger = EnsembleJudger()
    assert 'qwen-turbo' in EnsembleJudger.AVAILABLE_MODELS
    print("[OK] ensemble_judge  models=%s" % EnsembleJudger.AVAILABLE_MODELS)
except Exception as e:
    print("[FAIL] ensemble_judge: %s" % e)
    problems.append(('ensemble_judge', str(e)))

try:
    import services
    services.init_services()
    assert services.get_config() is not None
    assert services.get_db() is not None
    assert services.get_attack_graph() is not None
    print("[OK] services  rag_available=%s" % services.is_rag_available())
except Exception as e:
    print("[FAIL] services: %s" % e)
    problems.append(('services', str(e)))

try:
    from adversarial_mode import AdversarialEvaluator
    evaluator = AdversarialEvaluator(target_url='http://127.0.0.1:8000', max_rounds=3, attempts_per_round=2)
    import asyncio
    result = asyncio.run(evaluator.run_full_game())
    assert 'red_score' in result and 'blue_score' in result
    print("[OK] adversarial_mode  red=%s blue=%s rounds=%s" % (result['red_score'], result['blue_score'], len(result['rounds'])))
except Exception as e:
    print("[FAIL] adversarial_mode: %s" % e)
    problems.append(('adversarial_mode', str(e)))

try:
    from security import JWTAuth, RateLimiter
    auth = JWTAuth(secret='test_secret_key_at_least_32_chars_long')
    token = auth.generate_token('user1')
    assert token and len(token) > 10
    payload = auth.verify_token(token)
    assert payload.get('sub') == 'user1'
    print("[OK] security (JWT+RateLimiter)  subject=%s" % payload.get('sub'))
except Exception as e:
    print("[FAIL] security: %s" % e)
    problems.append(('security', str(e)))

try:
    from auto_patcher import AutoPatcher
    ap = AutoPatcher(container_name='none')
    patch = ap.generate_patch('CWE-89')
    assert patch, 'no patch template'
    print("[OK] auto_patcher  CWE-89 patch has %d chars" % len(str(patch)))
except Exception as e:
    print("[FAIL] auto_patcher: %s" % e)
    problems.append(('auto_patcher', str(e)))

print()
print("=" * 60)
if problems:
    print("发现 %d 个问题:" % len(problems))
    for name, msg in problems:
        print("  - %s: %s" % (name, msg))
    sys.exit(1)
else:
    print("所有核心模块检查通过 ✓")
    sys.exit(0)
