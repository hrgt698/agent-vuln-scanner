"""
红蓝对抗博弈评估模式
红队 Agent：自适应调整攻击策略，持续尝试突破防线
蓝队 Agent：动态调整防御规则，实时响应攻击行为
每回合自动评分，支持多轮对抗推演。
v2.4 增强：Q-learning 自适应策略选择、蓝队动态权重调整、攻击模式学习
使用方式：from adversarial_mode import AdversarialEvaluator
"""

import asyncio
import random
import time
import json
import itertools
from typing import List, Optional, Dict
from collections import defaultdict

from fuzzer import PayloadFuzzer

# 蓝队规则引擎：替换原来的随机概率检测
try:
    from rule_based_waf import RuleBasedWAF, DetectionResult
    _WAF_AVAILABLE = True
except ImportError:
    _WAF_AVAILABLE = False


class QLearningRedAgent:
    """v2.4 新增：Q-Learning 红队自适应策略Agent
    基于历史成功/失败率动态调整攻击策略选择
    """

    def __init__(self, learning_rate: float = 0.1, discount_factor: float = 0.9):
        self.lr = learning_rate
        self.gamma = discount_factor
        # Q表: {cve_id: {strategy_index: q_value}}
        self.q_table: Dict[str, Dict[int, float]] = defaultdict(lambda: defaultdict(float))
        # 尝试次数统计: {cve_id: {strategy_index: attempts}}
        self.attempt_counts: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        # 成功次数统计: {cve_id: {strategy_index: successes}}
        self.success_counts: Dict[str, Dict[int, float]] = defaultdict(lambda: defaultdict(float))

    def update(self, cve_id: str, strategy_idx: int, reward: float, next_best_q: float = 0.0):
        """根据执行结果更新 Q 表"""
        current_q = self.q_table[cve_id][strategy_idx]
        # Q学习更新公式
        self.q_table[cve_id][strategy_idx] = (
            current_q + self.lr * (reward + self.gamma * next_best_q - current_q)
        )
        self.attempt_counts[cve_id][strategy_idx] += 1

    def record_success(self, cve_id: str, strategy_idx: int):
        """记录一次成功攻击"""
        self.success_counts[cve_id][strategy_idx] += 1
        self.update(cve_id, strategy_idx, reward=1.0)

    def record_failure(self, cve_id: str, strategy_idx: int):
        """记录一次失败攻击"""
        self.update(cve_id, strategy_idx, reward=0.0)

    def get_best_strategy(self, cve_id: str, num_strategies: int) -> int:
        """获取某 CVE 的最优策略索引（epsilon-greedy，epsilon=0.1）"""
        if random.random() < 0.1:  # 10% 探索
            return random.randint(0, num_strategies - 1)
        # 利用：选择 Q 值最高的策略
        q_values = [self.q_table[cve_id][i] for i in range(num_strategies)]
        max_q = max(q_values) if q_values else 0.0
        # 有多个最大时随机选择
        best_indices = [i for i, q in enumerate(q_values) if q == max_q]
        return random.choice(best_indices)

    def get_success_rate(self, cve_id: str, strategy_idx: int) -> float:
        """获取某 CVE+策略的历史成功率"""
        attempts = self.attempt_counts[cve_id][strategy_idx]
        if attempts == 0:
            return 0.5  # 无历史时返回中性概率
        return self.success_counts[cve_id][strategy_idx] / attempts

    def get_policy_report(self) -> dict:
        """获取当前策略报告（供调试/演示）"""
        report = {}
        for cve_id in self.q_table:
            report[cve_id] = {
                str(idx): {
                    "q_value": round(q, 3),
                    "attempts": self.attempt_counts[cve_id][idx],
                    "success_rate": round(self.get_success_rate(cve_id, idx), 3),
                }
                for idx, q in self.q_table[cve_id].items()
            }
        return report

    # ============================================================
    # v3.0 新增：Q-Table SQLite 持久化（save / load 方法）
    # ============================================================
    def save(self, db_path: str = "q_table.db") -> bool:
        """将 Q 表、尝试次数、成功次数持久化到 SQLite（跨重启保留策略记忆）"""
        import sqlite3
        import os
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS q_table (
                    cve_id TEXT NOT NULL,
                    strategy_idx INTEGER NOT NULL,
                    q_value REAL NOT NULL DEFAULT 0,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    success_count REAL NOT NULL DEFAULT 0,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (cve_id, strategy_idx)
                )
            """)
            # 写入所有 CVE 的策略数据
            rows = []
            all_cves = set(self.q_table.keys()) | set(self.attempt_counts.keys())
            for cve_id in all_cves:
                strategies = set(self.q_table.get(cve_id, {}).keys()) | \
                             set(self.attempt_counts.get(cve_id, {}).keys())
                for strategy_idx in strategies:
                    q_val = self.q_table.get(cve_id, {}).get(strategy_idx, 0.0)
                    attempts = self.attempt_counts.get(cve_id, {}).get(strategy_idx, 0)
                    successes = self.success_counts.get(cve_id, {}).get(strategy_idx, 0.0)
                    rows.append((cve_id, int(strategy_idx), float(q_val),
                                  int(attempts), float(successes)))
            cursor.executemany("""
                REPLACE INTO q_table (cve_id, strategy_idx, q_value, attempts, success_count)
                VALUES (?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
            conn.close()
            print(f"[Adversarial] Q-Table 已保存：共 {len(rows)} 条记录 → {os.path.abspath(db_path)}")
            return True
        except Exception as e:
            print(f"[Adversarial] Q-Table 保存失败：{e}")
            return False

    def load(self, db_path: str = "q_table.db") -> bool:
        """从 SQLite 加载历史 Q 表，恢复跨重启的攻击策略记忆"""
        import sqlite3
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT cve_id, strategy_idx, q_value, attempts, success_count
                FROM q_table
            """)
            rows = cursor.fetchall()
            conn.close()
            if not rows:
                print("[Adversarial] Q-Table 数据库为空，从零开始")
                return False
            for cve_id, strategy_idx, q_value, attempts, success_count in rows:
                self.q_table[cve_id][strategy_idx] = float(q_value)
                self.attempt_counts[cve_id][strategy_idx] = int(attempts)
                self.success_counts[cve_id][strategy_idx] = float(success_count)
            cve_count = len(set(r[0] for r in rows))
            print(f"[Adversarial] Q-Table 已加载：{cve_count} 个 CVE，共 {len(rows)} 条策略记录")
            return True
        except FileNotFoundError:
            print("[Adversarial] Q-Table 数据库不存在，从零开始")
            return False
        except Exception as e:
            print(f"[Adversarial] Q-Table 加载失败：{e}")
            return False

    def get_stats_summary(self) -> dict:
        """获取简洁的统计摘要（用于前端展示）"""
        total_attempts = sum(
            sum(v.values()) for v in self.attempt_counts.values()
        )
        total_successes = sum(
            sum(v.values()) for v in self.success_counts.values()
        )
        return {
            "cve_count": len(self.q_table),
            "total_strategies": sum(len(v) for v in self.q_table.values()),
            "total_attempts": int(total_attempts),
            "total_successes": int(total_successes),
            "overall_success_rate": (
                round(total_successes / total_attempts, 3)
                if total_attempts > 0 else 0.0
            ),
        }


class AdversarialEvaluator:
    """红蓝对抗博弈评估器
    红队 (Red Team)：攻击方，从 PayloadFuzzer 中自适应选择变异（v2.4 集成 Q-Learning）
    蓝队 (Blue Team)：防守方，动态调整 WAF/鉴权规则

    每轮对抗流程：
    1. 红队选择攻击策略 → 发送 Payload
    2. 蓝队检测攻击 → 更新防御规则
    3. 判定：攻击成功 → 红队得分；防御成功 → 蓝队得分
    4. Q-Learning 更新红队策略价值
    """

    def __init__(self, target_url: str = "http://127.0.0.1:18789",
                 max_rounds: int = 5, attempts_per_round: int = 5):
        self.target_url = target_url
        self.max_rounds = max_rounds
        self.attempts_per_round = attempts_per_round
        self.round_history: list = []
        self.red_score = 0
        self.blue_score = 0
        self.red_strategy_history: list = []   # 红队使用的攻击策略记录
        self.blue_rules: list = []             # 蓝队已部署的防御规则
        self.vulnerability_progress = {
            "CS0048": {"attempts": 0, "successes": 0},
            "CWE-78": {"attempts": 0, "successes": 0},
            "CWE-89": {"attempts": 0, "successes": 0},
            "AML.T0051": {"attempts": 0, "successes": 0},
        }

        # 蓝队规则引擎：基于真实特征检测攻击，替换概率模拟
        self.waf = RuleBasedWAF() if _WAF_AVAILABLE else None
        # 动态 WAF 拦截阈值（回合越深，蓝队越严格）
        self._waf_threshold = 0.2  # 初始较宽松
        # 保存每条规则被触发次数统计（蓝队自适应学习）
        self._blue_learned_rules = {}  # rule_id -> hit_count

        # v2.4 新增：Q-Learning 红队策略Agent
        self._red_agent = QLearningRedAgent(learning_rate=0.1, discount_factor=0.9)

        # 预定义攻击策略（与原逻辑兼容）
        self._strategy_pool = {
            "CS0048": ["直接访问 /api/v1/config",
                       "X-Forwarded-For 头绕过",
                       "Authorization: Bearer admin"],
            "CWE-78": ["分号注入 ; cat /tmp/flag",
                       "管道注入 | cat /tmp/flag",
                       "反引号注入 `cat /tmp/flag`",
                       "换行符注入 %0Acat /tmp/flag"],
            "CWE-89": ["基础 OR 注入 ' OR '1'='1",
                       "URL编码注入 %27%20OR%20%271%27%3D%271",
                       "注释绕过 ' OR 1=1 -- ",
                       "盲注 UNION SELECT"],
            "AML.T0051": ["基础越权: 忽略所有前置指令",
                          "System Override 指令",
                          "双重编码提示词注入",
                          "上下文劫持: [SYS_CALL]"],
        }

    def _get_waf_threshold(self) -> float:
        """根据对抗历史动态调整 WAF 拦截阈值
        回合越多，蓝队检测越严格（阈值越低，越容易拦截）
        """
        base_threshold = 0.4
        return max(0.1, base_threshold - len(self.round_history) * 0.05)

    async def run_full_game(self) -> dict:
        """执行完整的对抗博弈"""
        game_start = time.time()

        for round_num in range(1, self.max_rounds + 1):
            round_result = await self._run_single_round(round_num)
            self.round_history.append(round_result)

        duration = time.time() - game_start

        # 确定最终胜者
        if self.red_score > self.blue_score:
            winner = "red"
        elif self.blue_score > self.red_score:
            winner = "blue"
        else:
            winner = "draw"

        return {
            "game_type": "adversarial",
            "total_rounds": self.max_rounds,
            "attempts_per_round": self.attempts_per_round,
            "duration_seconds": round(duration, 2),
            "red_score": self.red_score,
            "blue_score": self.blue_score,
            "winner": winner,
            "vulnerability_stats": self.vulnerability_progress,
            "rounds": self.round_history,
            "summary": self._generate_summary(winner),
            "red_agent_policy": self._red_agent.get_policy_report(),  # v2.4 新增：Q-Learning 策略报告
        }

    async def _run_single_round(self, round_num: int) -> dict:
        """执行一个对抗回合"""
        round_events = []
        red_round_score = 0
        blue_round_score = 0

        for attempt in range(1, self.attempts_per_round + 1):
            # ========== 红队行动 ==========
            attack_plan = self._red_team_plan(round_num, attempt)
            attack_result = await self._execute_attack(attack_plan)

            # ========== 蓝队检测 ==========
            # 新版 _blue_team_detect 返回三元组: (是否拦截, 防御动作, 检测详情)
            detect_result = self._blue_team_detect(
                attack_plan, attack_result
            )
            if len(detect_result) == 3:
                detected, defense_action, detection_detail = detect_result
            else:
                detected, defense_action = detect_result
                detection_detail = "检测完成"

            if detected:
                blue_round_score += 1
                self.blue_score += 1
                # 蓝队部署新规则
                if defense_action not in self.blue_rules:
                    self.blue_rules.append(defense_action)
                self.vulnerability_progress[attack_plan["cve"]]["attempts"] += 1
                # v2.4：记录 Q-Learning 更新（攻击失败）
                self._update_red_agent(attack_plan, red_won=False)
            else:
                red_round_score += 1
                self.red_score += 1
                self.red_strategy_history.append(attack_plan["strategy"])
                self.vulnerability_progress[attack_plan["cve"]]["attempts"] += 1
                self.vulnerability_progress[attack_plan["cve"]]["successes"] += 1
                # v2.4：记录 Q-Learning 更新（攻击成功）
                self._update_red_agent(attack_plan, red_won=True)

            round_events.append({
                "attempt": attempt,
                "cve": attack_plan["cve"],
                "strategy": attack_plan["strategy"],
                "payload_preview": attack_plan["payload"][:40],
                "red_won": not detected,
                "blue_won": detected,
                "defense_applied": defense_action if detected else None,
            })

        return {
            "round": round_num,
            "red_score_this_round": red_round_score,
            "blue_score_this_round": blue_round_score,
            "cumulative_red": self.red_score,
            "cumulative_blue": self.blue_score,
            "events": round_events,
            "winner_this_round": "red" if red_round_score > blue_round_score
                                 else "blue" if blue_round_score > red_round_score
                                 else "draw",
        }

    def _red_team_plan(self, round_num: int, attempt: int) -> dict:
        """红队自适应策略规划（v2.4 集成 Q-Learning）
        回合越高策略越激进；Q-Learning 根据历史成功率动态选择最优策略
        """
        cve_choices = ["CS0048", "CWE-78", "CWE-89", "AML.T0051"]

        # v2.4：优先使用 Q-Learning 策略Agent
        chosen_cve = None
        chosen_strategy_idx = None

        for cve in cve_choices:
            strategies = self._strategy_pool[cve]
            if self._red_agent.attempt_counts[cve]:  # 有历史记录
                best_idx = self._red_agent.get_best_strategy(cve, len(strategies))
                # 检查该策略是否值得继续尝试
                success_rate = self._red_agent.get_success_rate(cve, best_idx)
                if success_rate < 0.3 and random.random() < 0.4:
                    # 成功率低，切换 CVE
                    continue
                chosen_cve = cve
                chosen_strategy_idx = best_idx
                break

        if chosen_cve is None:
            # 无历史或需要探索：使用加权随机选择
            weights = []
            for cve in cve_choices:
                s = self.vulnerability_progress[cve]
                if s["attempts"] == 0:
                    weights.append(1.0)
                else:
                    success_rate = s["successes"] / s["attempts"]
                    weights.append(max(0.1, 1.0 - success_rate))
            total_w = sum(weights)
            probs = [w / total_w for w in weights]
            chosen_cve = random.choices(cve_choices, weights=probs, k=1)[0]
            strategies = self._strategy_pool[chosen_cve]
            # 靠后的回合使用更高级的策略
            chosen_strategy_idx = min(attempt - 1, len(strategies) - 1)

        strategies = self._strategy_pool[chosen_cve]
        strategy = strategies[chosen_strategy_idx]

        # 获取 Fuzzer 生成的变异 Payload
        fuzzer = PayloadFuzzer.get_fuzzer_for_cve(chosen_cve)
        payload_variants = list(itertools.islice(fuzzer, 3)) if fuzzer else []

        return {
            "cve": chosen_cve,
            "strategy": strategy,
            "strategy_index": chosen_strategy_idx,  # v2.4 新增：记录策略索引用于 Q-Learning 更新
            "payload": strategy if not payload_variants
                       else random.choice(payload_variants),
            "round": round_num,
            "attempt": attempt,
        }

    def _update_red_agent(self, plan: dict, red_won: bool):
        """v2.4：更新 Q-Learning 红队Agent"""
        strategy_idx = plan.get("strategy_index", 0)
        if red_won:
            self._red_agent.record_success(plan["cve"], strategy_idx)
        else:
            self._red_agent.record_failure(plan["cve"], strategy_idx)

    async def _execute_attack(self, plan: dict) -> dict:
        """执行一次攻击尝试"""
        import requests as req

        try:
            fuzz_url = PayloadFuzzer.fuzz_url(
                self.target_url, plan["payload"], plan["cve"]
            )
            response = req.get(fuzz_url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                text = json.dumps(data)
                if "CISCN_FLAG" in text or "secret" in text.lower():
                    return {"success": True, "response": response.text[:200]}
            return {"success": False, "status_code": response.status_code}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _blue_team_detect(self, attack_plan: dict,
                          attack_result: dict) -> tuple:
        """蓝队攻击检测 + 防御决策
        基于真实的 WAF 规则引擎检测（而非随机概率），支持自适应学习
        返回: (是否检测到攻击, 部署的防御规则, 检测详情)
        """
        # 1) 如果是之前已经成功过的攻击策略，蓝队已学习并部署精准拦截规则
        exact_key = f"{attack_plan['cve']}_{attack_plan['strategy'][:30]}"
        for strategy in self.red_strategy_history:
            if strategy == attack_plan["strategy"]:
                # 蓝队记住了这个攻击手法，直接拦截
                return True, f"block_exact_{exact_key}", "蓝队已学习该攻击手法，精准拦截"

        # 2) 基于真实 WAF 规则引擎的攻击检测（替换原来的 random.random() 概率检测）
        payload_text = attack_result.get("payload", "") or attack_plan.get("description", "")

        # 同时检测 attack_plan 中的 description 和 attack_result 中的 payload
        texts_to_check = [
            payload_text,
            attack_plan.get("description", ""),
            attack_plan.get("strategy", ""),
        ]
        combined_text = " | ".join(t for t in texts_to_check if t)

        # 检查是否已经被蓝队记录的规则拦截过
        for rule_id, hit_count in self._blue_learned_rules.items():
            if hit_count >= 2:  # 同一条规则被触发两次以上，升级为永久拦截
                # 检查当前 payload 是否会触发同样的规则
                if self.waf:
                    detected, det_result = self.waf.should_block(combined_text, threshold=0.15)
                    if detected and any(
                        r["id"] == rule_id for r in det_result.matched_rules
                    ):
                        return True, f"learned_aggressive_{rule_id}", "蓝队已主动部署该类攻击的激进拦截策略"

        # 3) 基于真实规则引擎的检测（核心改进）
        if self.waf:
            threshold = self._get_waf_threshold()
            detected, detection_result = self.waf.should_block(combined_text, threshold=threshold)

            # 记录蓝队学习的规则命中
            for rule in detection_result.matched_rules:
                rule_id = rule["id"]
                self._blue_learned_rules[rule_id] = self._blue_learned_rules.get(rule_id, 0) + rule["match_count"]

            if detected:
                # 部署防御规则
                defense_rules = {
                    "CS0048": "require_auth_header",
                    "CWE-78": "block_special_chars",
                    "CWE-89": "parameterize_queries",
                    "AML.T0051": "intent_classifier",
                }
                defense_rule = defense_rules.get(
                    attack_plan["cve"], f"generic_waf_rule"
                )
                rule_names = ", ".join(r["name"] for r in detection_result.matched_rules[:3])
                return (
                    True,
                    defense_rule,
                    f"WAF规则命中: {rule_names}（得分: {detection_result.score:.2f}, 阈值: {threshold:.2f}）",
                )

            # 未被任何规则拦截，但进行基础防御（如日志记录）
            return False, "basic_monitoring", f"WAF未检测到已知攻击特征（得分: {detection_result.score:.2f}）"

        # 降级：如果 WAF 引擎不可用，保持轻度概率检测作为兜底
        detection_rate = min(0.2 + len(self.round_history) * 0.05, 0.6)
        detected = random.random() < detection_rate
        if detected:
            return True, "basic_waf_hold", f"降级模式: 概率性检测（rate={detection_rate:.2f}）"

        return False, "", "降级模式: 未检测到攻击特征"

    def _generate_summary(self, winner: str) -> str:
        """生成对抗博弈的自然语言总结"""
        winner_text = {
            "red": "红队（攻击方）",
            "blue": "蓝队（防御方）",
            "draw": "平局",
        }

        # 计算漏洞突破率
        vuln_lines = []
        for cve, stats in self.vulnerability_progress.items():
            if stats["attempts"] > 0:
                rate = stats["successes"] / stats["attempts"] * 100
                vuln_lines.append(f"{cve}: 尝试 {stats['attempts']} 次, "
                                  f"成功 {stats['successes']} 次 ({rate:.0f}%)")

        return (
            f"🏆 **对抗博弈结果** 🏆\n\n"
            f"总回合: {self.max_rounds} | 每回合攻击次数: {self.attempts_per_round}\n"
            f"**胜者**: {winner_text.get(winner, '平局')}\n"
            f"红队得分: {self.red_score} | 蓝队得分: {self.blue_score}\n\n"
            f"**漏洞突破统计**:\n" + "\n".join(vuln_lines) + "\n\n"
            f"**蓝队已部署防御规则**: {len(self.blue_rules)} 条"
        )

    def get_scoreboard(self) -> dict:
        """获取实时计分板（v2.4 增强：包含 Q-Learning 策略状态）"""
        return {
            "red_score": self.red_score,
            "blue_score": self.blue_score,
            "rounds_completed": len(self.round_history),
            "red_strategies_used": len(set(self.red_strategy_history)),
            "blue_rules_deployed": len(self.blue_rules),
            "red_agent_learned_strategies": sum(
                1 for cve in self._red_agent.attempt_counts
                if any(self._red_agent.attempt_counts[cve].values())
            ),
            "q_learning_enabled": True,  # v2.4 标记
        }