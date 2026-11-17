#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""项目文件统计脚本"""
import os
from pathlib import Path

ROOT = Path(__file__).parent.parent
SKIP = {"node_modules", "__pycache__", ".git", ".venv", "venv", "dist", "build"}

ext_lines = {}
ext_files = {}
total_lines = 0
total_files = 0

for p in ROOT.rglob("*"):
    if not p.is_file():
        continue
    if any(part in SKIP for part in p.parts):
        continue
    try:
        sz = p.stat().st_size
        if sz > 5 * 1024 * 1024:
            continue
    except Exception:
        continue
    ext = p.suffix.lower() or "(no_ext)"
    if ext not in {".py", ".vue", ".js", ".ts", ".jsx", ".tsx",
                    ".md", ".yaml", ".yml", ".json", ".css", ".html",
                    ".sh", ".txt", ".conf", ".dockerfile", ".ini"}:
        continue
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            lines = sum(1 for _ in f)
    except Exception:
        lines = 0
    ext_lines[ext] = ext_lines.get(ext, 0) + lines
    ext_files[ext] = ext_files.get(ext, 0) + 1
    total_lines += lines
    total_files += 1

print(f"TOTAL_FILES={total_files}  TOTAL_LINES={total_lines}")
print()
print("| 文件扩展名 | 文件数 | 代码行数 | 占比 |")
print("|------------|--------|----------|------|")
for ext in sorted(ext_lines, key=lambda k: -ext_lines[k]):
    pct = 100 * ext_lines[ext] / total_lines if total_lines else 0
    print(f"| {ext:10s} | {ext_files[ext]:>5d} | {ext_lines[ext]:>8d} | {pct:>5.1f}% |")
