#!/usr/bin/env python3
# 从内存blob提取nuclei模板(POC): 以"id: xxx\r?\n\r?\ninfo:"为界切分, yaml校验后落盘
import os
import re
import sys

import yaml

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

blob = open(r'C:\tmp\dddd_mem\regions_all.bin', 'rb').read()

# 模板起点: \nid: <slug>\n\ninfo: 或 \r\n变体
pat = re.compile(rb'(?<![\w-])id: ([a-zA-Z0-9_.\-]+)\r?\n\r?\ninfo:', re.S)
starts = []
for m in pat.finditer(blob):
    # 回退到行首的 "id:"
    s = m.start()
    starts.append((s, m.group(1).decode()))

print("模板起点:", len(starts))

outdir = r"C:\tmp\dddd_pocs"
os.makedirs(outdir, exist_ok=True)
ok, bad, seen = 0, 0, {}
for i, (s, name) in enumerate(starts):
    e = starts[i + 1][0] if i + 1 < len(starts) else min(s + 65536, len(blob))
    raw = blob[s:e]
    # 修剪尾部: yaml结束后可能连着其他内存数据 — 找最后一个平衡点: 尝试逐段解析
    text = raw.decode('utf-8', 'replace')
    # 快速截断: 多数模板以\n\n结尾, 内存连接处常见乱码 — 尝试从后往前找合法yaml
    parsed = None
    # 先试整体
    try:
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict) or 'id' not in parsed:
            parsed = None
    except Exception:
        parsed = None
    if parsed is None:
        # 从尾部二分回退, 丢掉乱码尾巴
        lo, hi = 512, len(text)
        best = None
        for _ in range(24):
            mid = (lo + hi) // 2
            try:
                cand = yaml.safe_load(text[:mid])
                if isinstance(cand, dict) and 'id' in cand and 'info' in cand:
                    best = (mid, cand)
                    lo = mid
                else:
                    hi = mid
            except Exception:
                hi = mid
        if best:
            parsed = best[1]
            text = text[:best[0]]
    if parsed and isinstance(parsed, dict) and parsed.get('id'):
        fn = str(parsed['id']).replace('/', '_') + '.yaml'
        if fn in seen:
            continue
        seen[fn] = 1
        with open(os.path.join(outdir, fn), 'w', encoding='utf-8', newline='') as f:
            f.write(text)
        ok += 1
    else:
        bad += 1

print(f"提取成功 {ok} 条, 失败 {bad} 条 -> {outdir}")
