#!/usr/bin/env python3
# 提取dddd-pro内存中的workflow.yaml(产品→pocs映射) + 指纹黑名单清理
import sys

import yaml

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

blob = open(r'C:\tmp\dddd_mem\regions_all.bin', 'rb').read()
text = blob.decode('utf-8', 'replace')
lines = text.split('\n')

# ---- workflow提取: 产品:\n  type:\n    - x\n  pocs:\n    - y ----
wf = {}
i = 0
while i < len(lines):
    ln = lines[i].rstrip('\r')
    s = ln.strip()
    # 产品行(无缩进+冒号结尾)
    if ln and not ln[0].isspace() and s.endswith(':') and i + 1 < len(lines) and lines[i + 1].rstrip('\r').strip() == 'type:':
        name = s[:-1]
        j = i + 2
        types = []
        while j < len(lines) and lines[j].rstrip('\r').strip().startswith('- '):
            types.append(lines[j].rstrip('\r').strip()[2:])
            j += 1
        if j < len(lines) and lines[j].rstrip('\r').strip() == 'pocs:':
            j += 1
            pocs = []
            while j < len(lines) and lines[j].rstrip('\r').strip().startswith('- '):
                pocs.append(lines[j].rstrip('\r').strip()[2:])
                j += 1
            if pocs:
                wf[name] = {'type': types, 'pocs': pocs}
                i = j
                continue
    i += 1

print(f"workflow提取: {len(wf)} 个产品映射, poc引用总数: {sum(len(v['pocs']) for v in wf.values())}")
with open(r"C:\tmp\dddd_mem\workflow_ddddpro.yaml", "w", encoding="utf-8", newline='\n') as f:
    yaml.safe_dump(wf, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
print("写入 workflow_ddddpro.yaml")

# ---- 指纹清理: 去掉POC字段名等伪产品 ----
BAD = {'http', 'https', 'info', 'raw', 'matchers', 'extractors', 'requests', 'set',
       'variables', 'workflows', 'payloads', 'wordlists', 'helpers', 'digest'}
raw = open(r"C:\tmp\dddd_mem\finger_ddddpro.yaml", 'rb').read().replace(b'\x00', b'')
import io
# 逐产品校验: 单个产品块yaml解析失败则逐规则降级, 坏规则丢弃
doc, bad_rules = {}, 0
prod_lines, cur_name, cur_rules = [], None, []
for ln in raw.decode('utf-8', 'replace').split('\n'):
    if ln and not ln[0].isspace() and ln.rstrip().endswith(':'):
        if cur_name is not None:
            prod_lines.append((cur_name, cur_rules))
        cur_name, cur_rules = ln.rstrip()[:-1], []
    elif ln.strip().startswith('- ') and cur_name is not None:
        cur_rules.append(ln.strip()[2:])
if cur_name is not None:
    prod_lines.append((cur_name, cur_rules))
for name, rules in prod_lines:
    kept = []
    for r in rules:
        try:
            ok = yaml.safe_load(io.StringIO(f"t:\n  - {r}\n"))
            if ok and isinstance(ok.get('t'), list):
                kept.append(r)
                continue
        except Exception:
            pass
        bad_rules += 1
    if kept:
        doc[name] = kept
clean = {k: v for k, v in doc.items() if k not in BAD and isinstance(v, list) and v}
print(f"指纹清理: {len(doc)} 个产品(丢弃坏规则 {bad_rules} 条) -> {len(clean)} 个")
with open(r"C:\tmp\dddd_mem\finger_ddddpro.yaml", "w", encoding="utf-8", newline='\n') as f:
    yaml.safe_dump(clean, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
print("finger_ddddpro.yaml 已清理重写")

# Tags@前缀poc引用统计(pro版特殊引用)
tags_ref = sum(1 for v in wf.values() for p in v['pocs'] if p.startswith('Tags@'))
print(f"Tags@前缀引用: {tags_ref} 个")
