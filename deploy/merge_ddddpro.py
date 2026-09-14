#!/usr/bin/env python3
# dddd-pro提取资产合并进abcd: 指纹(同名规则并集)+POC(按id去重增量)+workflow(pocs并集)
import os
import sys

import yaml

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BUILD = r"C:\Users\Administrator\Desktop\Claude\abcd-build"
SRC = r"C:\tmp\dddd_mem"
POC_SRC = r"C:\tmp\dddd_pocs"

# ---------- 1) 指纹合并 ----------
old_f = yaml.safe_load(open(os.path.join(BUILD, 'common/config/finger.yaml'), encoding='utf-8'))
new_f = yaml.safe_load(open(os.path.join(SRC, 'finger_ddddpro.yaml'), encoding='utf-8'))
same, upd, add = 0, 0, 0
for name, rules in new_f.items():
    old_rules = old_f.get(name)
    if old_rules is None:
        old_f[name] = rules
        add += 1
    else:
        merged = list(old_rules)
        oldset = {str(r) for r in old_rules}
        for r in rules:
            if str(r) not in oldset:
                merged.append(r)
                upd += 1
        old_f[name] = merged
        same += 1
print(f"指纹: 原有{len(old_f)-add}产品, 新增{add}, 更新{same}(补规则{upd}条), 总{len(old_f)}")
out = yaml.safe_dump(old_f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=4096)
for p in [os.path.join(BUILD, 'common/config/finger.yaml'), os.path.join(BUILD, 'config/finger.yaml')]:
    open(p, 'w', encoding='utf-8', newline='\n').write(out)

# ---------- 2) POC合并: 按模板id去重 ----------
existing_ids = set()
poc_root = os.path.join(BUILD, 'common/config/pocs')
for base, _, files in os.walk(poc_root):
    for fn in files:
        if fn.endswith('.yaml') or fn.endswith('.yml'):
            existing_ids.add(os.path.splitext(fn)[0])
dst_dir = os.path.join(poc_root, 'ddddpro_20260912')
os.makedirs(dst_dir, exist_ok=True)
added = skipped = 0
for fn in os.listdir(POC_SRC):
    tid = os.path.splitext(fn)[0]
    if tid in existing_ids:
        skipped += 1
    else:
        with open(os.path.join(POC_SRC, fn), encoding='utf-8') as f:
            body = f.read()
        with open(os.path.join(dst_dir, fn), 'w', encoding='utf-8', newline='\n') as f:
            f.write(body)
        existing_ids.add(tid)
        added += 1
print(f"POC: 提取{len(os.listdir(POC_SRC))}, 已存在跳过{skipped}, 新增{added} -> pocs/ddddpro_20260912/")

# ---------- 3) workflow合并 ----------
old_w = yaml.safe_load(open(os.path.join(BUILD, 'common/config/workflow.yaml'), encoding='utf-8'))
new_w = yaml.safe_load(open(os.path.join(SRC, 'workflow_ddddpro.yaml'), encoding='utf-8'))
w_add = w_upd = 0
missing_poc = 0
for name, entry in new_w.items():
    if not isinstance(entry, dict):
        continue
    if name not in old_w:
        old_w[name] = entry
        w_add += 1
    else:
        old_p = [str(x) for x in (old_w[name].get('pocs') or [])]
        s = set(old_p)
        for p in entry.get('pocs') or []:
            if str(p) not in s:
                old_p.append(str(p))
        old_w[name]['pocs'] = old_p
        w_upd += 1
for name, entry in old_w.items():
    for p in entry.get('pocs') or []:
        if str(p) not in existing_ids and not str(p).startswith('Tags@'):
            missing_poc += 1
print(f"workflow: 原有{len(old_w)-w_add}, 新增{w_add}, 合并{w_upd}, 总{len(old_w)}; 指向不存在模板的引用{missing_poc}个(Tags@引用另行)")
outw = yaml.safe_dump(old_w, allow_unicode=True, default_flow_style=False, sort_keys=False, width=4096)
for p in [os.path.join(BUILD, 'common/config/workflow.yaml'), os.path.join(BUILD, 'config/workflow.yaml')]:
    open(p, 'w', encoding='utf-8', newline='\n').write(outw)
print("workflow.yaml 已写两份")
