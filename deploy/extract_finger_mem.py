#!/usr/bin/env python3
# 从内存blob提取dddd-pro指纹库: 状态机逐行匹配"产品名: + 缩进规则列表"结构
import re
import sys

import yaml

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

blob = open(r'C:\tmp\dddd_mem\regions_all.bin', 'rb').read()

# 按行处理整个blob, 识别指纹YAML行
# 产品行: 行首非空白字符+以":"结尾+\r\n; 规则行: "  - xxx"或"- xxx"且含FOVA语法特征
rule_kw = (b'body="', b'title="', b'header="', b'banner="', b'icon_hash="', b'status="',
           b'cert="', b'protocol="', b'port="', b'server="', b'domain=', b'body_all=', b'icp=')

lines_with_sep = blob.split(b'\n')
out_products = {}   # name -> [rules]
cur = None
pending_prod = None

def is_product_line(ln):
    s = ln.rstrip(b'\r')
    if not s or s[:1] in (b' ', b'-', b'#', b'/'):
        return False
    return s.endswith(b':') and b'"' not in s and b'~=' not in s and len(s) < 200

def is_rule_line(ln):
    s = ln.rstrip(b'\r').lstrip()
    if not s.startswith(b'- '):
        return False
    body = s[2:].strip(b'\'"')
    return any(k in s for k in rule_kw)

for ln in lines_with_sep:
    if is_product_line(ln):
        cur = ln.rstrip(b'\r')[:-1].decode('utf-8', 'replace').strip()
        if cur not in out_products:
            out_products[cur] = []
    elif cur is not None and is_rule_line(ln):
        rule = ln.rstrip(b'\r').strip()
        if rule.startswith(b'- '):
            rule = b'- ' + rule[2:].strip()
        out_products[cur].append(rule.decode('utf-8', 'replace'))
    elif cur is not None and ln.strip() == b'':
        continue  # 空行容忍(产品内)
    else:
        # 连续非匹配行=离开指纹区, 关闭当前产品(防止把POC内容吸进来)
        if cur is not None and out_products[cur]:
            cur = None

# 清理: 规则数<1或产品名异常的丢弃
clean = {k: v for k, v in out_products.items() if v}
print(f"提取产品指纹: {len(clean)} 个, 规则总数: {sum(len(v) for v in clean.values())}")

# yaml合法性自检
doc = {}
for k, v in clean.items():
    doc[k] = v
try:
    yaml.safe_load(__import__('io').StringIO(__import__('yaml').safe_dump(doc, allow_unicode=True)))
    print("yaml自检: OK")
except Exception as e:
    print("yaml自检失败:", e)

with open(r"C:\tmp\dddd_mem\finger_ddddpro.yaml", "w", encoding="utf-8", newline='\n') as f:
    for k, v in clean.items():
        f.write(f"{k}:\n")
        for r in v:
            f.write(f"  {r}\n")
print("写入 C:\\tmp\\dddd_mem\\finger_ddddpro.yaml")

# 顺带探测workflow: 内存里找 "pocs:" 列表结构
wf = blob.count(b'\n  pocs:')
print("workflow特征(pocs:列表):", wf)
