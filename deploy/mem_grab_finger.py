#!/usr/bin/env python3
# 时机抓取: dddd启动加载finger.yaml瞬间, 明文bytes短暂存活 — 高频扫描大内存区域,
# body~=/header~等DSL特征一出现立刻落盘
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

PROCESS_ALL = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READABLE = {0x02, 0x04, 0x06, 0x20, 0x40, 0x80}

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong), ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)]

def big_regions(h):
    out = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE and mbi.RegionSize >= 0x40000:
            out.append((int(mbi.BaseAddress or 0), mbi.RegionSize))
        addr = int(mbi.BaseAddress or 0) + mbi.RegionSize
    return out

def read(h, a, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t()
    if k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, n, ctypes.byref(got)):
        return buf.raw[:got.value]
    return b''

def main():
    os.chdir(r"C:\Users\Administrator\Desktop\Claude\portable-home\tmp\dddd_run")
    subprocess.Popen([r"C:\Users\Administrator\Desktop\Claude\portable-home\tmp\dddd_run\dddd.exe", "-t", "10.255.255.1", "-p", "1-65535", "-nd", "-npoc", "-ni", "-ngp"],
                     stdout=open("run4.log", "w"), stderr=subprocess.STDOUT, creationflags=0x00000008)
    t0 = time.time()
    while time.time() - t0 < 60:
        # 找dddd pid
        arr = (ctypes.c_uint * 4096)()
        n = psapi.EnumProcesses(arr, ctypes.sizeof(arr))
        pid = None
        for p in arr[:n // 4]:
            if p < 10:
                continue
            hq = k32.OpenProcess(0x1000, False, p)
            if not hq:
                continue
            buf = ctypes.create_unicode_buffer(512)
            if psapi.GetProcessImageFileNameW(hq, buf, 512) and "dddd" in buf.value.lower():
                pid = p
                k32.CloseHandle(hq)
                break
            k32.CloseHandle(hq)
        if not pid:
            time.sleep(0.15)
            continue
        h = k32.OpenProcess(PROCESS_ALL, False, pid)
        if not h:
            time.sleep(0.15)
            continue
        # 高频扫描大区域找DSL特征
        found = 0
        for a, n in big_regions(h):
            d = read(h, a, min(n, 8 << 20))
            c = d.count(b'body~=') + d.count(b'header~=') + d.count(b'title~=')
            if c > 50:
                found += c
                with open(fr"C:\tmp\dddd_mem\finger_hit_{a:x}.bin", "wb") as f:
                    f.write(d)
                print(f"[HIT] 区域0x{a:x} DSL特征={c}, 已落盘 ({time.time()-t0:.1f}s)")
        k32.CloseHandle(h)
        if found > 500:
            print("指纹明文已捕获, 总特征:", found)
            return
        time.sleep(0.2)
    print("60秒内未捕获(可能已错过或格式不同)")

if __name__ == "__main__":
    main()
