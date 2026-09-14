#!/usr/bin/env python3
# dddd-pro进程内存yaml明文提取: 枚举可读内存区域, 搜指纹/poc/workflow特征并dump到文件
import ctypes
import ctypes.wintypes as wt
import os
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

PROCESS_ALL = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READABLE = {0x02, 0x04, 0x06, 0x20, 0x40, 0x80}  # R/RW/RX/RWX等

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong), ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)]

def find_pid(name):
    arr = (ctypes.c_uint * 4096)()
    cb = ctypes.sizeof(arr)
    n = psapi.EnumProcesses(arr, cb)
    for pid in arr[:n // 4]:
        if pid == 0:
            continue
        h = k32.OpenProcess(0x1000 | 0x0400, False, pid)  # QUERY_Limited_INFORMATION
        if not h:
            continue
        buf = ctypes.create_unicode_buffer(512)
        if psapi.GetProcessImageFileNameW(h, buf, 512):
            if name.lower() in buf.value.lower():
                k32.CloseHandle(h)
                return pid
        k32.CloseHandle(h)
    return None

def main():
    pid = find_pid("dddd")
    if not pid:
        print("找不到dddd进程"); return
    print("PID:", pid)
    h = k32.OpenProcess(PROCESS_ALL, False, pid)
    if not h:
        print("OpenProcess失败:", ctypes.GetLastError()); return

    total = 0
    hits = {"finger": 0, "poc": 0, "workflow": 0}
    regions = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if ctypes.windll.kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE and mbi.RegionSize < 0x10000000:
            buf = ctypes.create_string_buffer(mbi.RegionSize)
            read = ctypes.c_size_t()
            if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, mbi.RegionSize, ctypes.byref(read)):
                data = buf.raw[:read.value]
                total += read.value
                regions.append((addr, data))
        addr = int(mbi.BaseAddress or 0) + mbi.RegionSize
    k32.CloseHandle(h)
    print(f"可读内存: {total/1048576:.0f}MB, {len(regions)}区域")

    os.makedirs(r"C:\tmp\dddd_mem", exist_ok=True)
    # 1) finger区域: 连续的"- name:\n  fingerprint"模式
    with open(r"C:\tmp\dddd_mem\regions_all.bin", "wb") as f:
        for a, d in regions:
            f.write(d)
    # 统计特征
    blob = b"".join(d for _, d in regions)
    for name, pat in [("finger", b"\n  fingerprint:"), ("poc", b"\nid: "), ("workflow", b"general-poc")]:
        hits[name] = blob.count(pat)
    print("特征统计:", hits)
    print("合并blob写入 C:\\tmp\\dddd_mem\\regions_all.bin")

if __name__ == "__main__":
    main()
