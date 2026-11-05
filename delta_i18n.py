#!/usr/bin/env python3
r"""Delta (Zed Industries) 简体中文汉化补丁工具 —— Windows x64 版。

Delta 是闭源的 Rust/GPUI 应用，界面文字被直接编译进主程序二进制，没有任何
语言包机制。本工具的做法（移植自 macOS arm64 版 delta-zh-cn）：

1. 解析 PE（x64），找出所有对 .rdata 里字符串字面量的引用：
   - 代码里的 lea reg, [rip+disp32]（取地址）+ 附近给出长度的立即数：
     * P1: mov r32, imm32(len) 后接 call（GPUI SharedString/label 构造）
     * P2: mov [base+off], ptrreg 后接 mov qword [base+off+8], imm32(len)
           （结构体字段里的 &str 胖指针）
     * P3: cmove 选择模式下与 lea 成对出现的 mov r32, imm32(len)
   - 数据段里经 .reloc DIR64 重定位的 (ptr, len) 胖指针。
   由此得到每条字面量精确的起点、长度与所有可改写引用。
2. 对词典里的每一条：
   - 译文字节数 ≤ 原文：**原位替换**，不足部分用零宽字符补齐；
   - 译文更长：把译文写到 .rdata 中已验证无引用的全零填充区（**搬迁**），
     改写所有 lea disp32 与长度立即数。PE 上这两处都是 4 字节立即数，改写安全。
   - 引用无法安全改写（如内联 memcmp 比较点）时该处保持英文。
3. 修正 PE 校验和（CheckSum）。Windows 不强制代码签名，无需重签名。

用法：
    python delta_i18n.py sync   [--exe ...] [--out delta-cn.exe] [--dict translations.json]
           # 从官方英文 delta-app.exe 生成中文 delta-cn.exe（官方文件保持原样，
           # Delta 升级更新互不影响；升级后重新执行 sync 即可刷新中文版）
    python delta_i18n.py check   [--exe ...] [--dict ...]    # 只报告，不改动
    python delta_i18n.py apply   [--exe ...]                 # 旧式原地补丁（默认不再推荐）
    python delta_i18n.py restore [--exe ...]                 # 还原官方文件（仅在用过 apply 时）
    python delta_i18n.py dump    [--exe ...] > strings.tsv   # 导出可翻译的字符串
"""
import argparse, json, os, re, shutil, struct, subprocess, sys, tempfile

try:
    import capstone
except ImportError:
    sys.exit("需要 capstone：pip install capstone")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

def _home_dir():
    """备份目录基址：优先 USERPROFILE/HOME，失败时退回 APPDATA 或脚本所在盘。"""
    for var in ("USERPROFILE", "HOME"):
        v = os.environ.get(var)
        if v and os.path.isabs(v):
            return v
    v = os.environ.get("APPDATA")
    if v and os.path.isabs(v):
        return os.path.dirname(v)
    return os.path.dirname(os.path.abspath(__file__))

BACKUP_DIR = os.path.join(_home_dir(), ".delta-zh-cn")

# ---------- 零宽填充 ----------
PAD4 = "\U000E0001".encode()  # 4 字节：Unicode TAG 字符，默认可忽略
PAD3 = "\u200b".encode()      # 3 字节：零宽空格
PAD2 = "\u034f".encode()      # 2 字节：组合字形连接符（零宽）
PAD1 = b" "                    # 1 字节：普通空格（兜底）


def pad_to(b: bytes, n: int) -> bytes:
    gap = n - len(b)
    assert gap >= 0
    out = b
    while gap > 0:
        if gap % 3 == 0:
            out += PAD3; gap -= 3
        elif gap % 3 == 1:
            if gap >= 4: out += PAD4; gap -= 4
            else: out += PAD1; gap -= 1
        else:
            out += PAD2; gap -= 2
    assert len(out) == n
    return out


# ---------- PE ----------
class PE:
    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            sys.exit("不是 PE 文件")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if struct.unpack_from("<I", data, e_lfanew)[0] != 0x4550:
            sys.exit("PE 签名错误")
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        if machine != 0x8664:
            sys.exit("只支持 x64 PE（Windows 版 Delta 就是这种）")
        ncmds = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        opt = e_lfanew + 24
        self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        self.checksum_fo = opt + 64
        self.sections = {}   # name -> dict
        self.sections_list = []
        off = opt + opt_size
        for _ in range(ncmds):
            name = data[off:off+8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
            self.sections[name] = {"name": name, "vsize": vsize, "vaddr": vaddr,
                                   "rsize": rsize, "rptr": rptr}
            self.sections_list.append(self.sections[name])
            off += 40
        if ".text" not in self.sections or ".rdata" not in self.sections or ".reloc" not in self.sections:
            sys.exit("缺少 .text/.rdata/.reloc 节区（不是标准 Windows 版 Delta？）")

    def va_to_fo(self, va):
        for s in self.sections_list:
            if s["vaddr"] <= va < s["vaddr"] + s["rsize"]:
                return s["rptr"] + (va - s["vaddr"])
        return None

    def fo_to_va(self, fo):
        for s in self.sections_list:
            if s["rptr"] <= fo < s["rptr"] + s["rsize"]:
                return s["vaddr"] + (fo - s["rptr"])
        return None

    def reloc_slots(self):
        """遍历 .reloc 的 DIR64 项，返回 [(slotFo, targetVA)]（VA 相对 ImageBase）。"""
        out = []
        sec = self.sections[".reloc"]
        data = self.data
        p = sec["rptr"]
        end = p + sec["rsize"]
        while p < end:
            pageRVA, blockSize = struct.unpack_from("<II", data, p)
            if blockSize == 0:
                break
            for i in range((blockSize - 8) // 2):
                e = struct.unpack_from("<H", data, p + 8 + i * 2)[0]
                typ, off = e >> 12, e & 0xFFF
                if typ != 10:   # IMAGE_REL_BASED_DIR64
                    continue
                slotVA = pageRVA + off
                slotFo = self.va_to_fo(slotVA)
                if slotFo is None:
                    continue
                target = struct.unpack_from("<Q", data, slotFo)[0] - self.image_base
                out.append((slotFo, target))
            p += blockSize
        return out

    def fix_checksum(self, buf: bytearray):
        """重算 PE CheckSum（与 link /release 一致的算法）。"""
        struct.pack_into("<I", buf, self.checksum_fo, 0)
        limit = len(buf)
        sum_ = 0
        i = 0
        while i < limit:
            w = struct.unpack_from("<I", buf, i)[0]
            sum_ += w
            if sum_ >= 0xFFFFFFFF:
                sum_ = (sum_ & 0xFFFFFFFF) + 1   # end-around carry
            i += 4
        sum_ = (sum_ & 0xFFFF) + (sum_ >> 16)
        sum_ = (sum_ & 0xFFFF) + (sum_ >> 16)
        checksum = sum_ + limit
        struct.pack_into("<I", buf, self.checksum_fo, checksum)


# ---------- 引用分析 ----------
class Ref:
    __slots__ = ("kind", "target_va", "patch_fo")
    # kind: 'lea'  -> patch_fo = (leaFo, immFo)  两个字段都要改
    # kind: 'fat'  -> patch_fo = (slotFo, immFo) 槽位 8 字节 + len 8 字节


class Literal:
    __slots__ = ("va", "fo", "length", "text", "refs")
    def __init__(self, va, fo, length, text):
        self.va, self.fo, self.length, self.text = va, fo, length, text
        self.refs = []


def build_lea_index(pe: PE):
    """扫描 .text 中所有 lea reg,[rip+disp32] 指向 .rdata 的引用。
    返回 {targetVA: [leaFo]}。"""
    text = pe.sections[".text"]
    rdata = pe.sections[".rdata"]
    data = pe.data
    idx = {}
    i = text["rptr"]
    end = i + text["rsize"]
    r_lo, r_hi = rdata["vaddr"], rdata["vaddr"] + rdata["vsize"]
    while i < end - 7:
        b = data[i]
        if (b == 0x48 or b == 0x4C) and data[i+1] == 0x8D and (data[i+2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", data, i + 3)[0]
            iva = text["vaddr"] + (i - text["rptr"])
            tgt = iva + 7 + disp
            if r_lo <= tgt < r_hi:
                idx.setdefault(tgt, []).append(i)
        i += 1
    return idx


def analyze_lea(pe: PE, lea_fo: int, want_len: int):
    """在 lea 之后寻找建立长度的立即数。返回 (immFo, kind) 或 None。
    P1: mov r32, imm32(len)（后接 call 或独立使用）
    P2: mov [base+off], ptrreg 之后 mov qword [base+off+8], imm32(len)
    比较点保护：lea 后紧跟 xmm 比较指令（pcmpeqd/movaps 等）时返回 ('cmp', None)。"""
    text = pe.sections[".text"]
    md = _md
    data = pe.data
    iva = text["vaddr"] + (lea_fo - text["rptr"])
    fwd = data[lea_fo:lea_fo+128]
    try:
        disas = list(md.disasm(fwd, iva))
    except Exception:
        return None
    if not disas:
        return None
    X86_OP_IMM = capstone.x86.X86_OP_IMM
    X86_OP_MEM = capstone.x86.X86_OP_MEM
    X86_OP_REG = capstone.x86.X86_OP_REG
    preg = disas[0].operands[0].reg
    stored_at = None
    for k in range(1, min(17, len(disas))):
        ins = disas[k]
        op = ins.operands
        mn = ins.mnemonic
        is_cmov = mn.startswith("cmov")
        # 内联 memcmp 保护：紧跟 lea 的 SSE/AVX 比较模式
        if k <= 2 and (mn.startswith("pcmpeq") or mn.startswith("movaps") or mn.startswith("movups") or mn.startswith("movdqa") or mn.startswith("movdqu")):
            return ("cmp", None)
        if mn == "mov" and len(op) == 2 and op[1].type == X86_OP_IMM:
            imm = op[1].imm
            if 1 <= imm <= 4096:
                ib = bytes(ins.bytes)
                imm_off = None
                is_store = False
                if ib[0] == 0x41 and 0xB8 <= ib[1] <= 0xBF:
                    imm_off = 2
                elif 0xB8 <= ib[0] <= 0xBF:
                    imm_off = 1
                elif (ib[0] in (0x48, 0x49) and ib[1] == 0xC7) or ib[0] == 0xC7:
                    imm_off = len(ib) - 4
                    is_store = True
                if imm_off is not None:
                    if imm == want_len:
                        if is_store:
                            if stored_at is not None and op[0].type == X86_OP_MEM:
                                m = op[0].mem
                                sb, sd = stored_at
                                if m.base == sb and m.disp == sd + 8:
                                    return ("len", (lea_fo, lea_fo + (ins.address - iva) + imm_off))
                        else:
                            return ("len", (lea_fo, lea_fo + (ins.address - iva) + imm_off))
                    # 与 want_len 不同的立即数长度：仅当它是寄存器赋值且后接 call 时，判定为另一字符串的长度，继续找
                    # 简化：遇到不同长度的寄存器立即数即停止（长度已确定，不是我们要的）
                    if not is_store and ib[0:1] in (b"\x41",) or (0xB8 <= ib[0] <= 0xBF):
                        return ("mismatch", None)
                    continue
        if mn == "mov" and len(op) == 2 and op[0].type == X86_OP_MEM and op[1].type == X86_OP_REG and op[1].reg == preg:
            stored_at = (op[0].mem.base, op[0].mem.disp)
        if mn in ("call", "jmp", "ret"):
            break
        if not is_cmov and len(op) >= 1 and op[0].type == X86_OP_REG and op[0].reg == preg:
            if mn == "mov" and len(op) == 2 and op[1].type == X86_OP_REG:
                continue
            break
    return None


_md = None


def analyze(pe: PE, want_strings):
    """主分析：对每个待翻译字符串，找到 (VA, 长度, 引用列表)。
    返回 {text: Literal}。"""
    global _md
    _md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    _md.detail = True
    data = pe.data
    text = pe.sections[".text"]
    rdata = pe.sections[".rdata"]
    r_lo, r_hi = rdata["vaddr"], rdata["vaddr"] + rdata["vsize"]

    lea_index = build_lea_index(pe)

    # 胖指针：reloc DIR64 指向 .rdata 的 (ptr,len) 槽
    fat_by_target = {}
    for slot_fo, tgt in pe.reloc_slots():
        if not (r_lo <= tgt < r_hi):
            continue
        ln = struct.unpack_from("<Q", data, slot_fo + 8)[0]
        if 0 < ln < 8192:
            fat_by_target.setdefault(tgt, []).append((slot_fo, int(ln)))

    # 字符串出现位置
    lits = {}
    for s in want_strings:
        eb = s.encode("utf-8")
        positions = []
        i = 0
        while True:
            i = data.find(eb, i)
            if i == -1:
                break
            va = pe.fo_to_va(i)
            if va is not None and r_lo <= va < r_hi:
                positions.append(va)
            i += len(eb)
        if not positions:
            continue
        for va in positions:
            refs = []
            for lea_fo in lea_index.get(va, []):
                res = analyze_lea(pe, lea_fo, len(eb))
                if res and res[0] == "len":
                    refs.append(("lea", res[1][0], res[1][1]))
                elif res and res[0] == "cmp":
                    refs.append(("cmp", lea_fo, None))
            for slot_fo, ln in fat_by_target.get(va, []):
                if ln == len(eb):
                    refs.append(("fat", slot_fo, None))
            key = (s, va)
            if key not in lits:
                lits[key] = Literal(va, pe.va_to_fo(va), len(eb), s)
            lits[key].refs = refs
    return lits


# ---------- 空闲空间 ----------
def free_regions(pe: PE, lits):
    """在 .rdata 中找全零且无 lea/reloc 引用的区域。"""
    data = pe.data
    rdata = pe.sections[".rdata"]
    r_lo, r_hi = rdata["vaddr"], rdata["vaddr"] + rdata["vsize"]

    # 已引用的目标集合
    text = pe.sections[".text"]
    referenced = set()
    i = text["rptr"]
    end = i + text["rsize"]
    while i < end - 7:
        b = data[i]
        if (b == 0x48 or b == 0x4C) and data[i+1] == 0x8D and (data[i+2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", data, i + 3)[0]
            iva = text["vaddr"] + (i - text["rptr"])
            tgt = iva + 7 + disp
            if r_lo <= tgt < r_hi:
                referenced.add(tgt)
        i += 1
    for _, tgt in pe.reloc_slots():
        if r_lo <= tgt < r_hi:
            referenced.add(tgt)

    # 扫描零块（>=256B），排除引用命中的 16 字节粒度单元
    regions = []
    run_start = -1
    rptr_end = rdata["rptr"] + rdata["rsize"]
    for i in range(rdata["rptr"], rptr_end):
        if data[i] == 0:
            if run_start < 0:
                run_start = i
        else:
            if run_start >= 0 and i - run_start >= 256:
                regions.append((run_start, i - run_start))
            run_start = -1
    if run_start >= 0 and rptr_end - run_start >= 256:
        regions.append((run_start, rptr_end - run_start))

    out = []
    for fo, size in regions:
        # 排除被引用单元
        clear_lo = fo
        clear_hi = fo + size
        bad = False
        va0 = pe.fo_to_va(fo)
        # 快速检查：引用落在该区间的比例
        for t in referenced:
            if va0 <= t < va0 + size:
                bad = True
                break
        if bad:
            # 尝试切割：找到无引用的子区间（16 字节粒度）
            cells = set()
            va_hi = va0 + size
            for t in referenced:
                if va0 <= t < va_hi:
                    cells.add((t - va0) // 16)
            ncells = size // 16
            # 找最大连续无引用单元段
            best = None
            cur_start = None
            for c in range(ncells):
                if c not in cells:
                    if cur_start is None:
                        cur_start = c
                else:
                    if cur_start is not None:
                        seg = (cur_start * 16, (c - cur_start) * 16)
                        if best is None or seg[1] > best[1]:
                            best = seg
                    cur_start = None
            if cur_start is not None:
                seg = (cur_start * 16, (ncells - cur_start) * 16)
                if best is None or seg[1] > best[1]:
                    best = seg
            if best and best[1] >= 64:
                out.append((fo + best[0], best[1]))
        else:
            out.append((fo, size))
    # 去掉头部/尾部 16 字节余量
    final = []
    for fo, size in out:
        if size > 48:
            final.append((fo + 16, size - 32))
    return final


class Allocator:
    def __init__(self, regions):
        self.regions = [[fo, fo + size] for fo, size in regions]
    def alloc(self, n):
        for r in self.regions:
            if r[1] - r[0] >= n:
                fo = r[0]
                r[0] += n
                return fo
        return None
    def remaining(self):
        return sum(r[1] - r[0] for r in self.regions)


# ---------- 计划与打补丁 ----------
def load_dict(path):
    d = json.load(open(path, encoding="utf-8"))
    return {k: (v["zh"] if isinstance(v, dict) else v) for k, v in d.items()
            if not k.startswith("_") and v}


def make_plan(pe: PE, table):
    lits = analyze(pe, list(table.keys()))
    by_text = {}
    for (text_, va), lit in lits.items():
        by_text.setdefault(text_, []).append(lit)

    # 判断每条是否所有引用安全
    def refs_safe(lit):
        return all(r[0] in ("lea", "fat") for r in lit.refs)

    def has_any_ref(lit):
        return any(r[0] in ("lea", "fat") for r in lit.refs)

    inplace, relocs, missing, unsafe = [], [], [], []
    alloc = None
    relocated_text = {}
    regions_needed = False

    # 第一遍：分类
    for en, zh in table.items():
        hits = [l for l in by_text.get(en, []) if has_any_ref(l)]
        if not hits:
            missing.append(en)
            continue
        zb = zh.encode("utf-8")
        for lit in hits:
            if len(zb) <= lit.length:
                inplace.append((lit, pad_to(zb, lit.length)))
            else:
                regions_needed = True
                relocs.append((lit, zb))

    if regions_needed:
        alloc = Allocator(free_regions(pe, lits))
        # 给每个搬迁目标分配空间
        new_relocs = []
        for lit, zb in relocs:
            if zb in relocated_text:
                fo = relocated_text[zb]
            else:
                fo = alloc.alloc(len(zb))
                if fo is None:
                    unsafe.append((lit.text, "空闲空间不足"))
                    continue
                relocated_text[zb] = fo
            new_relocs.append((lit, zb, fo))
        relocs = new_relocs

    return dict(inplace=inplace, relocs=relocs, missing=missing, unsafe=unsafe,
                alloc=alloc, by_text=by_text, lits=lits)


def report(plan, table):
    n_ok = len({lit.text for lit, _ in plan["inplace"]} | {lit.text for lit, _, _ in plan["relocs"]})
    print(f"词条 {len(table)} 条：原位替换 {len(plan['inplace'])} 处，搬迁 {len(plan['relocs'])} 处，覆盖 {n_ok} 条；"
          f"未找到/不可译 {len(plan['missing'])} 条；跳过 {len(plan['unsafe'])} 处")
    if plan["alloc"]:
        print(f"剩余空闲空间 {plan['alloc'].remaining()} 字节")
    if plan["unsafe"]:
        for en, why in plan["unsafe"][:20]:
            print(f"  [跳过·{why}] {en!r}")
    if plan["missing"]:
        print("  [未找到]", ", ".join(repr(x) for x in plan["missing"][:30]),
              "…" if len(plan["missing"]) > 30 else "")


def apply_plan(pe: PE, plan):
    buf = bytearray(pe.data)
    data = pe.data
    image_base = pe.image_base

    for lit, nb in plan["inplace"]:
        assert bytes(buf[lit.fo:lit.fo + lit.length]) == lit.text.encode("utf-8"), f"原位替换前校验失败: {lit.text!r}"
        buf[lit.fo:lit.fo + lit.length] = nb

    for lit, zb, fo in plan["relocs"]:
        new_va = pe.fo_to_va(fo)
        buf[fo:fo + len(zb)] = zb
        for r in lit.refs:
            if r[0] == "lea":
                lea_fo, imm_fo = r[1], r[2]
                # 改写 lea disp32: target = insnVA + 7 + disp
                iva = pe.fo_to_va(lea_fo)
                disp = new_va - (iva + 7)
                struct.pack_into("<i", buf, lea_fo + 3, disp)
                # 改写长度立即数（可能不存在）
                if imm_fo is not None:
                    struct.pack_into("<I", buf, imm_fo, len(zb))
            elif r[0] == "fat":
                slot_fo = r[1]
                struct.pack_into("<Q", buf, slot_fo, image_base + new_va)
                struct.pack_into("<Q", buf, slot_fo + 8, len(zb))

    pe.fix_checksum(buf)
    return bytes(buf)


# ---------- 命令 ----------
def default_exe():
    """自动探测官方 Delta 启动程序：delta.exe（0.24.0+）或 delta-app.exe（旧版）。"""
    names = ("delta.exe", "delta-app.exe")
    candidates = []
    here = os.path.dirname(os.path.abspath(__file__))
    for n in names:
        candidates.append(os.path.join(here, n))
    # D:\AI工具\Delta（用户当前安装位置）
    for n in names:
        candidates.append(os.path.join("D:\\AI工具\\Delta", n))
    # LOCALAPPDATA 常见安装路径
    la = os.environ.get("LOCALAPPDATA")
    if la:
        for d in ("Delta", "Programs\\Delta", "delta.dev"):
            for n in names:
                candidates.append(os.path.join(la, d, n))
    # Program Files
    for pf in ("C:\\Program Files\\Delta", "C:\\Program Files (x86)\\Delta"):
        for n in names:
            candidates.append(os.path.join(pf, n))
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]


def _pe_sections_fingerprint(data):
    pe = PE(data)
    return tuple((s["name"], s["vaddr"], s["vsize"], s["rsize"]) for s in pe.sections_list)


def backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    return BACKUP_DIR


def original_binary(exe):
    """返回未打过补丁的原始程序内容（优先用备份；按 PE 节表指纹匹配，跨补丁幂等）。"""
    cur = open(exe, "rb").read()
    try:
        cur_fp = _pe_sections_fingerprint(cur)
    except SystemExit:
        cur_fp = None
    if os.path.isdir(BACKUP_DIR):
        for name in sorted(os.listdir(BACKUP_DIR)):
            if not name.endswith(".orig.exe"):
                continue
            path = os.path.join(BACKUP_DIR, name)
            try:
                bkdata = open(path, "rb").read()
                if _pe_sections_fingerprint(bkdata) == cur_fp:
                    return bkdata, True
            except Exception:
                continue
    return cur, False


def do_sync(exe, out_path, dict_path, dry=False):
    """从官方英文 delta-app.exe 生成中文 delta-cn.exe 副本（官方文件保持原样）。"""
    if not os.path.exists(exe):
        sys.exit(f"找不到 {exe}")
    data = open(exe, "rb").read()
    # 输入若是已打补丁的文件则提示（避免二次补丁）
    if "\u5173\u4e8e Delta".encode("utf-8") in data:
        print("警告：输入文件似乎已包含中文补丁。请对官方英文原版执行 sync。")
    pe = PE(data)
    table = load_dict(dict_path)
    plan = make_plan(pe, table)
    report(plan, table)
    if dry:
        return
    if not plan["inplace"] and not plan["relocs"]:
        print("没有任何可应用的补丁。")
        return
    out = apply_plan(pe, plan)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(out)
    print(f"已生成中文版：{out_path}（官方文件 {exe} 未改动）")


def do_apply(exe, dict_path, dry):
    if not os.path.exists(exe):
        sys.exit(f"找不到 {exe}")
    data, from_backup = original_binary(exe)
    pe = PE(data)
    table = load_dict(dict_path)
    plan = make_plan(pe, table)
    report(plan, table)
    if dry:
        return
    if not plan["inplace"] and not plan["relocs"]:
        print("没有任何可应用的补丁。")
        return
    out = apply_plan(pe, plan)
    if not from_backup:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        import time
        bk = os.path.join(BACKUP_DIR, time.strftime("delta-%Y%m%d-%H%M%S.orig.exe"))
        shutil.copy2(exe, bk)
        print(f"已备份原始程序到 {bk}")
    with open(exe, "wb") as f:
        f.write(out)
    print("完成。启动 Delta 即可看到中文界面。")


def do_restore(exe):
    data, found = original_binary(exe)
    if not found:
        sys.exit(f"没有备份（{BACKUP_DIR}），请重新下载安装 Delta。")
    with open(exe, "wb") as f:
        f.write(data)
    print("已还原原版程序。")


def do_dump(exe):
    data, _ = original_binary(exe)
    pe = PE(data)
    rdata = pe.sections[".rdata"]
    lea_index = build_lea_index(pe)
    # 导出所有有 lea 引用且带长度立即数的可读字符串
    global _md
    _md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    _md.detail = True
    seen = set()
    results = []
    for tgt, leas in lea_index.items():
        for lea_fo in leas:
            # 尝试常见长度（从 2 到 64）找匹配的立即数
            for want in range(2, 65):
                res = analyze_lea(pe, lea_fo, want)
                if res and res[0] == "len":
                    fo = pe.va_to_fo(tgt)
                    try:
                        s = data[fo:fo+want].decode("utf-8")
                    except UnicodeDecodeError:
                        break
                    if all(c.isprintable() or c in "\n\t" for c in s) and re.search(r"[A-Za-z]", s):
                        if s not in seen:
                            seen.add(s)
                            results.append((tgt, want, s))
                    break
    for tgt, ln, s in sorted(results):
        if len(s) >= 2 and (s[0].isupper() or " " in s):
            if sum(c.isalpha() or c.isspace() or c in ".,'\u2019:;!?()-\u2014/&%\u2026" for c in s) / len(s) >= 0.85:
                print(f"{tgt:#x}\t{ln}\t{json.dumps(s, ensure_ascii=False)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["sync", "apply", "check", "restore", "dump"])
    ap.add_argument("--exe", default=None, help="官方 delta-app.exe 路径（默认自动探测常见安装位置）")
    ap.add_argument("--out", default=None, help="sync 输出的中文版 exe 路径（默认与官方同目录 delta-cn.exe）")
    ap.add_argument("--dict", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "translations.json"))
    a = ap.parse_args()
    exe = a.exe or default_exe()
    if a.cmd == "sync":
        out = a.out or os.path.join(os.path.dirname(os.path.abspath(exe)), "delta-cn.exe")
        do_sync(exe, out, a.dict)
    elif a.cmd == "apply":
        do_apply(exe, a.dict, dry=False)
    elif a.cmd == "check":
        do_apply(exe, a.dict, dry=True)
    elif a.cmd == "restore":
        do_restore(exe)
    elif a.cmd == "dump":
        do_dump(exe)


if __name__ == "__main__":
    main()
