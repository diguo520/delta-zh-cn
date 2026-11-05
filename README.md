# Delta 简体中文汉化包

<p align="center">面向 Zed Industries Delta 的二进制非侵入式简体中文语言补丁（Windows x64 / macOS arm64 / Linux x64）</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-22C55E?style=flat-square" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-4B5563?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square" alt="Python: 3.8+">
  <img src="https://img.shields.io/badge/Translations-2020-D97706?style=flat-square" alt="Translations">
</p>

Delta 是一款闭源的 AI 编程 Agent 客户端（Windows / macOS / Linux / Web）。由于应用未提供官方语言包机制，界面文本直接硬编码编译在主程序二进制中。

本项目通过静态分析二进制指令流与重定位表，实现精准的原位替换与安全内存搬迁，在完全不需要源码、不破坏核心功能的前提下，为 Delta 提供平滑自然的简体中文体验。

## 平台支持

| 平台 | 目标文件 | 工具 | 状态 |
|---|---|---|---|
| Windows x64 | `delta.exe`（PE） | `delta_i18n.py` | ✅ 已实测（Delta 0.24.0） |
| Linux x64 | `delta`（ELF） | `delta_i18n.py` | ✅ ELF 解析已实现，x86-64 逻辑与 Windows 共通 |
| macOS arm64 | `Delta.app/Contents/MacOS/delta`（Mach-O） | `delta_i18n_macos.py` | ✅ 原版实现（1150+ 词条，含签名处理） |

> 同一份 `translations.json` 词典服务三平台：Windows / Linux 共用 x86-64 引用分析逻辑，macOS 使用 arm64 的 `adrp+add` 分析。

## 核心能力

| 能力 | 说明 |
|---|---|
| 非侵入式补丁 | 仅修改界面静态字符串与引用，不改动网络传输、会话逻辑与 AI 协作机制 |
| 原位替换 | 译文不超长时直接覆写字节，用零宽字符（U+200B / U+034F / U+E0001）补齐对齐 |
| 安全搬迁 | 译文超长时写入已验证无引用的填充区并改写所有引用（Windows/Linux: `lea disp32` + 长度立即数；macOS: `adrp+add` + `movz`） |
| 比较点保护 | 内联 memcmp / SSE 比较引用的字符串保持原英文字节 |
| 独立启动器 | Windows 生成 `delta-cn.exe`，官方程序零改动，自动更新互不影响 |
| 幂等 | 重复执行 `sync` 始终从官方原版生成，不会叠加补丁 |
| 一键还原 | `restore` 从备份恢复官方原版 |

## 快速使用

### Windows x64

```bash
pip install capstone

# 生成中文启动器 delta-cn.exe（官方 delta.exe 完全不动）
python delta_i18n.py sync

# 指定路径
python delta_i18n.py sync --exe "D:\AI工具\Delta\delta.exe" --out "D:\AI工具\Delta\delta-cn.exe"

# 只看报告，不写文件
python delta_i18n.py sync --dry-run
```

之后双击 `delta-cn.exe` 进入中文界面；`delta.exe` 保持英文并照常自动更新。
**Delta 升级不会影响 `delta-cn.exe`**（安装器只覆盖官方清单内文件）；升级后重跑 `sync` 即可刷新。

### Linux x64

```bash
pip install capstone

# 自动探测 /opt/delta/delta 等常见路径
python delta_i18n.py sync

# 或显式指定
python delta_i18n.py sync --exe /opt/delta/delta --out /opt/delta/delta-cn
```

生成 `delta-cn`（ELF 无校验和，无需重签名），直接运行即可。

### macOS arm64

```bash
pip3 install numpy

python3 delta_i18n_macos.py apply     # 应用补丁（自动备份 + ad-hoc 重签名）
python3 delta_i18n_macos.py check     # 只报告
python3 delta_i18n_macos.py restore   # 还原
python3 delta_i18n_macos.py make-cert # 创建固定证书，避免钥匙串反复询问
```

## 覆盖情况

当前词典 **2020 条**，在 Delta 0.24.0（Windows x64）上实际生效 **1792 条**。

无法汉化的部分（非工具缺陷，属静态补丁的固有限制）：

- **快捷键动作名与分类名**：二进制中只存在 action ID（如 `project_panel::CollapseAllEntries`），显示文本由 GPUI 在运行时生成。
- **运行时拼装文本**：如 `Delete Thread`、`Copy as JSON`，由动作 ID 拼接而成，二进制中无完整静态字符串。
- **极短词**：中文最少 2 字（6 字节）长于英文 4–5 字节，且无长度立即数可搬迁，故保留英文。

## 词条贡献

词典为扁平的 `{"英文原文": "中文翻译"}` 映射，键必须与二进制中的字符串逐字节一致。

```bash
python delta_i18n.py dump > strings.tsv   # 导出当前二进制中可翻译的字符串
python delta_i18n.py sync --dry-run       # 校验覆盖率与跳过原因
```

1. 编辑 `translations.json` 增补词条；
2. `sync --dry-run` 确认能命中；
3. 提交 Pull Request。

### 核心术语对照

| 英文 | 译名 | 英文 | 译名 |
|---|---|---|---|
| Thread | 会话 | Subagent | 子代理 |
| Worktree | 工作树 | Checkout | 检出目录 |
| Runner | 运行器 | Review | 审查 |
| Pane | 窗格 | Command Palette | 命令面板 |
| Profile | 配置档案 | Compaction | 压缩上下文 |
| Fork | 分支副本 | Provider | 服务商 |

## 架构与工作原理

### Windows / Linux（x86-64）

```text
┌──────────────────────────┐         ┌─────────────────────────┐
│ delta.exe / delta (ELF)  │         │   translations.json     │
│ .text / .rdata / .reloc  │         │     界面词条词典        │
└────────────┬─────────────┘         └────────────┬────────────┘
             │                                    │
             └──────────────────┬─────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                        delta_i18n                            │
│  1. 解析容器：PE 节表/重定位/校验和 或 ELF 节区/.rela.dyn      │
│  2. 扫描 .text 引用：                                        │
│     • lea rip+disp32 + mov imm32(len) + call（标签构造）      │
│     • lea + mov [mem],reg + mov [mem+8],imm32（结构体字段）   │
│     • 重定位表胖指针 (ptr, len)                              │
│  3. 原位替换（零宽补齐）或搬迁到只读区空洞并改写引用          │
│  4. PE：重算 CheckSum；ELF：无需校验和                       │
└──────────────────────────────────────────────────────────────┘
```

### macOS（arm64）

```text
┌─────────────────────────┐         ┌─────────────────────────┐
│    Delta.app (arm64)    │         │    translations.json    │
│    Mach-O Executable    │         │     1100+ Dict Keys     │
└────────────┬────────────┘         └────────────┬────────────┘
             │                                   │
             └─────────────────┬─────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      delta_i18n_macos                       │
│  1. Scan & Parse Mach-O Binary                              │
│     - Instructions: adrp + add / adrp + ldr                 │
│     - Data Segment: __DATA_CONST chained fixups             │
│  2. Apply Patching Strategy                                 │
│     - Text <= Orig: In-place overwrite (zero-width padding) │
│     - Text >  Orig: Relocate to alignment gaps              │
│  3. Rewrite Pointer References & Register Lengths           │
│  4. Restore Entitlements & Ad-hoc Re-sign (codesign)        │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
                ┌─────────────────────────────┐
                │    Delta Localized (zh)     │
                │     macOS Arm64 Binary      │
                └─────────────────────────────┘
```

## macOS 权限说明

macOS 严格限制对 `/Applications` 中已安装 App 文件的直接就地写操作。当工具检测到权限不足时，会自动启用副本替换策略（复制 Delta.app 到临时目录打补丁后整包原子替换），无需手动调整系统 SIP 或文件权限。若启动时弹出 Gatekeeper 提示，在访达（Finder）中右键点击 Delta.app 并选择「打开」即可。

### 钥匙串反复询问

Delta 的登录凭据存在钥匙串里，钥匙串按代码签名身份授权。汉化后签名变了，首次启动会询问一次，点「始终允许」即可。
ad-hoc 签名每次打补丁都会变，为了只授权一次，推荐创建一张固定的自签名证书：

```bash
python3 delta_i18n_macos.py make-cert
```

证书只存在于你的登录钥匙串（名称 `Delta zh-CN Patch`），不影响系统信任链，可随时在「钥匙串访问」里删除。

## 已知限制

- **运行时动态拼接文本**：命令面板中的部分动作（如 `Edit Global Rules`、`Send Comment`）为运行时根据 Action Identifier 动态拼装生成，二进制中不存在完整静态字符串。
- **快捷键界面**：动作名与分类名均由 action ID 在运行时转换显示，无法静态汉化。
- **极短词汇**：`Pane`、`Copy`、`Proxy` 等 4–5 字节短词，中文至少 6 字节，无法原位替换且引用处无长度立即数，保留英文。
- **设置页标题比较**：设置窗口按页标题字符串匹配页面内容，这类比较被编译成立即数常量，部分状态词（如 `Connection`）刻意不翻译。
- **多重引用冲突**：某词条若存在多处实例且某处引用无法安全改写，为保证程序稳定会放弃该处替换。

## 参与维护与声明

- 工具脚本与词典采用 [MIT License](./LICENSE) 授权。
- Delta 商标及客户端所有权归 Zed Industries 所有。本项目为第三方开源语言补丁，不包含、不分发任何 Delta 原始二进制文件。
- Releases 中仅包含补丁脚本与词典，不含任何官方程序。
