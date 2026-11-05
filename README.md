# Delta 简体中文汉化包

<p align="center">面向 Zed Industries Delta 的二进制非侵入式简体中文语言补丁（Windows x64 + macOS arm64）</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-22C55E?style=flat-square" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%20x64%20%7C%20macOS%20arm64-4B5563?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square" alt="Python: 3.8+">
  <img src="https://img.shields.io/badge/Translations-880%2B-F59E0B?style=flat-square" alt="Translations: 880+">
</p>

Delta 是一款闭源的 AI 编程 Agent 客户端（Windows / macOS）。由于应用未提供官方语言包机制，界面文本直接硬编码编译在主程序二进制中。

本项目通过静态分析二进制指令流与重定位表，实现精准的原位替换与安全内存搬迁，在完全不需要源码、不破坏核心功能的前提下，为 Delta 提供平滑自然的简体中文体验。

## Windows x64 版（新增）

Windows 版工具 `delta_i18n.py` 现已支持 Windows x64 PE 二进制：

| 项目 | 说明 |
|---|---|
| 支持目标 | `delta-app.exe`（约 151 MB，x64 PE） |
| 引用分析 | `lea reg, [rip+disp32]`（取地址）+ `mov r32, imm32`（长度立即数）+ DIR64 重定位胖指针 |
| 原位替换 | 译文不超长时直接覆写字符串字节，零宽字符补齐 |
| 安全搬迁 | 译文超长时写入 .rdata 已验证无引用的填充区（约 1.5 MB 可用），改写 lea disp32 与长度立即数 |
| 比较点保护 | 内联 memcmp（SSE 比较模式）引用的字符串保持原英文字节，比较逻辑不受影响 |
| 校验和 | 自动重算 PE CheckSum；Windows 无需代码签名 |
| 覆盖率 | 1954 词典条目中 1764 条可译（90%），剩余为运行时拼装或第三方库内部文本 |

### Windows 快速使用（推荐：delta-cn.exe 独立启动器）

Delta 0.24.0 起官方启动程序为 `delta.exe`。推荐做法是**生成独立的中文启动器** `delta-cn.exe`，
官方 `delta.exe` 保持原样、照常自动更新，两者互不影响（类似 zed.exe / zedG.exe）：

```bash
# 以官方英文 delta.exe 为源，生成中文版 delta-cn.exe（官方文件不改动）
python delta_i18n.py sync

# 指定路径（默认自动探测 D:\AI工具\Delta\delta.exe）
python delta_i18n.py sync --exe "D:\AI工具\Delta\delta.exe" --out "D:\AI工具\Delta\delta-cn.exe"
```

之后：

- 双击 `delta-cn.exe` 启动中文界面；
- 双击 `delta.exe` 启动官方英文界面（自动更新照常）；
- **Delta 升级更新不会影响 delta-cn.exe** —— 更新器只会覆盖官方文件，中文启动器不在其清单内；
- Delta 升级后想用新版中文，重新执行一次 `sync` 即可（增量覆盖 delta-cn.exe）。

### Windows 快速使用（旧式：原地补丁）

```bash
python delta_i18n.py apply      # 直接改官方文件（会被自动更新还原，不推荐）
python delta_i18n.py restore    # 还原官方文件
python delta_i18n.py check      # 只报告
python delta_i18n.py dump > strings.tsv
```



补丁前自动备份原版程序到 `~/.delta-zh-cn/`；Delta 自动更新覆盖主程序后重新执行 `apply` 即可。

命令：`python delta_i18n.py apply [--exe <路径>]`，其余 check / restore / dump 与 macOS 版一致。

---

## macOS arm64 版（原版）

## 架构与工作原理

补丁工具 `delta_i18n.py` 内部处理管道如下：

```text
┌─────────────────────────┐         ┌─────────────────────────┐
│    Delta.app (arm64)    │         │    translations.json    │
│    Mach-O Executable    │         │     1150+ Dict Keys     │
└────────────┬────────────┘         └────────────┬────────────┘
             │                                   │
             └─────────────────┬─────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                        delta_i18n                           │
│                                                             │
│  1. Scan & Parse Mach-O Binary                              │
│     - Instructions: adrp + add / adrp + ldr                 │
│     - Data Segment: __DATA_CONST chained fixups             │
│                                                             │
│  2. Apply Patching Strategy                                 │
│     - Text <= Orig: In-place overwrite (zero-width padding) │
│     - Text >  Orig: Relocate to alignment gaps (~14 KB)     │
│                                                             │
│  3. Rewrite Pointer References & Register Lengths           │
│                                                             │
│  4. Restore Entitlements & Ad-hoc Re-sign (codesign)        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
                ┌─────────────────────────────┐
                │    Delta Localized (zh)     │
                │     macOS Arm64 Binary      │
                └─────────────────────────────┘
```

1. **定位字符串**：扫描 `__TEXT,__text` 段中的 `adrp + add` 与 `adrp + ldr` 指令序列、附近计算长度的 `movz`，以及 `__DATA_CONST` 段中经 chained fixups 重定位的 `(ptr, len)` 胖指针，确定字面量的绝对物理偏移与读取长度。
2. **原位替换**：译文字节数不超过原文时直接原地覆写，不足字节用渲染不可见的零宽字符（U+200B / U+034F / U+E0001）补全，并执行 UTF-8 切断保护与内联立即数覆盖分析。
3. **空间搬迁**：译文字节数超出原文时，将其写入 Mach-O 头部余量及 `__TEXT` / `__DATA_CONST` 段末尾的对齐空洞（约 14 KB），并同步改写所有寄存器与胖指针引用。
4. **重新签名**：调用 `codesign --sign -` 重新执行 ad-hoc 签名，保持原有 entitlements 与硬化运行时一致。

## 效果展示

| 外观设置 | 通用设置 |
|---|---|
| ![Delta 外观设置界面](./assets/screenshot_appearance.png) | ![Delta 通用设置界面](./assets/screenshot_general.png) |

## 环境要求

- 操作系统：macOS（Apple Silicon / arm64 架构）
- 目标软件：已安装 [Delta.app](https://delta.dev)
- 运行环境：Python 3 及 numpy 库

## 快速安装

```bash
git clone https://github.com/245678000000/delta-zh-cn.git
cd delta-zh-cn
pip3 install -r requirements.txt
```

## 快速启动

1. 彻底退出正在运行的 Delta 应用程序。
2. 执行补丁应用命令：

```bash
python3 delta_i18n.py apply
```

3. 重新打开 Delta，即可进入中文界面。

如需还原为官方英文原版，执行：

```bash
python3 delta_i18n.py restore
```

## 常用命令

| 命令 | 说明 |
|---|---|
| `python3 delta_i18n.py apply` | 应用中文补丁，自动备份原版程序并完成重签名 |
| `python3 delta_i18n.py check` | 模拟检测模式，只输出可替换/无法替换词条报告，不修改任何文件 |
| `python3 delta_i18n.py restore` | 从备份目录恢复官方原版程序 |
| `python3 delta_i18n.py dump > strings.tsv` | 导出当前 Delta 二进制中所有可翻译的英文字符串至 TSV 文件 |

### Delta 自动更新后的处理

Delta 自动更新后，官方安装包会覆盖主程序并恢复为英文界面。此时只需重新执行：

```bash
python3 delta_i18n.py apply
```

工具采用动态指令扫描机制，不依赖固定内存地址，可适配后续多数常规小版本更新。

### macOS 权限说明

macOS 严格限制对 `/Applications` 中已安装 App 文件的直接就地写操作。当工具检测到权限不足时，会自动启用副本替换策略（复制 Delta.app 到临时目录打补丁后整包原子替换），无需手动调整系统 SIP 或文件权限。若启动时弹出 Gatekeeper 提示，在访达（Finder）中右键点击 Delta.app 并选择"打开"即可。

### 钥匙串反复询问「Delta 想要访问你的钥匙串中的密钥」

Delta 的登录凭据存在钥匙串里，钥匙串按代码签名身份授权。汉化后签名变了，首次启动会询问一次，点「始终允许」即可。
但 ad-hoc 签名每次打补丁都会变，为了只授权一次，推荐创建一张固定的自签名证书：

```bash
python3 delta_i18n.py make-cert     # 会弹一次输入登录密码的对话框
python3 delta_i18n.py apply         # 之后 apply 自动用这张证书签名
```

证书只存在于你的登录钥匙串（名称 `Delta zh-CN Patch`），不影响系统信任链，可随时在「钥匙串访问」里删除。

## 已知限制

- **极短词汇保留英文**：4 至 5 字节的极短单词（如 `Pane`、`Code`、`Theme`、`Copy`、`Proxy`），因中文单字需占用 3 字节 UTF-8 编码，无法在严格受限的字节长度内完成原位替换，且其汇编引用形式无法安全搬迁，此类词汇会保持英文显示。
- **运行时动态拼接文本**：命令面板中的部分动作（例如 `Edit Global Rules`、`Send Comment`）为运行时根据 Action Identifier 动态拼装生成，二进制中不存在完整静态字符串，无法通过静态补丁修改。
- **多重引用冲突词条**：若某一词条在二进制中存在多处实例，且其中某处引用被判定为搬迁不安全，为保证程序稳定将放弃对该处进行替换。
- **设置页标题与部分状态词保留英文**：设置窗口按页标题字符串（`General`、`Thread`、`Skills` 等）匹配页面内容，且这类比较被编译成立即数常量，无法修改；同理，`Connection`、`Version`、`Private` 这类既是界面文字又可能作为 HTTP 头 / 序列化值的单词也刻意不翻译（工具会按引用来源 crate 自动过滤）。
- **架构支持**：目前仅支持 macOS arm64 架构二进制。

## 参与维护与词典贡献

词典保存在 `translations.json`，结构为扁平的 `{"英文原文": "中文翻译"}` 映射表。键名必须与二进制中的提取内容完全一致。

1. 导出最新版本的待翻译词条：

```bash
python3 delta_i18n.py dump > strings.tsv
```

2. 编辑更新 `translations.json` 后，使用测试模式验证兼容性：

```bash
python3 delta_i18n.py check
```

3. 验证无误后提交 Pull Request。

### 核心术语对照表

| 英文原词 | 推荐译名 |
|---|---|
| Thread | 会话 |
| Subagent | 子代理 |
| Worktree | 工作树 |
| Runner | 运行器 |
| Review | 审查 |
| Pane | 窗格 |
| Command Palette | 命令面板 |
| Profile | 配置档案 |
| Compaction | 压缩上下文 |
| Checkout | 检出目录 |

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=245678000000%2Fdelta-zh-cn&type=Date)](https://star-history.com/#245678000000/delta-zh-cn&Date)

## 开源协议与声明

- 本项目的工具脚本与词典文件采用 [MIT License](./LICENSE) 授权。
- Delta 商标及客户端所有权归 Zed Industries 所有。本项目为第三方开源语言补丁，不包含、不分发任何 Delta 原始二进制文件。
