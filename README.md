# Nuclei POC Gather

[![Go Nuclei POC Monitor](https://github.com/AMJIYU/NucleiPocGather/actions/workflows/go-monitor.yml/badge.svg)](https://github.com/AMJIYU/NucleiPocGather/actions/workflows/go-monitor.yml)

一个持续自动维护的 Nuclei POC 仓库。项目使用 Go 编写监控程序，由 GitHub Actions 每天自动收集、分类和校验全网公开的 Nuclei POC。

## 项目特点

- **每天自动运行**：GitHub Actions 每天自动同步多个公开 POC 来源并更新仓库。
- **自动校验兼容性**：每个 YAML POC 都会使用 Nuclei 的 `-validate` 进行校验，确保 `poc/` 中的模板可以被 Nuclei 加载。
- **无需本地下载和校验**：校验工作在 GitHub Actions 中完成，使用者不需要在本地下载来源仓库、安装 Go 或重新验证 POC。
- **下载即可使用**：本地只需要获取 `poc/` 目录，就可以直接交给 Nuclei 执行授权范围内的扫描。
- **自动分类和去重**：POC 按漏洞类型、产品和协议记录分类信息；最终 `poc/` 中相同内容全局只保留一份。
- **不兼容模板单独隔离**：解析失败或 Nuclei 校验失败的模板会原样放入 `incompatible/`，不会混入可用 POC。
- **增量监控**：首次运行建立完整清单；后续先比较来源仓库 HEAD，只同步发生变化的仓库，并只校验新增或内容变化的模板。
- **持续可追溯**：`metadata/` 保存来源、SHA-256、校验状态、失败原因和统计信息。

## 当前兼容性状态

仓库已使用 Nuclei `v3.11.1` 对 `poc/` 做全量校验：

```bash
nuclei -validate -t ./poc
```

当前命令返回码为 `0`。校验失败的模板已原样移到 `incompatible/`，并按 `validation-failed/`、`compile-failed/` 和 `missing-dependency/` 保存原始目录层级。`poc/` 中仍可能看到重复模板 ID warning，这是多个来源提供相同 ID 的可加载模板，不会导致 Nuclei 校验失败；相同内容会在自动收集时去重。

## 直接使用 POC

不需要运行本项目的 Go 程序，也不需要在本地重新校验模板。只获取 `poc/` 目录即可：

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/AMJIYU/NucleiPocGather.git
cd NucleiPocGather
git sparse-checkout set poc
```

在确认目标属于授权测试范围后，直接使用 Nuclei：

```bash
nuclei -t ./poc -l targets.txt
```

也可以按分类或严重性使用：

```bash
nuclei -t ./poc/cve -l targets.txt -s critical,high
nuclei -t ./poc/wordpress -l targets.txt
```

## 自动化流程

GitHub Actions 默认每天北京时间 `11:17` 运行一次，也支持手动触发。每次运行会：

1. 查询 `repo.txt` 中来源的最新提交；没有变化的来源直接跳过。
2. 对发生变化的来源只校验新增或 SHA-256 已变化的 YAML 模板。
3. 将兼容模板分类、去重并更新 `poc/`。
4. 将不兼容模板放入 `incompatible/`。
5. 写入校验清单和统计信息，并自动提交变更。

首次运行或使用 `--clean-output` 时会重新建立完整结果。每次运行结束都会扫描最终 `poc/` 并清理重复内容。增量状态保存在 `metadata/manifest.jsonl` 和 `metadata/sources.json` 中；删除来源或模板时，对应的旧结果也会清理。

Workflow：<https://github.com/AMJIYU/NucleiPocGather/actions/workflows/go-monitor.yml>

## 自动发布可执行文件

推送版本标签后，Release Workflow 会自动测试并编译常见平台：

- Windows amd64 / arm64
- macOS Intel / Apple Silicon（arm64）
- Linux amd64 / arm64

创建并推送版本标签：

```bash
git tag v1.0.0
git push origin v1.0.0
```

随后可在 [Releases](https://github.com/AMJIYU/NucleiPocGather/releases) 下载对应平台的压缩包和 `SHA256SUMS` 校验文件。也可以在 Actions 中手动运行 `Release Go Nuclei POC Monitor` 并填写版本标签。

## 目录说明

- `poc/`: 已通过 Nuclei `-validate` 的模板。
- `incompatible/`: YAML 结构错误或 Nuclei 校验失败的模板。
- `metadata/`: 来源、哈希、状态和统计信息。
- `repo.txt`: 自动监控的 POC 来源列表。
- `cmd/nuclei-poc-monitor/`、`internal/monitor/`: Go 版本监控程序。

## 安全说明

`-validate` 只检查模板语法和 Nuclei 兼容性，不会针对真实目标发起请求。实际扫描前必须确认目标属于明确授权范围，并自行评估模板中的主动探测、OAST、代码协议和写入型请求风险。
