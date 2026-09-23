# Nuclei POC Gather

[![Go Nuclei POC Monitor](https://github.com/AMJIYU/NucleiPocGather/actions/workflows/go-monitor.yml/badge.svg)](https://github.com/AMJIYU/NucleiPocGather/actions/workflows/go-monitor.yml)

一个持续自动维护的 Nuclei POC 仓库。项目使用 Go 编写监控程序，由 GitHub Actions 每天自动收集、分类和校验全网公开的 Nuclei POC。

## 项目特点

- **每天自动运行**：GitHub Actions 每天自动同步多个公开 POC 来源并更新仓库。
- **自动校验兼容性**：每个 YAML POC 都会使用 Nuclei 的 `-validate` 进行校验，确保 `poc/` 中的模板可以被 Nuclei 加载。
- **无需本地下载和校验**：校验工作在 GitHub Actions 中完成，使用者不需要在本地下载来源仓库、安装 Go 或重新验证 POC。
- **下载即可使用**：本地只需要获取 `poc/` 目录，就可以直接交给 Nuclei 执行授权范围内的扫描。
- **自动分类和去重**：POC 按漏洞类型、产品和协议分类，相同内容在同一分类中只保留一份。
- **不兼容模板单独隔离**：解析失败或 Nuclei 校验失败的模板会原样放入 `incompatible/`，不会混入可用 POC。
- **持续可追溯**：`metadata/` 保存来源、SHA-256、校验状态、失败原因和统计信息。

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

1. 同步 `repo.txt` 中的公开 POC 来源。
2. 使用 Nuclei 官方引擎验证所有发现的 YAML 模板。
3. 将兼容模板分类、去重并更新 `poc/`。
4. 将不兼容模板放入 `incompatible/`。
5. 写入校验清单和统计信息，并自动提交变更。

Workflow：<https://github.com/AMJIYU/NucleiPocGather/actions/workflows/go-monitor.yml>

## 目录说明

- `poc/`: 已通过 Nuclei `-validate` 的模板。
- `incompatible/`: YAML 结构错误或 Nuclei 校验失败的模板。
- `metadata/`: 来源、哈希、状态和统计信息。
- `repo.txt`: 自动监控的 POC 来源列表。
- `cmd/nuclei-poc-monitor/`、`internal/monitor/`: Go 版本监控程序。

## 安全说明

`-validate` 只检查模板语法和 Nuclei 兼容性，不会针对真实目标发起请求。实际扫描前必须确认目标属于明确授权范围，并自行评估模板中的主动探测、OAST、代码协议和写入型请求风险。
