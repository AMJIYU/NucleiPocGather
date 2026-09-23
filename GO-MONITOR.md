# Nuclei POC Monitor (Go)

这是 `NucleiPocGather` 的 Go 实现。它监控 `repo.txt` 中的 Git 仓库，收集 YAML 模板，并通过本地 Nuclei 引擎进行兼容性验证。

## 行为

1. 浅克隆或更新 `repo.txt` 中的仓库。
2. 对 YAML 做 Nuclei 基础结构检查，再调用 `nuclei -validate -t <file> -silent`。
3. 兼容模板按漏洞类型、产品和协议分类到 `poc/<category>/`。
4. YAML 解析失败、结构不完整或 Nuclei 校验失败的模板原样保存到 `incompatible/<reason>/`，不会被删除。
5. 生成 `metadata/manifest.jsonl` 和 `metadata/summary.json`，记录来源、哈希、状态、失败原因和输出路径。

分类是基于 `id`、文件路径、名称和 tags 的可解释规则；一个模板可以出现在多个类别，但同一类别内相同 SHA-256 内容只保存一次。

## 本地使用

需要 Go 1.20+、Git 和 Nuclei 3.x：

```bash
go run ./cmd/nuclei-poc-monitor \
  --sources repo.txt \
  --nuclei nuclei \
  --workers 4
```

先做小规模验证：

```bash
go run ./cmd/nuclei-poc-monitor --limit 20 --workers 2
```

常用参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--sources` | `repo.txt` | Git 仓库 URL 列表 |
| `--workspace` | `.cache/nuclei-poc-sources` | 仓库缓存目录 |
| `--compatible-dir` | `poc` | 兼容模板输出目录 |
| `--incompatible-dir` | `incompatible` | 不兼容模板输出目录 |
| `--metadata-dir` | `metadata` | 清单和统计目录 |
| `--nuclei` | `nuclei` | Nuclei 可执行文件 |
| `--workers` | `4` | 并发校验数 |
| `--limit` | `0` | 每次最多处理数量，0 为不限 |
| `--timeout` | `2m` | 单个命令超时 |

仓库只保留 Go 版本的收集器和 POC 数据。默认运行会刷新 `poc/`；执行前请确认 `repo.txt` 中的来源可用。

## 安全边界

`-validate` 只解析和校验模板，不会针对真实目标执行请求。模板的实际扫描仍需在明确授权的资产范围内使用 Nuclei 完成。模板中的主动探测、OAST、代码协议和写入型请求不会因为被归类为 compatible 就获得额外信任。
