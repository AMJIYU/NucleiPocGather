# Nuclei POC Gather

这是一个纯 Go 版本的 Nuclei POC 收集器。它从 [`repo.txt`](repo.txt) 监控多个 Git 仓库，使用本地 Nuclei 引擎验证模板，并将结果分类保存。

## 目录

- `poc/`: 通过 Nuclei `-validate` 的模板，按漏洞类型和产品分类。
- `incompatible/`: YAML 结构错误或 Nuclei 校验失败的模板，原样保留并按原因隔离。
- `metadata/`: 每次运行的来源、SHA-256、状态和统计信息。
- `cmd/nuclei-poc-monitor/`: Go CLI 入口。
- `internal/monitor/`: Git 同步、解析、验证、分类、去重和输出逻辑。

## 使用

环境要求：Go 1.20+、Git、Nuclei 3.x。

```bash
go run ./cmd/nuclei-poc-monitor --workers 4
```

小规模验证：

```bash
go run ./cmd/nuclei-poc-monitor --limit 20 --workers 2
```

完整说明见 [`GO-MONITOR.md`](GO-MONITOR.md)。GitHub Actions 会每日自动运行 Go 收集器。

仅在明确授权的资产范围内使用 Nuclei 执行实际扫描。收集器的 `-validate` 阶段只校验模板，不会向目标发起扫描请求。
