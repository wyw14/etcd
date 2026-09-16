# 验收材料归档 — precheck 528（离线比较两份 etcd 快照的业务键变化）

本目录是本次验收使用的测试函数与日志原件，随本分支发布到用户 fork，便于按交付提交复核。
交付分支与其提交未被改动：本分支的父提交就是该题的交付提交。

- task_id：etcd-io--etcd-pc-4d6387a27c48
- 交付提交：19f95397a53f2da34490a2cfcc766c371f6c5414
- 完整 Session：3313242430506617:626c568fc1e9116ac272d431088c29b1_6aa955aada143c3bd08cff9d.6aa955acda143c3bd08cffa0.6aa955aada143c3bd08cff9e:TraeCode CN.3.3.100.no_sid.no_ppe.T(2026/9/15 22:26:52)
- 基线：e9e56564d6f13af87747cdb785bc1832791090b4

## 测试函数（tests/，逐字复制）

文件名前缀标出了它们原本所属的包；放回仓库时的目标路径见下表。

| 归档文件名 | 放回后的路径 |
|---|---|
| 528__etcdutl__snapshot__zzv528_acceptance_test.go | etcdutl/snapshot/zzv528_acceptance_test.go |
| 528__etcdutl__etcdutl__zzv528_cli_acceptance_test.go | etcdutl/etcdutl/zzv528_cli_acceptance_test.go |
| 528__etcdutl__etcdutl__zzv528_cli_peak_windows_test.go | etcdutl/etcdutl/zzv528_cli_peak_windows_test.go |
| 528-zzvadv528_test.go | etcdutl/snapshot/zzvadv528_test.go |

运行方式（在 server 模块或 etcdutl 模块目录下）：

```
go test -count=1 -run '<测试函数名>' -v
```

## 日志与结论（logs/）

| 文件 |
|---|
| logs/528-independent.log |
| logs/528-module-regression.log |
| logs/528-snapshot-zzv.log |
| logs/528-zzv-all.log |
| logs/528-zzv-cli.log |
| logs/528-zzv-cli-e2e.log |
| logs/528-adversarial.log |

| conclusion.txt | 现场结论画面使用的文本（产物截图即由此文本真实渲染后截屏） |

## 证据关系

- 各测试函数名与逐条判定的对应关系见 `acceptance-result.json` 与 `conclusion.txt`；
- 530 的 `logs/530-attach-panic-stack.txt` 是第 4 条判为未通过的崩溃栈证据，
  `logs/530-baseline-comparison.log` 记录了回归失败项在未改动基线上的对照结果。
