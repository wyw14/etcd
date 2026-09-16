# 验收材料归档 — precheck 530（带预览凭据的受保护租约撤销）

本目录是本次验收使用的测试函数与日志原件，随本分支发布到用户 fork，便于按交付提交复核。
交付分支与其提交未被改动：本分支的父提交就是该题的交付提交。

- task_id：etcd-io--etcd-pc-91b1d8190733
- 交付提交：1e3fc0d15b55b59f48d877d4bf5066ad2abc0148
- 完整 Session：3313242430506617:be7d3d6450ef8fce8844825ccd3f3af0_6aa9569fda143c3bd08d0031.6aa956a1da143c3bd08d0034.6aa9569fda143c3bd08d0032:TraeCode CN.3.3.100.no_sid.no_ppe.T(2026/9/15 22:30:57)
- 基线：e9e56564d6f13af87747cdb785bc1832791090b4

## 测试函数（tests/，逐字复制）

文件名前缀标出了它们原本所属的包；放回仓库时的目标路径见下表。

| 归档文件名 | 放回后的路径 |
|---|---|
| 530__server__lease__zzv530_acceptance_test.go | server/lease/zzv530_acceptance_test.go |
| 530-zzvadv530_test.go | server/lease/zzvadv530_test.go |
| 530-zzvadv530b_test.go | server/lease/zzvadv530b_test.go |

运行方式（在 server 模块或 etcdutl 模块目录下）：

```
go test -count=1 -run '<测试函数名>' -v
```

## 日志与结论（logs/）

| 文件 |
|---|
| logs/530-independent.log |
| logs/530-independent-race.log |
| logs/530-module-regression.log |
| logs/530-adv2.log |
| logs/530-attach-panic-stack.txt |
| logs/530-baseline-comparison.log |
| logs/530-normalized.diff |
| logs/530-adversarial-superseded.log |
| logs/530-adversarial-superseded-note.txt |
| logs/530-race.log |

| conclusion.txt | 现场结论画面使用的文本（产物截图即由此文本真实渲染后截屏） |

## 证据关系

- 各测试函数名与逐条判定的对应关系见 `acceptance-result.json` 与 `conclusion.txt`；
- 530 的 `logs/530-attach-panic-stack.txt` 是第 4 条判为未通过的崩溃栈证据，
  `logs/530-baseline-comparison.log` 记录了回归失败项在未改动基线上的对照结果。
