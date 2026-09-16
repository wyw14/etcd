# 验收材料归档 — precheck 529（管理员权限变更的有效访问区间预览）

本目录是本次验收使用的测试函数与日志原件，随本分支发布到用户 fork，便于按交付提交复核。
交付分支与其提交未被改动：本分支的父提交就是该题的交付提交。

- task_id：etcd-io--etcd-pc-57395beb9564
- 交付提交：70e700a97d8db7b94b6e1908524ea2991fa9290f
- 完整 Session：3313242430506617:3cb230fd6fd6e13aaa133d8184580ba3_6aa9563eda143c3bd08d0020.6aa95640da143c3bd08d0023.6aa9563eda143c3bd08d0021:TraeCode CN.3.3.100.no_sid.no_ppe.T(2026/9/15 22:29:20)
- 基线：e9e56564d6f13af87747cdb785bc1832791090b4

## 测试函数（tests/，逐字复制）

文件名前缀标出了它们原本所属的包；放回仓库时的目标路径见下表。

| 归档文件名 | 放回后的路径 |
|---|---|
| 529__server__auth__zzv529_acceptance_test.go | server/auth/zzv529_acceptance_test.go |
| 529-zzvadv529_test.go | server/auth/zzvadv529_test.go |

运行方式（在 server 模块或 etcdutl 模块目录下）：

```
go test -count=1 -run '<测试函数名>' -v
```

## 日志与结论（logs/）

| 文件 |
|---|
| logs/529-independent.log |
| logs/529-module-regression.log |
| logs/529-adversarial.log |

| conclusion.txt | 现场结论画面使用的文本（产物截图即由此文本真实渲染后截屏） |

## 证据关系

- 各测试函数名与逐条判定的对应关系见 `acceptance-result.json` 与 `conclusion.txt`；
- 530 的 `logs/530-attach-panic-stack.txt` 是第 4 条判为未通过的崩溃栈证据，
  `logs/530-baseline-comparison.log` 记录了回归失败项在未改动基线上的对照结果。
