# Contributing to meow-rs

感谢你考虑为 meow-rs 做出贡献！本文档提供了参与项目开发的指南。

## 目录

- [开发环境设置](#开发环境设置)
- [分支策略](#分支策略)
- [PR 提交流程](#pr-提交流程)
- [代码规范](#代码规范)
- [测试要求](#测试要求)
- [提交消息规范](#提交消息规范)

---

## 开发环境设置

### 前置要求

- Rust 1.89+ (通过 `rustup` 安装)
- Git
- (可选) GitHub CLI (`gh`) 用于 PR 管理

### 克隆仓库

```bash
git clone https://github.com/madeye/meow-rs.git
cd meow-rs
```

### 构建与测试

```bash
# 构建
cargo build --release

# 运行单元测试
cargo test --lib

# 运行集成测试
cargo test --test rules_test
cargo test --test trojan_integration

# 完整回归检查（提交前必须通过）
./scripts/regression-check.sh  # 见下文
```

---

## 分支策略

meow-rs 采用 **Trunk-Based Development (主干开发)** 模式：

### 核心原则

1. **所有 PR 直接提交到 `main` 分支**
2. `main` 分支始终保持可发布状态
3. 通过强 CI 门禁保证代码质量
4. 避免长期存在的开发分支
5. 有依赖关系的 PR **串行合并**（前者进 main，后者 rebase）

### 日常开发流程

```bash
# 1. 从最新 main 创建功能分支
git checkout main
git pull origin main
git checkout -b feature/my-feature

# 2. 进行开发
# ... 编写代码 ...

# 3. 本地验证（见"测试要求"章节）
./scripts/regression-check.sh

# 4. 提交并推送
git add .
git commit -m "feat: add my feature"
git push origin feature/my-feature

# 5. 创建 PR 到 main
gh pr create --base main --title "feat: add my feature"

# 6. CI 通过后合并（使用 squash merge）
gh pr merge --squash
```

### 多个有依赖关系的 PR：串行合并

这是处理互相依赖 PR 的**标准做法**，不需要集成分支。

```bash
# 假设有 3 个 PR 有依赖关系：#101 → #102 → #103

# 1. 合并第一个
gh pr merge 101 --squash

# 2. 第二个 PR rebase 到最新 main
git checkout feature/pr-102
git fetch origin && git rebase origin/main
./scripts/regression-check.sh  # rebase 后必须重跑测试
git push --force-with-lease
gh pr merge 102 --squash

# 3. 第三个 PR 重复相同步骤
git checkout feature/pr-103
git fetch origin && git rebase origin/main
./scripts/regression-check.sh
git push --force-with-lease
gh pr merge 103 --squash
```

**为什么串行优于集成分支**:
- 每次只解决一对分支的冲突，而不是让多个 PR 的冲突在最后爆发
- 每一步都有独立的 CI 验证，出问题能立刻定位
- 回滚粒度是单个 PR（`git revert` 一个 squash 提交）
- 后续 PR 的作者在 rebase 时主动适配已合并的代码

### 参考资料

详细分支策略研究见 [`pr-management-research.md`](./pr-management-research.md)，包括 Rust 官方的 rollup 机制说明。

---

## PR 提交流程

### PR 大小指南

- **理想**: ≤500 行变更，单一功能
- **可接受**: ≤1000 行，功能内聚
- **需拆分**: >1000 行，考虑拆分为多个 PR

### PR 标题规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 风格：

```
<type>(<scope>): <description>

类型 (type):
  feat:     新功能
  fix:      Bug 修复
  refactor: 代码重构（不改变行为）
  perf:     性能优化
  test:     测试相关
  docs:     文档更新
  chore:    构建/工具链变更

作用域 (scope, 可选):
  dns, proxy, tunnel, config, api, listener, etc.

示例:
  feat(dns): add DNS-over-HTTPS support
  fix(proxy): correct Trojan handshake timeout
  refactor(tunnel): extract connection pool logic
  perf(relay): reduce allocations in TCP relay path
```

### PR 描述模板

```markdown
## 概述
简要说明此 PR 的目的（1-2 句话）。

## 变更内容
- 添加了 X 功能
- 修复了 Y 问题
- 重构了 Z 模块

## 测试
- [ ] 通过完整回归 bar (`./scripts/regression-check.sh`)
- [ ] 添加了新的单元测试（如适用）
- [ ] 添加了集成测试（如适用）
- [ ] 手动测试场景：...

## 性能影响
- [ ] 无性能影响
- [ ] 已通过基准测试验证（附结果）
- [ ] 影响类型大小（附 `-Zprint-type-sizes` 输出，见 ADR-0011）

## 破坏性变更
- [ ] 无破坏性变更
- [ ] 包含破坏性变更（详细说明）

## 相关 Issue
Closes #123
```

---

## 代码规范

### Lint 检查

工作区级别的 Clippy lint 配置在根 `Cargo.toml` 中（参见 [ADR-0010](./adr/0010-m1-hygiene-and-gates.md)）。

**强制通过**的检查：

```bash
# 格式化检查
cargo fmt --all -- --check

# 三路 Clippy 检查（必须全部通过）
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings

# 文档构建
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

### 代码风格

- 使用 `cargo fmt` 格式化代码
- 避免 `clone()` 在热路径（参见 [ADR-0008](./adr/0008-zero-alloc-invariants.md)）
- 优先使用 `Arc::clone(&x)` 而非 `x.clone()`（明确 refcount 操作）
- 错误处理使用 `anyhow` (应用层) 或 `thiserror` (库层)

### 关键类型大小约束

如果你的 PR 修改了以下类型，**必须**在提交消息中附上 `-Zprint-type-sizes` 的输出（参见 [ADR-0011](./adr/0011-m2-footprint-targets.md)）：

- `Metadata` (`crates/meow-common/src/metadata.rs`) — M2 baseline: 272 B
- `ConnectionInfo` (`crates/meow-tunnel/src/statistics.rs`) — M2 target: 120 B
- `UdpSession` (`crates/meow-tunnel/src/udp.rs`) — M2 target: 40 B
- `CacheEntry` / `ReverseEntry` (`crates/meow-dns/src/cache.rs`) — M2 target: 72 B

**检查命令**：

```bash
cargo +nightly rustc -p meow-common -- -Zprint-type-sizes | grep Metadata
```

---

## 测试要求

### 回归 Bar

**每次提交前必须通过以下检查**（建议创建 `scripts/regression-check.sh`）：

```bash
#!/bin/bash
set -e

echo "==> 格式化检查"
cargo fmt --all -- --check

echo "==> Clippy 三路检查"
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings

echo "==> 文档构建"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

echo "==> 单元测试 + 集成测试"
cargo test --lib --bin meow \
  --test common_test --test dns_cache_test --test config_test \
  --test statistics_test --test rules_test --test api_test \
  --test config_persistence_test --test systemd_config_test \
  --test trojan_integration --test vless_config_test --test vless_integration \
  --test v2ray_plugin_integration --test pre_resolve_test \
  --test tls_test --test boring_tls_test --test ws_test \
  --test crate_invariants_test

echo "✅ 所有检查通过！"
```

### 测试覆盖要求

- **新功能**: 必须添加单元测试
- **Bug 修复**: 必须添加回归测试
- **重构**: 确保现有测试通过

### 集成测试

某些集成测试需要外部依赖：

```bash
# Shadowsocks 集成测试（需要 ssserver）
cargo install shadowsocks-rust --features "stream-cipher aead-cipher-2022"
cargo test --test shadowsocks_integration

# Snell 集成测试（需要 Docker）
cargo test -p meow-proxy --features snell --test snell_server_docker_integration

# TProxy 测试（需要 Docker）
bash tests/test_tproxy_docker.sh
```

这些测试在 CI 中运行，本地开发**可选**。

---

## 提交消息规范

### 格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

### 示例

```
feat(dns): add concurrent A/AAAA queries

Implement per-address-family query strategy to reduce DNS resolution
latency. The resolver now sends A and AAAA queries concurrently and
returns the first successful response.

- Add `query_concurrent()` method to DnsClient
- Update tests to cover IPv4/IPv6 fallback scenarios
- Performance: 50ms → 25ms median latency (happy eyeballs benchmark)

Closes #463
```

### 最佳实践

- **主题行** (subject): ≤72 字符，动词开头，不要句号
- **正文** (body): 解释**为什么**而非**是什么**（代码已经说明了"是什么"）
- **引用 Issue**: 使用 `Closes #123` 或 `Fixes #456`
- **破坏性变更**: 在 footer 中添加 `BREAKING CHANGE: ...`

---

## 常见问题

### Q: 我的 PR 与最新 main 冲突了怎么办？

```bash
git checkout feature/my-feature
git fetch origin
git rebase origin/main
# 解决冲突
git push --force-with-lease
```

### Q: 如何在 PR 中请求评审？

```bash
# 创建 PR 时指定评审者
gh pr create --reviewer @username

# 或在 PR 页面使用 GitHub Web UI
```

### Q: CI 失败了怎么办？

1. 查看 CI 日志定位失败原因
2. 本地复现问题：`./scripts/regression-check.sh`
3. 修复后推送新提交（无需 force push）

### Q: 如何跟踪性能影响？

```bash
# 运行单个基准测试
cargo run -p meow-bench --release -- --only throughput

# 完整套件（含 Go mihomo 对比、footprint 与 reload legs）：
DURATION=30 bash bench.sh

# 对比基线（见 docs/benchmarks/）
```

`bench.sh` 按顺序跑 W1–W4 对比、idle/steady footprint、config-reload
负载。可用 `--only` 单独运行某条 leg（`throughput`、`latency`、
`connrate`、`dns`、`memleak`、`reload`、`idle`、`steady`、`proxied`）。
`proxied` leg 需要 sing-box 作为 VLESS 服务端：`SINGBOX_BINARY`（或
`SINGBOX_BIN`）指向二进制即可自动启用；未安装时该 leg 跳过。
`DURATION` 控制持续型 leg 的时长（默认 10s，CI 用 30s）。

---

## 行为准则

- 尊重所有贡献者
- 建设性地提供反馈
- 专注于代码质量和项目目标
- 遵循开源社区最佳实践

---

## 获取帮助

- **问题讨论**: 在 GitHub Issues 中提问
- **技术细节**: 查阅 `docs/adr/` 中的架构决策记录
- **实现指南**: 参考 `CLAUDE.md` 和 `AGENTS.md`

---

**最后更新**: 2026-08-27  
**维护者**: @meow-rs/core
