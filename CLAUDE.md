# CLAUDE.md

このファイルは、Claude Code (claude.ai/code) がこのリポジトリで作業する際のガイダンスを提供します。

## プロジェクト概要

xdp-ninja は、既存のXDPプログラムの**前後**でパケットをキャプチャするツール。
BPF trampoline (fentry/fexit) で既存プログラムに非侵襲的にアタッチする。
pcapng を stdout に出力し、`tcpdump -n -r -` 等にパイプして使う。

```
NIC Ingress
  ├── fentry (--mode entry)  ← XDP処理前にキャプチャ
  ▼
[既存XDPプログラム]
  ├── fexit  (--mode exit)   ← XDP処理後にキャプチャ (XDPアクション付き)
  ▼
TX / PASS / DROP / ...
```

## ビルド・テスト

```bash
make build                # バイナリビルド
make test                 # ユニットテスト (root不要)
make test-bpf             # BPF verifierロードテスト (root必要, clang必要)
make test-integration     # 統合テスト (root必要, clang/tcpdump必要)
make test-all             # 全テスト
make vet                  # go vet
```

前提: libpcap-dev, clang (テスト用)

## アーキテクチャ

```
cmd/xdp-ninja/main.go           CLI (urfave/cli)
internal/
  program/program.go             eBPFプログラムの動的生成 + アタッチ
  attach/attach.go               XDPプログラムの発見 (netlink / prog ID)
  capture/capture.go             per-CPU perf buffer からのパケット読み取り
  output/output.go               pcapng writer (stdout or file)
test/
  run_tests.sh                   統合テスト (veth + netns)
  setup.sh / cleanup.sh          テスト環境セットアップ
  setup_tailcall.sh / cleanup_tailcall.sh  tail callチェーンテスト
  xdp_pass.c                     ダミーXDPプログラム
  xdp_tailcall.c                 tail callテスト用 (dispatcher → prog_a)
```

### BPFプログラム動的生成 (internal/program)

fentry/fexit プログラムを `cilium/ebpf/asm` で動的に組み立てる。Cソースは使わない。

1. `loadPacketPointers()` — xdp_buff から data/data_end を直接読む (trusted pointer)
2. `runFilter()` — cbpfc 生成 eBPF フィルタを scratch buffer 上で実行 (フィルタ指定時のみ)
3. `captureToPerf()` — `bpf_xdp_output` でパケットを per-CPU perf buffer に送出
4. `link.AttachTracing` でアタッチ

### フィルタパイプライン

tcpdump 式 → `pcap.CompileBPFFilter` (cBPF) → `cbpfc.ToEBPF` (eBPF) → fentry/fexit にインライン埋め込み。
**カーネル内でフィルタ実行**。マッチしたパケットのみ perf に送出。

scratch buffer が必要な理由: verifier が xdp->data を scalar としか認識しないため、
per-CPU array (PTR_TO_MAP_VALUE) にコピーしてからフィルタを実行する。

### パケット出力

`bpf_xdp_output(xdp_buff, perf_map, (cap_len << 32) | BPF_F_CURRENT_CPU, &metadata, 8)`
カーネルが xdp_buff から直接パケットデータをコピー。bpf_probe_read_kernel 不要。

### 既知の制限

- tail call 先プログラムへの fentry/fexit は動作しない (カーネル制限)
  - dispatcher にアタッチすれば tail call 前のパケットは捕捉可能
  - 詳細は TODO.md

## 主要依存ライブラリ

- `cilium/ebpf` — BPFプログラムのロード・perf buffer・link・asm
- `cloudflare/cbpfc` — cBPF→eBPFコンパイラ
- `google/gopacket` — pcapフィルタコンパイル・pcapng書き出し
- `vishvananda/netlink` — XDPプログラムの発見
- `urfave/cli/v3` — CLI フレームワーク
