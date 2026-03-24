# ハンドテスト手順

## 前提条件

- Linux kernel 5.8+ (BTF有効: `/sys/kernel/btf/vmlinux` が存在すること)
- root権限 or `CAP_BPF` + `CAP_NET_ADMIN`
- 必要パッケージ: `clang`, `libpcap-dev`, `tcpdump`, `bpftool`

## 1. ビルド

```bash
cd xdp-ninja
make build
```

## 2. テスト環境セットアップ

veth pair + ダミーXDPプログラムを作成:

```bash
sudo test/setup.sh
```

確認:
```bash
# veth0 にXDPプログラムがアタッチされていること
sudo bpftool prog show name xdp_pass

# IP が付いていること
ip addr show veth0  # 10.0.0.1/24
sudo ip netns exec xdptest ip addr show veth1  # 10.0.0.2/24

# ping が通ること (veth1 は netns xdptest 内)
sudo ip netns exec xdptest ping -c 1 10.0.0.1
```

## 3. テスト実行

### 3.1 基本: フィルタなしキャプチャ

ターミナル1:
```bash
sudo ./xdp-ninja -i veth0 | tcpdump -n -r -
```

ターミナル2:
```bash
sudo ip netns exec xdptest ping -c 3 10.0.0.1
```

期待: ターミナル1に ICMP パケット等が表示される。Ctrl+C で停止。

### 3.2 フィルタ付きキャプチャ

ターミナル1:
```bash
sudo ./xdp-ninja -i veth0 "icmp" | tcpdump -n -r -
```

ターミナル2:
```bash
sudo ip netns exec xdptest ping -c 3 10.0.0.1
```

期待: ICMP echo request のみ表示。ARP や IPv6 NDP は表示されない。

### 3.3 フィルタ不一致の確認

ターミナル1:
```bash
sudo ./xdp-ninja -i veth0 "tcp port 80" | tcpdump -n -r -
```

ターミナル2:
```bash
sudo ip netns exec xdptest ping -c 5 10.0.0.1
```

期待: 何も表示されない（ICMP/ARP は tcp port 80 にマッチしない）。Ctrl+C で停止すると `0 packets captured`。

### 3.4 fexit (XDP処理後) キャプチャ

ターミナル1:
```bash
sudo ./xdp-ninja -i veth0 --mode exit | tcpdump -n -r -
```

ターミナル2:
```bash
sudo ip netns exec xdptest ping -c 3 10.0.0.1
```

期待: パケットが表示される。（ダミーXDPプログラムは XDP_PASS を返すので、パケットは通過する）

### 3.5 pcapファイル出力

```bash
sudo ./xdp-ninja -i veth0 -w /tmp/test.pcap -c 5
```

別ターミナル:
```bash
sudo ip netns exec xdptest ping -c 5 10.0.0.1
```

5パケットキャプチャ後に自動停止。確認:
```bash
tcpdump -n -r /tmp/test.pcap
```

### 3.6 パケット数制限

```bash
sudo ./xdp-ninja -i veth0 -c 3 | tcpdump -n -r -
```

別ターミナルから ping を送ると、3パケット後に自動停止。

### 3.7 verbose モード

```bash
sudo ./xdp-ninja -i veth0 -v "arp" | tcpdump -n -r -
```

stderr にプログラム情報とフィルタ式が表示される:
```
found XDP program "xdp_pass" (id=XXX)
filter: arp
capturing (prog "xdp_pass" id=XXX on veth0, mode=entry)...
```

### 3.8 プログラムID指定 (-p)

まずプログラムIDを調べる:
```bash
sudo bpftool prog show name xdp_pass
# 出力例: 123: xdp  name xdp_pass ...
```

ターミナル1:
```bash
sudo ./xdp-ninja -p 123 | tcpdump -n -r -
```

ターミナル2:
```bash
sudo ip netns exec xdptest ping -c 3 10.0.0.1
```

期待: `-i veth0` と同じようにパケットが表示される。multi-prog (libxdp) 環境では個別プログラムを狙い撃ちできる。

### 3.9 entry + exit 同時キャプチャ (2プロセス)

ターミナル1 (entry):
```bash
sudo ./xdp-ninja -i veth0 | tcpdump -n -r -
```

ターミナル2 (exit):
```bash
sudo ./xdp-ninja -i veth0 --mode exit | tcpdump -n -r -
```

ターミナル3:
```bash
sudo ip netns exec xdptest ping -c 3 10.0.0.1
```

期待: 両方のターミナルにパケットが表示される。

## 4. クリーンアップ

```bash
sudo test/cleanup.sh
```

## トラブルシューティング

### `no XDP program attached to veth0`
→ `sudo test/setup.sh` を実行してダミーXDPプログラムをアタッチしてください。

### `retrieve BTF ID: not supported`
→ ダミーXDPプログラムにBTFがない。`test/setup.sh` は `-g` 付きでコンパイルするので、再実行してください。

### `permission denied` (BPFロード時)
→ `sudo` で実行してください。または `CAP_BPF` + `CAP_NET_ADMIN` を付与。

### tcpdump に何も表示されない
→ stderr を確認: `sudo ./xdp-ninja -i veth0 -v 2>/tmp/err.txt | tcpdump -n -r -` してから `cat /tmp/err.txt`

### `lost N samples`
→ perf buffer が溢れている。パケットレートが高い場合に発生。キャプチャ対象を絞るフィルタを使うか、将来的にバッファサイズオプションの追加を検討。
