# arpens

**ARP + ENS — AI agents, reachable by name.**

`arpens` is a fork of [arpc](https://github.com/offgrid-ing/arp) that adds ENS and DNS-based agent identity discovery to the [Agent Relay Protocol (ARP)](https://arp.offgrid.ing).

Instead of exchanging raw public keys, agents can now be reached by their ENS name or DNS domain.

```bash
# Before arpens
arpc contact add alice 7Xq9MzK4nP2rBvYwQjE8sH3dFgLtUoZcXiAmWe5Nb6p

# With arpens
arpc contact add alice alice.eth
```

---

## How it works

ENS names and DNS domains resolve to ARP public keys via a simple record lookup:

**ENS:** Set an `agent.arp` text record on your ENS name.

```
alice.eth  →  agent.arp  →  7Xq9MzK4nP2rBvYwQjE8sH3dFgLtUoZcXiAmWe5Nb6p
```

**DNS:** Add a `_arpa` TXT record to your domain.

```
_arpa.alice.example.com  →  TXT  →  7Xq9MzK4nP2rBvYwQjE8sH3dFgLtUoZcXiAmWe5Nb6p
```

Both formats support an optional relay URL override. Both are fully backwards compatible with standard arpc.

---

## New commands

### Resolve a name

```bash
arpc resolve alice.eth
# Output:
#   ◈ Resolved  alice.eth
#   Pubkey      7Xq9MzK4nP2rBvYwQjE8sH3dFgLtUoZcXiAmWe5Nb6p

arpc resolve alice.example.com
```

### Add a contact by name

```bash
# ENS name (auto-resolves)
arpc contact add alice alice.eth

# DNS domain (auto-resolves)
arpc contact add bob bob.example.com

# Raw pubkey still works as before
arpc contact add carol 7Xq9MzK4nP2rBvYwQjE8sH3dFgLtUoZcXiAmWe5Nb6p
```

---

## Bind your agent to an ENS name

**Step 1.** Get your ARP public key:
```bash
arpc identity
```

**Step 2.** Go to [app.ens.domains](https://app.ens.domains) and open your name.

**Step 3.** Under **Text Records**, add:

| Key | Value |
|-----|-------|
| `agent.arp` | your public key from Step 1 |

**Step 4.** Save and confirm the transaction.

Your agent is now reachable by name.

---

## Bind your agent to a DNS domain

Add a TXT record to your DNS:

| Name | Type | Value |
|------|------|-------|
| `_arpa` | TXT | your ARP public key |

Example for `alice.example.com`:
```
_arpa.alice.example.com.  IN  TXT  "7Xq9MzK4nP2rBvYwQjE8sH3dFgLtUoZcXiAmWe5Nb6p"
```

---

## Installation

### Download binary (recommended)

Download the latest binary from the [Releases](https://github.com/DuanWangye9527/arpens/releases) page.

```bash
# Linux x86_64
curl -L https://github.com/DuanWangye9527/arpens/releases/latest/download/arpc-linux-x86_64 -o arpc
chmod +x arpc
sudo mv arpc /usr/local/bin/
```

### Build from source

```bash
git clone https://github.com/DuanWangye9527/arpens.git
cd arpens
cargo build --release -p arpc
```

Requires Rust 1.75+.

---

## Configuration

arpens is fully compatible with arpc's existing config file (`~/.config/arpc/config.toml`).

Optional ENS settings:

```toml
[discovery]
# Custom Ethereum RPC endpoint (optional, uses Cloudflare public RPC by default)
eth_rpc = "https://mainnet.infura.io/v3/YOUR_KEY"

# Cache TTL in seconds
ens_cache_ttl_s = 300
dns_cache_ttl_s = 60
```

---

## Identity standard

The ENS text record format used by arpens follows the **AEIS-1** standard.

**Minimal format** (pubkey only):
```
agent.arp = "7Xq9MzK4nP2rBvYwQjE8sH3dFgLtUoZcXiAmWe5Nb6p"
```

**Full format** (with relay override):
```json
{
  "version": "1",
  "pubkey": "7Xq9MzK4nP2rBvYwQjE8sH3dFgLtUoZcXiAmWe5Nb6p",
  "relay": "wss://your-relay.example.com"
}
```

Full standard: [github.com/DuanWangye9527/aeis](https://github.com/DuanWangye9527/aeis)

---

## Relationship to ARP

arpens is a fork of the official [arpc](https://github.com/offgrid-ing/arp) client (MIT license). All core ARP functionality is unchanged. ENS/DNS resolution is additive — raw public keys continue to work exactly as before.

ARP protocol: [arp.offgrid.ing](https://arp.offgrid.ing)

---

## License

MIT — same as the upstream ARP project.
