# Satoxcoin Seeder

DNS seed crawler for the Satoxcoin network. Discovers and monitors active Satoxcoin nodes, then serves them via a built-in DNS server. Written in Rust.

This is a port of the [bitcoin-seeder](https://github.com/sipa/bitcoin-seeder) approach, adapted for Satoxcoin parameters (KawPoW, port 60777).

## Features

- **P2P crawler** — connects to discovered nodes, validates protocol version, checks chain height and sync status
- **Exponential-decay scoring** — rates nodes by reliability, not just uptime
- **Embedded DNS server** — serves A/AAAA/SOA/NS records directly (raw UDP, no libunbound dependency)
- **Ban/ignore system** — filters misbehaving or low-version nodes
- **Cloudflare DNS publish** — pushes seed results to Cloudflare DNS as A records (`dnsseed-publish` binary)
- **Live stats** — periodic stats logging via tracing
- **Block height monitoring** — fetches latest block height from explorer API to reject out-of-sync nodes

## Project Structure

```
satoxcoin-seeder/
├── Cargo.toml                       # Workspace root
├── deny.toml                        # cargo-deny configuration
├── settings.toml                    # Network parameters
├── bin/
│   ├── seeder/                      # Main crawler + DNS daemon
│   └── dnsseed-publish/             # Cloudflare DNS publisher
└── crates/
    ├── seeder-core/                 # Core types: config, net, db, serialize, p2p handshake
    ├── dns-server/                  # Raw UDP DNS server (no bind dependency)
    └── seeder-publish/              # Cloudflare API client + dump parser
```

## Build

```bash
cargo build --release
```

Requires Rust 1.75+. No external C libraries needed.

## Usage

### Seeder Daemon

```bash
./target/release/seeder -h <hostname> -n <nameserver> -m <email> --config settings.toml
```

Common flags:

| Flag | Description |
|------|-------------|
| `-h` | Hostname of the DNS seed (e.g. `xnode1.satoverse.io`) |
| `-n` | Nameserver hostname for NS records |
| `-m` | E-mail address for SOA records (e.g. `admin.example.com`) |
| `-t` | Number of crawler threads (default: 96) |
| `-d` | DNS server threads (default: 4) |
| `-p` | DNS UDP port (default: 53) |
| `-a` | Address to listen on (default: `::`) |
| `-f` | Force IP version: `a`=all, `4`=IPv4 only, `6`=IPv6 only (default: `a`) |
| `--config` | Config file path (default: `settings.conf`) |
| `--wipe-ban` | Clear banned node list on start |
| `--wipe-ignore` | Clear ignored node list on start |
| `--dump-all` | Dump all known nodes at shutdown |
| `--no-dns` | Disable the DNS server (crawl only) |

### Cloudflare Publisher

```bash
./target/release/dnsseed-publish --config settings.toml
```

Reads `dnsseed.dump` (produced by the seeder at shutdown) and reconciles it with Cloudflare DNS A records on the configured domain.

Common flags:

| Flag | Description |
|------|-------------|
| `--config` | Config file path (default: `settings.conf`) |
| `--dump` | Seed dump file path (overrides config) |
| `--api-token` | Cloudflare API token (overrides config) |
| `--domain` | Cloudflare domain (overrides config) |
| `--prefix` | Cloudflare prefix (overrides config) |
| `--port` | Wallet port for filtering (overrides config) |
| `--max-seeds` | Maximum number of seeds (default: 25) |

### Configuration

`settings.toml` contains all Satoxcoin network parameters:

```toml
protocol_version = "70028"
init_proto_version = "209"
min_peer_proto_version = "70025"
pchMessageStart_0 = "0x63"    # S
pchMessageStart_1 = "0x56"    # A
pchMessageStart_2 = "0x65"    # T
pchMessageStart_3 = "0x65"    # T
wallet_port = "60777"
explorer_url = "https://xplore.satoverse.io/api/getblockcount"

# Cloudflare DNS publish (optional)
cf_domain = ""                 # Your domain
cf_domain_prefix = ""          # Subdomain for seed records
cf_api_key = ""                # Cloudflare API token
cf_seed_dump = "dnsseed.dump"  # Seed output file
```

## Tests

```bash
cargo test
```

## License

MIT — see [LICENSE](LICENSE).

## Author

Satoxcoin Core Developers
