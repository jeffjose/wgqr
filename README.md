# wgqr

Generate WireGuard peer configs with QR codes, from the terminal.

## Install

```sh
cargo install --path .
```

Or run directly:

```sh
cargo run --release -- --help
```

## Usage

Minimum: an address, a server endpoint, and the server's public key.

```sh
wgqr --address 10.0.0.2 \
     --endpoint vpn.example.com:51820 \
     --server-pubkey <SERVER_PUBKEY>
```

This writes `/tmp/wg-10.0.0.2.conf`, prints the server-side `[Peer]` block on
stderr (paste it into the server config), and renders a QR code of the client
config on stdout.

### Reuse defaults from an existing peer

`--template` reads an existing peer config and inherits its endpoint, server
public key, DNS, prefix length, AllowedIPs, keepalive, and ListenPort. You only
need to supply the new address:

```sh
wgqr --template /etc/wireguard/wg-10.0.0.2.conf --address 10.0.0.3
```

If the template file isn't readable, `wgqr` falls back to `sudo cat`.

### Just the keys

```sh
wgqr keys
```

Prints a fresh PrivateKey / PublicKey / PresharedKey triple. No files written.

## Flags

| Flag                  | Default        | Notes                                    |
| --------------------- | -------------- | ---------------------------------------- |
| `-a, --address`       | required       | `10.0.0.2` or `10.0.0.2/24`              |
| `-e, --endpoint`      | required\*     | `host:port`                              |
| `-s, --server-pubkey` | required\*     | server's WireGuard PublicKey             |
| `-t, --template`      |                | existing peer config to inherit defaults |
| `--dns`               | `<a.b.c>.1`    | derived from `--address`                 |
| `--listen-port`       | `51820`        |                                          |
| `--allowed-ips`       | `0.0.0.0/0`    |                                          |
| `--keepalive`         | `25`           | PersistentKeepalive seconds              |
| `--output-dir`        | `/tmp`         | written as `wg-<address>.conf`           |
| `-o, --output`        |                | explicit output path                     |
| `--no-file`           |                | don't write the config file              |
| `--no-qr`             |                | don't print the QR code                  |
| `--qr-size`           | `m`            | `xs`, `s`, `m`, `l`, `xl` (see below)    |

\* not required when `--template` provides them.

## QR size

Terminal QR codes are large because the encoded config is long. `--qr-size`
gives five buckets:

- `xs` — lower error correction, no quiet zone. Smallest possible.
- `s`  — lower error correction.
- `m`  — default.
- `l`  — modules scaled 2x.
- `xl` — modules scaled 3x.

Use `xs` for cramped terminals (Quake-style drop-downs, narrow splits) and
`l`/`xl` when scanning from across the room.

## License

MIT
