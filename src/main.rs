use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Parser;
use qrcode::QrCode;
use qrcode::render::unicode;
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(
    name = "wgqr",
    version,
    about = "Generate a WireGuard peer config and print its QR code"
)]
struct Cli {
    /// Peer address, e.g. 10.0.0.2 or 10.0.0.2/24 (prefix defaults to /24)
    #[arg(short, long)]
    address: String,

    /// Server endpoint, host:port
    #[arg(short, long)]
    endpoint: String,

    /// Server's WireGuard public key
    #[arg(short = 's', long)]
    server_pubkey: String,

    /// DNS server (default: first three octets of --address + .1)
    #[arg(long)]
    dns: Option<String>,

    /// Client ListenPort
    #[arg(long, default_value_t = 51820)]
    listen_port: u16,

    /// AllowedIPs (what gets routed through the tunnel)
    #[arg(long, default_value = "0.0.0.0/0")]
    allowed_ips: String,

    /// PersistentKeepalive in seconds
    #[arg(long, default_value_t = 25)]
    keepalive: u32,

    /// Directory to write the config into (filename: wg-<address>.conf)
    #[arg(long, default_value = "/tmp")]
    output_dir: PathBuf,

    /// Explicit output path (overrides --output-dir and the auto filename)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Don't write the config file
    #[arg(long)]
    no_file: bool,

    /// Don't print the QR code
    #[arg(long)]
    no_qr: bool,
}

fn generate_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(public.to_bytes()),
    )
}

fn generate_psk() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

fn parse_address(input: &str) -> Result<(Ipv4Addr, u8)> {
    if let Some((ip, prefix)) = input.split_once('/') {
        let ip = Ipv4Addr::from_str(ip).context("invalid IP in --address")?;
        let prefix: u8 = prefix.parse().context("invalid prefix in --address")?;
        Ok((ip, prefix))
    } else {
        let ip = Ipv4Addr::from_str(input).context("invalid IP in --address")?;
        Ok((ip, 24))
    }
}

fn default_dns(ip: Ipv4Addr) -> Ipv4Addr {
    let mut octets = ip.octets();
    octets[3] = 1;
    Ipv4Addr::from(octets)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let (ip, prefix) = parse_address(&cli.address)?;
    let dns = cli.dns.unwrap_or_else(|| default_dns(ip).to_string());

    let (private_key, peer_public_key) = generate_keypair();
    let psk = generate_psk();

    let config = format!(
        "[Interface]\n\
         Address = {ip}/{prefix}\n\
         DNS = {dns}\n\
         ListenPort = {listen_port}\n\
         PrivateKey = {private_key}\n\
         \n\
         [Peer]\n\
         AllowedIPs = {allowed_ips}\n\
         Endpoint = {endpoint}\n\
         PresharedKey = {psk}\n\
         PublicKey = {server_pubkey}\n\
         PersistentKeepalive = {keepalive}\n",
        listen_port = cli.listen_port,
        allowed_ips = cli.allowed_ips,
        endpoint = cli.endpoint,
        server_pubkey = cli.server_pubkey,
        keepalive = cli.keepalive,
    );

    if !cli.no_file {
        let path = match cli.output {
            Some(p) => p,
            None => {
                fs::create_dir_all(&cli.output_dir)
                    .with_context(|| format!("creating {}", cli.output_dir.display()))?;
                cli.output_dir.join(format!("wg-{ip}.conf"))
            }
        };
        fs::write(&path, &config).with_context(|| format!("writing {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    }

    eprintln!();
    eprintln!("Add this peer to the server config:");
    eprintln!();
    eprintln!("[Peer]");
    eprintln!("PublicKey = {peer_public_key}");
    eprintln!("PresharedKey = {psk}");
    eprintln!("AllowedIPs = {ip}/32");
    eprintln!();

    if !cli.no_qr {
        let code = QrCode::new(config.as_bytes()).context("building QR code")?;
        let rendered = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build();
        println!("{rendered}");
    }

    Ok(())
}
