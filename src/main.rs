use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Parser;
use qrcode::QrCode;
use qrcode::render::unicode;
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(
    name = "wgqr",
    version,
    about = "Generate a WireGuard peer config and print its QR code"
)]
struct Cli {
    /// Peer address, e.g. 10.0.0.2 or 10.0.0.2/24
    #[arg(short, long)]
    address: String,

    /// Inherit defaults from an existing peer config (endpoint, server pubkey, DNS, prefix, etc.)
    #[arg(short, long)]
    template: Option<PathBuf>,

    /// Server endpoint, host:port
    #[arg(short, long)]
    endpoint: Option<String>,

    /// Server's WireGuard public key
    #[arg(short = 's', long)]
    server_pubkey: Option<String>,

    /// DNS server (default: first three octets of --address + .1)
    #[arg(long)]
    dns: Option<String>,

    /// Client ListenPort (default: 51820)
    #[arg(long)]
    listen_port: Option<u16>,

    /// AllowedIPs (default: 0.0.0.0/0)
    #[arg(long)]
    allowed_ips: Option<String>,

    /// PersistentKeepalive in seconds (default: 25)
    #[arg(long)]
    keepalive: Option<u32>,

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

#[derive(Default)]
struct Template {
    prefix: Option<u8>,
    dns: Option<String>,
    listen_port: Option<u16>,
    endpoint: Option<String>,
    server_pubkey: Option<String>,
    allowed_ips: Option<String>,
    keepalive: Option<u32>,
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

fn parse_address(input: &str) -> Result<(Ipv4Addr, Option<u8>)> {
    if let Some((ip, prefix)) = input.split_once('/') {
        let ip = Ipv4Addr::from_str(ip).context("invalid IP in --address")?;
        let prefix: u8 = prefix.parse().context("invalid prefix in --address")?;
        Ok((ip, Some(prefix)))
    } else {
        let ip = Ipv4Addr::from_str(input).context("invalid IP in --address")?;
        Ok((ip, None))
    }
}

fn default_dns(ip: Ipv4Addr) -> Ipv4Addr {
    let mut octets = ip.octets();
    octets[3] = 1;
    Ipv4Addr::from(octets)
}

fn parse_template(path: &Path) -> Result<Template> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut t = Template::default();
    let mut section: &str = "";
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = match name.trim().to_ascii_lowercase().as_str() {
                "interface" => "interface",
                "peer" => "peer",
                _ => "",
            };
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.split('#').next().unwrap_or("").trim();
        match (section, key.as_str()) {
            ("interface", "address") => {
                if let Some((_, prefix)) = val.split_once('/') {
                    t.prefix = prefix.trim().parse().ok();
                }
            }
            ("interface", "dns") => t.dns = Some(val.to_string()),
            ("interface", "listenport") => t.listen_port = val.parse().ok(),
            ("peer", "endpoint") => t.endpoint = Some(val.to_string()),
            ("peer", "publickey") => t.server_pubkey = Some(val.to_string()),
            ("peer", "allowedips") => t.allowed_ips = Some(val.to_string()),
            ("peer", "persistentkeepalive") => t.keepalive = val.parse().ok(),
            _ => {}
        }
    }
    Ok(t)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let template = match &cli.template {
        Some(path) => parse_template(path)?,
        None => Template::default(),
    };

    let (ip, addr_prefix) = parse_address(&cli.address)?;
    let prefix = addr_prefix.or(template.prefix).unwrap_or(24);
    let dns = cli
        .dns
        .or(template.dns)
        .unwrap_or_else(|| default_dns(ip).to_string());
    let listen_port = cli.listen_port.or(template.listen_port).unwrap_or(51820);
    let endpoint = cli.endpoint.or(template.endpoint).ok_or_else(|| {
        anyhow!("--endpoint is required (or pass --template with an Endpoint line)")
    })?;
    let server_pubkey = cli.server_pubkey.or(template.server_pubkey).ok_or_else(|| {
        anyhow!("--server-pubkey is required (or pass --template with a [Peer] PublicKey line)")
    })?;
    let allowed_ips = cli
        .allowed_ips
        .or(template.allowed_ips)
        .unwrap_or_else(|| "0.0.0.0/0".to_string());
    let keepalive = cli.keepalive.or(template.keepalive).unwrap_or(25);

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
