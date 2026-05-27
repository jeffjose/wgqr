use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use qrcode::render::unicode;
use qrcode::{EcLevel, QrCode};
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(
    name = "wgqr",
    version,
    about = "Generate WireGuard peer configs with QR codes",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(flatten)]
    generate: GenerateArgs,

    #[command(subcommand)]
    command: Option<SubCmd>,
}

#[derive(Subcommand)]
enum SubCmd {
    /// Print a fresh PrivateKey / PublicKey / PresharedKey triple
    Keys,
}

#[derive(Args)]
struct GenerateArgs {
    /// Peer address, e.g. 10.0.0.2 or 10.0.0.2/24 (required)
    #[arg(short, long)]
    address: Option<String>,

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

    /// QR code size (xs|s|m|l|xl). xs/s lower error correction; l/xl scale modules up.
    #[arg(long, default_value_t = QrSize::M, value_enum)]
    qr_size: QrSize,
}

#[derive(Copy, Clone, ValueEnum)]
enum QrSize {
    Xs,
    S,
    M,
    L,
    Xl,
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

fn read_template_file(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => sudo_read(path),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn sudo_read(path: &Path) -> Result<String> {
    eprintln!(
        "permission denied on {}; re-reading via `sudo cat`",
        path.display()
    );
    let child = Command::new("sudo")
        .arg("cat")
        .arg(path)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(anyhow!(
                "sudo not found and {} is not readable",
                path.display()
            ));
        }
        Err(e) => return Err(e).context("spawning sudo cat"),
    };
    let output = child.wait_with_output().context("waiting for sudo cat")?;
    if !output.status.success() {
        return Err(anyhow!(
            "sudo cat {} failed ({})",
            path.display(),
            output.status
        ));
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("contents of {} are not valid UTF-8", path.display()))
}

fn parse_template(path: &Path) -> Result<Template> {
    let content = read_template_file(path)?;
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

fn run_keys() {
    let (private_key, public_key) = generate_keypair();
    let psk = generate_psk();
    println!("PrivateKey = {private_key}");
    println!("PublicKey = {public_key}");
    println!("PresharedKey = {psk}");
}

fn run_generate(args: GenerateArgs) -> Result<()> {
    let template = match &args.template {
        Some(path) => parse_template(path)?,
        None => Template::default(),
    };

    let address = args
        .address
        .as_deref()
        .ok_or_else(|| anyhow!("--address is required"))?;
    let (ip, addr_prefix) = parse_address(address)?;
    let prefix = addr_prefix.or(template.prefix).unwrap_or(24);
    let dns = args
        .dns
        .or(template.dns)
        .unwrap_or_else(|| default_dns(ip).to_string());
    let listen_port = args.listen_port.or(template.listen_port).unwrap_or(51820);
    let endpoint = args.endpoint.or(template.endpoint).ok_or_else(|| {
        anyhow!("--endpoint is required (or pass --template with an Endpoint line)")
    })?;
    let server_pubkey = args.server_pubkey.or(template.server_pubkey).ok_or_else(|| {
        anyhow!("--server-pubkey is required (or pass --template with a [Peer] PublicKey line)")
    })?;
    let allowed_ips = args
        .allowed_ips
        .or(template.allowed_ips)
        .unwrap_or_else(|| "0.0.0.0/0".to_string());
    let keepalive = args.keepalive.or(template.keepalive).unwrap_or(25);

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

    if !args.no_file {
        let path = match args.output {
            Some(p) => p,
            None => {
                fs::create_dir_all(&args.output_dir)
                    .with_context(|| format!("creating {}", args.output_dir.display()))?;
                args.output_dir.join(format!("wg-{ip}.conf"))
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

    if !args.no_qr {
        let ec = match args.qr_size {
            QrSize::Xs | QrSize::S => EcLevel::L,
            QrSize::M | QrSize::L | QrSize::Xl => EcLevel::M,
        };
        let code = QrCode::with_error_correction_level(config.as_bytes(), ec)
            .context("building QR code")?;
        let mut renderer = code.render::<unicode::Dense1x2>();
        renderer
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark);
        match args.qr_size {
            QrSize::Xs => {
                renderer.quiet_zone(false);
            }
            QrSize::S | QrSize::M => {}
            QrSize::L => {
                renderer.module_dimensions(2, 2);
            }
            QrSize::Xl => {
                renderer.module_dimensions(3, 3);
            }
        }
        let rendered = renderer.build();
        println!("{rendered}");
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(SubCmd::Keys) => {
            run_keys();
            Ok(())
        }
        None => run_generate(cli.generate),
    }
}
