use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use seeder_core::config::Config;
use seeder_publish::api::CloudflareSeeder;
use seeder_publish::parser::read_seed_dump;
use seeder_publish::reconcile::reconcile;

const MAX_SEEDS: usize = 25;

#[derive(Parser, Debug)]
#[command(name = "dnsseed-publish", version = "0.1.0")]
struct Cli {
    #[arg(
        long,
        default_value = "settings.conf",
        help = "Config file path"
    )]
    config: String,

    #[arg(long, help = "Seed dump file path (overrides config)")]
    dump: Option<PathBuf>,

    #[arg(long, help = "Cloudflare API token (overrides config)")]
    api_token: Option<String>,

    #[arg(long, help = "Cloudflare domain (overrides config)")]
    domain: Option<String>,

    #[arg(long, help = "Cloudflare prefix (overrides config)")]
    prefix: Option<String>,

    #[arg(long, help = "Own IP to always publish (overrides config)")]
    own_ip: Option<String>,

    #[arg(long, help = "Wallet port (overrides config)")]
    port: Option<u16>,

    #[arg(long, default_value = "25", help = "Maximum number of seeds")]
    max_seeds: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let cfg = match Config::from_file(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };

    let api_token = cli
        .api_token
        .or(cfg.cf_api_token)
        .unwrap_or_default();
    let domain = cli
        .domain
        .or(cfg.cf_domain)
        .unwrap_or_default();
    let prefix = cli
        .prefix
        .or(cfg.cf_domain_prefix)
        .unwrap_or_default();
    let dump_path = cli
        .dump
        .map(|p| p.to_string_lossy().to_string())
        .or(cfg.cf_seed_dump)
        .unwrap_or_else(|| "dnsseed.dump".to_string());
    let wallet_port = cli.port.unwrap_or(cfg.wallet_port);
    let max_seeds = cli.max_seeds.min(MAX_SEEDS);
    let own_ip = cli.own_ip.or(cfg.cf_own_ip).unwrap_or_default();

    if api_token.is_empty() || domain.is_empty() || prefix.is_empty() {
        eprintln!("error: cf_api_token, cf_domain, and cf_domain_prefix must be set in config or CLI");
        std::process::exit(1);
    }

    let seed_candidates = match read_seed_dump(&dump_path, wallet_port) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error reading seeds from {dump_path}: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!("Found {} good seeds from dump", seed_candidates.len());

    let cf = CloudflareSeeder::new(api_token, domain, prefix);

    // Get current seeds
    let current_seeds = match cf.get_seeds(false).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error getting current seeds from cloudflare: {e}");
            std::process::exit(1);
        }
    };
    // Also get flagged seeds
    let _current_flags = match cf.get_seeds(true).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error getting flagged seeds: {e}");
            std::process::exit(1);
        }
    };

    let plan = reconcile(
        &current_seeds,
        &seed_candidates,
        if own_ip.is_empty() {
            None
        } else {
            Some(own_ip.as_str())
        },
        max_seeds,
    );

    if !plan.to_delete.is_empty() {
        tracing::info!(
            "Removing {} stale/overflow seeds: {:?}",
            plan.to_delete.len(),
            plan.to_delete
        );
        if let Err(e) = cf.delete_seeds(&plan.to_delete).await {
            tracing::warn!("failed to delete seeds: {e}");
        }
    }

    let to_add = plan.to_add;
    if !to_add.is_empty() {
        tracing::info!("Adding {} new seeds: {:?}", to_add.len(), to_add);

        for seed in &to_add {
            if let Err(e) = cf.set_seed(seed, false, Some(120)).await {
                tracing::warn!("failed to set seed {seed}: {e}");
            }
            if let Err(e) = cf.set_seed(seed, true, Some(120)).await {
                tracing::warn!("failed to set flagged seed {seed}: {e}");
            }
        }
    }

    tracing::info!("Sync complete. {} seeds in cloudflare.", max_seeds);
}
