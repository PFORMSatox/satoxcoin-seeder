use std::fs;
use std::process;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use tracing_subscriber::EnvFilter;

use dns_server::server::{self, Addr, DnsOpt};
use seeder_core::config::Config;
use seeder_core::db::{new_shared_db, SharedDb};
use seeder_core::explorer::read_block_height;
use seeder_core::net::{lookup_host, Service};
use seeder_core::p2p::handshake::test_node;
use seeder_core::{app_state, init_app_state};

#[derive(Parser, Debug)]
#[command(name = "seeder", version = "0.1.0")]
struct Cli {
    #[arg(short = 'h', long, help = "Hostname of the DNS seed")]
    host: Option<String>,
    #[arg(short = 'n', long, help = "Hostname of the nameserver")]
    ns: Option<String>,
    #[arg(short = 'm', long, help = "E-Mail address for SOA records")]
    mbox: Option<String>,
    #[arg(short = 't', long, default_value = "96", help = "Number of crawlers")]
    threads: usize,
    #[arg(short = 'd', long, default_value = "4", help = "DNS server threads")]
    dns_threads: usize,
    #[arg(short = 'p', long, default_value = "53", help = "DNS UDP port")]
    port: u16,
    #[arg(short = 'a', long, default_value = "::", help = "Address to listen on")]
    address: String,
    #[arg(short = 'o', long, help = "Tor proxy IP:Port")]
    onion: Option<String>,
    #[arg(short = 'i', long, help = "IPv4 SOCKS5 proxy IP:Port")]
    proxy_ipv4: Option<String>,
    #[arg(short = 'k', long, help = "IPv6 SOCKS5 proxy IP:Port")]
    proxy_ipv6: Option<String>,
    #[arg(short = 'f', long, default_value = "a", help = "Force IP version (a=all, 4=IPv4, 6=IPv6)")]
    force_ip: String,
    #[arg(long, help = "Wipe list of banned nodes")]
    wipe_ban: bool,
    #[arg(long, help = "Wipe list of ignored nodes")]
    wipe_ignore: bool,
    #[arg(long, help = "Dump all nodes")]
    dump_all: bool,
    #[arg(long, default_value = "settings.conf", help = "Config file path")]
    config: String,
    #[arg(long, help = "Disable DNS server")]
    no_dns: bool,
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
            process::exit(1);
        }
    };

    init_app_state(&cfg);
    let state = app_state();

    tracing::info!("{} v{}", state.app_name, "0.1.0");

    let db = new_shared_db(state.wallet_port, state.min_peer_proto_version);

    {
        let mut guard = db.write().await;
        if let Ok(data) = fs::read("seeder.dat") {
            match postcard::from_bytes::<seeder_core::db::AddrDb>(&data) {
                Ok(saved) => {
                    guard.restore_from(&saved);
                    let count = guard.id_to_info_len();
                    tracing::info!("Loaded seeder.dat: {count} addresses");
                }
                Err(e) => {
                    tracing::warn!("Failed to deserialize seeder.dat: {e}, starting fresh");
                }
            }
        }
        if cli.wipe_ban {
            guard.banned.clear();
        }
        if cli.wipe_ignore {
            guard.reset_ignores();
        }
    }

    // Block height reader
    let explorer_url = cfg.explorer_url.clone();
    let explorer_url2 = cfg.second_explorer_url.clone();
    let requery = cfg.explorer_requery_seconds;
    let block_count = cfg.block_count;
    tokio::spawn(async move {
        block_reader_task(explorer_url, explorer_url2, requery, block_count).await;
    });

    // Seeder task: resolve seed hosts periodically
    let seeds = cfg.seeds.clone();
    let wallet_port = state.wallet_port;
    let db_seeder = db.clone();
    tokio::spawn(async move {
        loop {
            for seed in &seeds {
                if seed.is_empty() {
                    continue;
                }
                match lookup_host(seed) {
                    Ok(ips) => {
                        let mut guard = db_seeder.write().await;
                        for ip in ips {
                            guard.add_service(Service::new(ip, wallet_port), true);
                        }
                    }
                    Err(e) => tracing::warn!("seed lookup {seed}: {e}"),
                }
            }
            tokio::time::sleep(Duration::from_secs(1800)).await;
        }
    });

    // Crawler tasks
    for _ in 0..cli.threads {
        let db_crawler = db.clone();
        tokio::spawn(async move {
            crawler_task(db_crawler).await;
        });
    }

    // DNS server — uses a snapshot cache to avoid blocking in DNS callback
    let dns_ips: Arc<std::sync::RwLock<Vec<seeder_core::net::NetAddr>>> =
        Arc::new(std::sync::RwLock::new(Vec::new()));

    // Task: periodically snapshot good IPs into the DNS cache
    let db_dns_snapshot = db.clone();
    let dns_ips_clone = dns_ips.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let ips = {
                let guard = db_dns_snapshot.read().await;
                guard.snapshot_good_ips(1000)
            };
            if let Ok(mut cache) = dns_ips_clone.write() {
                *cache = ips;
            }
        }
    });

    if !cli.no_dns && cli.ns.is_some() && cli.host.is_some() {
        let host = cli.host.clone().unwrap();
        let ns = cli.ns.clone().unwrap();
        let mbox = cli.mbox.unwrap_or_default().replace('@', ".");
        let address = cli.address.clone();
        let port = cli.port;

        let dns_cache = dns_ips.clone();
        let cb: Arc<dyn Fn(&str) -> Vec<Addr> + Send + Sync> = Arc::new(move |_name| {
            let cache = dns_cache.read().unwrap();
            cache
                .iter()
                .filter_map(|ip| {
                    if let Some(v4) = ip.to_ipv4_addr() {
                        Some(Addr::v4(v4.octets()))
                    } else if let Some(v6) = ip.to_ipv6_addr() {
                        Some(Addr::v6(v6.octets()))
                    } else {
                        None
                    }
                })
                .collect()
        });

        let socket_addr = if address.contains(':') {
            format!("[{address}]:{port}").parse().unwrap()
        } else {
            format!("{address}:{port}").parse().unwrap()
        };

        let opt = Arc::new(DnsOpt {
            host,
            ns,
            mbox,
            addr: socket_addr,
            datattl: 3600,
            nsttl: 40000,
            cb,
        });

        for _ in 0..cli.dns_threads {
            let opt_clone = opt.clone();
            tokio::spawn(async move {
                if let Err(e) = server::run(opt_clone).await {
                    tracing::error!("dns server: {e}");
                }
            });
        }
    }

    // Stats task
    let db_stats = db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let stats = db_stats.read().await.get_stats();
            tracing::info!(
                "{}/{} available ({} tried, {} new, {} active), {} banned",
                stats.n_good,
                stats.n_avail,
                stats.n_tracked,
                stats.n_new,
                stats.n_avail - stats.n_tracked - stats.n_new,
                stats.n_banned,
            );
        }
    });

    // Dumper task
    let db_dump = db.clone();
    tokio::spawn(async move {
        let mut count = 0;
        loop {
            let sleep_secs = 100u64 << count.min(5);
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            if count < 5 {
                count += 1;
            }

            let reports = db_dump.read().await.get_all();
            let mut reports = reports;
            reports.sort_by(|a, b| {
                b.uptime[4]
                    .partial_cmp(&a.uptime[4])
                    .unwrap()
                    .then(b.uptime[3].partial_cmp(&a.uptime[3]).unwrap())
                    .then(b.client_version.cmp(&a.client_version))
            });

            if let Ok(mut f) = fs::File::create("dnsseed.dump") {
                use std::io::Write;
                let _ = writeln!(f, "# address                                        good  lastSuccess    %(2h)   %(8h)   %(1d)   %(7d)  %(30d)  blocks      svcs  version");
                for rep in &reports {
                    let _good = if rep.good && rep.blocks > 0 && rep.client_version > 0 && !rep.client_sub_version.is_empty() { 1 } else { 0 };
                    let _ = writeln!(
                        f,
                        "{:47}  {:4}  {:11}  {:6.2} {:6.2} {:6.2} {:6.2} {:6.2}  {:6}  {:08x}  {:5} \"{}\"",
                        rep.service.to_string_ip_port(),
                        _good,
                        rep.last_success,
                        100.0 * rep.uptime[0],
                        100.0 * rep.uptime[1],
                        100.0 * rep.uptime[2],
                        100.0 * rep.uptime[3],
                        100.0 * rep.uptime[4],
                        rep.blocks,
                        rep.services,
                        rep.client_version,
                        rep.client_sub_version,
                    );
                }
            }

            {
                let guard = db_dump.read().await;
                if let Ok(data) = postcard::to_allocvec(&*guard) {
                    let _ = fs::write("seeder.dat.new", &data);
                    let _ = fs::rename("seeder.dat.new", "seeder.dat");
                } else {
                    tracing::warn!("Failed to serialize seeder.dat");
                }
            }
        }
    });

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn block_reader_task(
    url1: Option<String>,
    url2: Option<String>,
    requery_secs: u64,
    default_height: i32,
) {
    let url1 = match url1 {
        Some(u) => u,
        None => return,
    };

    loop {
        let h1 = read_block_height(&url1).await.ok();
        let h2 = match &url2 {
            Some(u) => read_block_height(u).await.ok(),
            None => None,
        };

        let block = h2.or(h1).unwrap_or(default_height);
        tracing::info!("current block: {block}");

        tokio::time::sleep(Duration::from_secs(requery_secs)).await;
    }
}

async fn crawler_task(db: SharedDb) {
    loop {
        let ips = {
            let mut guard = db.write().await;
            guard.get_many(16)
        };

        if ips.is_empty() {
            tokio::time::sleep(Duration::from_millis(5000 + rand::random::<u64>() % 500)).await;
            continue;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut results = Vec::new();
        for res in &ips {
            let get_addr = res.our_last_success + 86400 < now;
            let state = app_state();
            let handshake = test_node(&res.service, state.current_block, get_addr).await;

            let is_good = handshake.ban == 0 && handshake.client_version > 0;
            let in_sync = if state.block_from_explorer {
                handshake.starting_height >= state.current_block - 5
                    && handshake.starting_height <= state.current_block + 5
            } else {
                handshake.starting_height >= state.current_block
            };

            results.push(seeder_core::db::ServiceResult {
                service: res.service,
                services: handshake.services,
                good: is_good,
                ban_time: handshake.ban,
                height: handshake.starting_height,
                client_v: handshake.client_version,
                client_sv: handshake.client_sub_version.clone(),
                our_last_success: 0,
                in_sync,
            });

            if !handshake.addresses.is_empty() {
                let mut guard = db.write().await;
                for addr in &handshake.addresses {
                    guard.add(addr, false);
                }
            }
        }

        {
            let mut guard = db.write().await;
            guard.result_many(&results);
        }
    }
}
