mod ca;
mod cli;
mod config;
mod dns;
mod logging;
mod platform;
mod proxy;
mod server;
mod tls;
mod trust_simulator;

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use config::AppConfig;
use rustls::crypto::ring::default_provider;

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 requires an explicit process-level crypto provider.
    // We install ring here once at startup to avoid runtime panics later.
    let _ = default_provider().install_default();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::CleanupCa {
            remove_files,
            ca_dir,
            cert_dir,
        }) => run_cleanup(remove_files, ca_dir, cert_dir),

        Some(Commands::TrustSimulator {
            ios,
            android,
            all,
            cleanup,
            config,
        }) => run_trust_simulator(ios, android, all, cleanup, &config),

        // サブコマンドなし or `run` → サーバー起動
        None | Some(Commands::Run { .. }) => {
            let config_path = cli.server_config();
            let config = AppConfig::from_file(config_path)?;

            logging::init(config.log_level);

            println!("holonomy started");
            println!("  config   : {}", config_path.display());
            println!("  dns      : {}", config.dns.listen);
            println!("  records  : {}", config.joined_domains());
            println!("  upstream : {}", config.dns.joined_upstream());
            println!("  proxies  : {}", config.joined_proxies());
            println!(
                "  tls      : {}",
                if config.tls.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("  log_level: {}", config.log_level.as_str());
            println!("press Ctrl+C to stop");

            server::run(config).await
        }
    }
}

fn run_trust_simulator(
    ios: bool,
    android: bool,
    all: bool,
    cleanup: bool,
    config_path: &Path,
) -> Result<()> {
    logging::init(logging::LogLevel::Info);

    let config = AppConfig::from_file(config_path)?;
    let ca_cert_path = config.tls.ca_dir.join("rootCA.pem");
    let targets = trust_simulator::resolve_targets(ios, android, all)?;

    let action = if cleanup { "cleanup" } else { "install" };
    println!("holonomy trust-simulator: {} starting", action);

    trust_simulator::run(&targets, cleanup, &ca_cert_path)?;

    println!("holonomy trust-simulator: {} complete", action);
    Ok(())
}

fn run_cleanup(
    remove_files: bool,
    ca_dir: Option<PathBuf>,
    cert_dir: Option<PathBuf>,
) -> Result<()> {
    logging::init(logging::LogLevel::Info);

    let cn_names = [ca::ROOT_CA_COMMON_NAME, ca::LEGACY_CA_COMMON_NAME];

    println!("holonomy: removing CA certificates from trust store");
    platform::uninstall_ca_cert(&cn_names)?;
    println!("holonomy: trust store cleanup complete");

    if remove_files {
        let ca_dir = ca_dir.unwrap_or_else(config::default_ca_dir);
        let cert_dir = cert_dir.unwrap_or_else(config::default_cert_dir);

        remove_dir_if_exists(&ca_dir)?;
        remove_dir_if_exists(&cert_dir)?;

        if let Some(legacy) = config::legacy_base_dir() {
            remove_dir_if_exists(&legacy)?;
        }

        println!("holonomy: local files cleanup complete");
    }

    Ok(())
}

fn remove_dir_if_exists(dir: &Path) -> Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir)
            .with_context(|| format!("failed to remove directory: {}", dir.display()))?;
        logging::info("CLEANUP", &format!("removed directory: {}", dir.display()));
    } else {
        logging::info(
            "CLEANUP",
            &format!("directory not found, skipping: {}", dir.display()),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_dir_if_exists_deletes_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep();
        assert!(path.exists());

        remove_dir_if_exists(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn remove_dir_if_exists_skips_nonexistent() {
        let path = PathBuf::from("/tmp/holonomy-test-nonexistent-dir");
        assert!(!path.exists());

        // エラーにならないことを確認
        remove_dir_if_exists(&path).unwrap();
    }
}
