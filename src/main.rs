mod ca;
mod config;
mod dns;
mod logging;
mod platform;
mod proxy;
mod server;
mod tls;

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use config::AppConfig;
use rustls::crypto::ring::default_provider;

/// holonomy - local DNS + TLS reverse proxy for development
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Configuration file path
    #[arg(default_value = "config.toml")]
    config: PathBuf,

    /// Remove CA certificates from the OS trust store and exit
    #[arg(long)]
    cleanup_ca: bool,

    /// Also delete local CA/cert files (requires --cleanup-ca)
    #[arg(long, requires = "cleanup_ca")]
    remove_files: bool,

    /// CA directory path for cleanup (overrides default)
    #[arg(long, requires = "cleanup_ca")]
    ca_dir: Option<PathBuf>,

    /// Certificate directory path for cleanup (overrides default)
    #[arg(long, requires = "cleanup_ca")]
    cert_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 requires an explicit process-level crypto provider.
    // We install ring here once at startup to avoid runtime panics later.
    let _ = default_provider().install_default();

    let cli = Cli::parse();

    if cli.cleanup_ca {
        return run_cleanup(&cli);
    }

    let config = AppConfig::from_file(&cli.config)?;

    logging::init(config.log_level);

    println!("holonomy started");
    println!("  config   : {}", cli.config.display());
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

fn run_cleanup(cli: &Cli) -> Result<()> {
    logging::init(logging::LogLevel::Info);

    let cn_names = [ca::ROOT_CA_COMMON_NAME, ca::LEGACY_CA_COMMON_NAME];

    println!("holonomy: removing CA certificates from trust store");
    platform::uninstall_ca_cert(&cn_names)?;
    println!("holonomy: trust store cleanup complete");

    if cli.remove_files {
        let ca_dir = cli.ca_dir.clone().unwrap_or_else(config::default_ca_dir);
        let cert_dir = cli
            .cert_dir
            .clone()
            .unwrap_or_else(config::default_cert_dir);

        remove_dir_if_exists(&ca_dir)?;
        remove_dir_if_exists(&cert_dir)?;

        if let Some(legacy) = config::legacy_base_dir() {
            remove_dir_if_exists(&legacy)?;
        }

        println!("holonomy: local files cleanup complete");
    }

    Ok(())
}

fn remove_dir_if_exists(dir: &PathBuf) -> Result<()> {
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
    use clap::error::ErrorKind;

    #[test]
    fn cli_default_config() {
        let cli = Cli::try_parse_from(["holonomy"]).unwrap();
        assert_eq!(cli.config, PathBuf::from("config.toml"));
        assert!(!cli.cleanup_ca);
        assert!(!cli.remove_files);
    }

    #[test]
    fn cli_custom_config() {
        let cli = Cli::try_parse_from(["holonomy", "custom.toml"]).unwrap();
        assert_eq!(cli.config, PathBuf::from("custom.toml"));
    }

    #[test]
    fn cli_cleanup_ca_flag() {
        let cli = Cli::try_parse_from(["holonomy", "--cleanup-ca"]).unwrap();
        assert!(cli.cleanup_ca);
        assert!(!cli.remove_files);
    }

    #[test]
    fn cli_cleanup_ca_with_remove_files() {
        let cli = Cli::try_parse_from(["holonomy", "--cleanup-ca", "--remove-files"]).unwrap();
        assert!(cli.cleanup_ca);
        assert!(cli.remove_files);
    }

    #[test]
    fn cli_remove_files_requires_cleanup_ca() {
        let err = Cli::try_parse_from(["holonomy", "--remove-files"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn cli_cleanup_ca_with_ca_dir() {
        let cli = Cli::try_parse_from(["holonomy", "--cleanup-ca", "--ca-dir", "/tmp/ca"]).unwrap();
        assert!(cli.cleanup_ca);
        assert_eq!(cli.ca_dir, Some(PathBuf::from("/tmp/ca")));
    }

    #[test]
    fn cli_ca_dir_requires_cleanup_ca() {
        let err = Cli::try_parse_from(["holonomy", "--ca-dir", "/tmp/ca"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn cli_cert_dir_requires_cleanup_ca() {
        let err = Cli::try_parse_from(["holonomy", "--cert-dir", "/tmp/certs"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

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
