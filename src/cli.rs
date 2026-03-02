use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// holonomy - local DNS + TLS reverse proxy for development
#[derive(Parser, Debug)]
#[command(version, about)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Configuration file path
    #[arg(default_value = "config.toml")]
    pub config: PathBuf,
}

impl Cli {
    /// サブコマンドに関わらず、サーバー起動用の config パスを返す
    pub fn server_config(&self) -> &PathBuf {
        match &self.command {
            Some(Commands::Run { config }) => config,
            _ => &self.config,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the DNS + TLS reverse proxy server
    Run {
        /// Configuration file path
        #[arg(default_value = "config.toml")]
        config: PathBuf,
    },

    /// Remove CA certificates from the OS trust store
    #[command(name = "cleanup-ca")]
    CleanupCa {
        /// Also delete local CA/cert files
        #[arg(long)]
        remove_files: bool,

        /// CA directory path for cleanup (overrides default)
        #[arg(long)]
        ca_dir: Option<PathBuf>,

        /// Certificate directory path for cleanup (overrides default)
        #[arg(long)]
        cert_dir: Option<PathBuf>,
    },

    /// Install/remove CA certificates in iOS Simulator or Android Emulator
    #[command(name = "trust-simulator")]
    TrustSimulator {
        /// Target iOS Simulator
        #[arg(long)]
        ios: bool,

        /// Target Android Emulator
        #[arg(long)]
        android: bool,

        /// Target both iOS and Android
        #[arg(long, conflicts_with_all = ["ios", "android"])]
        all: bool,

        /// Remove CA certificates instead of installing
        #[arg(long)]
        cleanup: bool,

        /// Configuration file path
        #[arg(default_value = "config.toml")]
        config: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    // --- サーバー起動（後方互換） ---

    #[test]
    fn cli_default_config() {
        let cli = Cli::try_parse_from(["holonomy"]).unwrap();
        assert_eq!(cli.config, PathBuf::from("config.toml"));
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_custom_config() {
        let cli = Cli::try_parse_from(["holonomy", "custom.toml"]).unwrap();
        assert_eq!(cli.config, PathBuf::from("custom.toml"));
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_run_subcommand() {
        let cli = Cli::try_parse_from(["holonomy", "run", "custom.toml"]).unwrap();
        match &cli.command {
            Some(Commands::Run { config }) => {
                assert_eq!(config, &PathBuf::from("custom.toml"));
            }
            _ => panic!("expected Run subcommand"),
        }
    }

    #[test]
    fn cli_run_default_config() {
        let cli = Cli::try_parse_from(["holonomy", "run"]).unwrap();
        match &cli.command {
            Some(Commands::Run { config }) => {
                assert_eq!(config, &PathBuf::from("config.toml"));
            }
            _ => panic!("expected Run subcommand"),
        }
    }

    #[test]
    fn server_config_without_subcommand() {
        let cli = Cli::try_parse_from(["holonomy", "custom.toml"]).unwrap();
        assert_eq!(cli.server_config(), &PathBuf::from("custom.toml"));
    }

    #[test]
    fn server_config_with_run_subcommand() {
        let cli = Cli::try_parse_from(["holonomy", "run", "custom.toml"]).unwrap();
        assert_eq!(cli.server_config(), &PathBuf::from("custom.toml"));
    }

    // --- cleanup-ca サブコマンド ---

    #[test]
    fn cli_cleanup_ca() {
        let cli = Cli::try_parse_from(["holonomy", "cleanup-ca"]).unwrap();
        match &cli.command {
            Some(Commands::CleanupCa {
                remove_files,
                ca_dir,
                cert_dir,
            }) => {
                assert!(!remove_files);
                assert!(ca_dir.is_none());
                assert!(cert_dir.is_none());
            }
            _ => panic!("expected CleanupCa subcommand"),
        }
    }

    #[test]
    fn cli_cleanup_ca_with_remove_files() {
        let cli = Cli::try_parse_from(["holonomy", "cleanup-ca", "--remove-files"]).unwrap();
        match &cli.command {
            Some(Commands::CleanupCa { remove_files, .. }) => {
                assert!(remove_files);
            }
            _ => panic!("expected CleanupCa subcommand"),
        }
    }

    #[test]
    fn cli_cleanup_ca_with_ca_dir() {
        let cli = Cli::try_parse_from(["holonomy", "cleanup-ca", "--ca-dir", "/tmp/ca"]).unwrap();
        match &cli.command {
            Some(Commands::CleanupCa { ca_dir, .. }) => {
                assert_eq!(ca_dir, &Some(PathBuf::from("/tmp/ca")));
            }
            _ => panic!("expected CleanupCa subcommand"),
        }
    }

    #[test]
    fn cli_cleanup_ca_with_cert_dir() {
        let cli =
            Cli::try_parse_from(["holonomy", "cleanup-ca", "--cert-dir", "/tmp/certs"]).unwrap();
        match &cli.command {
            Some(Commands::CleanupCa { cert_dir, .. }) => {
                assert_eq!(cert_dir, &Some(PathBuf::from("/tmp/certs")));
            }
            _ => panic!("expected CleanupCa subcommand"),
        }
    }

    // --- trust-simulator サブコマンド ---

    #[test]
    fn cli_trust_simulator_ios() {
        let cli = Cli::try_parse_from(["holonomy", "trust-simulator", "--ios", "c.toml"]).unwrap();
        match &cli.command {
            Some(Commands::TrustSimulator {
                ios,
                android,
                all,
                cleanup,
                config,
            }) => {
                assert!(ios);
                assert!(!android);
                assert!(!all);
                assert!(!cleanup);
                assert_eq!(config, &PathBuf::from("c.toml"));
            }
            _ => panic!("expected TrustSimulator subcommand"),
        }
    }

    #[test]
    fn cli_trust_simulator_android() {
        let cli =
            Cli::try_parse_from(["holonomy", "trust-simulator", "--android", "c.toml"]).unwrap();
        match &cli.command {
            Some(Commands::TrustSimulator {
                ios, android, all, ..
            }) => {
                assert!(!ios);
                assert!(android);
                assert!(!all);
            }
            _ => panic!("expected TrustSimulator subcommand"),
        }
    }

    #[test]
    fn cli_trust_simulator_all() {
        let cli = Cli::try_parse_from(["holonomy", "trust-simulator", "--all", "c.toml"]).unwrap();
        match &cli.command {
            Some(Commands::TrustSimulator {
                ios, android, all, ..
            }) => {
                assert!(!ios);
                assert!(!android);
                assert!(all);
            }
            _ => panic!("expected TrustSimulator subcommand"),
        }
    }

    #[test]
    fn cli_trust_simulator_ios_and_android() {
        let cli = Cli::try_parse_from([
            "holonomy",
            "trust-simulator",
            "--ios",
            "--android",
            "c.toml",
        ])
        .unwrap();
        match &cli.command {
            Some(Commands::TrustSimulator {
                ios, android, all, ..
            }) => {
                assert!(ios);
                assert!(android);
                assert!(!all);
            }
            _ => panic!("expected TrustSimulator subcommand"),
        }
    }

    #[test]
    fn cli_trust_simulator_cleanup_ios() {
        let cli = Cli::try_parse_from([
            "holonomy",
            "trust-simulator",
            "--cleanup",
            "--ios",
            "c.toml",
        ])
        .unwrap();
        match &cli.command {
            Some(Commands::TrustSimulator {
                ios,
                cleanup,
                config,
                ..
            }) => {
                assert!(ios);
                assert!(cleanup);
                assert_eq!(config, &PathBuf::from("c.toml"));
            }
            _ => panic!("expected TrustSimulator subcommand"),
        }
    }

    #[test]
    fn cli_trust_simulator_all_conflicts_with_ios() {
        let err = Cli::try_parse_from(["holonomy", "trust-simulator", "--all", "--ios", "c.toml"])
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn cli_trust_simulator_all_conflicts_with_android() {
        let err = Cli::try_parse_from([
            "holonomy",
            "trust-simulator",
            "--all",
            "--android",
            "c.toml",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn cli_trust_simulator_default_config() {
        let cli = Cli::try_parse_from(["holonomy", "trust-simulator", "--ios"]).unwrap();
        match &cli.command {
            Some(Commands::TrustSimulator { config, .. }) => {
                assert_eq!(config, &PathBuf::from("config.toml"));
            }
            _ => panic!("expected TrustSimulator subcommand"),
        }
    }
}
