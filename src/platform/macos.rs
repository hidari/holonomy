use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};

use crate::logging;

pub fn install_ca_cert(ca_cert_path: &Path) -> Result<()> {
    // Use System keychain so all local user processes can trust holonomy-issued certs.
    let output = Command::new("security")
        .arg("add-trusted-cert")
        .arg("-d")
        .arg("-r")
        .arg("trustRoot")
        .arg("-k")
        .arg("/Library/Keychains/System.keychain")
        .arg(ca_cert_path)
        .output()
        .context("failed to execute security command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "failed to install CA certificate to trust store: {}",
            stderr
        );
    }

    logging::info("TLS", "trust install target=system status=ok");
    Ok(())
}

pub fn uninstall_ca_cert(cn_names: &[&str]) -> Result<()> {
    for cn in cn_names {
        let output = Command::new("security")
            .arg("delete-certificate")
            .arg("-c")
            .arg(cn)
            .arg("/Library/Keychains/System.keychain")
            .output()
            .context("failed to execute security command")?;

        if output.status.success() {
            logging::info(
                "TLS",
                &format!("trust uninstall target=system cn={} status=ok", cn),
            );
        } else {
            // securityコマンドは証明書が見つからない場合に非ゼロで終了する
            logging::info(
                "TLS",
                &format!("trust uninstall target=system cn={} status=not_found", cn),
            );
        }
    }
    Ok(())
}
