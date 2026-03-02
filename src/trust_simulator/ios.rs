// iOS Simulator の信頼ストアにCA証明書をインストール/削除するモジュール。
// xcrun simctl keychain コマンドを使用する。
// macOS 以外のプラットフォームではスキップする。

use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};

use crate::logging;

/// iOS Simulatorデバイス情報
#[derive(Debug)]
struct SimDevice {
    udid: String,
    name: String,
}

/// 起動中のiOS Simulator全デバイスにCA証明書をインストールする。
#[cfg(not(target_os = "macos"))]
pub fn install_trust(_ca_cert_path: &Path) -> Result<()> {
    logging::info(
        "TRUST",
        "iOS Simulator is only available on macOS, skipping",
    );
    Ok(())
}

/// simctl の存在確認と起動中デバイスの取得を行う共通ヘルパー。
#[cfg(target_os = "macos")]
fn booted_devices() -> Result<Vec<SimDevice>> {
    check_simctl()?;
    let devices = list_booted_devices()?;
    if devices.is_empty() {
        bail!("起動中のiOS Simulatorデバイスが見つかりません (hint: Simulator を起動してください)");
    }
    Ok(devices)
}

/// 起動中のiOS Simulator全デバイスにCA証明書をインストールする。
#[cfg(target_os = "macos")]
pub fn install_trust(ca_cert_path: &Path) -> Result<()> {
    let devices = booted_devices()?;
    for device in &devices {
        add_root_cert(device, ca_cert_path)?;
    }
    Ok(())
}

/// 起動中のiOS Simulator全デバイスのキーチェーンをリセットする。
#[cfg(not(target_os = "macos"))]
pub fn cleanup_trust(_ca_cert_path: &Path) -> Result<()> {
    logging::info(
        "TRUST",
        "iOS Simulator is only available on macOS, skipping",
    );
    Ok(())
}

/// 起動中のiOS Simulator全デバイスのキーチェーンをリセットする。
/// 注意: simctl には個別の証明書削除コマンドが存在しないため、
/// キーチェーン全体をリセットする。holonomy 以外で追加した証明書も削除される。
#[cfg(target_os = "macos")]
pub fn cleanup_trust(_ca_cert_path: &Path) -> Result<()> {
    let devices = booted_devices()?;

    println!(
        "warning: iOS Simulator cleanup resets the entire keychain (all custom certificates will be removed)"
    );

    for device in &devices {
        reset_keychain(device)?;
    }
    Ok(())
}

/// xcrun simctl が利用可能か確認する。
#[cfg(target_os = "macos")]
fn check_simctl() -> Result<()> {
    let output = Command::new("xcrun")
        .arg("simctl")
        .arg("help")
        .output()
        .context(
            "xcrun simctl の実行に失敗 (hint: Xcode Command Line Tools をインストールしてください)",
        )?;

    if !output.status.success() {
        bail!(
            "xcrun simctl が利用できません (hint: Xcode Command Line Tools をインストールしてください)"
        );
    }
    Ok(())
}

/// 起動中のiOS Simulatorデバイス一覧を取得する。
/// `xcrun simctl list devices booted -j` のJSON出力をパースする。
#[cfg(target_os = "macos")]
fn list_booted_devices() -> Result<Vec<SimDevice>> {
    let output = Command::new("xcrun")
        .args(["simctl", "list", "devices", "booted", "-j"])
        .output()
        .context("xcrun simctl list の実行に失敗")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("xcrun simctl list が失敗: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_device_list_json(&stdout)
}

/// simctl list devices の JSON 出力をパースしてデバイスリストを返す。
fn parse_device_list_json(json: &str) -> Result<Vec<SimDevice>> {
    let parsed: serde_json::Value =
        serde_json::from_str(json).context("simctl JSONのパースに失敗")?;

    let devices_obj = parsed
        .get("devices")
        .and_then(|v| v.as_object())
        .context("simctl JSONに 'devices' オブジェクトがない")?;

    let mut result = Vec::new();
    for (_runtime, device_list) in devices_obj {
        let Some(devices) = device_list.as_array() else {
            continue;
        };
        for device in devices {
            let state = device.get("state").and_then(|v| v.as_str()).unwrap_or("");
            if state != "Booted" {
                continue;
            }
            let udid = device
                .get("udid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = device
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            if !udid.is_empty() {
                result.push(SimDevice { udid, name });
            } else {
                logging::debug(
                    "TRUST",
                    &format!("iOS Simulator device '{}' has empty udid, skipping", name),
                );
            }
        }
    }
    Ok(result)
}

/// 指定デバイスにCA証明書をインストールする。
#[cfg(target_os = "macos")]
fn add_root_cert(device: &SimDevice, ca_cert_path: &Path) -> Result<()> {
    let output = Command::new("xcrun")
        .args(["simctl", "keychain", &device.udid, "add-root-cert"])
        .arg(ca_cert_path)
        .output()
        .with_context(|| {
            format!(
                "xcrun simctl keychain add-root-cert の実行に失敗: device={}",
                device.name
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "CA証明書のインストールに失敗: device={} udid={}: {}",
            device.name,
            device.udid,
            stderr
        );
    }

    logging::info(
        "TRUST",
        &format!(
            "iOS Simulator trust installed device={} udid={}",
            device.name, device.udid
        ),
    );
    Ok(())
}

/// 指定デバイスのキーチェーンをリセットする。
#[cfg(target_os = "macos")]
fn reset_keychain(device: &SimDevice) -> Result<()> {
    let output = Command::new("xcrun")
        .args(["simctl", "keychain", &device.udid, "reset"])
        .output()
        .with_context(|| {
            format!(
                "xcrun simctl keychain reset の実行に失敗: device={}",
                device.name
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "キーチェーンのリセットに失敗: device={} udid={}: {}",
            device.name,
            device.udid,
            stderr
        );
    }

    logging::info(
        "TRUST",
        &format!(
            "iOS Simulator keychain reset device={} udid={}",
            device.name, device.udid
        ),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_booted_devices() {
        let json = r#"{
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-17-0": [
                    {
                        "name": "iPhone 15",
                        "udid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                        "state": "Booted",
                        "isAvailable": true
                    },
                    {
                        "name": "iPhone 15 Pro",
                        "udid": "11111111-2222-3333-4444-555555555555",
                        "state": "Shutdown",
                        "isAvailable": true
                    }
                ]
            }
        }"#;
        let devices = parse_device_list_json(json).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "iPhone 15");
        assert_eq!(devices[0].udid, "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
    }

    #[test]
    fn parse_no_booted_devices() {
        let json = r#"{ "devices": {} }"#;
        let devices = parse_device_list_json(json).unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn parse_multiple_runtimes() {
        let json = r#"{
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-16-4": [
                    {
                        "name": "iPhone 14",
                        "udid": "AAAA-1111",
                        "state": "Booted",
                        "isAvailable": true
                    }
                ],
                "com.apple.CoreSimulator.SimRuntime.iOS-17-0": [
                    {
                        "name": "iPhone 15",
                        "udid": "BBBB-2222",
                        "state": "Booted",
                        "isAvailable": true
                    }
                ]
            }
        }"#;
        let devices = parse_device_list_json(json).unwrap();
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn parse_all_shutdown() {
        let json = r#"{
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-17-0": [
                    {
                        "name": "iPhone 15",
                        "udid": "AAAA-1111",
                        "state": "Shutdown",
                        "isAvailable": true
                    }
                ]
            }
        }"#;
        let devices = parse_device_list_json(json).unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn parse_invalid_json_fails() {
        let err = parse_device_list_json("not json").unwrap_err();
        assert!(err.to_string().contains("パースに失敗"));
    }

    #[test]
    fn parse_missing_devices_key_fails() {
        let err = parse_device_list_json("{}").unwrap_err();
        assert!(err.to_string().contains("devices"));
    }
}
