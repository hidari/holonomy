// Android Emulator の信頼ストアにCA証明書をインストール/削除するモジュール。
// adb コマンドを使用する。
//
// Android 7+ ではシステム証明書ストアにインストールしないと
// アプリ内 WebView で信頼されないため、/system/etc/security/cacerts/ に配置する。

use std::{path::Path, process::Command, thread, time::Duration};

use anyhow::{Context, Result, bail};

use super::subject_hash;
use crate::logging;

/// システム証明書ストアのパス
const SYSTEM_CACERTS_DIR: &str = "/system/etc/security/cacerts";

/// Android Emulatorデバイス情報
#[derive(Debug)]
struct EmulatorDevice {
    serial: String,
}

/// adb/デバイスの準備を行い、ハッシュファイル名とデバイス一覧を返す。
fn prepare(ca_cert_path: &Path) -> Result<(String, Vec<EmulatorDevice>)> {
    check_adb()?;
    let hash = subject_hash::compute_from_pem_file(ca_cert_path)?;
    let hash_filename = format!("{}.0", hash);

    let devices = list_emulator_devices()?;
    if devices.is_empty() {
        bail!("接続中のAndroid Emulatorが見つかりません (hint: Emulator を起動してください)");
    }
    Ok((hash_filename, devices))
}

/// 接続中のAndroid Emulator全デバイスにCA証明書をインストールする。
pub fn install_trust(ca_cert_path: &Path) -> Result<()> {
    let (hash_filename, devices) = prepare(ca_cert_path)?;
    for device in &devices {
        install_to_device(device, ca_cert_path, &hash_filename)?;
    }
    Ok(())
}

/// 接続中のAndroid Emulator全デバイスからCA証明書を削除する。
pub fn cleanup_trust(ca_cert_path: &Path) -> Result<()> {
    let (hash_filename, devices) = prepare(ca_cert_path)?;
    for device in &devices {
        remove_from_device(device, &hash_filename)?;
    }
    Ok(())
}

/// adb が利用可能か確認する。
fn check_adb() -> Result<()> {
    let output = Command::new("adb").arg("version").output().context(
        "adb の実行に失敗 (hint: Android SDK Platform-Tools をインストールしてください)",
    )?;

    if !output.status.success() {
        bail!("adb が利用できません (hint: Android SDK Platform-Tools をインストールしてください)");
    }
    Ok(())
}

/// 接続中のエミュレータ一覧を取得する。
/// `adb devices` の出力をパースし、"emulator-" プレフィックスでフィルタする。
fn list_emulator_devices() -> Result<Vec<EmulatorDevice>> {
    let output = Command::new("adb")
        .arg("devices")
        .output()
        .context("adb devices の実行に失敗")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("adb devices が失敗: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_adb_device_list(&stdout))
}

/// adb devices の出力をパースしてエミュレータデバイスのリストを返す。
/// 物理デバイス（"emulator-" 以外のシリアル）は除外する。
fn parse_adb_device_list(output: &str) -> Vec<EmulatorDevice> {
    output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == "device" && parts[0].starts_with("emulator-") {
                Some(EmulatorDevice {
                    serial: parts[0].to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// 指定デバイスにCA証明書をインストールする。
/// adb root → adb remount → adb push → adb reboot の順で実行する。
fn install_to_device(
    device: &EmulatorDevice,
    ca_cert_path: &Path,
    hash_filename: &str,
) -> Result<()> {
    adb_root(device)?;
    // root 切り替え後に adb が再接続されるまで待機
    thread::sleep(Duration::from_secs(2));
    adb_remount(device)?;
    push_cert(device, ca_cert_path, hash_filename)?;
    set_cert_permissions(device, hash_filename)?;
    adb_reboot(device)?;

    logging::info(
        "TRUST",
        &format!(
            "Android Emulator trust installed serial={} cert={}",
            device.serial, hash_filename
        ),
    );
    Ok(())
}

/// 指定デバイスからCA証明書を削除する。
fn remove_from_device(device: &EmulatorDevice, hash_filename: &str) -> Result<()> {
    adb_root(device)?;
    thread::sleep(Duration::from_secs(2));
    adb_remount(device)?;
    remove_cert(device, hash_filename)?;
    adb_reboot(device)?;

    logging::info(
        "TRUST",
        &format!(
            "Android Emulator trust removed serial={} cert={}",
            device.serial, hash_filename
        ),
    );
    Ok(())
}

/// 指定デバイスに対して adb コマンドを実行し、成功を確認する共通ヘルパー。
/// 失敗時は error_msg を含むエラーを返す。
fn run_adb(
    device: &EmulatorDevice,
    args: &[&str],
    error_msg: &str,
) -> Result<std::process::Output> {
    let output = Command::new("adb")
        .args(["-s", &device.serial])
        .args(args)
        .output()
        .with_context(|| format!("{}: serial={}", error_msg, device.serial))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{}: serial={}: {}", error_msg, device.serial, stderr.trim());
    }
    Ok(output)
}

/// adb root モードに切り替える。
fn adb_root(device: &EmulatorDevice) -> Result<()> {
    let output = Command::new("adb")
        .args(["-s", &device.serial, "root"])
        .output()
        .with_context(|| format!("adb root の実行に失敗: serial={}", device.serial))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Google Play イメージでは adbd cannot run as root と表示される
    if combined.contains("cannot run as root") || combined.contains("not allowed") {
        bail!(
            "adb root に失敗: serial={} (hint: Google Play 搭載イメージでは root が使用できません。\
             非 Google Play のシステムイメージを -writable-system オプション付きで起動してください)",
            device.serial
        );
    }

    if !output.status.success() {
        bail!(
            "adb root に失敗: serial={}: {}",
            device.serial,
            combined.trim()
        );
    }

    logging::debug(
        "TRUST",
        &format!("adb root completed serial={}", device.serial),
    );
    Ok(())
}

/// システムパーティションを書き込み可能にリマウントする。
fn adb_remount(device: &EmulatorDevice) -> Result<()> {
    run_adb(
        device,
        &["remount"],
        "adb remount に失敗 (hint: Emulator を -writable-system オプション付きで起動してください)",
    )?;
    logging::debug(
        "TRUST",
        &format!("adb remount completed serial={}", device.serial),
    );
    Ok(())
}

/// CA証明書をシステム信頼ストアにプッシュする。
fn push_cert(device: &EmulatorDevice, ca_cert_path: &Path, hash_filename: &str) -> Result<()> {
    let dest = format!("{}/{}", SYSTEM_CACERTS_DIR, hash_filename);
    let ca_cert_str = ca_cert_path.to_str().context("証明書パスが不正なUTF-8")?;
    run_adb(
        device,
        &["push", ca_cert_str, &dest],
        "CA証明書のプッシュに失敗",
    )?;
    logging::debug(
        "TRUST",
        &format!("adb push completed serial={} dest={}", device.serial, dest),
    );
    Ok(())
}

/// プッシュした証明書のパーミッションを設定する。
fn set_cert_permissions(device: &EmulatorDevice, hash_filename: &str) -> Result<()> {
    let cert_path = format!("{}/{}", SYSTEM_CACERTS_DIR, hash_filename);
    run_adb(
        device,
        &["shell", "chmod", "644", &cert_path],
        "証明書のパーミッション設定に失敗",
    )?;
    Ok(())
}

/// CA証明書をシステム信頼ストアから削除する。
fn remove_cert(device: &EmulatorDevice, hash_filename: &str) -> Result<()> {
    let cert_path = format!("{}/{}", SYSTEM_CACERTS_DIR, hash_filename);
    run_adb(
        device,
        &["shell", "rm", "-f", &cert_path],
        "証明書の削除に失敗",
    )?;
    logging::debug(
        "TRUST",
        &format!("cert removed serial={} path={}", device.serial, cert_path),
    );
    Ok(())
}

/// エミュレータを再起動する。
fn adb_reboot(device: &EmulatorDevice) -> Result<()> {
    run_adb(device, &["reboot"], "adb reboot に失敗")?;
    logging::info(
        "TRUST",
        &format!("Android Emulator rebooting serial={}", device.serial),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_emulator_devices() {
        let output = "List of devices attached\nemulator-5554\tdevice\n1234abcd\tdevice\n";
        let devices = parse_adb_device_list(output);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].serial, "emulator-5554");
    }

    #[test]
    fn parse_multiple_emulators() {
        let output = "List of devices attached\nemulator-5554\tdevice\nemulator-5556\tdevice\n";
        let devices = parse_adb_device_list(output);
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].serial, "emulator-5554");
        assert_eq!(devices[1].serial, "emulator-5556");
    }

    #[test]
    fn parse_empty_device_list() {
        let output = "List of devices attached\n\n";
        let devices = parse_adb_device_list(output);
        assert!(devices.is_empty());
    }

    #[test]
    fn parse_excludes_physical_devices() {
        let output = "List of devices attached\n1234abcd\tdevice\nABCD5678\tdevice\n";
        let devices = parse_adb_device_list(output);
        assert!(devices.is_empty());
    }

    #[test]
    fn parse_excludes_offline_emulator() {
        let output = "List of devices attached\nemulator-5554\toffline\n";
        let devices = parse_adb_device_list(output);
        assert!(devices.is_empty());
    }

    #[test]
    fn parse_mixed_devices_and_states() {
        let output = "List of devices attached\nemulator-5554\tdevice\nemulator-5556\toffline\n1234abcd\tdevice\nemulator-5558\tdevice\n";
        let devices = parse_adb_device_list(output);
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].serial, "emulator-5554");
        assert_eq!(devices[1].serial, "emulator-5558");
    }
}
