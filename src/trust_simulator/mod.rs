// iOS Simulator / Android Emulator の信頼ストアに
// CA証明書をインストール/削除するモジュール。

mod android;
mod ios;
pub mod subject_hash;

use std::path::Path;

use anyhow::{Result, bail};

/// ターゲットプラットフォーム
#[derive(Debug, Clone, Copy)]
pub enum Target {
    Ios,
    Android,
}

/// 指定ターゲットに対して CA 証明書のインストール/クリーンアップを実行する。
pub fn run(targets: &[Target], cleanup: bool, ca_cert_path: &Path) -> Result<()> {
    if !ca_cert_path.exists() {
        bail!(
            "CA証明書が見つかりません: {} (hint: 先に `holonomy config.toml` を実行して CA を生成してください)",
            ca_cert_path.display()
        );
    }

    for target in targets {
        match (target, cleanup) {
            (Target::Ios, false) => ios::install_trust(ca_cert_path)?,
            (Target::Ios, true) => ios::cleanup_trust(ca_cert_path)?,
            (Target::Android, false) => android::install_trust(ca_cert_path)?,
            (Target::Android, true) => android::cleanup_trust(ca_cert_path)?,
        }
    }
    Ok(())
}

/// CLI フラグからターゲットリストを構築する。
/// --ios / --android は同時指定可能、--all はその両方と排他（clap側で制約済み）。
pub fn resolve_targets(ios: bool, android: bool, all: bool) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    if all || ios {
        targets.push(Target::Ios);
    }
    if all || android {
        targets.push(Target::Android);
    }
    if targets.is_empty() {
        bail!("--ios, --android, --all のいずれかを指定してください");
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_ios_only() {
        let targets = resolve_targets(true, false, false).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(matches!(targets[0], Target::Ios));
    }

    #[test]
    fn resolve_android_only() {
        let targets = resolve_targets(false, true, false).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(matches!(targets[0], Target::Android));
    }

    #[test]
    fn resolve_both() {
        let targets = resolve_targets(true, true, false).unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn resolve_all() {
        let targets = resolve_targets(false, false, true).unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn resolve_none_fails() {
        let err = resolve_targets(false, false, false).unwrap_err();
        assert!(err.to_string().contains("--ios"));
    }

    #[test]
    fn run_with_missing_cert_fails() {
        let err = run(&[Target::Ios], false, Path::new("/nonexistent/rootCA.pem")).unwrap_err();
        assert!(err.to_string().contains("CA証明書が見つかりません"));
    }
}
