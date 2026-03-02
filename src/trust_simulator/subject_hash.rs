// subject_hash_old: OpenSSL互換のsubjectハッシュ計算
//
// Android のシステム証明書ストアでは、証明書ファイル名に
// OpenSSL の subject_hash_old（MD5ベース）を使用する。
// このモジュールはその計算を純Rustで実装する。

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use md5::{Digest, Md5};

/// PEM形式のCA証明書ファイルから subject_hash_old を計算する。
/// OpenSSL互換の8桁16進数ハッシュ文字列を返す。
pub fn compute_from_pem_file(ca_cert_path: &Path) -> Result<String> {
    let pem_bytes = fs::read(ca_cert_path)
        .with_context(|| format!("証明書ファイルの読み込みに失敗: {}", ca_cert_path.display()))?;
    let der = pem_to_der(&pem_bytes)?;
    compute_from_der(&der)
}

/// DER形式の証明書バイト列から subject_hash_old を計算する。
pub fn compute_from_der(cert_der: &[u8]) -> Result<String> {
    let subject_der = extract_subject_der(cert_der)?;
    let hash_value = hash_subject(subject_der);
    Ok(format!("{:08x}", hash_value))
}

/// PEMバイト列からDERバイト列に変換する。
fn pem_to_der(pem_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut reader = std::io::Cursor::new(pem_bytes);
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut reader).collect::<std::result::Result<_, _>>()?;
    let cert = certs
        .into_iter()
        .next()
        .context("PEMファイルに証明書が含まれていない")?;
    Ok(cert.to_vec())
}

/// DER形式の証明書からsubject NameのDERバイト列を抽出する。
///
/// X.509証明書のASN.1構造:
/// Certificate ::= SEQUENCE {
///     tbsCertificate SEQUENCE {
///         version       [0] EXPLICIT INTEGER  -- OPTIONAL
///         serialNumber  INTEGER
///         signature     AlgorithmIdentifier (SEQUENCE)
///         issuer        Name (SEQUENCE)
///         validity      SEQUENCE
///         subject       Name (SEQUENCE)  ← これを抽出
///         ...
///     },
///     ...
/// }
fn extract_subject_der(cert_der: &[u8]) -> Result<&[u8]> {
    // 外側の SEQUENCE (Certificate) をパース
    let (tag, content) = parse_tlv(cert_der)?;
    if tag != 0x30 {
        bail!("証明書の外側がSEQUENCEではない: tag=0x{:02x}", tag);
    }

    // tbsCertificate SEQUENCE をパース
    let (tag, tbs_content) = parse_tlv(content)?;
    if tag != 0x30 {
        bail!("tbsCertificateがSEQUENCEではない: tag=0x{:02x}", tag);
    }

    let mut pos = tbs_content;

    // version [0] EXPLICIT (tag=0xA0) があればスキップ
    let (tag, _) = parse_tlv(pos)?;
    if tag == 0xA0 {
        let (_, _, total) = parse_tlv_with_size(pos)?;
        pos = &pos[total..];
    }

    // serialNumber INTEGER をスキップ
    let (_, _, total) = parse_tlv_with_size(pos)?;
    pos = &pos[total..];

    // signature AlgorithmIdentifier SEQUENCE をスキップ
    let (_, _, total) = parse_tlv_with_size(pos)?;
    pos = &pos[total..];

    // issuer Name SEQUENCE をスキップ
    let (_, _, total) = parse_tlv_with_size(pos)?;
    pos = &pos[total..];

    // validity SEQUENCE をスキップ
    let (_, _, total) = parse_tlv_with_size(pos)?;
    pos = &pos[total..];

    // subject Name SEQUENCE → TLV全体を返す
    let (tag, _, total) = parse_tlv_with_size(pos)?;
    if tag != 0x30 {
        bail!("subjectがSEQUENCEではない: tag=0x{:02x}", tag);
    }
    Ok(&pos[..total])
}

/// ASN.1 DERのTLVをパースし、(tag, content) を返す。
fn parse_tlv(data: &[u8]) -> Result<(u8, &[u8])> {
    let (tag, content, _) = parse_tlv_with_size(data)?;
    Ok((tag, content))
}

/// ASN.1 DERのTLVをパースし、(tag, content, total_length) を返す。
/// total_length はタグ+長さ+値の全体バイト数。
fn parse_tlv_with_size(data: &[u8]) -> Result<(u8, &[u8], usize)> {
    if data.is_empty() {
        bail!("ASN.1パースエラー: データが空");
    }

    let tag = data[0];
    let (content_len, header_len) = parse_length(&data[1..])?;
    let total_header = 1 + header_len;
    let total = total_header + content_len;

    if total > data.len() {
        bail!(
            "ASN.1パースエラー: データ不足 (必要={}, 残り={})",
            total,
            data.len()
        );
    }

    Ok((tag, &data[total_header..total], total))
}

/// ASN.1 DERの長さフィールドをパースし、(content_length, length_field_bytes) を返す。
fn parse_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        bail!("ASN.1パースエラー: 長さフィールドが不足");
    }

    let first = data[0];
    if first < 0x80 {
        // 短い形式: 1バイトで長さを表す
        return Ok((first as usize, 1));
    }

    // 長い形式: 最初のバイトの下位7ビットが後続のバイト数
    let num_bytes = (first & 0x7F) as usize;
    if num_bytes == 0 || num_bytes > 4 {
        bail!(
            "ASN.1パースエラー: 未対応の長さフィールドサイズ: {}",
            num_bytes
        );
    }
    if data.len() < 1 + num_bytes {
        bail!("ASN.1パースエラー: 長さフィールドのデータ不足");
    }

    let mut length: usize = 0;
    for i in 0..num_bytes {
        length = (length << 8) | (data[1 + i] as usize);
    }

    Ok((length, 1 + num_bytes))
}

/// subject DERバイト列からハッシュ値を計算する。
/// MD5の先頭4バイトをリトルエンディアンu32として解釈する。
fn hash_subject(subject_der: &[u8]) -> u32 {
    let digest = Md5::digest(subject_der);
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    // テスト用のCA証明書（openssl で生成、CN=holonomy test ca）
    // `openssl x509 -in testdata/test-ca.pem -subject_hash_old -noout` の結果: 9c880ff0
    const EXPECTED_HASH: &str = "9c880ff0";

    #[test]
    fn subject_hash_old_matches_openssl() {
        let hash = compute_from_pem_file(Path::new("testdata/test-ca.pem")).unwrap();
        assert_eq!(hash, EXPECTED_HASH);
    }

    #[test]
    fn hash_filename_format() {
        let hash = compute_from_pem_file(Path::new("testdata/test-ca.pem")).unwrap();
        // 8桁の16進数であること
        assert_eq!(hash.len(), 8);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn extract_subject_from_pem() {
        let pem_bytes = fs::read("testdata/test-ca.pem").unwrap();
        let der = pem_to_der(&pem_bytes).unwrap();
        let subject = extract_subject_der(&der).unwrap();
        // subjectの先頭はSEQUENCEタグ (0x30) であるべき
        assert_eq!(subject[0], 0x30);
        assert!(!subject.is_empty());
    }

    #[test]
    fn compute_from_der_works() {
        let pem_bytes = fs::read("testdata/test-ca.pem").unwrap();
        let der = pem_to_der(&pem_bytes).unwrap();
        let hash = compute_from_der(&der).unwrap();
        assert_eq!(hash, EXPECTED_HASH);
    }

    #[test]
    fn parse_length_short_form() {
        // 短い形式: 0x0A = 長さ10
        let (len, bytes) = parse_length(&[0x0A]).unwrap();
        assert_eq!(len, 10);
        assert_eq!(bytes, 1);
    }

    #[test]
    fn parse_length_long_form_1byte() {
        // 長い形式: 0x81 0x80 = 長さ128
        let (len, bytes) = parse_length(&[0x81, 0x80]).unwrap();
        assert_eq!(len, 128);
        assert_eq!(bytes, 2);
    }

    #[test]
    fn parse_length_long_form_2bytes() {
        // 長い形式: 0x82 0x01 0x00 = 長さ256
        let (len, bytes) = parse_length(&[0x82, 0x01, 0x00]).unwrap();
        assert_eq!(len, 256);
        assert_eq!(bytes, 3);
    }

    #[test]
    fn empty_data_fails() {
        let err = parse_tlv_with_size(&[]).unwrap_err();
        assert!(err.to_string().contains("データが空"));
    }

    #[test]
    fn invalid_pem_fails() {
        let err = pem_to_der(b"not a pem").unwrap_err();
        assert!(err.to_string().contains("証明書が含まれていない"));
    }
}
