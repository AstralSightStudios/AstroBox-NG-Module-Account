use crate::models::AccountRecord;
use aes::Aes128;
use anyhow::{Context, Result, anyhow};
use cbc::Encryptor;
use cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use crc::{CRC_32_ISO_HDLC, Crc};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const VIVO_OTA_BASE_URL: &str = "https://health.vivo.com";
const VIVO_OTA_QUERY_PATH: &str = "/ptsou/jvq/query.do";
const VIVO_BASE64_ALPHABET: &[u8; 64] =
    b"Q8vN-ryaEJGoTWOtK_qMkh5RZ6LxcUA3dnzeHu2XjSbVsFYwfPD94C0lm1Ip7gBi";
const VIVO_OTA_KEY_TOKEN: &str = "jnisgmain@com.vivo.health";
const VIVO_OTA_AES_KEY: [u8; 16] = [
    0xf1, 0x3f, 0xa5, 0x39, 0xd0, 0x8a, 0xb1, 0x8c, 0xba, 0x7a, 0xc3, 0x42, 0xe6, 0xa3, 0xda, 0xe3,
];
const VIVO_OTA_AES_IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const VIVO_OTA_CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VivoAccountProfile {
    pub open_id: String,
    #[serde(default)]
    pub vivo_token: Option<String>,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub nick_name: Option<String>,
    #[serde(default)]
    pub phone_number: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub updated_at: u64,
}

impl VivoAccountProfile {
    pub fn new(open_id: impl Into<String>) -> Self {
        Self {
            open_id: open_id.into(),
            vivo_token: None,
            user_name: None,
            nick_name: None,
            phone_number: None,
            avatar: None,
            updated_at: current_timestamp_secs(),
        }
    }

    pub fn normalize(mut self) -> Self {
        self.open_id = self.open_id.trim().to_string();
        self.vivo_token = normalize_optional(self.vivo_token);
        self.user_name = normalize_optional(self.user_name);
        self.nick_name = normalize_optional(self.nick_name);
        self.phone_number = normalize_optional(self.phone_number);
        self.avatar = normalize_optional(self.avatar);
        if self.updated_at == 0 {
            self.updated_at = current_timestamp_secs();
        }
        self
    }

    pub fn display_name(&self) -> String {
        self.nick_name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                self.user_name
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
            })
            .or_else(|| {
                self.phone_number
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
            })
            .unwrap_or("vivo Account")
            .to_string()
    }
}

#[derive(Debug, Clone)]
pub struct VivoFirmwareQuery {
    pub device: String,
    pub firmware_version: String,
    pub mac_address: String,
    pub client_id: String,
    pub version_type: i32,
    pub locale: String,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VivoOtaPackage {
    #[serde(default)]
    pub len: String,
    #[serde(default)]
    pub md5: String,
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VivoLatestVersion {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub vercode: i32,
    #[serde(default)]
    pub log: String,
    #[serde(rename = "logDef", default)]
    pub log_def: String,
    #[serde(default, deserialize_with = "deserialize_vivo_ota_package")]
    pub zip: Option<VivoOtaPackage>,
    #[serde(default)]
    pub redirect: String,
    #[serde(rename = "hitPk", default)]
    pub hit_pk: bool,
    #[serde(rename = "pkgType", default)]
    pub pkg_type: i32,
    #[serde(rename = "osVersionType", default)]
    pub os_version_type: i32,
    #[serde(default)]
    pub way: i32,
    #[serde(rename = "waySetting", default)]
    pub way_setting: String,
    #[serde(skip)]
    pub only_full: bool,
}

impl VivoLatestVersion {
    pub fn is_valid(&self) -> bool {
        !self.version.trim().is_empty()
            && self
                .zip
                .as_ref()
                .is_some_and(|zip| !zip.url.trim().is_empty() && !zip.md5.trim().is_empty())
    }

    pub fn version_name(&self) -> String {
        format_vivo_version_name(&self.version)
    }

    pub fn changelog(&self) -> Option<&str> {
        if !self.log.trim().is_empty() {
            Some(self.log.trim())
        } else if !self.log_def.trim().is_empty() {
            Some(self.log_def.trim())
        } else {
            None
        }
    }

    pub fn download_url(&self) -> Option<String> {
        let zip = self.zip.as_ref()?;
        let url = zip.url.trim();
        if url.is_empty() {
            return None;
        }
        if url.starts_with("http://") || url.starts_with("https://") {
            return Some(url.to_string());
        }

        let redirect = self.redirect.trim().trim_end_matches('/');
        if !redirect.is_empty() {
            return Some(format!("{redirect}/{}", url.trim_start_matches('/')));
        }

        Some(format!(
            "{}/{}",
            VIVO_OTA_BASE_URL,
            url.trim_start_matches('/')
        ))
    }

    pub fn download_md5(&self) -> Option<&str> {
        self.zip
            .as_ref()
            .map(|zip| zip.md5.trim())
            .filter(|md5| !md5.is_empty())
    }

    pub fn download_len(&self) -> Option<u64> {
        self.zip
            .as_ref()
            .and_then(|zip| zip.len.trim().parse::<u64>().ok())
    }

    pub fn is_diff_package(&self) -> bool {
        self.hit_pk || !self.only_full
    }
}

#[derive(Debug, Deserialize)]
struct VivoOtaResponse<T> {
    #[serde(default)]
    code: i32,
    #[serde(default)]
    msg: String,
    data: Option<T>,
}

pub fn build_account_record(profile: &VivoAccountProfile) -> AccountRecord {
    let profile = profile.clone().normalize();
    let mut record = AccountRecord::new(profile.open_id.clone(), profile.display_name())
        .with_avatar(profile.avatar.clone())
        .with_token(profile.vivo_token.clone());

    record.set_extra_value("openId", json!(profile.open_id));
    if let Some(vivo_token) = profile.vivo_token {
        record.set_extra_value("vivoToken", json!(vivo_token));
    }
    if let Some(user_name) = profile.user_name {
        record.set_extra_value("userName", json!(user_name));
    }
    if let Some(nick_name) = profile.nick_name {
        record.set_extra_value("nickName", json!(nick_name));
    }
    if let Some(phone_number) = profile.phone_number {
        record.set_extra_value("phoneNumber", json!(phone_number));
    }
    if let Some(avatar) = profile.avatar {
        record.set_extra_value("avatar", json!(avatar));
    }
    record.set_extra_value("updatedAt", json!(profile.updated_at));
    record
}

pub async fn fetch_vivo_latest_version(
    query: VivoFirmwareQuery,
) -> Result<Option<VivoLatestVersion>> {
    let device = query.device.trim().to_string();
    if device.is_empty() {
        return Err(anyhow!("vivo OTA device model is required"));
    }

    let firmware_version = query.firmware_version.trim().to_string();
    if firmware_version.is_empty() {
        return Err(anyhow!("Current firmware version is required"));
    }

    let client = crate::net::default_client_builder()
        .default_headers(vivo_ota_headers(&query.user_agent)?)
        .build()?;

    let version_code = vercode_from_vivo_version(&firmware_version);
    let mac_address = normalize_vivo_mac_address(&query.mac_address);
    let client_id = query.client_id.trim();
    let client_id = if client_id.is_empty() {
        "AstroBox"
    } else {
        client_id
    };
    let locale = normalize_vivo_locale(&query.locale);

    let diff = fetch_vivo_latest_version_once(
        &client,
        &device,
        version_code,
        client_id,
        &mac_address,
        query.version_type,
        &locale,
        false,
    )
    .await?;
    if diff.is_some() {
        return Ok(diff);
    }

    fetch_vivo_latest_version_once(
        &client,
        &device,
        version_code,
        client_id,
        &mac_address,
        query.version_type,
        &locale,
        true,
    )
    .await
}

pub fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn fetch_vivo_latest_version_once(
    client: &reqwest::Client,
    device: &str,
    vercode: i32,
    client_id: &str,
    mac_address: &str,
    version_type: i32,
    locale: &str,
    only_full: bool,
) -> Result<Option<VivoLatestVersion>> {
    let only_full_value = if only_full { 4 } else { 2 };
    let url = format!("{VIVO_OTA_BASE_URL}{VIVO_OTA_QUERY_PATH}");
    let plain_query = build_vivo_ota_query_string(
        device,
        vercode,
        client_id,
        only_full_value,
        mac_address,
        version_type,
        locale,
    );
    let jvq_param = encode_vivo_ota_jvq_param(&plain_query)?;
    let query = [("jvq_param", jvq_param)];
    let body = client
        .get(url)
        .query(&query)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let decoded = vivo_base64_decode(body.trim()).context("decode vivo OTA response")?;
    let decoded = String::from_utf8(decoded).context("decode vivo OTA response as utf-8")?;
    let response: VivoOtaResponse<VivoLatestVersion> = serde_json::from_str(&decoded)
        .with_context(|| format!("decode vivo OTA json failed: {decoded}"))?;

    match response.code {
        0 => {
            let mut latest = response
                .data
                .ok_or_else(|| anyhow!("vivo OTA response has no data"))?;
            latest.only_full = only_full;
            Ok(latest.is_valid().then_some(latest))
        }
        200 => Ok(None),
        code => Err(anyhow!(
            "fetch vivo latest version failed: code={}, msg={}",
            code,
            response.msg
        )),
    }
}

fn build_vivo_ota_query_string(
    device: &str,
    vercode: i32,
    client_id: &str,
    only_full: i32,
    mac_address: &str,
    version_type: i32,
    locale: &str,
) -> String {
    format!(
        "device={device}&vercode={vercode}&imei={client_id}&onlyFull={only_full}&mac1={mac_address}&vertype={version_type}&lang={locale}&needContent=1&needH5Content=1"
    )
}

fn encode_vivo_ota_jvq_param(plain_query: &str) -> Result<String> {
    let mut buffer = vec![0u8; plain_query.len() + 16];
    buffer[..plain_query.len()].copy_from_slice(plain_query.as_bytes());
    let encrypted_body =
        Encryptor::<Aes128>::new(&VIVO_OTA_AES_KEY.into(), &VIVO_OTA_AES_IV.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plain_query.len())
            .map_err(|_| anyhow!("encrypt vivo OTA jvq_param failed"))?
            .to_vec();

    let entry = render_vivo_crypto_entry_v1(&encrypted_body)?;
    Ok(vivo_base64_encode(&entry))
}

fn render_vivo_crypto_entry_v1(body: &[u8]) -> Result<Vec<u8>> {
    let key_token = VIVO_OTA_KEY_TOKEN.as_bytes();
    if key_token.len() >= 256 {
        return Err(anyhow!("vivo OTA key token is too long"));
    }

    let header_len = 16usize + key_token.len();
    let mut header = vec![0u8; header_len];
    header[0..2].copy_from_slice(&(header_len as u16).to_be_bytes());
    header[10..12].copy_from_slice(&1u16.to_be_bytes());
    header[12] = key_token.len() as u8;
    header[13..13 + key_token.len()].copy_from_slice(key_token);
    header[13 + key_token.len()..15 + key_token.len()].copy_from_slice(&2u16.to_be_bytes());
    header[15 + key_token.len()] = 5;

    let crc = VIVO_OTA_CRC32.checksum(&header[10..]) as u64;
    header[2..10].copy_from_slice(&crc.to_be_bytes());

    let mut entry = Vec::with_capacity(header.len() + body.len());
    entry.extend_from_slice(&header);
    entry.extend_from_slice(body);
    Ok(entry)
}

fn vivo_ota_headers(user_agent: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "User-Agent",
        HeaderValue::from_str(user_agent.trim()).context("invalid vivo OTA user agent")?,
    );
    headers.insert("Accept", HeaderValue::from_static("*/*"));
    Ok(headers)
}

fn deserialize_vivo_ota_package<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<VivoOtaPackage>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(raw)) => {
            let raw = raw.trim();
            if raw.is_empty() {
                Ok(None)
            } else {
                serde_json::from_str::<VivoOtaPackage>(raw)
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
        }
        Some(value @ serde_json::Value::Object(_)) => {
            serde_json::from_value::<VivoOtaPackage>(value)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
        Some(other) => Err(serde::de::Error::custom(format!(
            "unexpected vivo OTA zip field: {other}"
        ))),
    }
}

fn vivo_base64_decode(input: &str) -> Result<Vec<u8>> {
    let bytes = input.trim().as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut index = 0usize;
    while index < bytes.len() {
        let remaining = bytes.len() - index;
        let b0 = vivo_base64_value(bytes[index])?;
        index += 1;

        match remaining {
            1 => {
                let value = b0 << 2;
                if value > 0 {
                    output.push(value);
                }
            }
            2 => {
                let b1 = vivo_base64_value(bytes[index])?;
                index += 1;
                output.push((b0 << 2) | ((b1 & 0x30) >> 4));
                let value = (b1 & 0x0f) << 4;
                if value > 0 {
                    output.push(value);
                }
            }
            3 => {
                let b1 = vivo_base64_value(bytes[index])?;
                let b2 = vivo_base64_value(bytes[index + 1])?;
                index += 2;
                output.push((b0 << 2) | ((b1 & 0x30) >> 4));
                output.push(((b1 & 0x0f) << 4) | ((b2 & 0x3c) >> 2));
                let value = (b2 & 0x03) << 6;
                if value > 0 {
                    output.push(value);
                }
            }
            _ => {
                let b1 = vivo_base64_value(bytes[index])?;
                let b2 = vivo_base64_value(bytes[index + 1])?;
                let b3 = vivo_base64_value(bytes[index + 2])?;
                index += 3;
                output.push((b0 << 2) | ((b1 & 0x30) >> 4));
                output.push(((b1 & 0x0f) << 4) | ((b2 & 0x3c) >> 2));
                output.push(((b2 & 0x03) << 6) | b3);
            }
        }
    }

    Ok(output)
}

fn vivo_base64_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let b0 = chunk[0];
        let b1 = chunk[1];
        let b2 = chunk[2];
        output.push(VIVO_BASE64_ALPHABET[(b0 >> 2) as usize] as char);
        output.push(VIVO_BASE64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        output.push(VIVO_BASE64_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        output.push(VIVO_BASE64_ALPHABET[(b2 & 0x3f) as usize] as char);
    }

    let remainder = chunks.remainder();
    match remainder.len() {
        1 => {
            let b0 = remainder[0];
            output.push(VIVO_BASE64_ALPHABET[(b0 >> 2) as usize] as char);
            output.push(VIVO_BASE64_ALPHABET[((b0 & 0x03) << 4) as usize] as char);
        }
        2 => {
            let b0 = remainder[0];
            let b1 = remainder[1];
            output.push(VIVO_BASE64_ALPHABET[(b0 >> 2) as usize] as char);
            output.push(VIVO_BASE64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            output.push(VIVO_BASE64_ALPHABET[((b1 & 0x0f) << 2) as usize] as char);
        }
        _ => {}
    }

    output
}

fn vivo_base64_value(byte: u8) -> Result<u8> {
    VIVO_BASE64_ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
        .ok_or_else(|| anyhow!("invalid vivo base64 byte: 0x{byte:02x}"))
}

pub fn vercode_from_vivo_version(version: &str) -> i32 {
    let os_version = vivo_os_version(version);
    let formatted = format_vivo_version_name(&os_version);
    let parts = formatted
        .split('.')
        .map(|part| part.parse::<i32>())
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(parts) = parts else {
        return 0;
    };
    if parts.len() != 3 {
        return 0;
    }
    parts[0]
        .saturating_mul(10000)
        .saturating_add(parts[1].saturating_mul(100))
        .saturating_add(parts[2])
}

pub fn vivo_os_version(version: &str) -> String {
    let version = version.trim();
    if version.is_empty() || !version.contains('_') {
        return version.to_string();
    }

    let parts: Vec<&str> = version.split('_').collect();
    if parts.len() < 3 {
        return version.to_string();
    }
    parts.get(2).copied().unwrap_or(version).to_string()
}

pub fn vivo_hard_version(version: &str) -> String {
    let version = version.trim();
    if version.is_empty() || !version.contains('_') {
        return String::new();
    }

    let parts: Vec<&str> = version.split('_').collect();
    if parts.len() < 3 {
        return String::new();
    }
    parts[..2].join("_")
}

pub fn vivo_ota_device_from_request(requested_device: &str, firmware_version: &str) -> String {
    let requested_device = requested_device.trim();
    let hard_version = vivo_hard_version(firmware_version);
    if hard_version.trim().is_empty() {
        return requested_device.to_string();
    }
    if requested_device.is_empty() || !is_probably_vivo_ota_device(requested_device) {
        return hard_version;
    }
    requested_device.to_string()
}

fn is_probably_vivo_ota_device(device: &str) -> bool {
    let device = device.trim();
    if device.is_empty() || device.chars().any(char::is_whitespace) {
        return false;
    }

    let upper = device.to_ascii_uppercase();
    upper.starts_with("DPD") || upper.starts_with("PD") || upper.starts_with("IQOO")
}

pub fn format_vivo_version_name(version: &str) -> String {
    let version = version.trim();
    if version.len() < 3 {
        return String::new();
    }
    version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .unwrap_or(version)
        .to_string()
}

pub fn compare_vivo_firmware_versions(latest_version: &str, current_version: &str) -> i32 {
    let latest = comparable_version_parts(latest_version);
    let current = comparable_version_parts(current_version);
    let (Some(latest), Some(current)) = (latest, current) else {
        return 0;
    };

    let len = latest.len().max(current.len());
    for index in 0..len {
        let lhs = latest.get(index).copied().unwrap_or(0);
        let rhs = current.get(index).copied().unwrap_or(0);
        if lhs > rhs {
            return 1;
        }
        if lhs < rhs {
            return -1;
        }
    }
    0
}

fn comparable_version_parts(version: &str) -> Option<Vec<u64>> {
    let formatted = format_vivo_version_name(&vivo_os_version(version));
    if formatted.is_empty() {
        return None;
    }
    let parts = formatted
        .split('.')
        .map(|part| part.parse::<u64>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    (!parts.is_empty()).then_some(parts)
}

fn normalize_vivo_locale(locale: &str) -> String {
    let normalized = locale.trim().replace('-', "_");
    match normalized.as_str() {
        "" => "zh_CN".to_string(),
        "zh" | "zh_Hans" | "zh_CN" => "zh_CN".to_string(),
        "en" => "en_US".to_string(),
        value => value.to_string(),
    }
}

fn normalize_vivo_mac_address(mac_address: &str) -> String {
    let mac_address = mac_address.trim();
    if mac_address.is_empty() {
        return "00:00:00:00:00:00".to_string();
    }

    let hex: String = mac_address
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if hex.len() == 12 {
        return hex
            .as_bytes()
            .chunks(2)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":");
    }

    mac_address.to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vivo_base64_decodes_official_plaintext_response() {
        let decoded = vivo_base64_decode("ADJex0_uEejDTNQsE2C96DEIE2mz3K").unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            r#"{"code":200,"msg":"n"}"#
        );
    }

    #[test]
    fn vivo_base64_encodes_official_plaintext_response() {
        assert_eq!(
            vivo_base64_encode(br#"{"code":200,"msg":"n"}"#),
            "ADJex0_uEejDTNQsE2C96DEIE2mz3K"
        );
    }

    #[test]
    fn vivo_ota_query_string_matches_official_watch_v3_order() {
        assert_eq!(
            build_vivo_ota_query_string(
                "DPD2508AB_A",
                10000,
                "AstroBox",
                2,
                "00:00:00:00:00:00",
                0,
                "zh_CN",
            ),
            "device=DPD2508AB_A&vercode=10000&imei=AstroBox&onlyFull=2&mac1=00:00:00:00:00:00&vertype=0&lang=zh_CN&needContent=1&needH5Content=1"
        );
    }

    #[test]
    fn vivo_ota_jvq_param_matches_securitysdk_crypto_entry() {
        let plain_query = build_vivo_ota_query_string(
            "DPD2508AB_A",
            10000,
            "AstroBox",
            2,
            "00:00:00:00:00:00",
            0,
            "zh_CN",
        );

        assert_eq!(
            encode_vivo_ota_jvq_param(&plain_query).unwrap(),
            "QvHQQQQQnToaHKQ8y5SYLRWXx5rSxH8ex04YU2u0xD1j65rsUydQQdkvIoErSuTRAS_zCC_MxeE8vIBB6zTfX_GoyAZ4CmDgGFz9SIUvFPZinp54IXxwzi4U8v6W15diqZh99pFz67vkjs9mDVwSdNUgIlLrXOuJ0Y38PRx_60MIGpvuChtpniVNAuIjoamaS-Y62h6xw6758sIv8au0Fq-Im4kjZN4_8JSU5yWetADcBATfyvX8YAH"
        );
    }

    #[test]
    fn vivo_version_code_matches_official_triplet_formula() {
        assert_eq!(vercode_from_vivo_version("1.40.9"), 14009);
        assert_eq!(vercode_from_vivo_version("v1.40.9"), 14009);
        assert_eq!(vercode_from_vivo_version("DPD2468_A_1.40.9_extra"), 14009);
        assert_eq!(vercode_from_vivo_version("DPD2508AB_A_1.0.0"), 10000);
        assert_eq!(vercode_from_vivo_version("1.40.9.1"), 0);
    }

    #[test]
    fn vivo_hard_and_os_version_follow_domestic_split_rules() {
        assert_eq!(vivo_hard_version("DPD2468_A_1.40.9_extra"), "DPD2468_A");
        assert_eq!(vivo_os_version("DPD2468_A_1.40.9_extra"), "1.40.9");
        assert_eq!(vivo_hard_version("DPD2508AB_A_1.0.0"), "DPD2508AB_A");
        assert_eq!(vivo_os_version("DPD2508AB_A_1.0.0"), "1.0.0");
    }

    #[test]
    fn vivo_ota_device_falls_back_to_hard_version_for_marketing_model() {
        assert_eq!(
            vivo_ota_device_from_request("vivo WATCH GT2", "DPD2508AB_A_1.0.0"),
            "DPD2508AB_A"
        );
        assert_eq!(
            vivo_ota_device_from_request("DPD2508AB_A", "DPD2508AB_A_1.0.0"),
            "DPD2508AB_A"
        );
    }

    #[test]
    fn vivo_mac_address_matches_android_uppercase_style() {
        assert_eq!(
            normalize_vivo_mac_address("aa-bb-cc-dd-ee-ff"),
            "AA:BB:CC:DD:EE:FF"
        );
        assert_eq!(
            normalize_vivo_mac_address("aabbccddeeff"),
            "AA:BB:CC:DD:EE:FF"
        );
    }
}
