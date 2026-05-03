use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aes::Aes128;
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cipher::StreamCipher;
use md5::Md5;
use rand::{Rng, distributions::Uniform, rngs::OsRng};
use rc4::{KeyInit, Rc4, consts::U32};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest_cookie_store::{CookieStore, CookieStoreMutex, RawCookie};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use url::Url;

type Aes128CbcEncryptor = cbc::Encryptor<Aes128>;
type Aes128CbcDecryptor = cbc::Decryptor<Aes128>;

const ACCOUNT_AES_IV: &[u8; 16] = b"0102030405060708";

#[derive(Debug, Deserialize, Serialize)]
pub struct ServiceLoginAuthRespone {
    #[serde(default)]
    pub qs: String,
    #[serde(default)]
    pub ssecurity: String,
    pub code: u64,
    #[serde(rename = "passToken")]
    #[serde(default)]
    pub pass_token: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "securityStatus")]
    pub security_status: u64,
    #[serde(default)]
    pub nonce: u64,
    #[serde(rename = "userId")]
    #[serde(default)]
    pub user_id: u64,
    #[serde(rename = "cUserId")]
    #[serde(default)]
    pub c_user_id: String,
    pub result: String,
    #[serde(default)]
    pub psecurity: String,
    pub location: String,
    pub pwd: u64,
    pub child: u64,
    #[serde(default)]
    pub desc: String,
    #[serde(rename = "notificationUrl")]
    pub notification_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServiceLoginRespone {
    #[serde(rename = "_sign", default)]
    pub sign: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceDetail {
    #[serde(default)]
    pub beaconkey: String,
    #[serde(default)]
    pub encrypt_key: String,
    #[serde(default)]
    pub fw_ver: String,
    #[serde(default)]
    pub irq_key: String,
    #[serde(default)]
    pub last_bind_time: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub phone_id: String,
    #[serde(default)]
    pub sn: String,
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceInfo {
    pub sid: String,
    pub identifier: String,
    pub name: String,
    pub model: String,
    pub status: u64,
    pub create_time: u64,
    pub update_time: u64,
    pub detail: DeviceDetail,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceListResult {
    pub list: Vec<DeviceInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceListRespone {
    pub code: u64,
    pub message: String,
    pub result: DeviceListResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiAccountToken {
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub device_id: String,
    pub ssecurity: String,
    pub service_token: String,
    pub c_user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiNotificationAuthResult {
    pub user_id: String,
    pub service_token: String,
    pub psecurity_ph: String,
    pub psecurity_slh: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiUserCoreInfo {
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub nick_name: String,
    #[serde(default)]
    pub avatar_address: String,
    #[serde(default)]
    pub safe_phone: String,
    #[serde(default)]
    pub email_address: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiLatestVersion {
    #[serde(default)]
    pub version: String,
    #[serde(rename = "safe_url", default)]
    pub full_package_url: String,
    #[serde(rename = "changeLog", default)]
    pub change_log: String,
    #[serde(default)]
    pub md5: String,
    #[serde(rename = "upload_time")]
    pub upload_time: Option<i64>,
    #[serde(rename = "diff_safe_url", default)]
    pub diff_url: String,
    #[serde(rename = "diff_md5", default)]
    pub diff_md5: String,
    #[serde(default)]
    pub force: bool,
}

impl MiLatestVersion {
    pub fn is_valid(&self) -> bool {
        !self.version.trim().is_empty()
    }

    pub fn download_url(&self) -> Option<&str> {
        if !self.diff_url.trim().is_empty() {
            Some(self.diff_url.trim())
        } else if !self.full_package_url.trim().is_empty() {
            Some(self.full_package_url.trim())
        } else {
            None
        }
    }

    pub fn download_md5(&self) -> Option<&str> {
        if !self.diff_url.trim().is_empty() && !self.diff_md5.trim().is_empty() {
            Some(self.diff_md5.trim())
        } else if !self.md5.trim().is_empty() {
            Some(self.md5.trim())
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiWatchfaceLabel {
    #[serde(default)]
    pub label_id: String,
    #[serde(default)]
    pub label_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiWatchfaceIcon {
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub aod_icon: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiWatchfaceData {
    #[serde(default)]
    pub spu_id: String,
    #[serde(default)]
    pub spu_version: i64,
    #[serde(default)]
    pub sku_id: String,
    #[serde(default)]
    pub purchase_type: Option<i64>,
    #[serde(default)]
    pub purchase_status: i64,
    #[serde(default)]
    pub price: u64,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub aod_icon: String,
    #[serde(rename = "watch_face_version", default)]
    pub version_code: Option<u64>,
    #[serde(default)]
    pub package_name: String,
    #[serde(default)]
    pub package_name_hash: String,
    #[serde(default)]
    pub introduction: String,
    #[serde(default)]
    pub publish_name: String,
    #[serde(default)]
    pub config_file: String,
    #[serde(default)]
    pub file_hash: String,
    #[serde(default)]
    pub file_size: u64,
    #[serde(default)]
    pub file_hash_v2: String,
    #[serde(default)]
    pub file_size_v2: Option<u64>,
    #[serde(default)]
    pub download_count: i64,
    #[serde(default)]
    pub label_list: Vec<MiWatchfaceLabel>,
    #[serde(default)]
    pub icon_list: Vec<MiWatchfaceIcon>,
}

impl MiWatchfaceData {
    pub fn is_purchase_face(&self) -> bool {
        self.purchase_type.unwrap_or_default() == 21
    }

    pub fn can_purchase(&self) -> bool {
        self.is_purchase_face() && self.purchase_status == 0
    }

    pub fn is_vip(&self) -> bool {
        self.is_purchase_face() && self.purchase_status == 2
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiWatchfaceIndexItem {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "watchface_list", default)]
    pub watchface_list: Vec<MiWatchfaceData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiWatchfaceIndexResult {
    #[serde(rename = "in_white_list", default)]
    pub in_white_list: bool,
    #[serde(rename = "resource_pool_list", default)]
    pub resource_pool_list: Vec<MiWatchfaceIndexItem>,
    #[serde(rename = "feed_watchface_list", default)]
    pub feed_watchface_list: Vec<MiWatchfaceData>,
    #[serde(rename = "has_more", default)]
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiWatchfaceDetailResult {
    #[serde(rename = "watch_face")]
    pub watch_face: MiWatchfaceData,
    #[serde(default)]
    pub recommend_list: Vec<MiWatchfaceData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiWatchfaceDownloadInfo {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub config_file: Option<String>,
    #[serde(default)]
    pub file_hash: Option<String>,
    #[serde(default)]
    pub file_size: u64,
    #[serde(default)]
    pub config_file_v2: Option<String>,
    #[serde(default)]
    pub file_hash_v2: Option<String>,
    #[serde(default)]
    pub file_size_v2: u64,
}

impl MiWatchfaceDownloadInfo {
    pub fn preferred_url(&self, support_zip: bool) -> Option<&str> {
        if support_zip {
            self.config_file_v2
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    self.config_file
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                })
        } else {
            self.config_file
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    self.config_file_v2
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                })
        }
    }

    pub fn preferred_hash(&self, support_zip: bool) -> Option<&str> {
        if support_zip {
            self.file_hash_v2
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    self.file_hash
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                })
        } else {
            self.file_hash
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    self.file_hash_v2
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiWatchfaceDownloadResult {
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub sign: String,
    pub download_info: MiWatchfaceDownloadInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiWatchfaceLicensePayload {
    #[serde(default)]
    pub sign_time: i64,
    #[serde(default)]
    pub secret_id: String,
    #[serde(default)]
    pub trial_duration: Option<i64>,
    #[serde(default)]
    pub encrypt_type: i64,
    #[serde(default)]
    pub wf_hash: String,
    #[serde(default)]
    pub wf_id: String,
}

impl MiWatchfaceDownloadResult {
    pub fn trial_duration(&self) -> Option<i64> {
        serde_json::from_str::<MiWatchfaceLicensePayload>(&self.license)
            .ok()
            .and_then(|value| value.trial_duration)
    }
}

/// Remove Xiaomi’s magic prefix from JSON payloads.
fn strip_prefix(contents: &str) -> &str {
    const PREFIX: &str = "&&&START&&&";
    contents.strip_prefix(PREFIX).unwrap_or(contents)
}

/// Generate Mi nonce: 8 random bytes + 4-byte minutes since epoch (big-endian).
fn generate_nonce(millis: u64) -> String {
    let mut rand_part = [0u8; 8];
    OsRng.fill(&mut rand_part);
    let mut buf = Vec::with_capacity(12);
    buf.extend_from_slice(&rand_part);
    buf.extend_from_slice(&((millis / 60_000) as u32).to_be_bytes());
    general_purpose::STANDARD.encode(buf)
}

/// 6-character lowercase device id.
fn random_device_id() -> String {
    let range = Uniform::from(b'a'..=b'z');
    OsRng.sample_iter(&range).take(6).map(char::from).collect()
}

fn random_request_id(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let range = Uniform::from(0..CHARSET.len());
    OsRng
        .sample_iter(&range)
        .take(len)
        .map(|index| CHARSET[index] as char)
        .collect()
}

fn append_avatar_size_suffix(icon: &str) -> String {
    const SUFFIX: &str = "_320";
    let Some(dot_index) = icon.rfind('.') else {
        return icon.to_string();
    };
    if dot_index == 0 {
        return icon.to_string();
    }
    format!("{}{}{}", &icon[..dot_index], SUFFIX, &icon[dot_index..])
}

fn aes_encrypt_base64(security: &str, value: &str) -> Result<String> {
    let key = general_purpose::STANDARD
        .decode(security)
        .map_err(|err| anyhow!("decode account security failed: {err}"))?;
    let cipher = Aes128CbcEncryptor::new_from_slices(&key, ACCOUNT_AES_IV)
        .map_err(|err| anyhow!("init account aes encryptor failed: {err}"))?;
    let plain = value.as_bytes();
    let mut buffer = vec![0u8; plain.len() + 16];
    buffer[..plain.len()].copy_from_slice(plain);
    let encrypted = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plain.len())
        .map_err(|err| anyhow!("encrypt account payload failed: {err}"))?;
    Ok(general_purpose::STANDARD.encode(encrypted))
}

fn aes_decrypt_base64(security: &str, value: &str) -> Result<String> {
    let key = general_purpose::STANDARD
        .decode(security)
        .map_err(|err| anyhow!("decode account security failed: {err}"))?;
    let cipher = Aes128CbcDecryptor::new_from_slices(&key, ACCOUNT_AES_IV)
        .map_err(|err| anyhow!("init account aes decryptor failed: {err}"))?;
    let mut buffer = general_purpose::STANDARD
        .decode(value)
        .map_err(|err| anyhow!("decode encrypted account response failed: {err}"))?;
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|err| anyhow!("decrypt account response failed: {err}"))?;
    String::from_utf8(decrypted.to_vec())
        .map_err(|err| anyhow!("decode account response as utf-8 failed: {err}"))
}

fn generate_account_signature(
    method: &str,
    url: &str,
    params: &HashMap<String, String>,
    security: &str,
) -> Result<String> {
    if security.trim().is_empty() {
        return Err(anyhow!("account security is empty"));
    }

    let parsed_url = Url::parse(url)?;
    let mut keys: Vec<&String> = params.keys().collect();
    keys.sort();

    let mut pieces = Vec::with_capacity(2 + keys.len() + 1);
    pieces.push(method.to_uppercase());
    pieces.push(parsed_url.path().to_string());
    for key in keys {
        pieces.push(format!("{key}={}", params.get(key).unwrap()));
    }
    pieces.push(security.to_string());

    let raw = pieces.join("&");
    let mut sha1 = Sha1::default();
    sha1.update(raw.as_bytes());
    Ok(general_purpose::STANDARD.encode(sha1.finalize()))
}

fn parse_response_code(value: &serde_json::Value) -> i64 {
    value
        .get("code")
        .and_then(|raw| raw.as_i64().or_else(|| raw.as_str()?.parse::<i64>().ok()))
        .unwrap_or(-1)
}

fn parse_response_message(value: &serde_json::Value) -> String {
    for key in ["msg", "message", "description"] {
        if let Some(message) = value.get(key).and_then(|raw| raw.as_str()) {
            if !message.trim().is_empty() {
                return message.to_string();
            }
        }
    }
    String::new()
}

fn truncate_response_body(body: &str) -> String {
    const MAX_CHARS: usize = 400;
    let body = body.trim();
    if body.chars().count() <= MAX_CHARS {
        return body.to_string();
    }
    let truncated = body.chars().take(MAX_CHARS).collect::<String>();
    format!("{truncated}...")
}

fn insert_cookie_header(store: &mut CookieStore, url: &Url, cookie_header: &str) -> Result<()> {
    for raw_pair in cookie_header.split(';') {
        let pair = raw_pair.trim();
        if pair.is_empty() {
            continue;
        }

        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };

        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            continue;
        }

        store.insert_raw(&RawCookie::new(name.to_string(), value.to_string()), url)?;
    }

    Ok(())
}

fn extract_cookie_value(cookie_header: &str, name: &str) -> Option<String> {
    cookie_header.split(';').find_map(|raw_pair| {
        let pair = raw_pair.trim();
        let (cookie_name, value) = pair.split_once('=')?;
        (cookie_name.trim() == name).then(|| value.trim().to_string())
    })
}

fn non_empty_str(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn extract_header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn extract_header_by_suffix(headers: &HeaderMap, suffix: &str) -> Option<String> {
    headers.iter().find_map(|(name, value)| {
        name.as_str()
            .ends_with(suffix)
            .then(|| value.to_str().ok().map(str::trim).filter(|v| !v.is_empty()))
            .flatten()
            .map(ToOwned::to_owned)
    })
}

fn fill_auth_response_from_headers(
    mut auth_resp: ServiceLoginAuthRespone,
    headers: &HeaderMap,
) -> ServiceLoginAuthRespone {
    if auth_resp.pass_token.trim().is_empty() {
        if let Some(pass_token) = extract_header_value(headers, "passToken") {
            auth_resp.pass_token = pass_token;
        }
    }

    if auth_resp.c_user_id.trim().is_empty() {
        if let Some(c_user_id) = extract_header_value(headers, "cUserId") {
            auth_resp.c_user_id = c_user_id;
        }
    }

    if auth_resp.user_id == 0 {
        if let Some(user_id) =
            extract_header_value(headers, "userId").and_then(|user_id| user_id.parse::<u64>().ok())
        {
            auth_resp.user_id = user_id;
        }
    }

    if let Some(extension_pragma) = extract_header_value(headers, "Extension-Pragma")
        .or_else(|| extract_header_value(headers, "extension-pragma"))
    {
        if let Ok(extension_json) = serde_json::from_str::<serde_json::Value>(&extension_pragma) {
            if auth_resp.ssecurity.trim().is_empty() {
                if let Some(ssecurity) = extension_json
                    .get("ssecurity")
                    .and_then(|value| value.as_str())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    auth_resp.ssecurity = ssecurity.to_string();
                }
            }

            if auth_resp.psecurity.trim().is_empty() {
                if let Some(psecurity) = extension_json
                    .get("psecurity")
                    .and_then(|value| value.as_str())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    auth_resp.psecurity = psecurity.to_string();
                }
            }

            if auth_resp.nonce == 0 {
                if let Some(nonce) = extension_json.get("nonce").and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
                }) {
                    auth_resp.nonce = nonce;
                }
            }
        }
    }

    auth_resp
}

fn seed_xiaomi_login_cookies(
    cookie_store: &Arc<CookieStoreMutex>,
    sdk_version: &str,
    device_id: &str,
    cookie_header: Option<&str>,
    fallback_user_id: Option<&str>,
) -> Result<()> {
    let provided_user_id = cookie_header.and_then(|cookie_header| {
        extract_cookie_value(cookie_header, "userId").filter(|user_id| !user_id.trim().is_empty())
    });

    if let Some(user_id) = provided_user_id.as_deref() {
        log::info!(
            "[MiAccount.Login] using userId from seeded cookie: {}",
            user_id
        );
    }

    for domain in [
        "https://mi.com",
        "https://xiaomi.com",
        "https://account.xiaomi.com",
    ] {
        let url = Url::parse(domain)?;
        let mut store = cookie_store.lock().unwrap();
        store.insert_raw(&RawCookie::new("sdkVersion", sdk_version), &url)?;
        store.insert_raw(&RawCookie::new("deviceId", device_id.to_string()), &url)?;

        if domain.contains("xiaomi.com") {
            if provided_user_id.is_none() {
                if let Some(fallback_user_id) = fallback_user_id {
                    let raw = RawCookie::parse(format!(
                        "userId={fallback_user_id}; Domain=.xiaomi.com; Path=/"
                    ))?;
                    store.insert_raw(&raw, &url)?;
                }
            }

            if let Some(cookie_header) = cookie_header {
                insert_cookie_header(&mut store, &url, cookie_header)?;
            }
        }
    }

    Ok(())
}

/// SHA-256( ssecurity_b64_dec + nonce_b64_dec ) → Base64.
fn calc_signed_nonce(ssecurity: &str, nonce: &str) -> Result<String> {
    let mut hasher = Sha256::default();
    hasher.update(&general_purpose::STANDARD.decode(ssecurity)?);
    hasher.update(&general_purpose::STANDARD.decode(nonce)?);
    Ok(general_purpose::STANDARD.encode(hasher.finalize()))
}

/// Deterministic Xiaomi signature builder (ASCII sort on keys).
fn generate_enc_signature(
    url_path: &str,
    method: &str,
    signed_nonce: &str,
    params: &HashMap<String, String>,
) -> String {
    let mut keys: Vec<&String> = params.keys().collect();
    keys.sort(); // ASCII order
    let mut pieces = Vec::with_capacity(2 + keys.len() + 1);
    pieces.push(method.to_uppercase());
    pieces.push(url_path.to_owned());
    for k in keys {
        pieces.push(format!("{k}={}", params.get(k).unwrap()));
    }
    pieces.push(signed_nonce.to_owned());

    let raw = pieces.join("&");
    let mut sha1 = Sha1::default();
    sha1.update(raw.as_bytes());
    general_purpose::STANDARD.encode(sha1.finalize())
}

fn generate_client_sign(nonce: u64, ssecurity: &str) -> String {
    let raw = format!("nonce={nonce}&{ssecurity}");
    let mut sha1 = Sha1::default();
    sha1.update(raw.as_bytes());
    general_purpose::STANDARD.encode(sha1.finalize())
}

/// Encrypt payload parameters with RC4, respecting deterministic key order.
fn rc4_encrypt_params(
    signed_nonce: &str,
    params_plain: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    // Build a cipher, drop first 1024 bytes.
    let key_bytes = general_purpose::STANDARD.decode(signed_nonce)?;
    let key = rc4::Key::<U32>::from_slice(&key_bytes);
    let mut cipher = Rc4::<U32>::new(key);
    let mut drop_buf = [0u8; 1024];
    cipher.apply_keystream(&mut drop_buf);

    // Encrypt in deterministic order.
    let mut keys: Vec<&String> = params_plain.keys().collect();
    keys.sort(); // ASCII order

    let mut encrypted = HashMap::new();
    for k in keys {
        let mut data = params_plain.get(k).unwrap().as_bytes().to_vec();
        cipher.apply_keystream(&mut data);
        encrypted.insert(k.to_string(), general_purpose::STANDARD.encode(data));
    }
    Ok(encrypted)
}

fn resolve_service_signature_path(path: &str, path_prefix: &str) -> String {
    let trimmed_prefix = path_prefix.trim();
    let mut subpath = if trimmed_prefix.is_empty() {
        match path.find('/') {
            Some(index) => path[index..].to_string(),
            None => path.to_string(),
        }
    } else if let Some(index) = path.find(trimmed_prefix) {
        path[index + trimmed_prefix.len()..].to_string()
    } else {
        path.to_string()
    };

    if !subpath.starts_with('/') {
        subpath.insert(0, '/');
    }
    subpath
}

async fn mi_service_call_encrypted_internal(
    token: MiAccountToken,
    path_prefix: String,
    url: String,
    mut signed_form_params: HashMap<String, String>,
    passthrough_form_params: HashMap<String, String>,
    query_params: HashMap<String, String>,
    ua: String,
    cookie_locale: Option<String>,
) -> Result<String> {
    let client = crate::net::default_client_builder().build()?;

    let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let nonce = generate_nonce(millis);
    let signed_nonce = calc_signed_nonce(&token.ssecurity, &nonce)?;

    let url_parsed = Url::parse(&url)?;
    let url_path = resolve_service_signature_path(url_parsed.path(), &path_prefix);

    let rc4_hash = generate_enc_signature(&url_path, "POST", &signed_nonce, &signed_form_params);
    signed_form_params.insert("rc4_hash__".to_string(), rc4_hash);

    let mut encrypted_params = rc4_encrypt_params(&signed_nonce, &signed_form_params)?;
    let signature = generate_enc_signature(&url_path, "POST", &signed_nonce, &encrypted_params);
    encrypted_params.insert("signature".into(), signature);
    encrypted_params.insert("_nonce".into(), nonce.clone());

    let mut form_params = passthrough_form_params;
    form_params.extend(encrypted_params);

    let mut headers = HeaderMap::new();
    headers.insert("User-Agent", HeaderValue::from_str(&ua)?);
    headers.insert("region_tag", HeaderValue::from_static("cn"));
    headers.insert("HandleParams", HeaderValue::from_static("true"));

    let mut cookie_parts = vec![
        "sdkVersion=accountsdk-18.8.15".to_string(),
        format!(
            "locale={}",
            cookie_locale
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("en_us")
        ),
    ];
    if !token.device_id.trim().is_empty() {
        cookie_parts.push(format!("deviceId={}", token.device_id));
    }
    if !token.user_id.trim().is_empty() {
        cookie_parts.push(format!("userId={}", token.user_id));
    }
    if !token.c_user_id.trim().is_empty() {
        cookie_parts.push(format!("cUserId={}", token.c_user_id));
    }
    cookie_parts.push(format!("serviceToken={}", token.service_token));
    let cookie_header = cookie_parts.join("; ");

    let response = client
        .post(url)
        .headers(headers)
        .header("Cookie", cookie_header)
        .query(&query_params)
        .form(&form_params)
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(anyhow!("Mi API call failed: {}, body: {}", status, body));
    }

    let key_bytes = general_purpose::STANDARD.decode(&signed_nonce)?;
    let key = rc4::Key::<U32>::from_slice(&key_bytes);
    let mut cipher = Rc4::<U32>::new(key);
    let mut drop_buf = [0u8; 1024];
    cipher.apply_keystream(&mut drop_buf);

    let mut data = general_purpose::STANDARD.decode(body.trim_matches('"'))?;
    cipher.apply_keystream(&mut data);
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// Main encrypted API call.
/// `prefix` – path prefix that should be trimmed before signing (usually "").
pub async fn mi_service_call_encrypted(
    token: MiAccountToken,
    prefix: String,
    url: String,
    params_plain: HashMap<String, String>,
    ua: String,
) -> Result<String> {
    mi_service_call_encrypted_internal(
        token,
        prefix,
        url,
        params_plain,
        HashMap::new(),
        HashMap::new(),
        ua,
        None,
    )
    .await
}

pub async fn fetch_mi_user_core_info(
    token: MiAccountToken,
    locale: Option<String>,
) -> Result<MiUserCoreInfo> {
    let locale = locale
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "en_US".to_string());
    let mut params = HashMap::new();
    params.insert("userId".to_string(), token.user_id.clone());
    params.insert("transId".to_string(), random_request_id(15));
    params.insert("flags".to_string(), "11".to_string());

    let mut encrypted_params = HashMap::new();
    for (key, value) in params {
        encrypted_params.insert(key, aes_encrypt_base64(&token.ssecurity, &value)?);
    }
    let signature = generate_account_signature(
        "GET",
        "https://api.account.xiaomi.com/pass/v2/safe/user/coreInfo",
        &encrypted_params,
        &token.ssecurity,
    )?;
    encrypted_params.insert("signature".to_string(), signature);

    let mut cookie_parts = vec![
        format!("serviceToken={}", token.service_token),
        format!("uLocale={locale}"),
    ];
    if !token.c_user_id.trim().is_empty() {
        cookie_parts.push(format!("cUserId={}", token.c_user_id));
    } else if !token.user_id.trim().is_empty() {
        cookie_parts.push(format!("userId={}", token.user_id));
    }
    if !token.device_id.trim().is_empty() {
        cookie_parts.push(format!("deviceId={}", token.device_id));
    }

    let response = crate::net::default_client_builder()
        .build()?
        .get("https://api.account.xiaomi.com/pass/v2/safe/user/coreInfo")
        .header("Cookie", cookie_parts.join("; "))
        .query(&encrypted_params)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "fetch mi user core info failed: {}, body: {}",
            status,
            body
        ));
    }

    let decrypted_body = aes_decrypt_base64(&token.ssecurity, body.trim())?;
    let payload: serde_json::Value = serde_json::from_str(&decrypted_body)?;
    let code = parse_response_code(&payload);
    if code != 0 {
        return Err(anyhow!(
            "fetch mi user core info failed: code={}, msg={}",
            code,
            parse_response_message(&payload)
        ));
    }

    let data = payload
        .get("data")
        .and_then(|value| value.as_object())
        .ok_or_else(|| anyhow!("mi user core info missing data field"))?;

    let mut profile = MiUserCoreInfo {
        user_id: data
            .get("userId")
            .and_then(|value| value.as_str())
            .unwrap_or(token.user_id.as_str())
            .to_string(),
        user_name: data
            .get("userName")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        nick_name: data
            .get("nickName")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        avatar_address: data
            .get("icon")
            .and_then(|value| value.as_str())
            .map(append_avatar_size_suffix)
            .unwrap_or_default(),
        locale: data
            .get("locale")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        region: data
            .get("region")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        ..Default::default()
    };

    if let Some(addresses) = data.get("userAddresses").and_then(|value| value.as_array()) {
        for address in addresses {
            let Some(address_type) = address.get("addressType").and_then(|value| {
                value
                    .as_i64()
                    .or_else(|| value.as_str()?.parse::<i64>().ok())
            }) else {
                continue;
            };
            let Some(raw_address) = address.get("address").and_then(|value| value.as_str()) else {
                continue;
            };
            let flags = address
                .get("flags")
                .and_then(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_str()?.parse::<i64>().ok())
                })
                .unwrap_or(0);
            let is_primary = (flags & 2) != 0;

            match address_type {
                1 if is_primary => {
                    profile.safe_phone = raw_address.to_string();
                }
                2 if is_primary => {
                    profile.email_address = raw_address.to_string();
                }
                9 => {
                    profile.nick_name = raw_address
                        .strip_suffix("@ALIAS")
                        .unwrap_or(raw_address)
                        .to_string();
                }
                _ => {}
            }
        }
    }

    Ok(profile)
}

pub async fn fetch_mi_latest_version(
    token: MiAccountToken,
    did: String,
    model: String,
    app_level: u64,
    firmware_version: String,
    locale: String,
    ua: String,
) -> Result<MiLatestVersion> {
    let mut signed_form = HashMap::new();
    signed_form.insert(
        "data".to_string(),
        serde_json::json!({
            "did": did,
            "model": model,
            "platform": "a",
            "app_level": app_level.to_string(),
            "fw_ver": firmware_version,
            "channel": "prod",
        })
        .to_string(),
    );

    let mut query = HashMap::new();
    query.insert("locale".to_string(), locale.clone());

    let body = mi_service_call_encrypted_internal(
        token,
        "/healthapp/".to_string(),
        "https://hlth.io.mi.com/healthapp/device/latest_ver".to_string(),
        signed_form,
        HashMap::new(),
        query,
        ua,
        Some(locale.clone()),
    )
    .await?;

    let payload: serde_json::Value = serde_json::from_str(&body)?;
    let code = parse_response_code(&payload);
    if code != 0 && code != 200 {
        return Err(anyhow!(
            "fetch mi latest version failed: code={}, msg={}",
            code,
            parse_response_message(&payload)
        ));
    }

    let result = payload
        .get("result")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    serde_json::from_value(result).map_err(|err| anyhow!("decode mi latest version failed: {err}"))
}

async fn fetch_mi_watchface_result<T: DeserializeOwned>(
    token: MiAccountToken,
    endpoint: &str,
    data: serde_json::Value,
    ua: String,
) -> Result<T> {
    let mut signed_form = HashMap::new();
    signed_form.insert("data".to_string(), data.to_string());

    let body = mi_service_call_encrypted_internal(
        token,
        "".to_string(),
        format!("https://watch.iot.mi.com/ops/v1/{endpoint}"),
        signed_form,
        HashMap::new(),
        HashMap::new(),
        ua,
        None,
    )
    .await
    .with_context(|| format!("request mi watchface `{endpoint}` failed"))?;

    let payload: serde_json::Value = serde_json::from_str(&body).with_context(|| {
        format!(
            "decode mi watchface `{endpoint}` payload failed, body={}",
            truncate_response_body(&body)
        )
    })?;
    let code = parse_response_code(&payload);
    if code != 0 && code != 200 {
        return Err(anyhow!(
            "fetch mi watchface `{endpoint}` failed: code={}, msg={}, body={}",
            code,
            parse_response_message(&payload),
            truncate_response_body(&body)
        ));
    }

    let result = payload
        .get("result")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    serde_json::from_value(result).map_err(|err| {
        anyhow!(
            "decode mi watchface `{endpoint}` result failed: {err}, body={}",
            truncate_response_body(&body)
        )
    })
}

pub async fn fetch_mi_watchface_index(
    token: MiAccountToken,
    model: String,
    firmware_version: Option<String>,
    page: Option<u32>,
    size: Option<u32>,
    ua: String,
) -> Result<MiWatchfaceIndexResult> {
    fetch_mi_watchface_result(
        token,
        "paidwatchface/index",
        serde_json::json!({
            "model": model,
            "firmware_version": firmware_version,
            "page": page,
            "size": size,
        }),
        ua,
    )
    .await
}

pub async fn fetch_mi_watchface_detail(
    token: MiAccountToken,
    model: String,
    id: String,
    firmware_version: String,
    ua: String,
) -> Result<MiWatchfaceDetailResult> {
    fetch_mi_watchface_result(
        token,
        "paidwatchface/detail",
        serde_json::json!({
            "model": model,
            "id": id,
            "firmware_version": firmware_version,
            "ids": [],
        }),
        ua,
    )
    .await
}

pub async fn fetch_mi_watchface_download(
    token: MiAccountToken,
    did: String,
    model: String,
    id: String,
    is_trial: bool,
    album_child_id: Option<String>,
    ua: String,
) -> Result<MiWatchfaceDownloadResult> {
    fetch_mi_watchface_result(
        token,
        "paidwatchface/download",
        serde_json::json!({
            "did": did,
            "model": model,
            "id": id,
            "is_trial": is_trial,
            "album_child_id": album_child_id,
        }),
        ua,
    )
    .await
}

pub async fn report_mi_device_info(
    token: MiAccountToken,
    did: String,
    firmware_version: String,
    ua: String,
) -> Result<()> {
    let mut signed_form = HashMap::new();
    signed_form.insert(
        "data".to_string(),
        serde_json::json!({
            "did": did,
            "fw_ver": firmware_version,
        })
        .to_string(),
    );

    let body = mi_service_call_encrypted_internal(
        token,
        "/healthapp/".to_string(),
        "https://hlth.io.mi.com/healthapp/device/bledevice_info".to_string(),
        signed_form,
        HashMap::new(),
        HashMap::new(),
        ua,
        None,
    )
    .await?;

    let payload: serde_json::Value = serde_json::from_str(&body)?;
    let code = parse_response_code(&payload);
    if code != 0 && code != 200 {
        return Err(anyhow!(
            "report mi device info failed: code={}, msg={}",
            code,
            parse_response_message(&payload)
        ));
    }

    Ok(())
}

pub fn compare_firmware_versions(latest_version: &str, current_version: &str) -> i32 {
    fn parse_triplet(input: &str) -> Option<[u64; 3]> {
        let mut parts = input.trim().split('.');
        let major = parts.next()?.parse::<u64>().ok()?;
        let minor = parts.next()?.parse::<u64>().ok()?;
        let patch = parts.next()?.parse::<u64>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some([major, minor, patch])
    }

    let Some(latest) = parse_triplet(latest_version) else {
        return 0;
    };
    let Some(current) = parse_triplet(current_version) else {
        return 0;
    };

    for index in 0..3 {
        if latest[index] > current[index] {
            return 1;
        }
        if latest[index] < current[index] {
            return -1;
        }
    }

    0
}

/// Log in and obtain `MiAccountToken`.
pub async fn login_mi_account(
    username: String,
    password: String,
    ua: String,
) -> Result<MiAccountToken> {
    login_mi_account_with_options(username, password, ua, None, None).await
}

/// Log in and obtain `MiAccountToken`, optionally seeding extra cookies for Xiaomi domains.
pub async fn login_mi_account_with_cookie(
    username: String,
    password: String,
    ua: String,
    cookie_header: Option<String>,
) -> Result<MiAccountToken> {
    login_mi_account_with_options(username, password, ua, cookie_header, None).await
}

/// Log in and obtain `MiAccountToken`, optionally seeding extra cookies and reusing a device id.
pub async fn login_mi_account_with_options(
    username: String,
    password: String,
    ua: String,
    cookie_header: Option<String>,
    device_id: Option<String>,
) -> Result<MiAccountToken> {
    let cookie_device_id = cookie_header
        .as_deref()
        .and_then(|cookie_header| extract_cookie_value(cookie_header, "deviceId"));
    if let (Some(explicit_device_id), Some(cookie_device_id)) =
        (device_id.as_ref(), cookie_device_id.as_ref())
    {
        if explicit_device_id != cookie_device_id {
            log::warn!(
                "[MiAccount.Login] explicit device_id={} differs from cookie deviceId={}",
                explicit_device_id,
                cookie_device_id
            );
        }
    }
    let device_id = device_id
        .or(cookie_device_id)
        .unwrap_or_else(random_device_id);
    let sdk_version = "accountsdk-18.8.15";

    log::info!(
        "[MiAccount.Login] begin username={} device_id={} retry_with_cookie={}",
        username,
        device_id,
        cookie_header.is_some()
    );
    if let Some(cookie_header) = cookie_header.as_deref() {
        log::info!(
            "[MiAccount.Login] retry cookie header for account.xiaomi.com: {}",
            cookie_header
        );
    }

    let cookie_store = Arc::new(CookieStoreMutex::new(CookieStore::default()));
    let client = crate::net::default_client_builder()
        .cookie_provider(cookie_store.clone())
        .build()?;
    seed_xiaomi_login_cookies(
        &cookie_store,
        sdk_version,
        &device_id,
        cookie_header.as_deref(),
        Some(&username),
    )?;

    // --- Step 1: get _sign ---
    let step1 = client
        .get("https://account.xiaomi.com/pass/serviceLogin?sid=miothealth&_json=true")
        .header("User-Agent", ua.clone())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await?;
    let step1_headers = step1.headers().clone();

    if step1.status() != 200 {
        return Err(anyhow!("serviceLogin failed: {}", step1.status()));
    }
    let step1_body = strip_prefix(&step1.text().await?).to_string();
    let sign_resp: ServiceLoginRespone = serde_json::from_str(&step1_body)?;
    let sign = sign_resp.sign;

    log::info!(
        "[MiAccount.Login] serviceLogin succeeded for username={} device_id={} sign_present={}",
        username,
        device_id,
        !sign.is_empty()
    );

    if sign.is_empty() {
        let auth_resp: ServiceLoginAuthRespone = serde_json::from_str(&step1_body).map_err(|err| {
            anyhow!(
                "serviceLogin returned payload without _sign and failed to parse authenticated session: {}; body={}",
                err,
                step1_body
            )
        })?;
        let auth_resp = fill_auth_response_from_headers(auth_resp, &step1_headers);

        log::info!(
            "[MiAccount.Login] serviceLogin returned authenticated session directly code={} description={} notification_url={:?} device_id={} ssecurity_present={} c_user_id_present={} nonce={}",
            auth_resp.code,
            auth_resp.description,
            auth_resp.notification_url,
            device_id,
            !auth_resp.ssecurity.trim().is_empty(),
            !auth_resp.c_user_id.trim().is_empty(),
            auth_resp.nonce
        );

        return finish_login_with_auth_response(
            &client,
            &cookie_store,
            auth_resp,
            ua,
            &username,
            &device_id,
        )
        .await;
    }

    // --- Step 2: serviceLoginAuth2 ---
    let mut md5 = Md5::default();
    md5.update(password.as_bytes());
    let pwd_hash = format!("{:x}", md5.finalize()).to_uppercase();

    let mut fields = HashMap::<&str, &str>::new();
    fields.insert("sid", "miothealth");
    fields.insert("hash", &pwd_hash);
    fields.insert("callback", "https://sts-hlth.io.mi.com/healthapp/sts");
    fields.insert("qs", "%3Fsid%3Dmiothealth%26_json%3Dtrue");
    fields.insert("user", &username);
    fields.insert("_sign", &sign);
    fields.insert("_json", "true");

    let step2 = client
        .post("https://account.xiaomi.com/pass/serviceLoginAuth2")
        .header("User-Agent", ua.to_owned())
        .form(&fields)
        .send()
        .await?;
    let step2_headers = step2.headers().clone();

    if step2.status() != 200 {
        return Err(anyhow!("serviceLoginAuth2 failed: {}", step2.status()));
    }

    let auth_resp: ServiceLoginAuthRespone =
        serde_json::from_str(strip_prefix(&step2.text().await?))?;
    let auth_resp = fill_auth_response_from_headers(auth_resp, &step2_headers);

    log::info!(
        "[MiAccount.Login] serviceLoginAuth2 code={} description={} notification_url={:?} device_id={} ssecurity_present={} c_user_id_present={} nonce={}",
        auth_resp.code,
        auth_resp.description,
        auth_resp.notification_url,
        device_id,
        !auth_resp.ssecurity.trim().is_empty(),
        !auth_resp.c_user_id.trim().is_empty(),
        auth_resp.nonce
    );

    finish_login_with_auth_response(&client, &cookie_store, auth_resp, ua, &username, &device_id)
        .await
}

pub async fn fetch_2fa_session_with_cookie(
    ua: String,
    cookie_header: String,
    device_id: Option<String>,
) -> Result<ServiceLoginAuthRespone> {
    let cookie_device_id = extract_cookie_value(&cookie_header, "deviceId");
    if let (Some(explicit_device_id), Some(cookie_device_id)) =
        (device_id.as_ref(), cookie_device_id.as_ref())
    {
        if explicit_device_id != cookie_device_id {
            log::warn!(
                "[MiAccount.Login] explicit device_id={} differs from cookie deviceId={}",
                explicit_device_id,
                cookie_device_id
            );
        }
    }
    let device_id = device_id
        .or(cookie_device_id)
        .unwrap_or_else(random_device_id);
    let sdk_version = "accountsdk-18.8.15";

    log::info!(
        "[MiAccount.Login] refreshing verified 2FA session from cookie device_id={} cookie_len={}",
        device_id,
        cookie_header.len()
    );

    let cookie_store = Arc::new(CookieStoreMutex::new(CookieStore::default()));
    let client = crate::net::default_client_builder()
        .cookie_provider(cookie_store.clone())
        .build()?;

    seed_xiaomi_login_cookies(
        &cookie_store,
        sdk_version,
        &device_id,
        Some(cookie_header.as_str()),
        None,
    )?;

    let step1 = client
        .get("https://account.xiaomi.com/pass/serviceLogin?sid=miothealth&_json=true")
        .header("User-Agent", ua)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await?;
    let step1_headers = step1.headers().clone();

    if step1.status() != 200 {
        return Err(anyhow!(
            "verified 2FA session serviceLogin failed: {}",
            step1.status()
        ));
    }

    let step1_body = strip_prefix(&step1.text().await?).to_string();
    let sign_resp: ServiceLoginRespone = serde_json::from_str(&step1_body)?;
    if !sign_resp.sign.is_empty() {
        log::warn!(
            "[MiAccount.Login] verified 2FA cookie still returned _sign device_id={}",
            device_id
        );
        return Err(anyhow!(
            "verified 2FA cookie session still requires credential step"
        ));
    }

    let auth_resp: ServiceLoginAuthRespone = serde_json::from_str(&step1_body).map_err(|err| {
        anyhow!(
            "verified 2FA session parse failed: {}; body={}",
            err,
            step1_body
        )
    })?;
    let auth_resp = fill_auth_response_from_headers(auth_resp, &step1_headers);

    log::info!(
        "[MiAccount.Login] fetched verified 2FA session code={} ssecurity_present={} notification_url={:?} device_id={}",
        auth_resp.code,
        !auth_resp.ssecurity.trim().is_empty(),
        auth_resp.notification_url,
        device_id
    );

    if auth_resp.code != 0 {
        return Err(anyhow!(
            "verified 2FA session invalid: code={}, description={}",
            auth_resp.code,
            auth_resp.description
        ));
    }

    if let Some(url) = auth_resp
        .notification_url
        .as_deref()
        .and_then(non_empty_str)
    {
        return Err(anyhow!("verified 2FA cookie still requires 2FA: {}", url));
    }

    if auth_resp.ssecurity.trim().is_empty() {
        return Err(anyhow!("verified 2FA session missing ssecurity"));
    }

    Ok(auth_resp)
}

pub async fn fetch_notification_auth_result(
    sts_url: String,
    ua: String,
    cookie_header: Option<String>,
) -> Result<MiNotificationAuthResult> {
    log::info!(
        "[MiAccount.Login] fetching notification auth result from sts url={}",
        sts_url
    );

    let client = crate::net::default_client_builder().build()?;
    let mut request = client.get(&sts_url).header("User-Agent", ua);
    if let Some(cookie_header) = cookie_header.filter(|value| !value.trim().is_empty()) {
        log::info!(
            "[MiAccount.Login] attaching verified 2FA cookie header to notification auth request len={}",
            cookie_header.len()
        );
        request = request.header("Cookie", cookie_header);
    }
    let response = request.send().await?;
    let headers = response.headers().clone();
    let status = response.status();
    let body = response.text().await?;

    if !status.is_success() {
        return Err(anyhow!(
            "notification auth sts request failed: {}, body: {}",
            status,
            body
        ));
    }

    let service_token = extract_header_value(&headers, "serviceToken")
        .or_else(|| extract_header_by_suffix(&headers, "_serviceToken"))
        .ok_or_else(|| anyhow!("notification auth response missing serviceToken header"))?;
    let user_id = extract_header_value(&headers, "userId").unwrap_or_default();
    let psecurity_ph = extract_header_value(&headers, "passportsecurity_ph")
        .or_else(|| extract_header_by_suffix(&headers, "_ph"))
        .unwrap_or_default();
    let psecurity_slh = extract_header_value(&headers, "passportsecurity_slh")
        .or_else(|| extract_header_by_suffix(&headers, "_slh"))
        .unwrap_or_default();

    log::info!(
        "[MiAccount.Login] notification auth result user_id={} service_token_len={} ph_present={} slh_present={}",
        user_id,
        service_token.len(),
        !psecurity_ph.is_empty(),
        !psecurity_slh.is_empty()
    );

    Ok(MiNotificationAuthResult {
        user_id,
        service_token,
        psecurity_ph,
        psecurity_slh,
    })
}

pub async fn complete_2fa_login_with_sts_url(
    ssecurity: String,
    c_user_id: String,
    sts_url: String,
    nonce: u64,
    ua: String,
    cookie_header: Option<String>,
) -> Result<MiAccountToken> {
    if sts_url.trim().is_empty() {
        return Err(anyhow!("2FA sts url missing"));
    }
    if ssecurity.trim().is_empty() {
        return Err(anyhow!("2FA ssecurity missing"));
    }
    if nonce == 0 {
        return Err(anyhow!("2FA nonce missing"));
    }

    let client_sign = generate_client_sign(nonce, &ssecurity);
    let user_id = cookie_header
        .as_deref()
        .and_then(|cookie_header| extract_cookie_value(cookie_header, "userId"))
        .unwrap_or_default();
    let device_id = cookie_header
        .as_deref()
        .and_then(|cookie_header| extract_cookie_value(cookie_header, "deviceId"))
        .unwrap_or_default();
    let request_cookie_header = cookie_header
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .cloned();
    log::info!(
        "[MiAccount.Login] finalizing 2FA session through sts url nonce={} c_user_id={} url={}",
        nonce,
        c_user_id,
        sts_url
    );

    let client = crate::net::default_client_builder().build()?;
    let mut request = client
        .get(&sts_url)
        .query(&[
            ("clientSign", client_sign.as_str()),
            ("_userIdNeedEncrypt", "true"),
        ])
        .header("User-Agent", ua);
    if let Some(cookie_header) = request_cookie_header {
        log::info!(
            "[MiAccount.Login] attaching verified 2FA cookie header to sts finalize request len={}",
            cookie_header.len()
        );
        request = request.header("Cookie", cookie_header);
    }
    let response = request.send().await?;
    let headers = response.headers().clone();
    let status = response.status();
    let body = response.text().await?;

    if !status.is_success() {
        return Err(anyhow!(
            "2FA sts url finalize failed: {}, body: {}",
            status,
            body
        ));
    }

    let service_token = extract_header_value(&headers, "serviceToken")
        .or_else(|| extract_header_by_suffix(&headers, "_serviceToken"))
        .ok_or_else(|| anyhow!("serviceToken header missing after sts finalize"))?;

    log::info!(
        "[MiAccount.Login] 2FA sts url finalized service_token_len={} c_user_id={}",
        service_token.len(),
        c_user_id
    );

    Ok(MiAccountToken {
        user_id,
        device_id,
        ssecurity,
        service_token,
        c_user_id,
    })
}

pub async fn complete_2fa_login_with_cookie(
    ssecurity: String,
    c_user_id: String,
    location: String,
    ua: String,
    cookie_header: String,
    device_id: Option<String>,
) -> Result<MiAccountToken> {
    let sdk_version = "accountsdk-18.8.15";
    let device_id = device_id
        .or_else(|| extract_cookie_value(&cookie_header, "deviceId"))
        .unwrap_or_else(random_device_id);

    log::info!(
        "[MiAccount.Login] finalizing 2FA session with cookie device_id={} c_user_id={} location={}",
        device_id,
        c_user_id,
        location
    );

    if location.trim().is_empty() {
        return Err(anyhow!("2FA location missing"));
    }

    let cookie_store = Arc::new(CookieStoreMutex::new(CookieStore::default()));
    let client = crate::net::default_client_builder()
        .cookie_provider(cookie_store.clone())
        .build()?;

    for domain in [
        "https://mi.com",
        "https://xiaomi.com",
        "https://account.xiaomi.com",
        "https://sts-hlth.io.mi.com",
    ] {
        let url = Url::parse(domain)?;
        let mut store = cookie_store.lock().unwrap();
        store.insert_raw(&RawCookie::new("sdkVersion", sdk_version), &url)?;
        store.insert_raw(&RawCookie::new("deviceId", device_id.clone()), &url)?;
        if domain.contains("xiaomi.com") {
            insert_cookie_header(&mut store, &url, &cookie_header)?;
        }
    }

    let step3 = client
        .get(&location)
        .header("User-Agent", ua)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await?;

    let status = step3.status();
    let body = step3.text().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "2FA location redirect failed: {}, body: {}",
            status,
            body
        ));
    }

    let store = cookie_store.lock().unwrap();
    let service_token = store
        .get("sts-hlth.io.mi.com", "/", "serviceToken")
        .map(|ck| ck.value().to_string())
        .ok_or_else(|| anyhow!("serviceToken cookie missing after 2FA finalize"))?;

    log::info!(
        "[MiAccount.Login] 2FA session finalized device_id={} service_token_len={}",
        device_id,
        service_token.len()
    );

    Ok(MiAccountToken {
        user_id: extract_cookie_value(&cookie_header, "userId").unwrap_or_default(),
        device_id,
        ssecurity,
        service_token,
        c_user_id,
    })
}

async fn finish_login_with_auth_response(
    client: &reqwest::Client,
    cookie_store: &Arc<CookieStoreMutex>,
    auth_resp: ServiceLoginAuthRespone,
    ua: String,
    username: &str,
    device_id: &str,
) -> Result<MiAccountToken> {
    if auth_resp.code != 0 || auth_resp.ssecurity.is_empty() {
        match auth_resp.code {
            0 => {}
            70016 => return Err(anyhow!("登录失败：用户名或密码错误")),
            _ => {
                return Err(anyhow!(
                    "未知错误：serviceLoginAuth error: code={}, description={}",
                    auth_resp.code,
                    auth_resp.description
                ));
            }
        }
    }

    if let Some(url) = auth_resp
        .notification_url
        .as_deref()
        .and_then(non_empty_str)
    {
        log::warn!(
            "[MiAccount.Login] 2FA required for username={} device_id={} url={}",
            username,
            device_id,
            url
        );
        return Err(anyhow!(
            "2-f-a={}\ndevice-id={}\nssecurity={}\nc-user-id={}\nlocation={}\nnonce={}\npsecurity={}\npass-token={}",
            url,
            device_id,
            auth_resp.ssecurity,
            auth_resp.c_user_id,
            auth_resp.location,
            auth_resp.nonce,
            auth_resp.psecurity,
            auth_resp.pass_token
        ));
    }

    let step3 = client
        .get(&auth_resp.location)
        .header("User-Agent", ua)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await?;

    if step3.status() != 200 {
        return Err(anyhow!("location redirect failed: {}", step3.status()));
    }

    let store = cookie_store.lock().unwrap();
    let service_token = store
        .get("sts-hlth.io.mi.com", "/", "serviceToken")
        .map(|ck| ck.value().to_string())
        .ok_or_else(|| anyhow!("serviceToken cookie missing"))?;

    log::info!(
        "[MiAccount.Login] login completed username={} device_id={} c_user_id={} service_token_len={}",
        username,
        device_id,
        auth_resp.c_user_id,
        service_token.len()
    );

    Ok(MiAccountToken {
        user_id: auth_resp.user_id.to_string(),
        device_id: device_id.to_string(),
        ssecurity: auth_resp.ssecurity,
        service_token,
        c_user_id: auth_resp.c_user_id,
    })
}
