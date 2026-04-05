use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose;
use cipher::StreamCipher;
use md5::Md5;
use rand::{Rng, distributions::Uniform, rngs::OsRng};
use rc4::{KeyInit, Rc4, consts::U32};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest_cookie_store::{CookieStore, CookieStoreMutex, RawCookie};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use url::Url;

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

/// Main encrypted API call.
/// `prefix` – path prefix that should be trimmed before signing (usually "")
pub async fn mi_service_call_encrypted(
    token: MiAccountToken,
    prefix: String,
    url: String,
    mut params_plain: HashMap<String, String>,
    ua: String,
) -> Result<String> {
    let client = crate::net::default_client_builder().build()?;

    let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let nonce = generate_nonce(millis);
    let signed_nonce = calc_signed_nonce(&token.ssecurity, &nonce)?;

    // Path for signature
    let url_parsed = Url::parse(&url)?;
    let url_path = url_parsed.path().trim_start_matches(&prefix).to_string();

    // 1. rc4_hash__ over *plain* params
    let rc4_hash = generate_enc_signature(&url_path, "POST", &signed_nonce, &params_plain);
    params_plain.insert("rc4_hash__".to_string(), rc4_hash);

    // 2. RC4-encrypt all fields
    let mut params_enc = rc4_encrypt_params(&signed_nonce, &params_plain)?;

    // 3. Final signature & nonce
    let sig = generate_enc_signature(&url_path, "POST", &signed_nonce, &params_enc);
    params_enc.insert("signature".into(), sig);
    params_enc.insert("_nonce".into(), nonce.clone());

    // 4. Headers & cookies
    let mut headers = HeaderMap::new();
    headers.insert("User-Agent", HeaderValue::from_str(&ua)?);
    headers.insert("region_tag", HeaderValue::from_static("cn"));
    headers.insert("HandleParams", HeaderValue::from_static("true"));

    let mut cookie_parts = vec![
        "sdkVersion=accountsdk-18.8.15".to_string(),
        "locale=en_us".to_string(),
    ];
    if !token.device_id.trim().is_empty() {
        cookie_parts.push(format!("deviceId={}", token.device_id));
    }
    if !token.user_id.trim().is_empty() {
        cookie_parts.push(format!("userId={}", token.user_id));
    }
    cookie_parts.push(format!("cUserId={}", token.c_user_id));
    cookie_parts.push(format!("serviceToken={}", token.service_token));
    let cookie_header = cookie_parts.join("; ");

    log::info!(
        "[MiAccount.DeviceList] request cookie device_id={} user_id={} c_user_id={} service_token_len={}",
        token.device_id,
        token.user_id,
        token.c_user_id,
        token.service_token.len()
    );

    // 5. Request
    let resp = client
        .post(url)
        .headers(headers)
        .header("Cookie", cookie_header)
        .form(&params_enc)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        return Err(anyhow!("Mi API call failed: {}, body: {}", status, body));
    }

    // 6. Decrypt
    let key_bytes = general_purpose::STANDARD.decode(&signed_nonce)?;
    let key = rc4::Key::<U32>::from_slice(&key_bytes);
    let mut cipher = Rc4::<U32>::new(key);
    let mut drop_buf = [0u8; 1024];
    cipher.apply_keystream(&mut drop_buf);

    let mut data = general_purpose::STANDARD.decode(body.trim_matches('"'))?;
    cipher.apply_keystream(&mut data);
    Ok(String::from_utf8_lossy(&data).into_owned())
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
