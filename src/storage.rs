use crate::models::AccountRecord;
use anyhow::{Context, Result, anyhow};
use hostio::frontend::DEFAULT_TIMEOUT;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const METHOD_STORAGE_GET_JSON: &str = "host/storage/local/get_json";
const METHOD_STORAGE_SET_JSON: &str = "host/storage/local/set_json";
const METHOD_STORAGE_REMOVE: &str = "host/storage/local/remove";

#[derive(Serialize)]
struct LocalStorageKeyPayload<'a> {
    key: &'a str,
}

#[derive(Serialize)]
struct LocalStorageSetPayload<'a> {
    key: &'a str,
    value: Value,
}

#[derive(Deserialize)]
struct LocalStorageAcknowledge {
    success: bool,
}

/// 经宿主调用前端方法（与原先 `invoke_frontend` 一样使用默认超时）。
async fn invoke_frontend<T, P>(method: &str, payload: P) -> Result<T>
where
    T: DeserializeOwned,
    P: Serialize,
{
    hostio::frontend::invoke(method, payload, Some(DEFAULT_TIMEOUT))
        .await
        .map_err(|err| anyhow!(err))
}

pub async fn local_storage_get_json<T>(key: impl AsRef<str>) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    let key = key.as_ref();
    let payload = LocalStorageKeyPayload { key };
    let value: Option<Value> = invoke_frontend(METHOD_STORAGE_GET_JSON, payload)
        .await
        .with_context(|| format!("localStorage get_json {}", key))?;
    if let Some(value) = value {
        serde_json::from_value(value)
            .with_context(|| format!("deserialize value stored in localStorage[{key}]"))
            .map(Some)
    } else {
        Ok(None)
    }
}

pub async fn local_storage_set_json<T>(key: impl AsRef<str>, data: &T) -> Result<()>
where
    T: Serialize,
{
    let key = key.as_ref();
    let payload = LocalStorageSetPayload {
        key,
        value: serde_json::to_value(data)
            .with_context(|| format!("serialize localStorage value for key {key}"))?,
    };
    let ack: LocalStorageAcknowledge = invoke_frontend(METHOD_STORAGE_SET_JSON, payload)
        .await
        .with_context(|| format!("localStorage set_json {}", key))?;
    if ack.success {
        Ok(())
    } else {
        Err(anyhow!(
            "frontend rejected localStorage set_json for key {key}"
        ))
    }
}

pub async fn local_storage_remove(key: impl AsRef<str>) -> Result<()> {
    let key = key.as_ref();
    let payload = LocalStorageKeyPayload { key };
    let ack: LocalStorageAcknowledge = invoke_frontend(METHOD_STORAGE_REMOVE, payload)
        .await
        .with_context(|| format!("localStorage remove {}", key))?;
    if ack.success {
        Ok(())
    } else {
        Err(anyhow!(
            "frontend rejected localStorage remove for key {key}"
        ))
    }
}

#[derive(Debug, Clone)]
pub struct AccountStore {
    key: String,
}

impl AccountStore {
    pub fn new(provider_name: impl AsRef<str>) -> Self {
        let normalized = normalize_key(provider_name.as_ref());
        Self {
            key: format!("account_provider_{normalized}"),
        }
    }

    pub fn with_key(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub async fn load(&self) -> Result<Option<AccountRecord>> {
        local_storage_get_json(self.key()).await
    }

    pub async fn save(&self, account: &AccountRecord) -> Result<()> {
        local_storage_set_json(self.key(), account).await
    }

    pub async fn clear(&self) -> Result<()> {
        local_storage_remove(self.key()).await
    }

    pub async fn list_accounts(&self) -> Result<Vec<AccountRecord>> {
        Ok(self.load().await?.into_iter().collect())
    }

    pub async fn get_account(&self, account_id: &str) -> Result<Option<AccountRecord>> {
        Ok(self
            .load()
            .await?
            .filter(|account| account.id == account_id))
    }

    pub async fn upsert_account(&self, account: AccountRecord) -> Result<AccountRecord> {
        if account.id.trim().is_empty() {
            return Err(anyhow!("account id is required"));
        }
        self.save(&account).await?;
        Ok(account)
    }

    pub async fn remove_account(&self, account_id: &str) -> Result<()> {
        if let Some(account) = self.load().await? {
            if account.id == account_id {
                self.clear().await?;
            }
        }
        Ok(())
    }
}

fn normalize_key(input: &str) -> String {
    input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}
