use crate::models::AccountRecord;
use anyhow::{Context, Result, anyhow};
use frontbridge::invoke_frontend;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::AppHandle;

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

pub async fn local_storage_get_json<T>(
    app_handle: &AppHandle,
    key: impl AsRef<str>,
) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    let key = key.as_ref();
    let payload = LocalStorageKeyPayload { key };
    let value: Option<Value> = invoke_frontend(app_handle, METHOD_STORAGE_GET_JSON, payload)
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

pub async fn local_storage_set_json<T>(
    app_handle: &AppHandle,
    key: impl AsRef<str>,
    data: &T,
) -> Result<()>
where
    T: Serialize,
{
    let key = key.as_ref();
    let payload = LocalStorageSetPayload {
        key,
        value: serde_json::to_value(data)
            .with_context(|| format!("serialize localStorage value for key {key}"))?,
    };
    let ack: LocalStorageAcknowledge =
        invoke_frontend(app_handle, METHOD_STORAGE_SET_JSON, payload)
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

pub async fn local_storage_remove(app_handle: &AppHandle, key: impl AsRef<str>) -> Result<()> {
    let key = key.as_ref();
    let payload = LocalStorageKeyPayload { key };
    let ack: LocalStorageAcknowledge = invoke_frontend(app_handle, METHOD_STORAGE_REMOVE, payload)
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

    pub async fn load(&self, app_handle: &AppHandle) -> Result<Option<AccountRecord>> {
        local_storage_get_json(app_handle, self.key()).await
    }

    pub async fn save(&self, app_handle: &AppHandle, account: &AccountRecord) -> Result<()> {
        local_storage_set_json(app_handle, self.key(), account).await
    }

    pub async fn clear(&self, app_handle: &AppHandle) -> Result<()> {
        local_storage_remove(app_handle, self.key()).await
    }

    pub async fn list_accounts(&self, app_handle: &AppHandle) -> Result<Vec<AccountRecord>> {
        Ok(self.load(app_handle).await?.into_iter().collect())
    }

    pub async fn get_account(
        &self,
        app_handle: &AppHandle,
        account_id: &str,
    ) -> Result<Option<AccountRecord>> {
        Ok(self
            .load(app_handle)
            .await?
            .filter(|account| account.id == account_id))
    }

    pub async fn upsert_account(
        &self,
        app_handle: &AppHandle,
        account: AccountRecord,
    ) -> Result<AccountRecord> {
        if account.id.trim().is_empty() {
            return Err(anyhow!("account id is required"));
        }
        self.save(app_handle, &account).await?;
        Ok(account)
    }

    pub async fn remove_account(&self, app_handle: &AppHandle, account_id: &str) -> Result<()> {
        if let Some(account) = self.load(app_handle).await? {
            if account.id == account_id {
                self.clear(app_handle).await?;
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
