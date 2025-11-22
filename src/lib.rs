pub mod models;
pub mod storage;

use crate::models::AccountRecord;
use async_trait::async_trait;
use std::sync::{Arc, Mutex, OnceLock};

pub use storage::{
    AccountStore, local_storage_get_json, local_storage_remove, local_storage_set_json,
};

pub static ACCOUNT_PROVIDERS: OnceLock<Mutex<Vec<Arc<dyn AccountProvider>>>> = OnceLock::new();

pub async fn add_account_provider(provider: Arc<dyn AccountProvider>) {
    let providers = ACCOUNT_PROVIDERS.get_or_init(|| Mutex::new(Vec::new()));
    let mut locked = providers.lock().unwrap();
    locked.push(provider);
}

pub async fn remove_account_provider(name: &str) {
    let providers = ACCOUNT_PROVIDERS.get_or_init(|| Mutex::new(Vec::new()));
    let mut locked = providers.lock().unwrap();
    locked.retain(|p| p.provider_name() != name);
}

pub async fn get_account_provider(name: &str) -> Option<Arc<dyn AccountProvider>> {
    let providers = ACCOUNT_PROVIDERS.get_or_init(|| Mutex::new(Vec::new()));
    let locked = providers.lock().unwrap();
    for provider in locked.iter() {
        if provider.provider_name() == name {
            return Some(Arc::clone(provider));
        }
    }
    None
}

pub async fn list_account_providers() -> Vec<String> {
    let providers = ACCOUNT_PROVIDERS.get_or_init(|| Mutex::new(Vec::new()));
    let locked = providers.lock().unwrap();
    locked.iter().map(|p| p.provider_name()).collect()
}

#[async_trait]
pub trait AccountProvider: Send + Sync {
    fn provider_name(&self) -> String;

    async fn refresh(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn list_accounts(&self) -> anyhow::Result<Vec<AccountRecord>>;

    async fn get_account(&self, account_id: &str) -> anyhow::Result<Option<AccountRecord>> {
        let accounts = self.list_accounts().await?;
        Ok(accounts.into_iter().find(|acc| acc.id == account_id))
    }

    async fn upsert_account(&self, account: AccountRecord) -> anyhow::Result<AccountRecord>;

    async fn remove_account(&self, account_id: &str) -> anyhow::Result<()>;
}
