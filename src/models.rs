use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountRecord {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub extra: Map<String, Value>,
}

impl AccountRecord {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            avatar: None,
            token: None,
            extra: Map::new(),
        }
    }

    pub fn with_avatar(mut self, avatar: impl Into<Option<String>>) -> Self {
        self.avatar = avatar.into();
        self
    }

    pub fn with_token(mut self, token: impl Into<Option<String>>) -> Self {
        self.token = token.into();
        self
    }

    pub fn extra_value(&self, key: &str) -> Option<&Value> {
        self.extra.get(key)
    }

    pub fn extra_as<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.extra_value(key)
            .and_then(|value| serde_json::from_value(value.clone()).ok())
    }

    pub fn set_extra_value(&mut self, key: impl Into<String>, value: Value) -> Option<Value> {
        self.extra.insert(key.into(), value)
    }

    pub fn remove_extra(&mut self, key: &str) -> Option<Value> {
        self.extra.remove(key)
    }
}

impl Default for AccountRecord {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            avatar: None,
            token: None,
            extra: Map::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BindingStatus {
    Linked,
    Unlinked,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicAccountBinding {
    pub provider: String,
    pub status: BindingStatus,
    pub id: Option<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
}

impl PublicAccountBinding {
    pub fn unavailable(provider: &str) -> Self {
        Self {
            provider: provider.into(),
            status: BindingStatus::Unavailable,
            id: None,
            username: None,
            display_name: None,
            avatar: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicAccountProfile {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub avatar: Option<String>,
    pub source: String,
    pub bindings: Vec<PublicAccountBinding>,
}
