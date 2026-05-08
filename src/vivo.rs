use crate::models::AccountRecord;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

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
