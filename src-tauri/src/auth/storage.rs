//! Account storage module - manages reading and writing accounts.json

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use keyring::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{
    parse_chatgpt_id_token_claims, AccountsStore, AppSettings, AuthData, AuthDotJson,
    StoredAccount, TokenData,
};

const KEYRING_SERVICE: &str = "codex-switcher";
const KEYRING_API_KEY_PREFIX: &str = "api-key";
const KEYRING_CHATGPT_PREFIX: &str = "chatgpt";
const CHATGPT_CREDENTIAL_VERSION: u8 = 1;
const KEYRING_CHUNK_UTF16_UNITS: usize = 1000;
const MAX_TOKEN_CHUNKS: u16 = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatGptCredentialGeneration {
    id: String,
    id_token_chunks: u16,
    access_token_chunks: u16,
    refresh_token_chunks: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatGptCredentialManifest {
    version: u8,
    active_generation: ChatGptCredentialGeneration,
    #[serde(default)]
    stale_generations: Vec<ChatGptCredentialGeneration>,
}

enum ChatGptKeyringRecord {
    Current(ChatGptCredentialManifest),
    Legacy(TokenData),
}

fn api_key_entry_name(account_id: &str) -> String {
    format!("{KEYRING_API_KEY_PREFIX}:{account_id}")
}

fn chatgpt_manifest_entry_name(account_id: &str) -> String {
    format!("{KEYRING_CHATGPT_PREFIX}:{account_id}")
}

fn chatgpt_token_entry_name(
    account_id: &str,
    generation: &str,
    field: &str,
    chunk_index: u16,
) -> String {
    format!("{KEYRING_CHATGPT_PREFIX}:{account_id}:{generation}:{field}:{chunk_index}")
}

fn keyring_entry(entry_name: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, entry_name)
        .with_context(|| format!("Failed to open credential entry '{entry_name}'"))
}

fn read_keyring_value(entry_name: &str) -> Result<Option<String>> {
    match keyring_entry(entry_name)?.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("Failed to read credential entry '{entry_name}'"))
        }
    }
}

fn write_keyring_value(entry_name: &str, value: &str) -> Result<()> {
    keyring_entry(entry_name)?
        .set_password(value)
        .with_context(|| format!("Failed to write credential entry '{entry_name}'"))
}

fn delete_keyring_value(entry_name: &str) -> Result<()> {
    match keyring_entry(entry_name)?.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("Failed to delete credential entry '{entry_name}'"))
        }
    }
}

fn read_api_key_from_keyring(account_id: &str) -> Result<Option<String>> {
    read_keyring_value(&api_key_entry_name(account_id))
}

fn write_api_key_to_keyring(account_id: &str, key: &str) -> Result<()> {
    write_keyring_value(&api_key_entry_name(account_id), key)
}

fn read_chatgpt_keyring_record(account_id: &str) -> Result<Option<ChatGptKeyringRecord>> {
    let Some(payload) = read_keyring_value(&chatgpt_manifest_entry_name(account_id))? else {
        return Ok(None);
    };

    if let Ok(manifest) = serde_json::from_str::<ChatGptCredentialManifest>(&payload) {
        if manifest.version != CHATGPT_CREDENTIAL_VERSION
            || manifest.active_generation.id.trim().is_empty()
        {
            anyhow::bail!("Unsupported ChatGPT credential manifest for account '{account_id}'");
        }
        return Ok(Some(ChatGptKeyringRecord::Current(manifest)));
    }

    let legacy = serde_json::from_str::<TokenData>(&payload).with_context(|| {
        format!("Invalid ChatGPT credential manifest for account '{account_id}'")
    })?;
    Ok(Some(ChatGptKeyringRecord::Legacy(legacy)))
}

fn read_chatgpt_generation(
    account_id: &str,
    manifest: &ChatGptCredentialManifest,
) -> Result<TokenData> {
    let read_token = |field: &str, chunk_count: u16| -> Result<String> {
        if chunk_count == 0 || chunk_count > MAX_TOKEN_CHUNKS {
            anyhow::bail!(
                "Invalid chunk count for credential field '{field}' in account '{account_id}'"
            );
        }

        let mut token = String::new();
        for chunk_index in 0..chunk_count {
            let entry_name = chatgpt_token_entry_name(
                account_id,
                &manifest.active_generation.id,
                field,
                chunk_index,
            );
            let chunk = read_keyring_value(&entry_name)?.with_context(|| {
                format!(
                    "Credential entry '{entry_name}' is missing from Windows Credential Manager"
                )
            })?;
            token.push_str(&chunk);
        }
        Ok(token)
    };

    Ok(TokenData {
        id_token: read_token("id-token", manifest.active_generation.id_token_chunks)?,
        access_token: read_token(
            "access-token",
            manifest.active_generation.access_token_chunks,
        )?,
        refresh_token: read_token(
            "refresh-token",
            manifest.active_generation.refresh_token_chunks,
        )?,
        account_id: None,
    })
}

fn read_chatgpt_tokens_from_keyring(account_id: &str) -> Result<Option<(TokenData, bool)>> {
    match read_chatgpt_keyring_record(account_id)? {
        Some(ChatGptKeyringRecord::Current(manifest)) => Ok(Some((
            read_chatgpt_generation(account_id, &manifest)?,
            false,
        ))),
        Some(ChatGptKeyringRecord::Legacy(tokens)) => Ok(Some((tokens, true))),
        None => Ok(None),
    }
}

fn delete_chatgpt_generation(
    account_id: &str,
    generation: &ChatGptCredentialGeneration,
) -> Result<()> {
    let mut first_error = None;
    let fields = [
        ("id-token", generation.id_token_chunks),
        ("access-token", generation.access_token_chunks),
        ("refresh-token", generation.refresh_token_chunks),
    ];
    for (field, chunk_count) in fields {
        for chunk_index in 0..chunk_count {
            let entry_name =
                chatgpt_token_entry_name(account_id, &generation.id, field, chunk_index);
            if let Err(error) = delete_keyring_value(&entry_name) {
                first_error.get_or_insert(error);
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn tokens_match(left: &TokenData, right: &TokenData) -> bool {
    left.id_token == right.id_token
        && left.access_token == right.access_token
        && left.refresh_token == right.refresh_token
}

fn split_keyring_value(value: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut chunk = String::new();
    let mut utf16_units = 0;

    for character in value.chars() {
        let character_units = character.len_utf16();
        if utf16_units + character_units > KEYRING_CHUNK_UTF16_UNITS {
            chunks.push(chunk);
            chunk = String::new();
            utf16_units = 0;
        }
        chunk.push(character);
        utf16_units += character_units;
    }
    chunks.push(chunk);
    chunks
}

fn write_chatgpt_token_chunks(
    account_id: &str,
    generation: &str,
    field: &str,
    value: &str,
    written_entries: &mut Vec<String>,
) -> Result<u16> {
    let chunks = split_keyring_value(value);
    let chunk_count = u16::try_from(chunks.len()).context("OAuth token has too many chunks")?;
    if chunk_count > MAX_TOKEN_CHUNKS {
        anyhow::bail!("OAuth token is too large to store safely");
    }

    for (chunk_index, chunk) in chunks.into_iter().enumerate() {
        let chunk_index = u16::try_from(chunk_index).context("Invalid token chunk index")?;
        let entry_name = chatgpt_token_entry_name(account_id, generation, field, chunk_index);
        write_keyring_value(&entry_name, &chunk)?;
        written_entries.push(entry_name);
    }
    Ok(chunk_count)
}

fn write_chatgpt_tokens_to_keyring(account_id: &str, tokens: &TokenData) -> Result<()> {
    let current_record = read_chatgpt_keyring_record(account_id)?;
    if let Some(ChatGptKeyringRecord::Current(manifest)) = &current_record {
        let existing = read_chatgpt_generation(account_id, manifest)?;
        if tokens_match(&existing, tokens) {
            let mut cleaned_manifest = manifest.clone();
            let stale_count = cleaned_manifest.stale_generations.len();
            cleaned_manifest
                .stale_generations
                .retain(|stale_generation| {
                    delete_chatgpt_generation(account_id, stale_generation).is_err()
                });
            if cleaned_manifest.stale_generations.len() != stale_count {
                let payload = serde_json::to_string(&cleaned_manifest)
                    .context("Failed to serialize credentials")?;
                write_keyring_value(&chatgpt_manifest_entry_name(account_id), &payload)?;
            }
            return Ok(());
        }
    }

    let generation_id = Uuid::new_v4().to_string();
    let mut written_fields: Vec<String> = Vec::new();
    let generation = (|| -> Result<ChatGptCredentialGeneration> {
        Ok(ChatGptCredentialGeneration {
            id: generation_id.clone(),
            id_token_chunks: write_chatgpt_token_chunks(
                account_id,
                &generation_id,
                "id-token",
                &tokens.id_token,
                &mut written_fields,
            )?,
            access_token_chunks: write_chatgpt_token_chunks(
                account_id,
                &generation_id,
                "access-token",
                &tokens.access_token,
                &mut written_fields,
            )?,
            refresh_token_chunks: write_chatgpt_token_chunks(
                account_id,
                &generation_id,
                "refresh-token",
                &tokens.refresh_token,
                &mut written_fields,
            )?,
        })
    })();
    let generation = match generation {
        Ok(generation) => generation,
        Err(error) => {
            for written_field in written_fields {
                let _ = delete_keyring_value(&written_field);
            }
            return Err(error);
        }
    };

    let mut stale_generations = match current_record {
        Some(ChatGptKeyringRecord::Current(manifest)) => {
            let mut generations = manifest.stale_generations;
            generations.push(manifest.active_generation);
            generations
        }
        Some(ChatGptKeyringRecord::Legacy(_)) | None => Vec::new(),
    };
    stale_generations.sort_by(|left, right| left.id.cmp(&right.id));
    stale_generations.dedup_by(|left, right| left.id == right.id);

    let mut manifest = ChatGptCredentialManifest {
        version: CHATGPT_CREDENTIAL_VERSION,
        active_generation: generation,
        stale_generations,
    };
    let manifest_name = chatgpt_manifest_entry_name(account_id);
    let payload = serde_json::to_string(&manifest).context("Failed to serialize credentials")?;
    if let Err(error) = write_keyring_value(&manifest_name, &payload) {
        let _ = delete_chatgpt_generation(account_id, &manifest.active_generation);
        return Err(error);
    }

    let had_stale_generations = !manifest.stale_generations.is_empty();
    manifest.stale_generations.retain(|stale_generation| {
        delete_chatgpt_generation(account_id, stale_generation).is_err()
    });
    if had_stale_generations {
        let payload =
            serde_json::to_string(&manifest).context("Failed to serialize credentials")?;
        write_keyring_value(&manifest_name, &payload)?;
    }

    Ok(())
}

fn delete_account_credentials_from_keyring(account: &StoredAccount) -> Result<()> {
    match &account.auth_data {
        AuthData::ApiKey { .. } => delete_keyring_value(&api_key_entry_name(&account.id)),
        AuthData::ChatGPT { .. } => {
            if let Some(record) = read_chatgpt_keyring_record(&account.id)? {
                if let ChatGptKeyringRecord::Current(manifest) = record {
                    let mut generations = manifest.stale_generations;
                    generations.push(manifest.active_generation);
                    for generation in generations {
                        delete_chatgpt_generation(&account.id, &generation)?;
                    }
                }
                delete_keyring_value(&chatgpt_manifest_entry_name(&account.id))?;
            }
            Ok(())
        }
    }
}

pub fn sync_active_account_tokens(store: &mut AccountsStore, auth: &AuthDotJson) -> bool {
    let Some(active_id) = store.active_account_id.as_deref() else {
        return false;
    };
    let Some(tokens) = auth.tokens.as_ref() else {
        return false;
    };
    let Some(account) = store
        .accounts
        .iter_mut()
        .find(|account| account.id == active_id)
    else {
        return false;
    };
    let AuthData::ChatGPT {
        id_token,
        access_token,
        refresh_token,
        account_id,
    } = &mut account.auth_data
    else {
        return false;
    };

    let stored_account_id = parse_chatgpt_id_token_claims(id_token)
        .account_id
        .or_else(|| account_id.clone());
    let current_account_id = parse_chatgpt_id_token_claims(&tokens.id_token)
        .account_id
        .or_else(|| tokens.account_id.clone());
    let (Some(stored_account_id), Some(current_account_id)) =
        (stored_account_id, current_account_id)
    else {
        return false;
    };
    if stored_account_id != current_account_id {
        return false;
    }

    let changed = *id_token != tokens.id_token
        || *access_token != tokens.access_token
        || *refresh_token != tokens.refresh_token
        || account_id.as_ref() != Some(&current_account_id);
    if !changed {
        return false;
    }

    id_token.clone_from(&tokens.id_token);
    access_token.clone_from(&tokens.access_token);
    refresh_token.clone_from(&tokens.refresh_token);
    *account_id = Some(current_account_id);
    true
}

/// Get the path to the codex-switcher config directory
pub fn get_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not find home directory")?;
    Ok(home.join(".codex-switcher"))
}

/// Get the path to accounts.json
pub fn get_accounts_file() -> Result<PathBuf> {
    Ok(get_config_dir()?.join("accounts.json"))
}

pub fn get_settings_file() -> Result<PathBuf> {
    Ok(get_config_dir()?.join("settings.json"))
}

fn hydrate_account_credentials_from_keyring(account: &mut StoredAccount) -> Result<bool> {
    let credential_id = account.id.clone();
    match &mut account.auth_data {
        AuthData::ApiKey { key } => {
            if !key.is_empty() {
                write_api_key_to_keyring(&credential_id, key)?;
                return Ok(true);
            }

            *key = read_api_key_from_keyring(&credential_id)?
                .filter(|stored_key| !stored_key.is_empty())
                .with_context(|| format!("API key is missing for account '{credential_id}'"))?;
            Ok(false)
        }
        AuthData::ChatGPT {
            id_token,
            access_token,
            refresh_token,
            account_id,
        } => {
            let has_file_tokens =
                !id_token.is_empty() || !access_token.is_empty() || !refresh_token.is_empty();
            if has_file_tokens {
                let tokens = TokenData {
                    id_token: id_token.clone(),
                    access_token: access_token.clone(),
                    refresh_token: refresh_token.clone(),
                    account_id: account_id.clone(),
                };
                write_chatgpt_tokens_to_keyring(&credential_id, &tokens)?;
                return Ok(true);
            }

            let (stored_tokens, used_legacy_format) =
                read_chatgpt_tokens_from_keyring(&credential_id)?.with_context(|| {
                    format!("ChatGPT credentials are missing for account '{credential_id}'")
                })?;
            *id_token = stored_tokens.id_token;
            *access_token = stored_tokens.access_token;
            *refresh_token = stored_tokens.refresh_token;

            let mut migrated = used_legacy_format;
            if let Some(stored_account_id) = stored_tokens.account_id {
                if account_id.as_ref() != Some(&stored_account_id) {
                    *account_id = Some(stored_account_id);
                    migrated = true;
                }
            }
            if used_legacy_format {
                let tokens = TokenData {
                    id_token: id_token.clone(),
                    access_token: access_token.clone(),
                    refresh_token: refresh_token.clone(),
                    account_id: account_id.clone(),
                };
                write_chatgpt_tokens_to_keyring(&credential_id, &tokens)?;
            }

            Ok(migrated)
        }
    }
}

fn persist_account_credentials_to_keyring(account: &mut StoredAccount) -> Result<()> {
    let credential_id = account.id.clone();
    match &mut account.auth_data {
        AuthData::ApiKey { key } => {
            if key.is_empty() {
                read_api_key_from_keyring(&credential_id)?
                    .filter(|stored_key| !stored_key.is_empty())
                    .with_context(|| format!("API key is missing for account '{credential_id}'"))?;
            } else {
                write_api_key_to_keyring(&credential_id, key)?;
            }
            key.clear();
        }
        AuthData::ChatGPT {
            id_token,
            access_token,
            refresh_token,
            account_id,
        } => {
            let has_tokens =
                !id_token.is_empty() || !access_token.is_empty() || !refresh_token.is_empty();
            if has_tokens {
                let tokens = TokenData {
                    id_token: id_token.clone(),
                    access_token: access_token.clone(),
                    refresh_token: refresh_token.clone(),
                    account_id: account_id.clone(),
                };
                write_chatgpt_tokens_to_keyring(&credential_id, &tokens)?;
            } else {
                read_chatgpt_tokens_from_keyring(&credential_id)?.with_context(|| {
                    format!("ChatGPT credentials are missing for account '{credential_id}'")
                })?;
            }
            id_token.clear();
            access_token.clear();
            refresh_token.clear();
        }
    }

    Ok(())
}

/// Load the accounts store from disk
pub fn load_accounts() -> Result<AccountsStore> {
    let path = get_accounts_file()?;

    if !path.exists() {
        return Ok(AccountsStore::default());
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read accounts file: {}", path.display()))?;

    let mut store: AccountsStore = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse accounts file: {}", path.display()))?;

    let mut migrated = false;
    for account in &mut store.accounts {
        migrated |= hydrate_account_credentials_from_keyring(account)?;
    }

    if migrated {
        save_accounts(&store).context("Failed to remove plaintext credentials after migration")?;
    }

    Ok(store)
}

pub fn load_app_settings() -> Result<AppSettings> {
    let path = get_settings_file()?;

    if !path.exists() {
        return Ok(AppSettings::default());
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read settings file: {}", path.display()))?;

    let settings: AppSettings = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse settings file: {}", path.display()))?;

    Ok(settings)
}

pub fn save_app_settings(settings: &AppSettings) -> Result<()> {
    let path = get_settings_file()?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
    }

    let content = serde_json::to_string_pretty(settings).context("Failed to serialize settings")?;
    fs::write(&path, content)
        .with_context(|| format!("Failed to write settings file: {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

/// Save the accounts store to disk
pub fn save_accounts(store: &AccountsStore) -> Result<()> {
    let path = get_accounts_file()?;

    // Ensure the config directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
    }

    let mut disk_store = store.clone();
    for account in &mut disk_store.accounts {
        persist_account_credentials_to_keyring(account)?;
    }

    let content =
        serde_json::to_string_pretty(&disk_store).context("Failed to serialize accounts store")?;

    fs::write(&path, content)
        .with_context(|| format!("Failed to write accounts file: {}", path.display()))?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

/// Add a new account to the store
pub fn add_account(account: StoredAccount) -> Result<StoredAccount> {
    let mut store = load_accounts()?;

    // Check for duplicate names
    if store.accounts.iter().any(|a| a.name == account.name) {
        anyhow::bail!("An account with name '{}' already exists", account.name);
    }

    let account_clone = account.clone();
    store.accounts.push(account);

    // If this is the first account, make it active
    if store.accounts.len() == 1 {
        store.active_account_id = Some(account_clone.id.clone());
    }

    save_accounts(&store)?;
    Ok(account_clone)
}

/// Remove an account by ID
pub fn remove_account(account_id: &str) -> Result<()> {
    let mut store = load_accounts()?;

    let index = store
        .accounts
        .iter()
        .position(|account| account.id == account_id)
        .with_context(|| format!("Account not found: {account_id}"))?;
    let removed_account = store.accounts.remove(index);

    // If we removed the active account, clear it or set to first available
    if store.active_account_id.as_deref() == Some(account_id) {
        store.active_account_id = store.accounts.first().map(|a| a.id.clone());
    }

    save_accounts(&store)?;
    delete_account_credentials_from_keyring(&removed_account)?;
    Ok(())
}

/// Update the active account ID
pub fn set_active_account(account_id: &str) -> Result<()> {
    let mut store = load_accounts()?;

    // Verify the account exists
    if !store.accounts.iter().any(|a| a.id == account_id) {
        anyhow::bail!("Account not found: {account_id}");
    }

    store.active_account_id = Some(account_id.to_string());
    save_accounts(&store)?;
    Ok(())
}

/// Get an account by ID
pub fn get_account(account_id: &str) -> Result<Option<StoredAccount>> {
    let store = load_accounts()?;
    Ok(store.accounts.into_iter().find(|a| a.id == account_id))
}

/// Get the currently active account
pub fn get_active_account() -> Result<Option<StoredAccount>> {
    let store = load_accounts()?;
    let active_id = match &store.active_account_id {
        Some(id) => id,
        None => return Ok(None),
    };
    Ok(store.accounts.into_iter().find(|a| a.id == *active_id))
}

/// Update an account's last_used_at timestamp
pub fn touch_account(account_id: &str) -> Result<()> {
    let mut store = load_accounts()?;

    if let Some(account) = store.accounts.iter_mut().find(|a| a.id == account_id) {
        account.last_used_at = Some(chrono::Utc::now());
        save_accounts(&store)?;
    }

    Ok(())
}

/// Update an account's metadata (name, email, plan_type, subscription expiry)
pub fn update_account_metadata(
    account_id: &str,
    name: Option<String>,
    email: Option<String>,
    plan_type: Option<String>,
    subscription_expires_at: Option<Option<DateTime<Utc>>>,
) -> Result<StoredAccount> {
    let mut store = load_accounts()?;

    // Check for duplicate names first (if renaming)
    if let Some(ref new_name) = name {
        if store
            .accounts
            .iter()
            .any(|a| a.id != account_id && a.name == *new_name)
        {
            anyhow::bail!("An account with name '{new_name}' already exists");
        }
    }

    // Now find and update the account
    let account = store
        .accounts
        .iter_mut()
        .find(|a| a.id == account_id)
        .context("Account not found")?;

    let mut changed = false;

    if let Some(new_name) = name {
        if account.name != new_name {
            account.name = new_name;
            changed = true;
        }
    }

    if let Some(new_email) = email {
        if account.email.as_ref() != Some(&new_email) {
            account.email = Some(new_email);
            changed = true;
        }
    }

    if let Some(new_plan_type) = plan_type {
        if account.plan_type.as_ref() != Some(&new_plan_type) {
            account.plan_type = Some(new_plan_type);
            changed = true;
        }
    }

    if let Some(subscription_expires_at) = subscription_expires_at {
        if account.subscription_expires_at != subscription_expires_at {
            account.subscription_expires_at = subscription_expires_at;
            changed = true;
        }
    }

    let updated = account.clone();
    if changed {
        save_accounts(&store)?;
        println!("[Account] Saved updated metadata for: {}", updated.name);
    }
    Ok(updated)
}

/// Update ChatGPT OAuth tokens for an account and return the updated account.
pub fn update_account_chatgpt_tokens(
    account_id: &str,
    id_token: String,
    access_token: String,
    refresh_token: String,
    chatgpt_account_id: Option<String>,
    email: Option<String>,
    plan_type: Option<String>,
    subscription_expires_at: Option<DateTime<Utc>>,
) -> Result<StoredAccount> {
    let mut store = load_accounts()?;

    let account = store
        .accounts
        .iter_mut()
        .find(|a| a.id == account_id)
        .context("Account not found")?;

    match &mut account.auth_data {
        AuthData::ChatGPT {
            id_token: stored_id_token,
            access_token: stored_access_token,
            refresh_token: stored_refresh_token,
            account_id: stored_account_id,
        } => {
            *stored_id_token = id_token;
            *stored_access_token = access_token;
            *stored_refresh_token = refresh_token;
            if let Some(new_account_id) = chatgpt_account_id {
                *stored_account_id = Some(new_account_id);
            }
        }
        AuthData::ApiKey { .. } => {
            anyhow::bail!("Cannot update OAuth tokens for an API key account");
        }
    }

    if let Some(new_email) = email {
        account.email = Some(new_email);
    }

    if let Some(new_plan_type) = plan_type {
        account.plan_type = Some(new_plan_type);
    }

    if let Some(subscription_expires_at) = subscription_expires_at {
        account.subscription_expires_at = Some(subscription_expires_at);
    }

    let updated = account.clone();
    save_accounts(&store)?;
    Ok(updated)
}

/// Get the list of masked account IDs
pub fn get_masked_account_ids() -> Result<Vec<String>> {
    let store = load_accounts()?;
    Ok(store.masked_account_ids.clone())
}

/// Set the list of masked account IDs
pub fn set_masked_account_ids(ids: Vec<String>) -> Result<()> {
    let mut store = load_accounts()?;
    store.masked_account_ids = ids;
    save_accounts(&store)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sync_active_account_tokens;
    #[cfg(target_os = "windows")]
    use super::{
        delete_account_credentials_from_keyring, read_chatgpt_tokens_from_keyring,
        write_chatgpt_tokens_to_keyring,
    };
    use crate::types::{AccountsStore, AuthData, AuthDotJson, StoredAccount, TokenData};
    use base64::Engine;

    #[cfg(target_os = "windows")]
    struct TestCredentialCleanup(StoredAccount);

    #[cfg(target_os = "windows")]
    impl Drop for TestCredentialCleanup {
        fn drop(&mut self) {
            let _ = delete_account_credentials_from_keyring(&self.0);
        }
    }

    fn account(name: &str, account_id: &str, suffix: &str) -> StoredAccount {
        StoredAccount::new_chatgpt(
            name.into(),
            None,
            None,
            None,
            format!("id-{suffix}"),
            format!("access-{suffix}"),
            format!("refresh-{suffix}"),
            Some(account_id.into()),
        )
    }

    fn auth(account_id: &str, suffix: &str) -> AuthDotJson {
        AuthDotJson {
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: format!("id-{suffix}"),
                access_token: format!("access-{suffix}"),
                refresh_token: format!("refresh-{suffix}"),
                account_id: Some(account_id.into()),
            }),
            last_refresh: None,
        }
    }

    fn refresh_token(account: &StoredAccount) -> &str {
        match &account.auth_data {
            AuthData::ChatGPT { refresh_token, .. } => refresh_token,
            AuthData::ApiKey { .. } => panic!("expected ChatGPT account"),
        }
    }

    fn id_token_with_account_id(account_id: &str, suffix: &str) -> String {
        let payload =
            format!(r#"{{"https://api.openai.com/auth":{{"chatgpt_account_id":"{account_id}"}}}}"#);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("header.{encoded}.{suffix}")
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn stores_large_oauth_tokens_as_separate_windows_credentials() {
        let account = account("keyring-test", "workspace-test", "initial");
        let _cleanup = TestCredentialCleanup(account.clone());
        let tokens = TokenData {
            id_token: "i".repeat(2200),
            access_token: "a".repeat(2200),
            refresh_token: "r".repeat(2200),
            account_id: Some("workspace-test".into()),
        };

        write_chatgpt_tokens_to_keyring(&account.id, &tokens).unwrap();
        let (stored, legacy) = read_chatgpt_tokens_from_keyring(&account.id)
            .unwrap()
            .expect("credentials should exist");

        assert!(!legacy);
        assert_eq!(stored.id_token, tokens.id_token);
        assert_eq!(stored.access_token, tokens.access_token);
        assert_eq!(stored.refresh_token, tokens.refresh_token);
    }

    #[test]
    fn preserves_rotated_tokens_before_switching_away_and_back() {
        let account_a = account("A", "workspace-a", "a1");
        let account_a_id = account_a.id.clone();
        let account_b = account("B", "workspace-b", "b1");
        let account_b_id = account_b.id.clone();
        let mut store = AccountsStore {
            accounts: vec![account_a, account_b],
            active_account_id: Some(account_a_id.clone()),
            ..AccountsStore::default()
        };

        assert!(!sync_active_account_tokens(
            &mut store,
            &auth("workspace-b", "wrong-account")
        ));
        assert_eq!(refresh_token(&store.accounts[0]), "refresh-a1");

        let mut auth_without_top_level_id = auth("workspace-b", "missing-id");
        let tokens = auth_without_top_level_id.tokens.as_mut().unwrap();
        tokens.id_token = id_token_with_account_id("workspace-b", "signature");
        tokens.account_id = None;
        assert!(!sync_active_account_tokens(
            &mut store,
            &auth_without_top_level_id
        ));
        assert_eq!(refresh_token(&store.accounts[0]), "refresh-a1");

        let mut auth_without_identity = auth("workspace-a", "unknown");
        auth_without_identity.tokens.as_mut().unwrap().account_id = None;
        assert!(!sync_active_account_tokens(
            &mut store,
            &auth_without_identity
        ));
        assert_eq!(refresh_token(&store.accounts[0]), "refresh-a1");

        assert!(sync_active_account_tokens(
            &mut store,
            &auth("workspace-a", "a2")
        ));
        store.active_account_id = Some(account_b_id);

        let restored_a = store
            .accounts
            .iter()
            .find(|account| account.id == account_a_id)
            .unwrap();
        let AuthData::ChatGPT { refresh_token, .. } = &restored_a.auth_data else {
            panic!("expected ChatGPT account");
        };
        assert_eq!(refresh_token, "refresh-a2");
    }

    #[test]
    fn rejects_live_tokens_when_stored_account_identity_is_unknown() {
        let mut account = account("A", "workspace-a", "a1");
        let account_id = account.id.clone();
        let AuthData::ChatGPT {
            id_token,
            account_id: chatgpt_account_id,
            ..
        } = &mut account.auth_data
        else {
            panic!("expected ChatGPT account");
        };
        *id_token = "opaque-id-token".into();
        *chatgpt_account_id = None;

        let mut store = AccountsStore {
            accounts: vec![account],
            active_account_id: Some(account_id),
            ..AccountsStore::default()
        };

        assert!(!sync_active_account_tokens(
            &mut store,
            &auth("workspace-a", "a2")
        ));
        assert_eq!(refresh_token(&store.accounts[0]), "refresh-a1");
    }

    #[test]
    fn derives_stored_identity_from_id_token_and_backfills_account_id() {
        let mut account = account("A", "workspace-a", "a1");
        let account_id = account.id.clone();
        let AuthData::ChatGPT {
            id_token,
            account_id: chatgpt_account_id,
            ..
        } = &mut account.auth_data
        else {
            panic!("expected ChatGPT account");
        };
        *id_token = id_token_with_account_id("workspace-a", "stored");
        *chatgpt_account_id = None;

        let mut store = AccountsStore {
            accounts: vec![account],
            active_account_id: Some(account_id),
            ..AccountsStore::default()
        };

        assert!(sync_active_account_tokens(
            &mut store,
            &auth("workspace-a", "a2")
        ));
        let AuthData::ChatGPT { account_id, .. } = &store.accounts[0].auth_data else {
            panic!("expected ChatGPT account");
        };
        assert_eq!(account_id.as_deref(), Some("workspace-a"));
        assert_eq!(refresh_token(&store.accounts[0]), "refresh-a2");
    }
}
