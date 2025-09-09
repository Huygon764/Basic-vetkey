// src/timelock.rs

use ic_cdk::{query, update};
use ic_cdk::api::msg_caller;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use candid::{CandidType, Principal};

// Import shared items
use crate::shared::*;

// ============================================================================
// TYPES
// ============================================================================

#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct TimelockMessage {
    pub id: String,
    pub creator: Principal,
    pub title: String,
    pub encrypted_content: String,
    pub unlock_timestamp: u64,
    pub timelock_identity: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct TimelockInfo {
    pub id: String,
    pub title: String,
    pub unlock_timestamp: u64,
    pub is_expired: bool,
}

// ============================================================================
// STORAGE
// ============================================================================

thread_local! {
    static TIMELOCK_MESSAGES: RefCell<HashMap<String, TimelockMessage>> = RefCell::new(HashMap::new());
    static USER_TIMELOCKS: RefCell<HashMap<Principal, Vec<String>>> = RefCell::new(HashMap::new());
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Generate timelock identity for IBE
fn generate_timelock_identity(timelock_id: &str) -> String {
    format!("timelock_{}", timelock_id)
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Get master public key for timelock encryption
#[update]
pub async fn timelock_encryption_key() -> Result<String, String> {
    debug_println_caller("timelock_encryption_key");
    
    match get_public_key(TIMELOCK_CONTEXT).await {
        Ok(response) => Ok(response.key_hex),
        Err(err) => Err(err.error),
    }
}

/// Create a time-locked message
#[update]
pub async fn create_timelock_message(
    content: String,
    unlock_timestamp: u64,
    title: String,
) -> Result<String, String> {
    debug_println_caller("create_timelock_message");
    
    let caller = msg_caller();
    let current_time = current_timestamp_seconds();
    
    // Basic validation
    if unlock_timestamp <= current_time {
        return Err("Unlock timestamp must be in the future".to_string());
    }
    
    if content.trim().is_empty() {
        return Err("Content cannot be empty".to_string());
    }
    
    if title.trim().is_empty() {
        return Err("Title cannot be empty".to_string());
    }
    
    // Generate timelock ID
    let timelock_id = generate_unique_id("timelock", caller);
    let timelock_identity = generate_timelock_identity(&timelock_id);
    
    // Create message
    let message = TimelockMessage {
        id: timelock_id.clone(),
        creator: caller,
        title: title.trim().to_string(),
        encrypted_content: content, // Frontend will replace with IBE ciphertext
        unlock_timestamp,
        timelock_identity,
    };
    
    // Store message
    TIMELOCK_MESSAGES.with(|messages| {
        messages.borrow_mut().insert(timelock_id.clone(), message);
    });
    
    // Add to user's list
    USER_TIMELOCKS.with(|user_timelocks| {
        user_timelocks
            .borrow_mut()
            .entry(caller)
            .or_insert_with(Vec::new)
            .push(timelock_id.clone());
    });
    
    Ok(timelock_id)
}

/// Get decryption key for timelock (only if expired)
#[update]
pub async fn get_timelock_decryption_key(
    timelock_id: String,
    transport_public_key: Vec<u8>,
) -> Result<String, String> {
    debug_println_caller("get_timelock_decryption_key");
    
    let caller = msg_caller();
    let current_time = current_timestamp_seconds();
    
    // Get message
    let message = TIMELOCK_MESSAGES.with(|messages| {
        messages.borrow().get(&timelock_id).cloned()
    });
    
    let msg = match message {
        Some(m) => m,
        None => return Err("Timelock message not found".to_string()),
    };
    
    // Check ownership
    if msg.creator != caller {
        return Err("Access denied".to_string());
    }
    
    // Check if expired
    if current_time < msg.unlock_timestamp {
        return Err("Timelock not yet expired".to_string());
    }
    
    // Derive decryption key
    match derive_key(
        TIMELOCK_CONTEXT,
        msg.timelock_identity.as_bytes().to_vec(),
        transport_public_key,
    ).await {
        Ok(response) => Ok(response.key_hex),
        Err(err) => Err(err.error),
    }
}

/// Get user's timelock messages
#[query]
pub fn get_my_timelocks() -> Vec<TimelockInfo> {
    let caller = msg_caller();
    let current_time = current_timestamp_seconds();
    
    USER_TIMELOCKS.with(|user_timelocks| {
        let user_timelocks = user_timelocks.borrow();
        
        if let Some(timelock_ids) = user_timelocks.get(&caller) {
            TIMELOCK_MESSAGES.with(|messages| {
                let messages = messages.borrow();
                
                timelock_ids
                    .iter()
                    .filter_map(|id| messages.get(id))
                    .map(|msg| TimelockInfo {
                        id: msg.id.clone(),
                        title: msg.title.clone(),
                        unlock_timestamp: msg.unlock_timestamp,
                        is_expired: current_time >= msg.unlock_timestamp,
                    })
                    .collect()
            })
        } else {
            Vec::new()
        }
    })
}

/// Get timelock message content (for frontend to get encrypted content)
#[query]
pub fn get_timelock_content(timelock_id: String) -> Result<String, String> {
    let caller = msg_caller();
    
    TIMELOCK_MESSAGES.with(|messages| {
        let messages = messages.borrow();
        
        if let Some(message) = messages.get(&timelock_id) {
            if message.creator != caller {
                return Err("Access denied".to_string());
            }
            
            Ok(message.encrypted_content.clone())
        } else {
            Err("Timelock message not found".to_string())
        }
    })
}

/// Get timelock identity (for frontend IBE encryption)
#[query]
pub fn get_timelock_identity(timelock_id: String) -> Result<String, String> {
    let caller = msg_caller();
    
    TIMELOCK_MESSAGES.with(|messages| {
        let messages = messages.borrow();
        
        if let Some(message) = messages.get(&timelock_id) {
            if message.creator != caller {
                return Err("Access denied".to_string());
            }
            
            Ok(message.timelock_identity.clone())
        } else {
            Err("Timelock message not found".to_string())
        }
    })
}

/// Update encrypted content (called by frontend after IBE encryption)
#[update]
pub async fn update_timelock_content(
    timelock_id: String,
    encrypted_content: String,
) -> Result<bool, String> {
    debug_println_caller("update_timelock_content");
    
    let caller = msg_caller();
    
    TIMELOCK_MESSAGES.with(|messages| {
        let mut messages = messages.borrow_mut();
        
        if let Some(message) = messages.get_mut(&timelock_id) {
            if message.creator != caller {
                return Err("Access denied".to_string());
            }
            
            message.encrypted_content = encrypted_content;
            Ok(true)
        } else {
            Err("Timelock message not found".to_string())
        }
    })
}
