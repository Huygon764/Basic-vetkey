use candid::{CandidType};
use serde::{Deserialize, Serialize};

// Common Response Types
#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct KeyResponse {
    pub key_hex: String,
    pub caller: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct ErrorResponse {
    pub error: String,
}

// Common Result Type
pub type VetKeyResult<T> = Result<T, ErrorResponse>;