use ic_cdk::{update};
use ic_cdk::api::msg_caller;

// Import shared items
use crate::shared::*;


/// Get public key for symmetric key verification
#[update]
pub async fn symmetric_key_verification_key() -> VetKeyResult<KeyResponse> {
    debug_println_caller("symmetric_key_verification_key");
    get_public_key(SYMMETRIC_KEY_CONTEXT).await
}

/// Get encrypted symmetric key for the calling user
#[update]
pub async fn encrypted_symmetric_key_for_caller(
    transport_public_key: Vec<u8>,
) -> VetKeyResult<KeyResponse> {
    debug_println_caller("encrypted_symmetric_key_for_caller");
    
    derive_key(
        SYMMETRIC_KEY_CONTEXT,
        msg_caller().as_slice().to_vec(),
        transport_public_key,
    ).await
}

/// Get IBE encryption key (master public key)
#[update]
pub async fn ibe_encryption_key() -> VetKeyResult<KeyResponse> {
    debug_println_caller("ibe_encryption_key");
    get_public_key(IBE_ENCRYPTION_CONTEXT).await
}

/// Get encrypted IBE decryption key for the calling user
#[update]
pub async fn encrypted_ibe_decryption_key_for_caller(
    transport_public_key: Vec<u8>,
) -> VetKeyResult<KeyResponse> {
    debug_println_caller("encrypted_ibe_decryption_key_for_caller");
    
    derive_key(
        IBE_ENCRYPTION_CONTEXT,
        msg_caller().as_slice().to_vec(),
        transport_public_key,
    ).await
}
