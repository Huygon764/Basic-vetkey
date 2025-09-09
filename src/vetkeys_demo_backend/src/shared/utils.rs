use candid::Principal;
use ic_cdk::api::{msg_caller, time};
use ic_cdk::management_canister::{VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId, VetKDPublicKeyArgs};
use super::constants::*;
use super::types::*;

/// Get current time in seconds
pub fn current_timestamp_seconds() -> u64 {
    time() / NANOSECONDS_PER_SECOND
}

/// Debug helper to print caller information
pub fn debug_println_caller(method_name: &str) {
    ic_cdk::println!(
        "{}: caller: {} (isAnonymous: {})",
        method_name,
        msg_caller().to_text(),
        msg_caller() == Principal::anonymous()
    );
}

pub fn default_vetkey_id() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: DFX_TEST_KEY_NAME.to_string(),
    }
}

/// Generate unique ID with timestamp
pub fn generate_unique_id(prefix: &str, principal: Principal) -> String {
    let timestamp = current_timestamp_seconds();
    format!("{}_{}_{}",  prefix, principal.to_text(), timestamp)
}


pub async fn get_public_key(context: &[u8]) -> VetKeyResult<KeyResponse> {
    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context: context.to_vec(),
        key_id: default_vetkey_id(),
    };

    match ic_cdk::management_canister::vetkd_public_key(&request).await {
        Ok(response) => Ok(KeyResponse {
            key_hex: hex::encode(response.public_key),
            caller: msg_caller().to_text(),
        }),
        Err(err) => Err(ErrorResponse {
            error: format!("Failed to get public key: {:?}", err),
        }),
    }
}

pub async fn derive_key(
    context: &[u8],
    input: Vec<u8>,
    transport_public_key: Vec<u8>,
) -> VetKeyResult<KeyResponse> {
    let request = VetKDDeriveKeyArgs {
        input,
        context: context.to_vec(),
        key_id: default_vetkey_id(),
        transport_public_key,
    };

    match ic_cdk::management_canister::vetkd_derive_key(&request).await {
        Ok(response) => Ok(KeyResponse {
            key_hex: hex::encode(response.encrypted_key),
            caller: msg_caller().to_text(),
        }),
        Err(err) => Err(ErrorResponse {
            error: format!("Failed to derive key: {:?}", err),
        }),
    }
}
