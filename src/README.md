# 🛡️ VetKeys Demo

A comprehensive demonstration of **vetKeys** (verifiably encrypted threshold keys) on the Internet Computer, showcasing three powerful cryptographic features for secure, decentralized encryption.

## 🌟 Features Overview

### 🔑 Symmetric Key Encryption
**Self-encryption with AES-GCM-256**

Secure personal data encryption where each user gets a unique, deterministic symmetric key. Perfect for password managers, personal notes, and confidential document storage. The same user always receives the same key across sessions and devices.

**Key Benefits:**
- Deterministic key derivation
- Client-side AES-GCM-256 encryption
- Multi-device compatibility
- No key storage required

**Flow**
1. User clicks "Fetch vetKey" ↓
2. Frontend generates transport key pair ↓
3. Call backend.symmetric_key_verification_key() → Get public key ↓
4. Call backend.encrypted_symmetric_key_for_caller(transport_public_key) → Get encrypted private key ↓
5. Frontend decrypts private key using transport private key ↓
6. Convert to DerivedKeyMaterial (AES-GCM-256 ready) ↓
7. User enters plaintext → Click "Encrypt" → AES encrypt locally ↓
8. User pastes ciphertext → Click "Decrypt" → AES decrypt locally


### 👥 Identity-Based Encryption (IBE)
**Cross-user encryption without key exchange**

Send encrypted messages to any Internet Computer principal without prior key exchange. Anyone can encrypt data for a specific user using only their principal ID, but only the intended recipient can decrypt the message.

**Key Benefits:**
- No prior key exchange needed
- Encrypt to any principal ID
- Asymmetric encryption model
- Scalable secure messaging

**Flow**
ENCRYPT (Anyone can do):
1. User enters message + target principal ↓
2. Call backend.ibe_encryption_key() → Get master public key ↓
3. Frontend IBE encrypts TO target principal using master public key ↓
4. Show IBE ciphertext

DECRYPT (Only target principal):
1. Target user pastes IBE ciphertext → Click "IBE Decrypt" ↓
2. Frontend generates transport key pair ↓
3. Call backend.ibe_encryption_key() → Get master public key (for verification) ↓
4. Call backend.encrypted_ibe_decryption_key_for_caller(transport_public_key) ↓
5. Frontend decrypts private key using transport private key ↓
6. Use private key to decrypt IBE ciphertext → Show plaintext

### ⏰ Time-locked Encryption
**Temporal access control with cryptographic guarantees**

Create messages that can only be decrypted after a specific timestamp. The Internet Computer's consensus mechanism enforces time constraints, making it impossible to decrypt messages before their unlock time - even for the message creator.

**Key Benefits:**
- Cryptographically enforced time locks
- Trustless temporal access control
- Perfect for auctions, wills, and scheduled reveals
- Immutable time constraints

**Flow**
CREATE TIMELOCK:
1. User enters title + message + unlock datetime ↓
2. Call backend.create_timelock_message() → Create timelock record, get timelock_id ↓
3. Call backend.timelock_encryption_key() → Get master public key ↓
4. Call backend.get_timelock_identity(timelock_id) → Get IBE identity ↓
5. Frontend IBE encrypts message TO timelock_identity ↓
6. Call backend.update_timelock_content() → Store encrypted content ↓
7. Show success + timelock_id

VIEW TIMELOCKS:
1. User clicks "View My Messages" ↓
2. Call backend.get_my_timelocks() → Get list with status ↓
3. Show list with color coding (expired = green, locked = yellow)

DECRYPT (Only after unlock time):
1. User clicks "Decrypt Now" (if expired) or manually inputs timelock_id ↓
2. Backend checks: current_time >= unlock_timestamp? ↓
3. If YES: Call backend.get_timelock_decryption_key() → Get encrypted private key ↓
4. Frontend decrypts private key using transport key ↓
5. Call backend.get_timelock_content() → Get IBE ciphertext ↓
6. Frontend IBE decrypts using private key → Show original message ↓
7. If NO: Show "Timelock not yet expired"

## 🚀 Installation

### Prerequisites
- **dfx** (Internet Computer SDK) - [Install Guide](https://internetcomputer.org/docs/current/developer-docs/setup/install/)
- **Node.js** v16 or higher
- **Rust** (for canister development)

### Setup Steps
```bash
# Clone the repository
git clone git@github.com:Huygon764/Basic-vetkey.git
cd vetkeys-demo

# Install frontend dependencies
npm install

# Start local Internet Computer replica
dfx start --clean --background

# Deploy the canisters
dfx deploy

