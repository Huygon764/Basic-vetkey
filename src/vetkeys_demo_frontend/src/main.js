import { createActor } from "../../declarations/vetkeys_demo_backend";
import { canisterId as backendCanisterId } from "../../declarations/vetkeys_demo_backend";
import { TransportSecretKey, EncryptedVetKey, DerivedPublicKey, IbeCiphertext, IbeIdentity, IbeSeed } from "@dfinity/vetkeys";
import { HttpAgent, Actor } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";

// Polyfill for environment variables in Vite
const DFX_NETWORK = import.meta.env.DFX_NETWORK || "local";

let fetched_derived_key_material = null;
let app_backend_actor;
let app_backend_principal;

// Initialize
async function initializeApp() {
  try {
    const agent = new HttpAgent({
      host: DFX_NETWORK === "ic" ? "https://ic0.app" : "http://localhost:4943",
    });
    
    if (DFX_NETWORK !== "ic") {
      await agent.fetchRootKey();
    }
    
    app_backend_actor = createActor(backendCanisterId, { agent });
    app_backend_principal = await Actor.agentOf(app_backend_actor).getPrincipal();
    
    document.getElementById("principal").innerHTML = annotated_principal(app_backend_principal);
  } catch (error) {
    console.error("Failed to initialize app:", error);
    document.getElementById("principal").innerHTML = "Failed to connect to backend";
  }
}

initializeApp();

document.getElementById("get_vetkey_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.setAttribute("disabled", true);
  const result = document.getElementById("get_vetkey_result");

  try {
    result.innerText = "Fetching vetKey...";
    const derived_key_material = await get_derived_key_material();
    result.innerText = "Done. vetKey available for local usage.";

    fetched_derived_key_material = derived_key_material;
    update_plaintext_button_state();
    update_ciphertext_button_state();
  } catch (error) {
    result.innerText = "Error: " + error.message;
    console.error("Failed to get vetKey:", error);
  }

  button.removeAttribute("disabled");
  return false;
});

document.getElementById("encrypt_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.setAttribute("disabled", true);
  const result = document.getElementById("encrypt_result");

  try {
    result.innerText = "Encrypting...";
    const message = document.getElementById("plaintext").value;
    const message_encoded = new TextEncoder().encode(message);
    const ciphertext_hex = hex_encode(await fetched_derived_key_material.encryptMessage(message_encoded, "vetkd-demo"));

    result.innerText = "ciphertext: " + ciphertext_hex;
    
    // Auto-fill decrypt form
    document.getElementById("ciphertext").value = ciphertext_hex;
    update_ciphertext_button_state();
  } catch (error) {
    result.innerText = "Error: " + error.message;
    console.error("Encryption failed:", error);
  }

  button.removeAttribute("disabled");
  return false;
});

document.getElementById("decrypt_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.setAttribute("disabled", true);
  const result = document.getElementById("decrypt_result");

  try {
    result.innerText = "Decrypting...";
    const ciphertext_hex = document.getElementById("ciphertext").value;
    const plaintext_bytes = await fetched_derived_key_material.decryptMessage(hex_decode(ciphertext_hex), "vetkd-demo");
    const plaintext_string = new TextDecoder().decode(plaintext_bytes);
    result.innerText = "plaintext: " + plaintext_string;
  } catch (error) {
    result.innerText = "Error: " + error.message;
    console.error("Decryption failed:", error);
  }

  button.removeAttribute("disabled");
  return false;
});

// Event listeners
document.getElementById("plaintext").addEventListener("keyup", update_plaintext_button_state);
document.getElementById("ciphertext").addEventListener("keyup", update_ciphertext_button_state);

function update_plaintext_button_state() {
  const submit_plaintext_button = document.getElementById("submit_plaintext");
  if (document.getElementById("plaintext").value === "" || fetched_derived_key_material === null) {
    submit_plaintext_button.setAttribute("disabled", true);
  } else {
    submit_plaintext_button.removeAttribute("disabled");
  }
}

function update_ciphertext_button_state() {
  const submit_ciphertext_button = document.getElementById("submit_ciphertext");
  if (document.getElementById("ciphertext").value === "" || fetched_derived_key_material === null) {
    submit_ciphertext_button.setAttribute("disabled", true);
  } else {
    submit_ciphertext_button.removeAttribute("disabled");
  }
}

async function get_derived_key_material() {
  try {
    const tsk = TransportSecretKey.random();

    const ek_bytes_hex = await app_backend_actor.encrypted_symmetric_key_for_caller(Array.from(tsk.publicKeyBytes()));
    if (ek_bytes_hex.Err) {
      throw new Error(ek_bytes_hex.Err.error);
    }
    const encryptedVetKey = new EncryptedVetKey(hex_decode(ek_bytes_hex.Ok.key_hex));

    const pk_bytes_hex = await app_backend_actor.symmetric_key_verification_key();
    if (pk_bytes_hex.Err) {
      throw new Error(pk_bytes_hex.Err.error);
    }
    const dpk = DerivedPublicKey.deserialize(hex_decode(pk_bytes_hex.Ok.key_hex));

    const vetKey = encryptedVetKey.decryptAndVerify(tsk, dpk, app_backend_principal.toUint8Array());

    return await vetKey.asDerivedKeyMaterial();
  } catch (error) {
    console.error("get_derived_key_material failed:", error);
    throw error;
  }
}

// IBE functions
document.getElementById("ibe_encrypt_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.setAttribute("disabled", true);
  const result = document.getElementById("ibe_encrypt_result");

  try {
    const ibe_ciphertext = await ibe_encrypt(document.getElementById("ibe_plaintext").value);
    result.innerText = "IBE ciphertext: " + ibe_ciphertext;
    
    document.getElementById("ibe_ciphertext").value = ibe_ciphertext;
    update_ibe_decrypt_button_state();
  } catch (error) {
    result.innerText = "Error: " + error.message;
    console.error("IBE encryption failed:", error);
  }

  button.removeAttribute("disabled");
  return false;
});

document.getElementById("ibe_decrypt_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.setAttribute("disabled", true);
  const result = document.getElementById("ibe_decrypt_result");

  try {
    const ibe_plaintext = await ibe_decrypt(document.getElementById("ibe_ciphertext").value);
    result.innerText = "IBE plaintext: " + ibe_plaintext;
  } catch (error) {
    result.innerText = "Error: " + error.message;
    console.error("IBE decryption failed:", error);
  }

  button.removeAttribute("disabled");
  return false;
});


// Set minimum datetime and default value
document.addEventListener('DOMContentLoaded', function() {
  const now = new Date();
  const datetimeInput = document.getElementById('timelock_datetime');
  if (datetimeInput) {
    // Set minimum to current time
    now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
    datetimeInput.min = now.toISOString().slice(0, 16);
    
    // Set default to 1 hour from now
    const oneHourLater = new Date(now.getTime() + 60 * 60 * 1000);
    datetimeInput.value = oneHourLater.toISOString().slice(0, 16);
  }
});

// Timelock event listeners
document.getElementById("timelock_title").addEventListener("keyup", update_timelock_create_button_state);
document.getElementById("timelock_content").addEventListener("keyup", update_timelock_create_button_state);
document.getElementById("timelock_datetime").addEventListener("change", update_timelock_create_button_state);
document.getElementById("decrypt_timelock_id").addEventListener("keyup", update_timelock_decrypt_button_state);

function update_timelock_create_button_state() {
  const button = document.getElementById("create_timelock_btn");
  const title = document.getElementById("timelock_title").value.trim();
  const content = document.getElementById("timelock_content").value.trim();
  const datetime = document.getElementById("timelock_datetime").value;
  
  if (title && content && datetime) {
    button.removeAttribute("disabled");
  } else {
    button.setAttribute("disabled", true);
  }
}

function update_timelock_decrypt_button_state() {
  const button = document.getElementById("decrypt_timelock_btn");
  const timelockId = document.getElementById("decrypt_timelock_id").value.trim();
  
  if (timelockId) {
    button.removeAttribute("disabled");
  } else {
    button.setAttribute("disabled", true);
  }
}

// Create timelock message
document.getElementById("timelock_create_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.setAttribute("disabled", true);
  const result = document.getElementById("timelock_create_result");

  try {
    const title = document.getElementById("timelock_title").value.trim();
    const content = document.getElementById("timelock_content").value.trim();
    const datetime = document.getElementById("timelock_datetime").value;
    
    // Convert datetime to Unix timestamp
    const unlockTimestamp = Math.floor(new Date(datetime).getTime() / 1000);
    
    result.innerText = "Creating timelock message...";
    
    // Step 1: Create timelock message
    const createResult = await app_backend_actor.create_timelock_message(content, BigInt(unlockTimestamp), title);
    
    if (createResult.Err) {
      throw new Error(createResult.Err);
    }
    
    const timelockId = createResult.Ok;
    
    result.innerText = "Encrypting message with IBE...";
    
    // Step 2: Get master public key for timelock
    const pkResult = await app_backend_actor.timelock_encryption_key();
    if (pkResult.Err) {
      throw new Error(pkResult.Err);
    }
    
    const masterPublicKey = DerivedPublicKey.deserialize(hex_decode(pkResult.Ok));
    
    // Step 3: Get timelock identity
    const identityResult = await app_backend_actor.get_timelock_identity(timelockId);
    if (identityResult.Err) {
      throw new Error(identityResult.Err);
    }
    
    const timelockIdentity = identityResult.Ok;
    
    // Step 4: IBE encrypt message
    const messageEncoded = new TextEncoder().encode(content);
    const ibeIdentity = IbeIdentity.fromBytes(new TextEncoder().encode(timelockIdentity));
    const ibeCiphertext = IbeCiphertext.encrypt(
      masterPublicKey,
      ibeIdentity,
      messageEncoded,
      IbeSeed.random()
    );
    
    const encryptedContentHex = hex_encode(ibeCiphertext.serialize());
    
    result.innerText = "Updating timelock with encrypted content...";
    
    // Step 5: Update timelock with encrypted content
    const updateResult = await app_backend_actor.update_timelock_content(timelockId, encryptedContentHex);
    if (updateResult.Err) {
      throw new Error(updateResult.Err);
    }
    
    result.innerText = `✅ Time-locked message created successfully!\nTimelock ID: ${timelockId}\nUnlocks at: ${new Date(unlockTimestamp * 1000).toLocaleString()}`;
    
    // Clear form
    document.getElementById("timelock_title").value = "";
    document.getElementById("timelock_content").value = "";
    update_timelock_create_button_state();
    
  } catch (error) {
    result.innerText = "Error: " + error.message;
    console.error("Create timelock failed:", error);
  }

  button.removeAttribute("disabled");
  return false;
});

// Load and display user's timelocks
async function loadTimelocks() {
  const listElement = document.getElementById("timelocks_list");
  
  try {
    listElement.innerHTML = "Loading timelocks...";
    
    const timelocks = await app_backend_actor.get_my_timelocks();
    
    if (timelocks.length === 0) {
      listElement.innerHTML = "<p>No time-locked messages found.</p>";
      return;
    }
    
    let html = "<div style='margin-top: 10px;'>";
    
    timelocks.forEach(timelock => {
      const unlockDate = new Date(Number(timelock.unlock_timestamp) * 1000);
      const isExpired = timelock.is_expired;
      
      html += `
        <div style='border: 1px solid #ccc; padding: 15px; margin: 10px 0; border-radius: 5px; background: ${isExpired ? '#e8f5e8' : '#fff8dc'}'>
          <strong>${timelock.title}</strong><br>
          <small>ID: ${timelock.id}</small><br>
          <small>Unlocks: ${unlockDate.toLocaleString()}</small><br>
          <small>Status: ${isExpired ? '🔓 EXPIRED - Can decrypt' : '🔒 LOCKED'}</small>
          ${isExpired ? `<br><button onclick="quickDecrypt('${timelock.id}')" style='margin-top: 10px; padding: 5px 10px; background: #27ae60; color: white; border: none; border-radius: 3px; cursor: pointer;'>Decrypt Now</button>` : ''}
        </div>
      `;
    });
    
    html += "</div>";
    listElement.innerHTML = html;
    
  } catch (error) {
    listElement.innerHTML = "Error loading timelocks: " + error.message;
    console.error("Load timelocks failed:", error);
  }
}

// Quick decrypt function for buttons in the list
window.quickDecrypt = async function(timelockId) {
  const result = document.getElementById("timelock_decrypt_result");
  
  try {
    result.innerText = "Decrypting timelock message...";
    
    // Get decryption key
    const tsk = TransportSecretKey.random();
    const keyResult = await app_backend_actor.get_timelock_decryption_key(timelockId, Array.from(tsk.publicKeyBytes()));
    
    if (keyResult.Err) {
      throw new Error(keyResult.Err);
    }
    
    const encryptedVetKey = new EncryptedVetKey(hex_decode(keyResult.Ok));
    
    // Get master public key for verification
    const pkResult = await app_backend_actor.timelock_encryption_key();
    if (pkResult.Err) {
      throw new Error(pkResult.Err);
    }
    
    const masterPublicKey = DerivedPublicKey.deserialize(hex_decode(pkResult.Ok));
    
    // Get timelock identity
    const identityResult = await app_backend_actor.get_timelock_identity(timelockId);
    if (identityResult.Err) {
      throw new Error(identityResult.Err);
    }
    
    const timelockIdentity = identityResult.Ok;
    
    // Decrypt vetKey
    const vetKey = encryptedVetKey.decryptAndVerify(
      tsk,
      masterPublicKey,
      new TextEncoder().encode(timelockIdentity)
    );
    
    // Get encrypted content
    const contentResult = await app_backend_actor.get_timelock_content(timelockId);
    if (contentResult.Err) {
      throw new Error(contentResult.Err);
    }
    
    // Decrypt content
    const ibeCiphertext = IbeCiphertext.deserialize(hex_decode(contentResult.Ok));
    const decryptedBytes = ibeCiphertext.decrypt(vetKey);
    const decryptedMessage = new TextDecoder().decode(decryptedBytes);
    
    result.innerText = `✅ Decrypted message:\n"${decryptedMessage}"`;
    
    // Auto-fill the decrypt form
    document.getElementById("decrypt_timelock_id").value = timelockId;
    update_timelock_decrypt_button_state();
    
  } catch (error) {
    result.innerText = "Error: " + error.message;
    console.error("Quick decrypt failed:", error);
  }
};

// Manual decrypt form
document.getElementById("timelock_decrypt_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const timelockId = document.getElementById("decrypt_timelock_id").value.trim();
  await quickDecrypt(timelockId);
  return false;
});

// Refresh timelocks button
document.getElementById("refresh_timelocks_btn").addEventListener("click", loadTimelocks);

// IBE event listeners
document.getElementById("ibe_plaintext").addEventListener("keyup", update_ibe_encrypt_button_state);
document.getElementById("ibe_principal").addEventListener("keyup", update_ibe_encrypt_button_state);
document.getElementById("ibe_ciphertext").addEventListener("keyup", update_ibe_decrypt_button_state);

function update_ibe_encrypt_button_state() {
  const ibe_encrypt_button = document.getElementById("ibe_encrypt");
  if (document.getElementById("ibe_plaintext").value === "" || document.getElementById("ibe_principal").value === "") {
    ibe_encrypt_button.setAttribute("disabled", true);
  } else {
    ibe_encrypt_button.removeAttribute("disabled");
  }
}

function update_ibe_decrypt_button_state() {
  const ibe_decrypt_button = document.getElementById("ibe_decrypt");
  if (document.getElementById("ibe_ciphertext").value === "") {
    ibe_decrypt_button.setAttribute("disabled", true);
  } else {
    ibe_decrypt_button.removeAttribute("disabled");
  }
}

async function ibe_encrypt(message) {
  try {
    document.getElementById("ibe_encrypt_result").innerText = "Fetching IBE encryption key..."
    const pk_bytes_hex = await app_backend_actor.ibe_encryption_key();
    if (pk_bytes_hex.Err) {
      throw new Error(pk_bytes_hex.Err.error);
    }
    const dpk = DerivedPublicKey.deserialize(hex_decode(pk_bytes_hex.Ok.key_hex));

    document.getElementById("ibe_encrypt_result").innerText = "Preparing IBE-encryption..."
    const message_encoded = new TextEncoder().encode(message);
    let ibe_principal = Principal.fromText(document.getElementById("ibe_principal").value);

    document.getElementById("ibe_encrypt_result").innerText = "IBE-encrypting for principal " + ibe_principal.toText() + "...";
    const ibe_ciphertext = IbeCiphertext.encrypt(
      dpk,
      IbeIdentity.fromPrincipal(ibe_principal),
      message_encoded,
      IbeSeed.random(),
    );
    return hex_encode(ibe_ciphertext.serialize());
  } catch (error) {
    console.error("IBE encrypt failed:", error);
    throw error;
  }
}

async function ibe_decrypt(ibe_ciphertext_hex) {
  try {
    document.getElementById("ibe_decrypt_result").innerText = "Fetching IBE encryption key (needed for verification)..."
    const pk_bytes_hex = await app_backend_actor.ibe_encryption_key();
    if (pk_bytes_hex.Err) {
      throw new Error(pk_bytes_hex.Err.error);
    }
    const dpk = DerivedPublicKey.deserialize(hex_decode(pk_bytes_hex.Ok.key_hex));

    document.getElementById("ibe_decrypt_result").innerText = "Fetching IBE decryption key..."
    const tsk = TransportSecretKey.random();
    const ek_bytes_hex = await app_backend_actor.encrypted_ibe_decryption_key_for_caller(Array.from(tsk.publicKeyBytes()));
    if (ek_bytes_hex.Err) {
      throw new Error(ek_bytes_hex.Err.error);
    }
    const encryptedVetKey = new EncryptedVetKey(hex_decode(ek_bytes_hex.Ok.key_hex));

    document.getElementById("ibe_decrypt_result").innerText = "Decrypting and verifying IBE decryption key..."
    const vetKey = encryptedVetKey.decryptAndVerify(
      tsk,
      dpk,
      app_backend_principal.toUint8Array()
    );

    document.getElementById("ibe_decrypt_result").innerText = "Using IBE decryption key to decrypt ciphertext..."
    const ibe_ciphertext = IbeCiphertext.deserialize(hex_decode(ibe_ciphertext_hex));
    const ibe_plaintext = ibe_ciphertext.decrypt(vetKey);
    return new TextDecoder().decode(ibe_plaintext);
  } catch (error) {
    console.error("IBE decrypt failed:", error);
    throw error;
  }
}

function annotated_principal(principal) {
  let principal_string = principal.toString();
  if (principal_string == "2vxsx-fae") {
    return "Anonymous principal (2vxsx-fae)";
  } else {
    return "Principal: " + principal_string;
  }
}

const hex_decode = (hexString) =>
  Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
const hex_encode = (bytes) =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');