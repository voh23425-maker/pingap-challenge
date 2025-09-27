// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use block_padding::Pkcs7;
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit};
use md5::{Digest, Md5};

// type alias
type Aes256Cbc = Decryptor<Aes256>;

/// Key derivation function (EvpKDF)
fn evp_kdf(
    password: &[u8],
    salt: &[u8],
    key_len: usize,
    iv_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    let mut derived_key_material = Vec::new();
    let mut last_digest = Vec::<u8>::new();

    while derived_key_material.len() < key_len + iv_len {
        let mut hasher = Md5::new();
        if !last_digest.is_empty() {
            hasher.update(&last_digest);
        }
        hasher.update(password);
        hasher.update(salt);
        last_digest = hasher.finalize().to_vec();
        derived_key_material.extend_from_slice(&last_digest);
    }
    (
        derived_key_material[..key_len].to_vec(),
        derived_key_material[key_len..key_len + iv_len].to_vec(),
    )
}

/// Decryption function
pub(crate) fn decrypt(
    encrypted_base64: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_data = STANDARD.decode(encrypted_base64)?;

    let salt_header = b"Salted__";
    if encrypted_data.len() < 16 || &encrypted_data[..8] != salt_header {
        return Err(
            "Invalid encrypted data format: missing salt header.".into()
        );
    }

    let salt = &encrypted_data[8..16];
    let ciphertext = &encrypted_data[16..];

    let (key, iv) = evp_kdf(password.as_bytes(), salt, 32, 16);

    let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;

    let buf = ciphertext.to_vec();
    let decrypted_bytes = cipher
        .decrypt_padded_vec_mut::<Pkcs7>(&buf)
        .map_err(|e| e.to_string())?;

    Ok(String::from_utf8(decrypted_bytes.to_vec())?)
}
