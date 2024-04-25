use crate::{process_genpass, TextEncryptFormat, TextSignFormat};
use anyhow::Result;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::{collections::HashMap, io::Read};

pub trait TextSigner {
    // signer could sign any input data
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    // verifier could verify any input data
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

pub struct XChaCha20Poly1305Encryptor {
    key: [u8; 32],
}

pub struct XChaCha20Poly1305Decrypter {
    key: [u8; 32],
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes() == sig)
    }
}

impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let signature = self.key.sign(&buf);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = (&sig[..64]).try_into()?;
        let signature = Signature::from_bytes(sig);
        Ok(self.key.verify(&buf, &signature).is_ok())
    }
}

pub trait TextEncrypt {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextDecrypt {
    fn decrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

impl TextEncrypt for XChaCha20Poly1305Encryptor {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .expect("Key needs to be of correct size for XChaCha20Poly1305");

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, buf.as_ref())
            .expect("Encryption failure!");

        // Combine the nonce and the ciphertext for output
        let mut output = Vec::with_capacity(nonce.len() + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }
}

impl TextDecrypt for XChaCha20Poly1305Decrypter {
    fn decrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .expect("Key needs to be of correct size for XChaCha20Poly1305");
        // Ensure the buffer has enough bytes for extracting the nonce
        let nonce_size = XChaCha20Poly1305::generate_nonce(&mut OsRng).len();
        let (nonce_bytes, ciphertext) = buf.split_at(nonce_size);
        let nonce = GenericArray::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .expect("Decryption failure!");

        Ok(plaintext)
    }
}

impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to &[u8; 32]
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake3.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl Ed25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk: SigningKey = SigningKey::generate(&mut csprng);
        let pk: VerifyingKey = (&sk).into();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.to_bytes().to_vec());
        map.insert("ed25519.pk", pk.to_bytes().to_vec());

        Ok(map)
    }
}

impl Ed25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

impl XChaCha20Poly1305Encryptor {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        let key = key.as_ref();
        // TODO: check key length, if not long enough, extend it
        let key = (&key[..32]).try_into().unwrap();
        Self { key }
    }
}

impl XChaCha20Poly1305Decrypter {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        let key = key.as_ref();
        // TODO: check key length, if not long enough, extend it
        let key = (&key[..32]).try_into().unwrap();
        Self { key }
    }
}

pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8], // (ptr, length)
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
    };

    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

pub fn process_text_key_encrypt(
    reader: &mut dyn Read,
    key: &[u8],
    format: TextEncryptFormat,
) -> Result<Vec<u8>> {
    let encryptor: Box<dyn TextEncrypt> = match format {
        TextEncryptFormat::XChaCha20Poly1305 => Box::new(XChaCha20Poly1305Encryptor::new(key)),
    };
    encryptor.encrypt(reader)
}

pub fn process_text_key_decrypt(
    reader: &mut dyn Read,
    key: &[u8],
    format: TextEncryptFormat,
) -> Result<Vec<u8>> {
    let decrypter: Box<dyn TextDecrypt> = match format {
        TextEncryptFormat::XChaCha20Poly1305 => Box::new(XChaCha20Poly1305Decrypter::new(key)),
    };
    decrypter.decrypt(reader)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let mut reader1 = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = "33Ypo4rveYpWmJKAiGnnse-wHQhMVujjmcVkV4Tl43k";
        let sig = URL_SAFE_NO_PAD.decode(sig)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        if ret {
            println!("Signature is valid");
        } else {
            println!("Signature is invalid");
        }
        Ok(())
    }

    #[test]
    fn text_process_text_key_generate() -> Result<()> {
        let format = TextSignFormat::Blake3;
        let map = process_text_key_generate(format)?;
        assert_eq!(map.len(), 1);
        Ok(())
    }

    #[test]
    fn text_process_text_key_encrypt() -> Result<()> {
        let mut reader = fs::File::open("Cargo.toml")?;
        let format = TextEncryptFormat::XChaCha20Poly1305;
        let key = process_genpass(32, true, true, true, true)?;
        let key = key.as_bytes();
        let encrypted = process_text_key_encrypt(&mut reader, key, format)?;
        let encoded = URL_SAFE_NO_PAD.encode(encrypted);
        let decoded = URL_SAFE_NO_PAD.decode(encoded)?;
        let decrypted = process_text_key_decrypt(&mut decoded.as_slice(), key, format)?;
        assert_eq!(decrypted, fs::read("Cargo.toml")?);
        Ok(())
    }
}
