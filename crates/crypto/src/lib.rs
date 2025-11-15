use age::{x25519, Decryptor, Encryptor};
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption disabled")]
    Disabled,
    #[error("crypto error: {0}")]
    Generic(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CryptoConfig {
    pub recipients: Vec<String>,
    pub enabled: bool,
}

#[derive(Clone)]
pub struct CryptoFacade {
    cfg: CryptoConfig,
    // In future: cache parsed recipients/keys
}

impl CryptoFacade {
    #[must_use]
    pub fn new(cfg: CryptoConfig) -> Self {
        Self { cfg }
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError> {
        if !self.cfg.enabled {
            return Ok(plaintext.to_owned());
        }
        let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();
        for r in &self.cfg.recipients {
            let rec =
                x25519::Recipient::from_str(r).map_err(|e| CryptoError::Generic(e.to_string()))?;
            recipients.push(Box::new(rec));
        }
        let encryptor = Encryptor::with_recipients(recipients)
            .ok_or_else(|| CryptoError::Generic("no recipients".into()))?;
        let mut out = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|e| CryptoError::Generic(e.to_string()))?;
        writer
            .write_all(plaintext.as_bytes())
            .map_err(|e| CryptoError::Generic(e.to_string()))?;
        writer
            .finish()
            .map_err(|e| CryptoError::Generic(e.to_string()))?;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        Ok(B64.encode(out))
    }

    pub fn decrypt(&self, ciphertext: &str, secret: &SecretString) -> Result<String, CryptoError> {
        if !self.cfg.enabled {
            return Ok(ciphertext.to_owned());
        }
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let data = B64
            .decode(ciphertext)
            .map_err(|e| CryptoError::Generic(e.to_string()))?;
        let dec = Decryptor::new(&data[..]).map_err(|e| CryptoError::Generic(e.to_string()))?;
        match dec {
            Decryptor::Recipients(d) => {
                let id = x25519::Identity::from_str(secret.expose_secret())
                    .map_err(|e| CryptoError::Generic(e.to_string()))?;
                let mut reader = d
                    .decrypt(std::iter::once(&id as &dyn age::Identity))
                    .map_err(|e| CryptoError::Generic(e.to_string()))?;
                let mut out = String::new();
                reader
                    .read_to_string(&mut out)
                    .map_err(|e| CryptoError::Generic(e.to_string()))?;
                Ok(out)
            }
            Decryptor::Passphrase(_) => {
                Err(CryptoError::Generic("passphrase mode unsupported".into()))
            }
        }
    }
}
