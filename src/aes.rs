use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use rand::RngCore;

pub struct SecureAes {
    cipher: Aes256Gcm,
}

impl SecureAes {
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = self.cipher
            .encrypt(&nonce, data)
            .map_err(|e| format!("Erreur de chiffrement: {}", e))?;
        
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted_data.len() < 12 + 16 { // nonce + minimum tag size
            return Err("Données chiffrées trop courtes".to_string());
        }
        
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Erreur de déchiffrement ou données corrompues: {}", e))?;
        
        Ok(plaintext)
    }

    pub fn encrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = self.cipher
            .encrypt(&nonce, aes_gcm::aead::Payload { msg: data, aad })
            .map_err(|e| format!("Erreur de chiffrement: {}", e))?;
        
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    pub fn decrypt_with_aad(&self, encrypted_data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted_data.len() < 12 + 16 {
            return Err("Données chiffrées trop courtes".to_string());
        }
        
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = self.cipher
            .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
            .map_err(|e| format!("Erreur de déchiffrement ou données corrompues: {}", e))?;
        
        Ok(plaintext)
    }
}

pub mod simple {
    use super::*;

    pub fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = SecureAes::new(key);
        cipher.encrypt(data)
    }

    pub fn decrypt(key: &[u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = SecureAes::new(key);
        cipher.decrypt(encrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_encryption() {
        let key = SecureAes::generate_key();
        let cipher = SecureAes::new(&key);
        
        let data = "Message secret à protéger!".as_bytes();
        
        // Test chiffrement/déchiffrement simple
        let encrypted = cipher.encrypt(data).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(data.to_vec(), decrypted);
        
        // Test que deux chiffrements du même message sont différents (nonce unique)
        let encrypted2 = cipher.encrypt(data).unwrap();
        assert_ne!(encrypted, encrypted2);
        
        // Mais les deux se déchiffrent correctement
        let decrypted2 = cipher.decrypt(&encrypted2).unwrap();
        assert_eq!(data.to_vec(), decrypted2);
    }

    #[test]
    fn test_tampering_detection() {
        let key = SecureAes::generate_key();
        let cipher = SecureAes::new(&key);
        
        let data = b"Message important";
        let mut encrypted = cipher.encrypt(data).unwrap();
        
        // Modifie un byte des données chiffrées
        encrypted[15] ^= 1;
        
        // Le déchiffrement doit échouer
        assert!(cipher.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_with_aad() {
        let key = SecureAes::generate_key();
        let cipher = SecureAes::new(&key);
        
        let data = "Données secrètes".as_bytes();
        let aad = "Métadonnées publiques".as_bytes();
        
        let encrypted = cipher.encrypt_with_aad(data, aad).unwrap();
        let decrypted = cipher.decrypt_with_aad(&encrypted, aad).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
        
        // Test avec de mauvaises AAD
        let wrong_aad = "Mauvaises métadonnées".as_bytes();
        assert!(cipher.decrypt_with_aad(&encrypted, wrong_aad).is_err());
    }
}