mod constants;
mod rsa;
mod aes;
mod version;

#[tokio::main]
async fn main() {
    let good_version = version::check_version().await;
    if !good_version {
        println!("Le c2 n'est pas à jour !");
        std::process::exit(1);
    } else {
        let key = aes::SecureAes::generate_key();
        let cypher = aes::SecureAes::new(&key);
        let message = "Salut à super bg".as_bytes();
        let encrypted_msg = cypher.encrypt(message).unwrap();

        let decrypted_msg = cypher.decrypt(&encrypted_msg).unwrap();

        let french_string = String::from_utf8(decrypted_msg).unwrap();

        println!("{:?}", french_string)

    }

    std::process::exit(0);
}

