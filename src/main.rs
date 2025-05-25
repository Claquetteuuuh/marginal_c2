mod constants;
mod rsa;
mod version;

#[tokio::main]
async fn main() {
    let good_version = version::check_version().await;
    if !good_version {
        println!("Le c2 n'est pas à jour !");
        std::process::exit(1);
    } else {
        
    }

    std::process::exit(0);
}

