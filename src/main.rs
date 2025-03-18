mod version;
mod constants;

#[tokio::main]
async fn main() {
    let good_version = version::check_version().await;
    if !good_version {
        println!("Le c2 n'est pas à jour !");
    } else {
        println!("Le c2 est à jour !");
    }
}
