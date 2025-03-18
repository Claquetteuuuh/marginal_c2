mod constants;
use std::fs;

async fn check_version() -> bool {
    let mut local_version: String = String::new();
    match get_local_version(String::from("version.txt")).await {
        Ok(my_version) => local_version = my_version,
        Err(e) => eprintln!("Error getting version: {}", e),
    }

    let mut latest_version: String = String::new();
    match get_latest_version().await {
        Ok(result) => latest_version = result,
        Err(e) => eprintln!("Error checking version: {}", e),
    }

    if latest_version == local_version {
        return true;
    }
    return false;
}

async fn get_latest_version() -> Result<String, reqwest::Error> {
    let body = reqwest::get(constants::get_github_repository_url())
        .await?
        .text()
        .await?;

    return Ok(body);
}

async fn get_local_version(version_file: String) -> Result<String, std::io::Error> {
    let contents = fs::read_to_string(version_file);
    return contents;
}

#[tokio::main]
async fn main() {
    let good_version = check_version().await;
    if !good_version {
        println!("Le c2 n'est pas à jour !");
    } else {
        println!("Le c2 est à jour !");
    }
}
