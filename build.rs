use reqwest::blocking::Client;
use std::error::Error;
use std::fs::{File, create_dir_all};
use std::io::copy;
use std::path::{Path, PathBuf};

/// download semaphore artifacts by required tree depth
fn download_semaphore_artifacts(depth: usize) -> Result<(), Box<dyn Error>> {
    let base_url = "https://snark-artifacts.pse.dev/semaphore/latest/";
    let remote_filenames = [
        format!("semaphore-{}.wasm", depth),
        format!("semaphore-{}.zkey", depth),
    ];
    let local_filenames = ["semaphore.wasm", "semaphore.zkey"];

    let client = Client::new();
    let target_dir = Path::new("./zkey");

    // Verify if those files have been downloaded or not. Skip downloading if yes.
    let version_path = target_dir.join("depth");
    if version_path.exists() {
        let current_version = std::fs::read_to_string(&version_path)?.trim().to_string();
        if current_version == depth.to_string() {
            println!(
                "Artifacts for depth {} already downloaded, skipping.",
                depth
            );
            return Ok(());
        }
    }
    // create ./zkey folder
    create_dir_all(target_dir)?;

    // download artifacts
    for (remote, local) in remote_filenames.iter().zip(local_filenames.iter()) {
        let url = format!("{}{}", base_url, remote);
        let dest_path: PathBuf = target_dir.join(local);

        eprintln!("Downloading {}...", url);
        let mut resp = client.get(&url).send()?.error_for_status()?;
        let mut out = File::create(&dest_path)?;
        copy(&mut resp, &mut out)?;
        eprintln!("Saved as {}", dest_path.display());
    }

    // update depth info
    std::fs::write(&version_path, depth.to_string())?;

    Ok(())
}

fn main() {
    // Default depth is 10 for testing purposes; can be overridden via SEMAPHORE_DEPTH environment variable
    let depth: usize = std::env::var("SEMAPHORE_DEPTH")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .expect("SEMAPHORE_DEPTH must be a valid usize");

    download_semaphore_artifacts(depth).expect("Failed to download artifacts");

    rust_witness::transpile::transpile_wasm("./zkey".to_string());
}
