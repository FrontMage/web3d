use ethers::core::rand::thread_rng;
use ethers::signers::LocalWallet;
use std::path::Path;
/// Making sure wallet file exists and readable
pub fn ensure_wallet(
    wallet_dir: &str,
    wallet_filename: &str,
    password: &str,
) -> Result<LocalWallet, std::io::Error> {
    if !Path::new(wallet_dir).exists() {
        std::fs::create_dir_all(wallet_dir)?;
    }
    let key_path = Path::new(wallet_dir).join(wallet_filename);
    match LocalWallet::decrypt_keystore(&key_path, password) {
        Ok(wallet) => {
            log::info!("Restore evm wallet from key {:?}", key_path.to_str());
            Ok(wallet)
        }
        Err(e) => {
            if !key_path.exists() {
                log::info!("No existing key found, creating new evm wallet");
                let (wallet, filename) =
                    LocalWallet::new_keystore(&wallet_dir, &mut thread_rng(), password).unwrap();
                std::fs::rename(Path::new(wallet_dir).join(filename), &key_path)?;
                Ok(wallet)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{:?}", e),
                ))
            }
        }
    }
}
