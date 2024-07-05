use ethers::{
    core::k256::{ecdsa::SigningKey},
    signers::{LocalWallet, Wallet},
};

pub fn load_oeprator_wallet(
    ecdsa_key_path: &String,
    password: &String,
) -> Result<Wallet<SigningKey>, Box<dyn std::error::Error>> {
    // Generate a random wallet
    let wallet_result = LocalWallet::decrypt_keystore(ecdsa_key_path, password);

    let wallet = match wallet_result {
        Ok(signer) => signer,
        Err(error) => panic!("Problem loading ECDSA key: {error:?}"),
    };

    Ok(wallet)
}
