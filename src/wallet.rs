use crate::{bn254::BN254SigningKey, vec_to_fr};

pub fn load_operator_bls_key(
    bls_key_path: &String,
    password: &String,
) -> Result<BN254SigningKey, Box<dyn std::error::Error>> {
    let bn254_private_key_result = eth_bn254_keystore::decrypt_key(&bls_key_path, &password);

    let bn254_private_key = match bn254_private_key_result {
        Ok(signer) => signer,
        Err(error) => panic!("Problem loading BLS key: {error:?}"),
    };
    let bn254_private_key = vec_to_fr(bn254_private_key).unwrap();

    Ok(bn254_private_key)
}
