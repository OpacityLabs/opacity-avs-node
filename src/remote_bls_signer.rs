use ark_bn254::{g1::G1Affine, Fq};
use ark_ff::PrimeField;
use cerberus_api::{client::SignerClient, SignGenericRequest, SignGenericResponse};
use eyre::Result;

pub async fn get_signature(
    public_key: &str,
    message_bytes: [u8; 32],
    password: &str,
    signer_endpoint: String,
) -> Result<G1Affine> {
    let mut client = SignerClient::connect(signer_endpoint).await?;
    let request = tonic::Request::new(SignGenericRequest {
        public_key: public_key.to_string(),
        data: message_bytes.to_vec(),
        password: password.to_string(),
    });
    let response: tonic::Response<SignGenericResponse> = client.sign_generic(request).await?;
    let g1_affine = response_to_g1_affine(response.into_inner())?;
    Ok(g1_affine)
}

pub fn response_to_g1_affine(response: SignGenericResponse) -> Result<G1Affine> {
    let signature_bytes = response.signature.clone();
    Ok(G1Affine::new(
        Fq::from_be_bytes_mod_order(&signature_bytes[0..32]),
        Fq::from_be_bytes_mod_order(&signature_bytes[32..64]),
    ))
}
