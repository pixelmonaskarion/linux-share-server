use std::collections::HashMap;

use jsonwebtoken::{DecodingKey, Validation, Algorithm, decode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub aud: String,
    pub iss: String,
    pub email: String,
    pub email_verified: bool,
    pub sub: String,
}

async fn get_keys() -> Result<HashMap<String, String>, reqwest::Error> {
    Ok(reqwest::get("https://www.googleapis.com/oauth2/v1/certs")
    .await?
    .json()
    .await?)
}

pub async fn verify_id_token(token: &str, client_id: &str) -> Option<Claims> {
    // Fetch the Google public keys.
    let keys = get_keys().await;
    if keys.is_err() {
        println!("{}", keys.err().unwrap());
        return None;
    }
    let keys = keys.unwrap();
    // Loop through the keys to find one that successfully decodes the token.
    for key in keys.values() {
        let decoding_key = DecodingKey::from_rsa_pem(key.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[client_id.to_string()]);
        validation.set_issuer(&["accounts.google.com".to_string(), "https://accounts.google.com".into()]);
        
        if let Ok(token_data) = decode::<Claims>(token, &decoding_key, &validation) {
            return Some(token_data.claims);
        }
    }

    return None;
}