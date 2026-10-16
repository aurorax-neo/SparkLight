//! 仅测试构建：公开标量 1 不得用于账号；不提供任何生产签名 API。
use super::sdk_runtime::official_ticket_input;
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::{
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    pkcs8::DecodePublicKey,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("sdk/ecdsa_offline_baseline.json")).unwrap()
}

fn decode(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

#[test]
fn official_ecdsa_der_signatures_verify_in_rust() {
    let data = fixture();
    let point = decode(&data["public_key_sec1_base64"]);
    assert_eq!(point.len(), 65);
    assert_eq!(point[0], 4);
    let public = VerifyingKey::from_sec1_bytes(&point).unwrap();
    let spki = VerifyingKey::from_public_key_der(&decode(&data["public_key_spki_base64"])).unwrap();
    assert_eq!(public, spki);
    for case in data["cases"].as_array().unwrap() {
        let input = &case["input"];
        let output = official_ticket_input(
            input["path"].as_str().unwrap(),
            input["ticket"].as_str().unwrap(),
            input["timestamp"].as_i64().unwrap(),
        )
        .unwrap();
        assert_eq!(output.sign_data, case["sign_data"].as_str().unwrap());
        let der = decode(&case["official_signature_der_base64"]);
        let signature = Signature::from_der(&der).unwrap();
        assert_eq!(signature.to_der().as_bytes(), der);
        public
            .verify(output.sign_data.as_bytes(), &signature)
            .unwrap();
        // 改路径、票据或时间均不得通过；这些仅为公开离线输入。
        for altered in [
            output
                .sign_data
                .replace(input["path"].as_str().unwrap(), "/other"),
            output.sign_data.replace("offline-ticket", "other-ticket"),
            output
                .sign_data
                .replace(input["timestamp"].to_string().as_str(), "1700009999"),
        ] {
            assert!(public.verify(altered.as_bytes(), &signature).is_err());
        }
    }
}

#[test]
fn rust_ecdsa_der_signatures_match_cross_verification_fixture() {
    let data = fixture();
    let scalar = hex::decode(data["test_scalar_hex"].as_str().unwrap()).unwrap();
    let key = SigningKey::from_slice(&scalar).unwrap();
    assert_eq!(
        key.verifying_key().to_encoded_point(false).as_bytes(),
        decode(&data["public_key_sec1_base64"])
    );
    for case in data["cases"].as_array().unwrap() {
        let message = case["sign_data"].as_str().unwrap().as_bytes();
        let signature: Signature = key.sign(message);
        key.verifying_key().verify(message, &signature).unwrap();
        assert_eq!(
            signature.to_der().as_bytes(),
            decode(&case["rust_signature_der_base64"])
        );
    }
}

#[test]
fn ecdsa_rejects_wrong_keys_tampering_and_invalid_encoding() {
    let data = fixture();
    let case = &data["cases"][0];
    let message = case["sign_data"].as_str().unwrap().as_bytes();
    let der = decode(&case["official_signature_der_base64"]);
    let signature = Signature::from_der(&der).unwrap();
    let wrong_key = SigningKey::from_slice(&[2; 32]).unwrap();
    assert!(
        wrong_key
            .verifying_key()
            .verify(message, &signature)
            .is_err()
    );
    let public = VerifyingKey::from_sec1_bytes(&decode(&data["public_key_sec1_base64"])).unwrap();
    let mut changed = signature.to_bytes();
    changed[10] ^= 1;
    if let Ok(changed) = Signature::from_slice(&changed) {
        assert!(public.verify(message, &changed).is_err());
    }
    assert!(Signature::from_der(&signature.to_bytes()).is_err());
    assert!(Signature::from_der(&der[..der.len() - 1]).is_err());
    let mut trailing = der;
    trailing.push(0);
    assert!(Signature::from_der(&trailing).is_err());
    assert!(STANDARD.decode("!not-base64!").is_err());
}
