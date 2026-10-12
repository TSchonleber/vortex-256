//! Checks the Rust implementation against vectors produced by the TypeScript
//! reference (`npm run vectors` writes ../vectors/vectors.json).

use vortex256::{aead_decrypt, aead_encrypt, decrypt_block, encrypt_block, expand_key};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Pulls `"name": "value"` string fields out of one JSON object, in order.
fn field<'a>(obj: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\": \"");
    let start = obj.find(&key).unwrap_or_else(|| panic!("missing {name}")) + key.len();
    &obj[start..start + obj[start..].find('"').unwrap()]
}

fn objects<'a>(json: &'a str, section: &str) -> Vec<&'a str> {
    let start = json.find(&format!("\"{section}\": [")).unwrap();
    let body = &json[start..start + json[start..].find(']').unwrap()];
    body.split('{').skip(1).collect()
}

const VECTORS: &str = include_str!("../../vectors/vectors.json");

#[test]
fn block_vectors_match_typescript() {
    for v in objects(VECTORS, "block") {
        let ks = expand_key(&unhex(field(v, "key")));
        let pt = unhex(field(v, "plaintext"));
        let ct = encrypt_block(&pt, &ks);
        assert_eq!(ct.to_vec(), unhex(field(v, "ciphertext")));
        assert_eq!(decrypt_block(&ct, &ks).to_vec(), pt);
    }
}

#[test]
fn aead_vectors_match_typescript() {
    for v in objects(VECTORS, "aead") {
        let (key, nonce, aad, pt) = (unhex(field(v, "key")), unhex(field(v, "nonce")), unhex(field(v, "aad")), unhex(field(v, "plaintext")));
        let (ct, tag) = aead_encrypt(&key, &nonce, &pt, &aad).unwrap();
        assert_eq!(ct, unhex(field(v, "ciphertext")));
        assert_eq!(tag.to_vec(), unhex(field(v, "tag")));
        assert_eq!(aead_decrypt(&key, &nonce, &ct, &tag, &aad).unwrap(), Some(pt));
    }
}
