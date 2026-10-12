//! Checks the Rust vault against vectors produced by the TypeScript implementation
//! (`npm run vectors` writes ../vectors/vortex-pq-vault.json).

use vortex256::vault::{vault_open_with, vault_seal_with, Argon2Params};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn field<'a>(obj: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\": \"");
    let start = obj.find(&key).unwrap_or_else(|| panic!("missing {name}")) + key.len();
    &obj[start..start + obj[start..].find('"').unwrap()]
}

fn number(obj: &str, name: &str) -> u32 {
    let key = format!("\"{name}\": ");
    let start = obj.find(&key).unwrap_or_else(|| panic!("missing {name}")) + key.len();
    obj[start..].chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap()
}

const VECTORS: &str = include_str!("../../vectors/vortex-pq-vault.json");

#[test]
fn vaults_match_typescript() {
    let body = &VECTORS[VECTORS.find("\"vectors\": [").unwrap()..];
    // Each vector object starts with "password"; split on that to keep nested "params" together.
    let objects: Vec<&str> = body.split("\"password\"").skip(1).collect();
    assert!(!objects.is_empty());
    for v in objects {
        let v = format!("\"password\"{v}");
        let params = Argon2Params { m: number(&v, "m"), t: number(&v, "t"), p: number(&v, "p") as u8 };
        let salt: [u8; 32] = unhex(field(&v, "salt")).try_into().unwrap();
        let (pw, pt, aad) = (unhex(field(&v, "password")), unhex(field(&v, "plaintext")), unhex(field(&v, "aad")));
        let vault = vault_seal_with(&pw, &pt, &aad, params, &salt, true).unwrap();
        assert_eq!(vault, unhex(field(&v, "vault")));
        assert_eq!(vault_open_with(&pw, &vault, &aad, true).unwrap(), pt);
    }
}
