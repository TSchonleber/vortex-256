//! Checks the Rust VORTEX-PQ implementation against vectors produced by the TypeScript
//! implementation (`npm run vectors` writes ../vectors/vortex-pq.json).

use vortex256::pq::{open, public_key_from_seed, seal_with_eseed};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn field<'a>(obj: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\": \"");
    let start = obj.find(&key).unwrap_or_else(|| panic!("missing {name}")) + key.len();
    &obj[start..start + obj[start..].find('"').unwrap()]
}

const VECTORS: &str = include_str!("../../vectors/vortex-pq.json");

#[test]
fn envelopes_match_typescript() {
    let body = &VECTORS[VECTORS.find("\"vectors\": [").unwrap()..];
    let objects: Vec<&str> = body.split('{').skip(1).collect();
    assert!(!objects.is_empty());
    for v in objects {
        let seed = unhex(field(v, "seed"));
        let pk = public_key_from_seed(&seed).unwrap();
        assert_eq!(pk, unhex(field(v, "public_key")), "public key");
        let (pt, aad) = (unhex(field(v, "plaintext")), unhex(field(v, "aad")));
        let env = seal_with_eseed(&pk, &pt, &aad, &unhex(field(v, "eseed"))).unwrap();
        assert_eq!(env, unhex(field(v, "envelope")), "envelope");
        assert_eq!(open(&seed, &env, &aad).unwrap(), pt);
    }
}
