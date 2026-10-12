//! HSS/LMS: RFC 8554 Appendix F + RFC 9858 Appendix A vectors, keygen-from-seed
//! reproduction, and the TypeScript-generated cross-language vectors
//! (../vectors/lms-cross.json), plus round-trip / tamper / state tests.

use vortex256::lms::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Pulls a `"name": "value"` string field out of one flat JSON object.
fn field<'a>(obj: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\": \"");
    let start = obj.find(&key).unwrap_or_else(|| panic!("missing {name}")) + key.len();
    &obj[start..start + obj[start..].find('"').unwrap()]
}

/// The flat objects inside the top-level `"cases": [ ... ]` array.
fn cases(json: &str) -> Vec<&str> {
    let start = json.find("\"cases\": [").unwrap();
    let body = &json[start..start + json[start..].find(']').unwrap()];
    body.split('{').skip(1).collect()
}

const RFC8554: &str = include_str!("../../vectors/rfc8554.json");
const RFC9858: &str = include_str!("../../vectors/rfc9858.json");
const CROSS: &str = include_str!("../../vectors/lms-cross.json");

fn seq(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

fn name_to_ots(name: &str) -> u32 {
    LMOTS_PARAMS.iter().find(|p| p.name == name).unwrap().typecode
}

fn name_to_lms(name: &str) -> u32 {
    LMS_PARAMS.iter().find(|p| p.name == name).unwrap().typecode
}

#[test]
fn all_rfc_vectors_verify_and_round_trip() {
    let all: Vec<&str> = cases(RFC8554).into_iter().chain(cases(RFC9858)).collect();
    assert_eq!(all.len(), 6);
    for c in all {
        let (pk, msg, sig) = (unhex(field(c, "publicKey")), unhex(field(c, "message")), unhex(field(c, "signature")));
        assert!(hss_verify(&pk, &msg, &sig), "{}", field(c, "name"));
        assert_eq!(HssPublicKey::decode(&pk).unwrap().encode(), pk);
        assert_eq!(HssSignature::decode(&sig).unwrap().encode(), sig);
        let mut bad = msg.clone();
        bad[0] ^= 1;
        assert!(!hss_verify(&pk, &bad, &sig));
    }
}

#[test]
fn rfc9858_keygen_from_seed_reproduces_h5_vectors() {
    let mut checked = 0;
    for c in cases(RFC9858) {
        let pk = HssPublicKey::decode(&unhex(field(c, "publicKey"))).unwrap();
        if pk.top.lms.h > 10 {
            continue; // A.4 is H20: verify-only
        }
        let sig = HssSignature::decode(&unhex(field(c, "signature"))).unwrap();
        let key = LmsPrivateKey::from_seed(pk.top.lms.typecode, pk.top.ots.typecode, &unhex(field(c, "seed")), &unhex(field(c, "i")), sig.sig.q).unwrap();
        let hss = HssPrivateKey::from_lms_keys(vec![key]).unwrap();
        assert_eq!(tohex(&hss.public_key()), field(c, "publicKey"));
        let signed = hss_sign(hss, &unhex(field(c, "message"))).unwrap();
        assert_eq!(tohex(&signed.signature), field(c, "signature"), "{}", field(c, "name"));
        checked += 1;
    }
    assert_eq!(checked, 3);
}

#[test]
fn rfc8554_test_case_2_reproduces_from_seeds() {
    let c = cases(RFC8554)[1];
    let pk = HssPublicKey::decode(&unhex(field(c, "publicKey"))).unwrap();
    let sig = HssSignature::decode(&unhex(field(c, "signature"))).unwrap();
    let (top_sig, child_pub) = &sig.signed_public_keys[0];
    let top = LmsPrivateKey::from_seed(pk.top.lms.typecode, pk.top.ots.typecode, &unhex(field(c, "seed")), &unhex(field(c, "i")), top_sig.q).unwrap();
    let child = top.derive_child(child_pub.lms.typecode, child_pub.ots.typecode).unwrap();
    assert_eq!(tohex(child.seed()), field(c, "seed2"));
    assert_eq!(tohex(child.i()), field(c, "i2"));
    let child_at_q = LmsPrivateKey::from_seed(child_pub.lms.typecode, child_pub.ots.typecode, child.seed(), child.i(), sig.sig.q).unwrap();
    let hss = HssPrivateKey::from_lms_keys(vec![top, child_at_q]).unwrap();
    assert_eq!(tohex(&hss.public_key()), field(c, "publicKey"));
    let signed = hss_sign(hss, &unhex(field(c, "message"))).unwrap();
    assert_eq!(tohex(&signed.signature), field(c, "signature"));
}

#[test]
fn cross_language_vectors_match_typescript() {
    let all = cases(CROSS);
    assert_eq!(all.len(), 3);
    for c in all {
        let levels: Vec<(u32, u32)> = field(c, "levels")
            .split(',')
            .map(|l| {
                let (a, b) = l.split_once('/').unwrap();
                (a.parse().unwrap(), b.parse().unwrap())
            })
            .collect();
        let (pk, mut key) = hss_keygen(&levels, &unhex(field(c, "seed")), &unhex(field(c, "i"))).unwrap();
        assert_eq!(tohex(&pk), field(c, "publicKey"), "{}", field(c, "name"));
        for _ in 0..field(c, "index").parse::<u32>().unwrap() {
            key = hss_sign(key, b"filler").unwrap().next_key;
        }
        let msg = unhex(field(c, "message"));
        let signed = hss_sign(key, &msg).unwrap();
        assert_eq!(tohex(&signed.signature), field(c, "signature"), "{}", field(c, "name"));
        assert!(hss_verify(&pk, &msg, &signed.signature));
    }
}

#[test]
fn round_trip_every_ots_parameter_set_at_h5() {
    for ots in LMOTS_PARAMS.iter() {
        let lms_name = ots.name.replace("LMOTS_", "LMS_").replace(&format!("_N{}_W{}", ots.n, ots.w), &format!("_M{}_H5", ots.n));
        let lms = lms_params(name_to_lms(&lms_name)).unwrap();
        let (pk, key) = lms_keygen(lms.typecode, ots.typecode, &seq(0x11, lms.m), &seq(0x77, 16)).unwrap();
        let msg = format!("round trip {}", ots.name).into_bytes();
        let s1 = lms_sign(key, &msg).unwrap();
        assert_eq!(s1.signature.len(), 4 + 4 + ots.n + ots.p * ots.n + 4 + lms.h * lms.m);
        assert!(lms_verify(&pk, &msg, &s1.signature), "{}", ots.name);
        assert_eq!(s1.next_key.q(), 1);
        let s2 = lms_sign(s1.next_key, &msg).unwrap();
        assert!(lms_verify(&pk, &msg, &s2.signature));
        assert_ne!(s1.signature, s2.signature);
    }
}

#[test]
fn tampering_is_rejected() {
    let levels = [
        (name_to_lms("LMS_SHAKE_M24_H5"), name_to_ots("LMOTS_SHAKE_N24_W4")),
        (name_to_lms("LMS_SHA256_M24_H5"), name_to_ots("LMOTS_SHA256_N24_W4")),
    ];
    let (pk, key) = hss_keygen(&levels, &seq(0x30, 24), &seq(0x60, 16)).unwrap();
    let msg = b"tamper target";
    let sig = hss_sign(key, msg).unwrap().signature;
    assert!(hss_verify(&pk, msg, &sig));
    for i in 0..sig.len() {
        let mut bad = sig.clone();
        bad[i] ^= 1;
        assert!(!hss_verify(&pk, msg, &bad), "signature byte {i}");
    }
    for i in 0..pk.len() {
        let mut bad = pk.clone();
        bad[i] ^= 0x80;
        assert!(!hss_verify(&bad, msg, &sig), "public key byte {i}");
    }
    assert!(!hss_verify(&pk, msg, &sig[..sig.len() - 1]));
    let mut longer = sig.clone();
    longer.push(0);
    assert!(!hss_verify(&pk, msg, &longer));
    assert!(!hss_verify(&pk, msg, &[]));
}

#[test]
fn lms_exhaustion_refuses_to_sign() {
    let (pk, mut key) = lms_keygen(name_to_lms("LMS_SHAKE_M24_H5"), name_to_ots("LMOTS_SHAKE_N24_W1"), &seq(7, 24), &seq(8, 16)).unwrap();
    for k in 0..32 {
        let s = lms_sign(key, format!("x{k}").as_bytes()).unwrap();
        if k == 31 {
            assert!(lms_verify(&pk, b"x31", &s.signature));
        }
        key = s.next_key;
    }
    assert_eq!(key.remaining(), 0);
    assert_eq!(lms_sign(key, b"one too many").err(), Some(LmsError::Exhausted));
}

#[test]
fn hss_exhaustion_refuses_to_sign() {
    let p = (name_to_lms("LMS_SHA256_M24_H5"), name_to_ots("LMOTS_SHA256_N24_W1"));
    let (pk, mut key) = hss_keygen(&[p, p], &seq(1, 24), &seq(1, 16)).unwrap();
    for k in 0..1024 {
        let s = hss_sign(key, k.to_string().as_bytes()).unwrap();
        if k == 1023 {
            assert!(hss_verify(&pk, b"1023", &s.signature));
        }
        key = s.next_key;
    }
    assert_eq!(hss_sign(key, b"one too many").err(), Some(LmsError::Exhausted));
}

#[test]
fn serialized_state_resumes_identically() {
    let levels = [
        (name_to_lms("LMS_SHAKE_M24_H5"), name_to_ots("LMOTS_SHAKE_N24_W2")),
        (name_to_lms("LMS_SHA256_M24_H5"), name_to_ots("LMOTS_SHA256_N24_W2")),
    ];
    let (pk, mut key) = hss_keygen(&levels, &seq(2, 24), &seq(3, 16)).unwrap();
    for _ in 0..33 {
        key = hss_sign(key, b"fill").unwrap().next_key;
    }
    let restored = HssPrivateKey::deserialize(&key.serialize()).unwrap();
    assert_eq!(restored.keys().iter().map(|k| k.q()).collect::<Vec<_>>(), vec![2, 1]);
    let a = hss_sign(key, b"resume").unwrap().signature;
    let b = hss_sign(restored, b"resume").unwrap().signature;
    assert_eq!(a, b);
    assert!(hss_verify(&pk, b"resume", &b));
}

#[test]
fn malformed_key_material_is_rejected() {
    let (lms, ots) = (name_to_lms("LMS_SHA256_M32_H5"), name_to_ots("LMOTS_SHA256_N32_W8"));
    assert!(lms_keygen(lms, ots, &seq(0, 24), &seq(0, 16)).is_err());
    assert!(lms_keygen(lms, ots, &seq(0, 32), &seq(0, 15)).is_err());
    assert!(lms_keygen(0x99, ots, &seq(0, 32), &seq(0, 16)).is_err());
    assert!(hss_keygen(&[], &seq(0, 32), &seq(0, 16)).is_err());
}
