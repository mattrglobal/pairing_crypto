use core::convert::TryFrom;
use pairing_crypto::bls12_381;

#[test]
fn bls_single_sign() {
    use pairing_crypto::schemes::bls::SECRET_KEY_SALT;

    const SEED: &'static [u8] = b"bls_sign_test";
    let tests = [
        ("", "rKpxIy6O5H5mFuKFP-FnXJeNJSsC3Ykoy3kle06ViDy54stNt9TKrvlmyo9BOLSW", "qstlnb8niJXGLAtw3dT32292-NX2kBp9EeHXlQw2yMK15UMnQ-egyczkr47wuN5kEShotyuukWCS0UHp6bunAotbBboK-FHeRJAiNR1eueSEvFZFzJ1_mrKPIkAvOwdP"),
        ("aaa", "lW3uDy7w0-WG2dVmYKOJBioGfasz7tAjY6LoQQrOH2f0v5X0BgkPtuwdjT2IJBo2", "tZlS-3KdXCKH4wxP20xct6j-GyYwjPhkfupHm7jdhZzObf1cc24jiMUjqc2LW-9yF5GZkEHFMXnALlRiw_pTZn8zFg2tRZWCbbm6CbV9txMNGGaXb-h0LKxzb9EBmeAl"),
        ("aaaaaa", "jlWvwPNq6QcR2RmlGKacRb2ZKGL2xEzLl_rBULdNfahQvfoE4ORHwPjrIJc4GMCT", "rVu2xpYrSWhBIqzAC7XX4BV-Gz9H-87G767wm9cfZsoNopTNlx7wBqwWPWqiirDxGc4-qhoTakPDvBWX-iEacSaSoQJmiRu_0ZW2WWVH7B6y9IQBI7jOhTQ5n7bFKs6-")
    ];
    let sk = bls12_381::SecretKey::from_seed(SECRET_KEY_SALT, SEED).unwrap();

    for (m, g1, g2) in &tests {
        let sig2 = bls12_381::bls::SignatureVt::new(&sk, m.as_bytes()).unwrap();
        let sig1 = bls12_381::bls::Signature::new(&sk, m.as_bytes()).unwrap();

        let e_sig1_bytes = base64_url::decode(g1).unwrap();
        let e_sig2_bytes = base64_url::decode(g2).unwrap();

        let e_sig1 =
            bls12_381::bls::Signature::from_bytes(&<[u8; 48]>::try_from(e_sig1_bytes).unwrap())
                .unwrap();
        let e_sig2 =
            bls12_381::bls::SignatureVt::from_bytes(&<[u8; 96]>::try_from(e_sig2_bytes).unwrap())
                .unwrap();

        assert_eq!(sig1, e_sig1);
        assert_eq!(sig2, e_sig2);

        let pk1 = bls12_381::PublicKey::from(&sk);
        let pk2 = bls12_381::PublicKeyVt::from(&sk);

        assert_eq!(sig1.verify(pk1, m.as_bytes()).unwrap_u8(), 1u8);
        assert_eq!(sig2.verify(pk2, m.as_bytes()).unwrap_u8(), 1u8);
    }
}

#[test]
fn bls_serialization() {
    use pairing_crypto::schemes::bls::SECRET_KEY_SALT;

    const SEED: &'static [u8] = b"bls_sign_test";
    let sk = bls12_381::SecretKey::from_seed(SECRET_KEY_SALT, SEED).unwrap();
    let pk1 = bls12_381::PublicKey::from(&sk);
    let pk2 = bls12_381::PublicKeyVt::from(&sk);

    let sig1 = bls12_381::bls::Signature::new(&sk, SEED).unwrap();
    let sig2 = bls12_381::bls::SignatureVt::new(&sk, SEED).unwrap();

    let bytes = pk1.to_bytes();
    let tmp = bls12_381::PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(tmp.is_valid().unwrap_u8(), 1u8);
    assert_eq!(pk1, tmp);

    let bytes = pk2.to_bytes();
    let tmp = bls12_381::PublicKeyVt::from_bytes(&bytes).unwrap();
    assert_eq!(tmp.is_valid().unwrap_u8(), 1u8);
    assert_eq!(pk2, tmp);

    let bytes = sig1.to_bytes();
    let tmp = bls12_381::bls::Signature::from_bytes(&bytes).unwrap();
    assert_eq!(tmp.is_valid().unwrap_u8(), 1u8);
    assert_eq!(sig1, tmp);

    let bytes = sig2.to_bytes();
    let tmp = bls12_381::bls::SignatureVt::from_bytes(&bytes).unwrap();
    assert_eq!(tmp.is_valid().unwrap_u8(), 1u8);
    assert_eq!(sig2, tmp);
}
