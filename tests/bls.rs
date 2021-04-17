use core::convert::TryFrom;
use pairing_crypto::bls12_381;

#[test]
fn bls_sign_tests() {
    const SEED: &'static [u8] = b"bls_sign_test";
    let tests = [
        ("", "pZk8xHItVlHqpPfDJkGzP4fVHJADZlu22Kjfwy4x4E_K9jQVMMkJinFKg8Mw2FFv", "l8k4MM0wd75hlFNvfI7RjLGCISeEXKi0ErJBGVkuBFJsKlsSg2I9fTzdlwMusrkCEeNU5Zu6DtIH4pEapM3LBrmDGT9uiqu-CoNTwXm0XDV6FVm_YPexl-oDDj1k6NM0"),
        ("aaa", "hRkBVHp8pHj11jaAKalc-g1dZE52OTnwmBuVnqgA_zUefzMqkWrERW7ozTi2bQG8", "ghnfwPNN3M4V-L3crAFkTUoUuFwV8tp0zZiNwpeo--IorSLv6LEE_wiSH7hObYM-ChvXL02y0-HSf-TS6g2rD9GRwK7qOIvkHDK5Vikv8w5H_eeOGoOjn7Y8QbW6Eg4v"),
        ("aaaaaa", "gYAJAPyW5pjfdXNoi8yJw42Q_4dynMuDkRjOF8HR0hQI-xuZcGuh3SwZxJv6eG3k", "o8DFShb0m4NIqyfepqhD_tg4u5z8PVYkytEjz0qF05-yEQiNHclzzZQAyMHHCHlQEMho0kqzjLxF-XD8Qn7LFeGzisjKT3tc_csNloVFpMkhSZR-rkvGOnaF6S5U9137")
    ];
    let sk = bls12_381::SecretKey::hash(SEED).unwrap();

    for (m, g1, g2) in &tests {
        let sig2 = bls12_381::SignatureVt::new(&sk, m.as_bytes()).unwrap();
        let sig1 = bls12_381::Signature::new(&sk, m.as_bytes()).unwrap();

        let e_sig1_bytes = base64_url::decode(g1).unwrap();
        let e_sig2_bytes = base64_url::decode(g2).unwrap();

        let e_sig1 =
            bls12_381::Signature::from_bytes(&<[u8; 48]>::try_from(e_sig1_bytes).unwrap()).unwrap();
        let e_sig2 =
            bls12_381::SignatureVt::from_bytes(&<[u8; 96]>::try_from(e_sig2_bytes).unwrap())
                .unwrap();

        assert_eq!(sig1, e_sig1);
        assert_eq!(sig2, e_sig2);
    }
}
