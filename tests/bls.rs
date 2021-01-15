use pairing_crypto::{curves::KeyGen, schemes::bls::BlsSigBasic};

use pairing_plus::{
    bls12_381::{G1, G2},
    serdes::SerDes,
};
use std::io::Cursor;

#[test]
fn bls_sign_tests() {
    const SEED: &'static [u8] = b"bls_sign_test";
    let tests = [
        ("", "pZk8xHItVlHqpPfDJkGzP4fVHJADZlu22Kjfwy4x4E_K9jQVMMkJinFKg8Mw2FFv", "l8k4MM0wd75hlFNvfI7RjLGCISeEXKi0ErJBGVkuBFJsKlsSg2I9fTzdlwMusrkCEeNU5Zu6DtIH4pEapM3LBrmDGT9uiqu-CoNTwXm0XDV6FVm_YPexl-oDDj1k6NM0"),
        ("aaa", "hRkBVHp8pHj11jaAKalc-g1dZE52OTnwmBuVnqgA_zUefzMqkWrERW7ozTi2bQG8", "ghnfwPNN3M4V-L3crAFkTUoUuFwV8tp0zZiNwpeo--IorSLv6LEE_wiSH7hObYM-ChvXL02y0-HSf-TS6g2rD9GRwK7qOIvkHDK5Vikv8w5H_eeOGoOjn7Y8QbW6Eg4v"),
        ("aaaaaa", "gYAJAPyW5pjfdXNoi8yJw42Q_4dynMuDkRjOF8HR0hQI-xuZcGuh3SwZxJv6eG3k", "o8DFShb0m4NIqyfepqhD_tg4u5z8PVYkytEjz0qF05-yEQiNHclzzZQAyMHHCHlQEMho0kqzjLxF-XD8Qn7LFeGzisjKT3tc_csNloVFpMkhSZR-rkvGOnaF6S5U9137")
    ];
    let kp1 = G1::keygen(Some(SEED));
    let kp2 = G2::keygen(Some(SEED));

    for (m, g1, g2) in &tests {
        let sig2 = G2::sign(&kp1, m.as_bytes());
        let sig1 = G1::sign(&kp2, m.as_bytes());

        let e_sig1_bytes = base64_url::decode(g1).unwrap();
        let e_sig2_bytes = base64_url::decode(g2).unwrap();

        let mut cur = Cursor::new(e_sig1_bytes);
        let e_sig1 = G1::deserialize(&mut cur, true).unwrap();
        let mut cur = Cursor::new(e_sig2_bytes);
        let e_sig2 = G2::deserialize(&mut cur, true).unwrap();

        assert_eq!(sig1, e_sig1);
        assert_eq!(sig2, e_sig2);
    }
}
