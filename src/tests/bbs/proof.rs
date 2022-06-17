use super::{
    create_generator_helper,
    EXPECTED_SIGS,
    KEY_GEN_SEED,
    TEST_CLAIMS,
    TEST_HEADER,
    TEST_KEY_INFOS,
    TEST_PRESENTATION_HEADER,
};
use crate::{
    bbs::{
        ciphersuites::bls12_381::{
            Message,
            ProofMessage,
            PublicKey,
            SecretKey,
            Signature,
            MAP_MESSAGE_TO_SCALAR_DST,
        },
        core::proof::Proof,
    },
    tests::mock_rng::MockRng,
};
use core::convert::TryFrom;

#[test]
fn default_value_deserialization() {
    let p = Proof::default();
    let bytes = p.to_octets();
    let _ = Proof::from_octets(&bytes)
        .expect_err("default value deserialization should fail");
}

#[test]
fn gen_verify_e2e_nominal() {
    use rand::SeedableRng;
    let mut rng = MockRng::from_seed([1u8; 16]);
    let test_atts = TEST_CLAIMS
        .iter()
        .map(|b| {
            Message::from_arbitrary_data(
                b.as_ref(),
                MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
            )
        })
        .collect::<Result<Vec<Message>, _>>()
        .expect("claims to `Message` conversion failed");

    let expected_proofs = [
            ["a3cbb15d5879891fd2e0d6d2acee15dfbfc0600d0963a8ef2d5a7e5127f536dbee3479b96983ab372919b00a1a310cc8a5d74278e1e642b692e5fa41f2d741cda81f96157005b502d54d76e13cea0ec1f71a44bf2a8aaf1c188da30a79f7f8b8b54c8022b5f03ee3260569509dd442ba350d6b25d0bb60fa679f5ccd087dace1e367642f12eeaaa05d9071ec78db04bd3b2e1df01f26354a0906ea60abce29e6f9bbddf098ccdbd181fa7219dd0f8a2f136e816c9e721c2fac1510548e6585f4f3fb542bbf3bb4416c20e95c7143ec9823897ce6433e0fa4594d1b38714a634fa8a2722bbf53de46837c5bc7efcd812b22478664c5cf3600292a230072c82cadb406e88635c1bfaaab3d9f46953c23484bc94ed0fa15c6379a987f776052e685683f9abff3d7ca6588d2f96d95f8cbb772b26947d6e2fa6e48acf773b938ed2f7a10491e8e1c820f3c587bbb91219be447205aa8cbd3c7b39a7ca20fbbf6d549002a8d744c4c0f351205ff9cc832eed559bc1093f12e15d1671f52b246ea0acdf0e072b699bec55c74b1937c6e0e71aa65fc66ffabe1f7a5e02c3c5222c7371f6ecc13d15cc1465d0cef28a8de430923116b14745be3d6859c57511f0a0749bc03ab0e0457787bcc3d73bf5b22bd3d145dcf61d3fa6d7b40c523632acf2db37933a6ff51042b32216eb6a0f2efbc29b6", "83ea4819f56c5fc702a1cf901c9f41cd8d1429281aa64d2045d4a6fa346181f75d0f24c3b5d0d8b8f30220357c0fe8049642a659ab56e487cd422655b5b4e6b3dff75f822871566fb637da05bb871f76d874dbccb0fcec7da6146a1258a9c17586e822738bc586e7dc483030e98899219e77935ddaf0526d1403d122352e858be91bdc1346118baf352a4e1759b78cbd29e241f9a394904a8b684dd4f411705af7c97a9628a47a470e325e7940ea1f1808cd2aa34d6096458b531327726a4659677818c5b04ac218cc3dcca2e9178c6b1f0a2ff67fd0ccf4db1003dc65980082fb2d015283e1201eb3b699f96a90f0b730873316f084ce05ea986a2b4c8de52c9bda47461f6f991c88e854161ae2058c138b707e883559c2f3aecba834d6a66409545bcf16a70875be0c1983374fcef463652541d885abd2a293306154bc96945429b093a21418396e930bd911d4c6ee09c52f829c68fe18d368c0266f9f4c6f2ff42281e4675b41f06ae045a37a71033054f190765415cc9c150c02d3fa8f86802d93f1f88b48251376a6cadf4b740b49955664f97b68c0dfcb320c593649857884a665a1ac97276a397253d1fbff6431b7394d512096d99612ed0b737a246b102709cf3448c9c865e7532d08fe7cc4", "b2489a5c89b0aa4903ba4d4a7e8e9ed8e17727688bc67b576f6a2a9298dbe071620458c05fb6083a028995dd273ce7aeaddac96ff97fb84c75825b9ab5a0832d9ff59de569c0b765a39b3feb05bb59585e4bea3596d22b16c5bef886d04b64ad8e484399e63479d7f6e6585f67cd0b1c4d0f01e6b1c072a62bceea20b80ec3538c57cf3ad05487c341929ab56b429466384e2a1fca470f5926d21a7d1fc458b60923e0535d4d03c94da71bb26d58030e032fe64c8006e196b21bde4414b7d7875bdc169f775933714e18c69ed00c60a13965560d73fb7ffa0ea4132e92ec429a6d64442650d53ed40affa03a500fff802b2543c35e0a0e1397bc917af3b86b38c321d38cb2722c622c919d72a1df69b72bb56ec4640dbaba1990fdbe4d0542bc995df084a6d21ef41dece5ba505b097a3e0af3c0fa26e981ed5163320096d053029218ce4a5d777299c4842bceeaf78f6732081200c1c4218fafc41cb386e424256435c62ab21117cda6f5b81f554d7d02b9353064dccf20c8c82dbe71e7ce213c6b1782da947ccccb9411defc4247d260e5c008e2e762e97f3f979573da058b6126cfc2ea8cde2a17f8917cb7cb8c79", "986f3c4eea5ec4fe04764185ef47f48744c02c35e3f5140ecfd7230cfbea1cd08c0ca9ae7d0b7447008c453f3aba806494afce10a3d52cb6eb99437313899d279e2f86b5dea5d4191ca8dbc487ccff12aeba04ccf0730164a180261ed029788baa61eb6ddc2d7de515bd1f725a3ec3f6055c025405af953fe73d130335c88bb8c5143894d668a30d4d9c520726503b8043bea05ce6c8040ba2c0ebba1f7c8401d5ac74949939d622c5940c827e82a1c62eb3c1d3b466ea081341dee4323228f30b8c4d89a8cd45dfb69ded477a5a5edf558359c14ea7ae061a81ef67f98679752641ca0272ad1795898787d2772ac62826b89721bd57544c3f5f7e4d65c0c6f6ef05d40d23866e8dd8c476170f35f2f573251432ed7639be1bcd36afeb914724666a45d647eba926978585013d04099257a948eed6c8bab0651d8802c9340fac3d24a34916322cd77b0fbdebded2352a642c74652cfd141b286361393d6d12c803f79224f02f6a77429929f74f78f26f5fb46030e8bc05792afa0fd063fe217e8b6e2dea66ecf11c7b7138f10748a680", "992447983ee860eb35b8b9bd700cad3bc43930bc74fe896c70d2ed9df088da641d1011a183035807d3e31ff0261d027e8fbeb25f2bc7eb8de18493fc18fd6e4ed2e54cdeee2fb5490d31e7978afc40d7d2cdbc9baeb802884698239e16ab83b9960b16d90154271364579c79325ef09356f3d396ea6efb81981da286dde711228a257db72ce7a9f005bb904de7303ce44ec6aec94e777f6f2284bb1d7a13b54791b9f12dbfa6110de6ed0df8267ba36441232597f993b32fca68d98440e886ac0fdcadc51e6474afc380d76d9d78191413bcd67b188ecc5b078f23716ea1dcce635af3956cdb735305e6ef7084a49ac45795b667bc1ce9924732c895a438e02e416ce01b8ea211537f5d59536493d504070d548c3f77d24ed217a25247c84eef2d9539aef5b9f55e7346040561136f4a0d15b6df6a090083caa9701d2a7cdda07c42f182eae46f4e028fe7b9ee5ba1c55bb7df50efcc8959e8f265ff2f9cd2b695175041f23aef3cdfeb3d8a95173ef0", "8ffbca0d5cdd0dd2f80d3107070a7e91a329ca2a01fe950db2dd335aa6a819d2c0c89c19e336000055a4663895e1ebeb849790ae3affd3926c0ef6a5ffe6fb7ff44904ef885ec1df0cf776f848ab19c81749d113a0b1d98697a67f4a781342f7a7d7367eb35fe743d21f8137b0ff7e7a30e759bdd2a0461abf7b243c62d09e3916bbcb6ba3467c8d1a6e2e3da1a1d86e15d825aea13a9bf33d7612319484c96bda0d5611f6bb91e8cd294f6f0b6459322d86f9d3f25860ddf217d1b87f61015bcaf7b1e85d65924dfb515c4e74e3ebed5c692123054af4a00ddeb1d5a23a8d2c0c67b9ad697f78d38b4bd04f08dc835d51eb944962f0dc7691301a700ca6e8c86cd35aae64ce62030e371122d31a427a3f48c8edd765ab9f301a6f00ab30406815158c6923a90abda26031a8a31c90f85b5daa6f7d326b0b40f051e976f7c8fa4c5ba357ae665a732ca747b7d57894db"],
            ["a4106daa3d766c0c7b7dc7bf6dbd572c1d628fca301d309413e61e1a8fc92f3fbc154d77bb50da1b4c83b86e162c0c1497af233ae4e124391118539b83b959239de6058579951ea0d6ced935c56ab77fbf9d7020ef8c0acc22fe65f6046ee10096d5865e5f328ff67e1842cb58d16126ac8a9809bf8d08b04510080db3897c38ed9dfcf8247297482b7984edce9a27a85c49d529fb36c91353dfbf826c0bbdbcc89a5aff7d84ad857e64c201b28a26fc109b793287d4f71a4bac8f324bf1475994661e22fab04bd63bce87154b49d52f03de6cb1e61fcc346e56a12a70f51ec3f9acc05607c938d29bd80939526713bf6cdeb2b2ce1aa55c41cb4702799da72e064f0a1fa83bee0a97b4fb7731348b116b91bb1277be3ea849e111b5357ec291648e7cc0e71f5021eff11668b74ff0a44a8928eda5f252b2474d379cf7e4861381e73b792b4d6dd731931092ae322ae035b11695310bf19911760aa31aa442dec483c8b59e71bb2e5720b02f6cb0934a66b51fbacc1abf791baa1ad7214a7669614e10cb67506476a53370e387c1d0ab0afc0490fa4f089186e36bd0c81d6d2b1312bcf63ae9c4d5c952283b692764bb09d1e09180da75f972131a830f23ac818d362f323ee5efd33754d3f1d0020bf96d571140e2aa079776bb0a39ad2ba8e3368af0668149ccbad7168a55f7862f62", "a29e72cde0bac32041231120e9443180d1742563b3764017cd503f75ca17e7963334556735a376702c9a2757993ef9aca65fa5518e4898769a404f42a962f9bdf816384f28d5c1ea0b48d6750de457288dad0fa56e899a0da61dcaa260c7f2a28f3ad2c990f0d1097653bf907ad35a4e19c2d6d4dcc46a84e278f277f71d71c4f777840c6eccfece1cd162817c3672e4057faffd2bb836fdd95d449ddb31ed97de95863f1bf9d05b5c187f6fe3ebd27b17c427ee44b25d06070a961e2bdfab0383e490d72670d87a77d67a08a9b8896051979cbb606186da89d24933c5b8244b14d9e496d4cb772417e5b518e5431f866793bab9a1e361069bd78e0729bf0c4f3cc3f46ba7f3a5608511f25d51ad2f1d684e76b9c9a8dbbee8e97e3c816bf6eb072b6b0a60e69825c89045c28ce2141b18342a2711543b180853d56d83f467a65dcede67229ae95521cf6bcba13eb88463f91e1d782d81e9051801feac4a2184ed10e5ad6e35d535bc48b13a1c4f420617625da0c55644461c7c9c38eaf2672f1de7ad56d89a6195aa39bd2e911b384c6968eab9b58c5fde0021a400c7906740831673066c360c3b32829e1f42e9965e5bd708b55af45db74fe6026d5c864f1b875f4d2b6a871f2067c10f28862566b2", "8270c7897ed3e9558b50a996132fc9a2321d798013f0af4900c0547383962f2862db674c05736a584287a5c46c92111db53057e142d3a28ee85dd75f89c23ab23f0251a3f572102b7443e28d9df681bc7779d2021c9113abdba3c547011f5354b7970e0c11b01cb129115c18649c50a9c3021312b65d993258c72fc44bd73e376076e680ada11ed2104a41c442b427225aa0a41cc25873ffde6bc640fb4a7820d11fd9db45f846ab3991140452c1a498086b9bc03de98b7b0ce7e20fc5cc546650b272dfeac341a05dedc75b157c76f84ed9eb025738bb9eb3713f0602a81bb2eb8fe09f7d77aba8960ede20ed4f07e165858b03fec90589ffe312a1a8a91d065a97c4be3e221931cb3bb2abe4b38d673c4546d0eefdab2141a41966d64232d0a64cacfbcb21ac4deaca260ad6b9a0c52bf06227524cbba2e620e4986e4dd78ee033c352e06621ec3f5f2af26baac0cb07f6af3d7c9043a5d5b21954cee42ef93fcbad98b50c96fb7628e905a22fed17476cfb694166e654e6571e982214154f588ce2a896c2e6ba594fba915c8ac36860d475969955b21c4a688c3b97877c2aad578cee37e2cb4401892ea6d65e055d", "a4057876f2760a1fd342030d2d69763aac7f4b15eb0613ceb7255f7144fbe52b888886afe0c27a193f22340ef881f82794d959d9a9cca414611d029d6a43ab165b6a14f500704202f977d3610b3d6d09f5ebcca4a972ae53587fbecd615c48ebabf8db17084e7bf471bb1552687d29cc74be53491f471caf132e93395b6ef67ab02882acce1dac262fd0bc4270384d2930bb247cf4b6eb77a0439e76bb482aeec25a999dbff4c029f5877a2c6556aff2547ea430c35def7add764aa8af065f0aa7fae3d693569463d0d1aacbab87f4d82ff54f1aea3fd941e9b59e6d40221daa396bdfb40e84255f76ae1431abf4b55d68f57dd06c84345bcc3584f4a3cb565882c5e8caa1e8eb6ff7ecab42b366750248f472fb8534d5a26cd4c7a13636f812172eea19f2a370ccc670f57f0aa77cb1032d2b018180892b266c689f16c01e3c47103848aaf4f0d1c29f393c63df12271a608688e790d0e1dda18070f6d366d6fc96f798c70c825497dcf52a3b84ce8d2c9a26cc93ab8190b781872093bade46688544f8994ed1889768bbf4fb5f8508", "8e80d591b2ef02594d2e3c1e42577da662a9ffb0014b8089a5086d4714f8e791add84cecfc795c5aa3cd747947f7987aa4a55b37b6ecf626447573f56ee265a6a8a78985dc1165915c4d770c3a720c79ebab7cab985224299cb4e3c9aa15feb0ac59bdc0e9c7c6ec82655e0e7cdc0146c801260bd73016c9c908b6235ccf186396339d8a829f6ade872b569ad8e3e37534bdbc4814ba618f0d5c4b6a47de918d1cdd168690374f47e9916283b2c241894baf0cb2e54e4a653d27dc71b08814d37acefdc36d9b2868dd7adbff9d54f23d576f3d559a07b207dfdfe2c9c5911ed6461e47a82195cc0f132015242c20891c39b2fdbefb94537d5473a1f6ec7686e5f1658d069d7b1819370e262622e860ec3cb6fecbbda122ab4425473264ce0f8fe5d0094f9a4a509312568755f1eb6aba184b6cb69604cd806aa6939bc2309cd14244f41296ff2803ee932a7806fe958a53c92fdc5b7050051207e0009beea4d2c3b46a8004288f798c895ef8048efa4b", "840dc9909a62036fcb9984f97ed66d619b2fadb184fbe6fbdaafe8d3e3e427af023e9c5962392f32c583eb1179359166a0be91043e40611c738279b522893a286390a391fc0a7895d6cfe3c9dea633df3946411300ea225fc054c6ffe589408eaf759c06a203462e7d50ad349738331c045b7cc798f0db0e4561684d622911ef996829c2777f63cb75eb8f1732acc7e744fdba429f2fbd60b7e06a1e708586ce0802ef04dcb5facabefb8476c9c2b28b459f4b169c043f94a362592b25af4c75a0a03436e0daa74263955153085e10d229088be31d85164cd7a02ac103c68783fea159ebb6900ebd2b5909a0602f5e9508f0dd6d0ae0f52202728fc874bc4246bd293053806bf91b6641773c79929d9a6d95c40f946a90a8d517c119ca9d588626280c5c1c2ff5c7c73d796350073af628632a069edf2cede9324e862f2b128c046f0ac89fa084038b70b05a1eab62ba"],
            ["a92a9d55cdbff789314b914ec547ae03907d173d5c708d9ce2e98d313b235be42e0ebe5e085d6234e6822e5ef7003dbab0a36728d8a298d8de6bf5daecb554212d15172832f0db2e04231204e313807e790da1ae2b85bc13705f840d3b59cc138ff7432081c2d0f604a99fd45e6d49385bbafd610afa3a3ac2fd64f86666426a4ecff86a3be138a6cf59235582e4bbb431edc5733e0a9490c18f56c6718372846c001532296e241f60a9999dc832add0004f094b6626bac0fbafe55da10b1736d893cbdafab1b5b27ea7125caff171b044c5b61f86ffdc22007641bcc475dbd5304209f5d94874eb888658ecd973ecd1231e89bd4cbc8366c29266ea8f4bfc2872d40c7710a2fdc01cef5eddc5ea4b01448d77f26518404fc836fc70cab60ab5192b2fdaa28dfbb51ecc8084d9637111146303821ae31bd4973b7933867e38734e6c07bc78d2754374afc3ca2d728d5a3376106d0b0d19c685c79ab9d9ca5f03c1480d26fafb5bbf5321d2f5692bcd2e73283ade93757743808e98d701274cf8aea5c109bd1b539ee0d34f539bff2ded0edee90fb4fa7cf35f5921979beb91096e90354c1d6f9079ad36ee6f4d491b453797e81cb777e2e15c246ee1301c0b805d4a60dd4ace58f8af2989d04dab2eac65a4164eef9e5bc65a6d4b17921d8cfbe6de8929ce5969445946e70382d205fd", "99548fdfb0ddc5dc756df4e6e7a4971084498e901b7901f27cf765d1f829258a3892e8026483293f2159371e1b38867fa9d07434dab09802fec993524b9de2aa754118df5b67c256a730e476b2b5ddafc472dcc669ebcec042129a19009cc3678668483b624b01cec310bcc43fdcfee384ce1ba5513c6249f0099bdafd27f9e7f7d25c7896ec683dc11b09445646db0b66609fb309a1da076571141d5c67d64b7e282e8da80dadeb6d4a412cec09e42229516d22a061961d9f54d973278ea4d8caafe31d7f76ce151657d352ad8c04875314de61ee43cafac4befc3eb3e04cfa554376dbc90a8e3a2579628ccd22af6d2e7ad6777671bbea5948d7a3e73b6161cba05e5bbb7dfeb0efe0a3bb933f18b83ceb5765d79ff68a9a4a7191e3d08c704db2ce00c8138cea70725c1426b8620842f1213f193a14b0287ae4f020ea33267cfa4636b5d15b5199bd595f398aa7a47243c03a2aa36aae7660a8673f0a04b36e3c1ae227c30662eaf8f17158cacd1c38f66eb95ad737162a9f1e2481b65edec6e4b915c04af7e6d3b5b77c8a08ccdf6c423656f2fe06ad75166c08444b2a9ddbb58428f0788c0466bce945d1ded28307aaa55b484b9c0c3184d387978647229b0d1014396c8d2e591cd42fdae0c712", "a4c53d93930c45c846a54e91a3c2cfdcd0ae1a28cc359fd540578c3767a99cb079c71ff41362f5bd3ba6380987b881b6b1a66b4cb3593550b70410db228441ad87ee7f4f3139950079481c6c358286f5be3318acbfc70d4f0a3512ee5baf373da3dfba85061449806cf5c03d0f553abc8cead503aa620a61f13ae0e9a98593d4970fcd29baab23711e15337689c98c300f62c204fb65ae2894ca35f37edcf5959c838c6bd948b1ca26b0064baec1da7b64a3b63e347d30923822df5c037b3fbb40b9e3d313fb03ba8437f92d305e504f3d855da8dfb74a66a9e1bcc990f90c27e3595313ca8c7298f5ce076a42889ebb3089098848cdeb89ccf640a27a6db879ca1035f621f22e8a16c1370bc54c58f4413254efd990b651960dc674e210a0c0811bd3738a17afee38a669585f62734a009e1d543879d4554ddde5e728e67a06f15e542bc0aac5e71c469d7fe8370e320912b3524f2898c7a2d7df4a5edf980aa0c5645328c924fc2c671e44b53a22ec146e5cafdb6cc04e41e1a414d4bd59484402f939f29d4435bd7ba7271da3072d53e9ef1b227e119aac2a8beba990f5f41290c62a30cde5b7fc5221fcb57b208a", "83d0e1972ef402671d2414f2e45f5494c0289ceec185ec34bb45608665c3081c1e09e76d1c41e7804469f19aecc0939c81324b947e2aa0a5efad4264ee3728f5b2bdbbb875497a9c3ac68eb218cc93465b86e75a962bf9c3ceecfa688389b8b3b0de8eed700d1f42db8c4999452c9216cdd0c7800783e884e6409560540251682ca03878b5bedead3505241d9ff76cd56458005a0dbcc7c4cd58fbb4993f157f6e6956d3a5d2c3f00fc9c16cc4b2106f2f742a0c216a2bb1e5e704dba63d7de2170f726802c68c89e5354dae0fd063ea40e7331f637d494bbd5c5e241ababd2cb16d2fc6092b81fd4814b386364ae3e467c62a624ccdd5d7fcd43ca848b69eeda829c758abb7f7df44c3981b970f264d0edfed214ad7bac0bd3dfd2d5d7c31882e23de2d1bdb611eea8b57eed518572039c5c16a0eb649f5eabff579e88b19df8c6e9076a2286f596404e8003f1226c300a1934f5e709eba89976f024995985c036d5394dd44e3d4e6519ee07e1167573e9e04a408f20f0fb47555f14918da75e9eccb74995f8bc7d7c6c787a05e81eb", "9015145c3c629ab09e71c7f3916f62d4408d5377ddbfbb7884780a7823c8029f245d9cf48067c71ce5658325095613b4afc3bf2861c4a649c200984110ec3d9ded7f992d8cab2242458ada7a06603d66573afd204e3d5f84534f0d9c9280655db9197159191cb91d58e204d5d57739eb95e38c20cb7595380eb0a028e4700d91b0a83f384b9160c82f265e0119763bbe2b61158f928be7197449be37c7d433bf8f4add13e3dcabf72cd7dc10a8e897d6674063e9e67130d55e76dc0b72c330cba54b69b133735619a591f52ecd2559a2244fdc62ed354daf348b22f5325911ff6a86e2d3301f37b42e5dce5684c91e2e37c214d398463d537c8d2741b035b69e1a9ccdb071eb2ba18c7c47b7ced05a2055d70023f31f5429d09e21396ec4f1bec030dd5ae44eadfb1f05b018412be3622cbbd16e3277563ea189d9ae0a42a1cd6bec070365cc060259ce38a08d8ed6f04f71b5c24ba5ca026510893585385dee14800903a0cc3775d5f54db1f2b5320b", "a5648c5fb9ab295ca3fa81754c104f68c77ea2c09cf12453b34ff4881504f2256b8a303e38196c4477137ba3968146b6a3ac634b1262b73c58cbe911fec28c9c2b1b68ac9fecfb22c083c0b922b1dc44bdd353cbb9ddaffc6fc1153bfabd81b8a55ee84660a21aca1d8303fabd0a508af26ba74aa8113aa7d7831b3ef1fd0486153f1114879ab43feec47c08790a90fc3064e37ff77689cf916eb256a6f5b3544b12c43fa72c19f2292c107ec8e297033cae611cca063fe9e2881f08b92ff7b21ebe5d79ea2cdb92ff90e0149db3c08961196c6d26cebed3a227a0b3c916269c16ba5c670ab42234f3230e4496f323e26fd3f4143e9677c7e752fa5292f9f9ea95320060789ad27085a85b4db21fe76e1f50db8345d0dacf1a9fcf1193d298e5b4debd22a10e14d120294cfd0a266a1f0ecf851b7bd4d4bb5f74f04d48127c8255d32bb5560bd4f5fd55d144a41fdf7f"],
            ["9506238d5b039129f431bd32a59cc44d31592933aa5d33590c00c7712ad8a05616ee69d8ac2be11dc3c37f17835977918f0043400b9f613982fe246e309b1c8bc46d711508dc70d8bbdc0a37f855580c0862d58d555407a2041980f255328e11ad92ad2c1beb0a4d762f10e3b79c13dea38b6533b71873a769f5daf2b05a2c92b4504b22a3e5980a5ee9d832a9b5ccf56690c0ea23e339e07c13f2df7ab4d8996274de4a7eca58ab38e4094c4bca65596c9d0ac219ce477873debf62c341ed04d6ffe40c22b83ec73c9931233539e47a6d2eb44ab3a9c93882747bd508790f24ccc49b68e1bc6b7c1d97ea44d200754a5325a32dbbb69de991aeff40f88b7884b725d23f996f29e862c3d561233414ef1d1b9f59f59a2da65f4cb9c84e702dc1d69156b96ffad6595523cefc517bbd9f1c8bcaa33b9c005d0be1942ee8b96a08cb441be0e76866d1b3af88f8e1272d10674b41a6ede30035de6e29c36cbd0e4525d0279134792ee2f822ddf432625f47298f95d428b2cfd3fbaf068a706c3254184dca1c2ee3189237d565e066fdeb832f82b7858f7f4b31d014e9110c9a690df0bca289ac64dba816409c57f42f497d0151d2c281b1694f76d3e8fadf07778ee2ec4015434357b6484212d10d7c1c46719f3321dd70ccfea13c72277e95264bb98513e190ff84c415b9c55accf2fcc5", "88cf3d04065ce71be9aeb6471662ea57507e65537a27bda9e49d6ee671199776b0dfdb96da3473d6a867530b8736f090833d1ac7cd4222ec2e8f8c294bb3f4025e8a8b21da04900dfe10d8d72f2606c311574f22adfea7cf25e3e96b36e4131488ef88d25fbae38b8a395f6a6b230383ff85a613497c6e2a75aab3575e35b73bde48de55770df35fd7ed43abd085b1e26fbcfb71c365cd513425ad80de29d9201332fa632b5155cfda6fa854fef6df583218b3f30dee1787baefbfddb5c086060cbdefd7ea667a4e0826ba5c07cb53f75255edac04794c3b230235863fb35ffa58d96bed9edbf9b04e7fa31fd93822a82487ee4bafc620f4f9b69504a60f5c5a673c617ce7e1c908c1ad90015b2bbe33421f5d0fad8383aec476d741306b51d2ec71166a759af2815d3340d87220b68c069dbf908c0cf70f91b56053d331dcf1e9b39a0e5567b000a2ccdad9940137ef4b0e62bfa46b3b9e7e3903785ec47a8c420d8975ca0ba1f43225c72f90e747a408503aaf03d697ada126375ebddc46abd39a5f5c565783642c9d2b8e02ff8a820baa9e0d2263a3528dcd5334c1a1f83a15f2d885aa926afd71340bc6bfd127590965d108b0c49feb9d71538f71317f8e9acf08aa231c4bfdf9a910526251c9bd", "92712c5c0d2362625e289f8105f195037c58c543c9eff9893f43cbe275b4657a66d152906d83f80cde96e33b95cf7aff983dd4eaa4b6c5c853dc4666d202a878b8ec62d267d73b868ffb43945a8c36fbd4f010d727cb7b0534709ca3b744945593d8ffea022b301d2398199ff668968cbbc316a12506f48f12c25ab662af979997a57bc445c867134b4b893b13971efa3263c360ce956b23e3c8d84931033a9fc57ab56d3671c7dd0dc541804240bf5b5087b33ce1a7a9eef3d8307d309e5956dc2cc1898f9b927a33ed45b721e8712033727f80e59f44f9c6c03098144cb7ada7f657a58a3f6141d4fc1c424c977a191001a510f0f803fa67fa9660c8932e025abb4778e122a1e37fd44d81e3916f2012b10f02091270c8c4933824bf79251dd35ce12ca942c4a2657aaf3db2ca73de4f6b4aeca3d4d11d052245f5dfd280f0d0c96866f88e5852efa6a8d2006c03bb19c04217ba36fae6a467a56899852f00de1526713b8982232707a73f26ac42680274a7103e0b0f0c0da26831732c82a80d749119eaf17d1ac48ccd79a0e8ffbd33109eb81497bc144aed362efca8caefd0ab791ead146c1a2567c6e7a0d81e36", "908fd024aa62d4f7fd8cbeb8a1379e5fcdbaa957c6a68bb6a35da5cef6911ee6f0ac30a03e600dfb84f75d8a881dbf55a6496ffc6be90486c5fcdb3c3754bd143ee4bc2dabd40afa4f4c9fe0fd33301767da1b0f4ec7866a2ff782baf0f0166786f1e73080503b858376bf88ecba35cc9bfc2bd8cae80bad4fde41659322a70b010e8cf8fbce1d117429660dc228a4d36328e16bbb0a712bd9ca261bc688169ad4bd2501c07a17b303f048b3bb7319dd2dc914a2bfde8665b849c8b2cea285e8e8dc6468fd1820ff3ddb6afb68b4d2e5693e1a5416950d168efff7f8c1ee356c7ee39380db3f3965577feb773335848a03d54cfa0a7d0cd012493770cb7ac9672426128f2b20b0a7d911a337b20b51f66f718232364c8816d26941366fcb41e7b493b2853cf339e50f611fa17b89c7496d1a9312de1a04c27acdefc2c4259aeebb46654ed1441f48fc84c494071e43b55fee250c6e1099f25009684bccc4409452b70285f899f082d3fb72693d8924066d5154943aea5eba6ddb3bb322e0c3e47edc3cddad5cb2234fc042909454b643", "888ec27f52574dc62728628bdc719d5109fcfcb8e0951e46b6197157b2c9d2cd4731315a3d32a17ee58378f1736a06aead6db1c4620458cb8d974de0dee9efaf5f29e213e2e92a4cc5136cc8571581ae591ef64a0517f687383fdae1d4fa7b1081d7e0ee49ad90ce23d48d3d71c3189d7eb48835f18183355bc27ca90ac8cbda5e97dd49444ac7d56cc8eccbdeb1344117f903bb47652263832b2063da27021a2cd2a109aad9413f487bce6e5cc019013d9b017cd2e5885c7ec9c29ab4366048362c216f834d3fe560ac01a49a5205c01da77a747ba6e2992f9360fb24b893e314e685f22ea093f539cf87c73d58855c3906fe9b479784bb6b17c91b2fcb41fbd55a5ee1e5b5b5b91e8f12140191b0566bf59392c58728fc230b07cfb3cc68fadb802b7bf9f25fbce6872e60541999ee3a7c1ae16189b1cdc48f401faff0333331cd561fd64d5298fd04c34a6ccd555f4e91bbd074cdba5f0500a676b30a8e868f945fbee12fd5b44c7b37597febca99", "8fc5e842b98d349222fbac8f4e8dda4099ebe9a8938f38917052f06700b5d7e6f025fa6e42449b41970fff96335a617790632d16e6cfd48c2490052cbace9dacd3aa2347f0e221085c86bde8d710f9fa37d2f7bd48f0bbb4fc49ea611ee9ce27b7b5f8c8f07008a354e9452099cf12b6d5abe0edbee1fe782404e518f2f9d2de602a44be19b0c6d02995be17895d803612a34f7c370745653a65226dd25d68351859f174f86b6826a128a1b31d93cd4d183465120d439d9cbb16768190c4f3e8e0960e190bd37156027288d155d62eaf2cc586b43f00fd44a7210821af2d6e52be1c3ad908a4e4181cb615ec01ebc3bf446f195174018907ba2244404ed15b6cc5d73444b732c8e4f568af5350fb798c39230f67f906e8d55b26d514283ef56b780e8f52644591d37eb27d9539af831919f0638b1fc4c05bf1b272b027b1d0b5914efe192d0654d3f01e0e118de15ed5"],
            ["92f9851f35df15f5793ec9eeaad5f490a33177a08b2d574c2182cd704afe6d602b554109acf9d2d609b7efd90ecdf4dbaaafd9210def117ccfe1f2e47141740efab4fefcac322a4229f4e3c66138f5eff454fcb188506e621e7ac94e1d344158a9d19f203c603a8c2601b8d7afb51cfc9a1d70c4ba3c1ca48321b819243ac001592d06f5f260e4a88eb7d2cffea7ab5c13ddf75b678b49dbdb630054772344eba26d4c40601508992a725ee0b63fddf86c568c92a19e465e99f0169b6a9bcc1196d54f0d7c5510729b18f832e9a5e65e59f78321d1edb4a597cb6b7bcca5f522e1071b389c3fc89458ea80445d8f7fee19a0f13138a69c35ec98f175f55f854ac909c154ce10e45f4d3046fded087b32499d1c1bc552ac2561254bda71e1fd4083aa3fc9c25ee317ee8874da4ffcdc98643e3d5c708ff42a89878197a832a8ece6f69ef0fad786e8bc03de0f429c699f14d7dd8ffa58d33f14fcbfb7c374e607f51da95a44f019b07c17b1eac5c94f2f20f389298057ec0ca8c0626d22a2a8ba380bdfe975478b008fef082007fa9a2e40405f1de04ca0dd1bb3bceaee89f05bd58471fa97b9f0427d9253406cceb62b17b3458f47f7c06270ef4466576b64296e4e051076c654bc73914e69ed2250e928c9a099d1058761cc79c31925d4245d817c46abf21765c11f710764183fc001", "8b75907f4ec68a2f0535a593521d772355e9e70e02a398a41a13223d7125dae73aa46412aaae43fa05b32bad66cd03fb88eaeee38872bc963b1c74d91dec5d0f00ab6e133c7bdf0627cf52932b977c95326b365c74c738dca0da7e09b24403c9ad446c8184d8592eaf2b4df6ff07bb634de78af341a3d81269a0b4f23895af5db0af77d2da5c90de881081d905d363f51bf4a62fa39becb43115c84b1901cbb14e471f37a29b70ef57bce86453949bad26b1a001712f1926ece07e875437e3f676f6ffea498da0b6cd64c4cd947810bc3965f9339f0a64db2b3047ad2d55bd459b924f071541e6c993366e683dd066b72568809bb70050248e4fcd076b2001378f3a8aa7a756ad2caa7a8c2c5b4dcbf802e297054e69ae7ab99f04ec7160c7f91b6e37ea3aed4faf2f15d92805c6c7f6462a1e63c4149c77e5e40f59394a776a12c6b6275352f63b806b2f3ecb36f20e4094840cb93bc610d0de7876972f8486c75e41a2ae7ed65d79aa8e115baab83a004b361c18ccc2b61ad1d50d8ec28f03fc65d5a2686458095386d4869b337f0b14c1b0b8da9885bbefd934fb0f29ebad19d22226293f73497f0a5e61b770796211f8a50de3956f92b52c0c2db2c83e80d4e07593ae50468066e1364434dd3640", "8a57d9671f59202ad277785b87a63704152a9b7ac7526db09551aeeda90fa9555504d28a744889d650f15c75c55825f88a27ad00ef41e1bd4a8f33c7e8a82de86322abb7f9c8e02eff5af6215398e633270a5e003a22b80be80eb857bc5f8e05978ad36c1d3fb7955230674168d957c37ef43ce72eaee31f7874b9f0d28013ba68fe5faed8fe72736ade587dc61a455d405505ba6110fae0a9b97504e47fb42b47815958d4c6d9eaa86817c400633b104054bda7977c633e2854044007800cb1affea34bff6b0ce489a198bb05405c6f47446e0ce222561fe656d6b816cb3e457bf89a48885bdd42827ccc21a5e55d0b6ab5f6bb8660a7f945caa23965594be0e3eaa8e91aab2a932d2dff0775ae24d9158480e35fb0f63b199f994dc3f32c0b527befed51fca4cbf66f0d2a01829fea361359ea409cf72ae5e0d3b5bfdfb74b86f327e66e312b0caf3c632b77a78d711125a706537df7d947c4fe9e774d590c956be76b97ea51652cc021b341be74773feb3bf483a2932114f673f19c89f26acfe586efa52c071a8d98468efd98c1603bd8f489e78e30677bdbe0f315a64f188fa52352936840954bfe2ab3f50ce3a1", "893613f69f72268e8423294e1c6566168459da82cbd8f0f4858270cf46bac408748d7b33af2a0605d0e6b38faba3342896b7aa673814bb3aea9771780763e64be373ece6bc2917800364cb4ceadff8bc27c049c2b0ad0aafc28269277b5e7dfd8f6f64f817d7f054a9771fabece2dda799bf27816c73362a5bac7581a2c46a8cbf55acfb7871043979b6070231f2da625ce5c90320a37d17e8d4fb99d457f128f24c4e4f2688375e3cc201d29303eb7e2dc774fd1cc2a31f4bfcfaaf29d7794f2ed13d545e5368fbcdcfeab490bfc5d262017adadb3d63b2e86f2207fa927ae29d6cfb499209ac3d551297a04a6b180028974d8062f00a1a01c3b3ad24e77e3aaca474f57777ecc4941b90f72adfcd0c03a4cc093f540487dbd81a951fa71e6242cd595ee6b7e863cf6e06c948f3ffc70b1047498813dbcd19c5fef4e46881d36715783e0ff2f270e701266fc6e81e8f15e2688d6e61226b55d115772e3ccf8a2f6c89dbab6406d5099e4d7c31c28a066923e003f66ed656ad9fec9098d51d729d4d1a5ed4f939ef2aa52a57f4e9193c", "8cc4e3e8c9867419c023f8a866c947c370fd0f9a3d6fd21f4f54af0388047616df6e058a04a6ffb982a4559943300824a7d4c4f3b5821a3a5324fe8c937e8e48d6c900cbc9e578955fc34eb65b406df525be8cbb5691c8edd8ea4eb707a4de309353dafc5c44e53db094568811bfaaa4e344e9dbe3e945141075512b2dc3a42c1143b545ea1aeb99935af801bc9196ab6d2f38c264c7f90e0d64b6b0c4265c550ae62c939e0400990b21a38b021116c2615b136bc59c5c0267e7fdd90c556d07a0f952933654f9318ff9b3b573d14816361caa486cb97d1539fae17003026e6dfc4df3106c855bef69fd0a6b24d23cf1426ad8e3fd771eddd4ad79916006d752b135b06aaa6bdd853f26f22b2498cdec6225a89897e4dc5993790625385c41d89b850581a26b75f6704200d62e7f9c4f55511ec941020afed8fd2deada4d1b23968efab4277c6b7b232da693f04d794532d92c6bb63faa9c84996ad44056c9ecf9bf70c81c96dcc186598e00eec9a687", "b1a898683ef36314401a5fa7264e0cd3e044a658a8ff0ad732b4b8333c415a6ccbfd013110ef9a5e71cbc5edb03f3ece99c366250b6b084127e4ebf2376851346cd6694ed3234509c11fa6710d5a0b989a9494e24bc6349fa9a1f25e1cd0830cac3f5f60b8f57c786a2b1de8a7d6edfaabc230ea62b7ac1ba18c6cb23cacb124ed53d932ef53dbe9e00122c64e4e137e4774b9e527d23e9dfe36f4725def03976eb38985f3d4732c3ec3ce78a5d47f2c04d157b6a8602fffc630b9260b4c7088ef2723342df2856d2157f7dc4bd390412a2728a26b4953c1b31bb31850a0d154a55a435e2d6efae9ab02edb44b7efcbd63bd9703d68944d50234f330e8a701af18fec3bffd8a47ca69b017293c2f4c0e5d9bd285c203d1355214fc444379cd92d62ef50d440bedb09029262529d3594e4c136ef1bde07568ac72c9c7fc5faae31b871839ea4573b7e097836ee5cec47d"],
            ["90865fd1c82d54924720b2c17ddaf02e730898efb14f7dcc25057bd4257983516e6b7c9cdc2ae41dc82b3d08cff4e1ee803ea46a2ef1d3f619c55654ba7d3f91bcff53ddd070218e02ea4540faf92db1a78808c8f347371a382a6472e8c3b1c9a77a5c29adaf6d0444a58de73f8e67d36611c85f948fa352a2a0bec0164ba0aea88e111086bb9a7034eccd788669b39b3065120d4ce2d39a21666e7c56a0a14d942764dd026cdad6bfd22b25a54ae0a0329de1b13109dea402522a3a87a441c57af87e8b39b0339bc8bf711903c5ee3c5052da4b1bb5d2dc9f9bffd2fc0e1c790d207e029bc27794827804f7739b1ebf4f515b8ff2383e671ad25ba3c266de4e82b6a4b40bb84d81e7431ced4a88c8c846d9d494e2a242eaa36971875cc1ddbde7767777af703bb7efaea79fc7014c2e1a41a12b3463ee49323946428aa77b874a9f19f5869cebe8c236ee53a1654c1f44c7eb2b0cd364f8904e9a5f198d76a60bf6bc974dc13e9eed4b1c63a90f27a40f2178088e30cb747c58c8c25b6fb70137402885e1c987a72ed0d7c1fafd1ff643af38707cc1b95453c2abb5200cf150889567f130a917352b68576ed34160a7001a4e2c291c294d9ac20aa7605ce0acbf36bbca466a303497a4b2a6d063093a4eb653cacd73691731b51494f464d372d965d9d92b7af8e0b8ef1a46d4868bd1", "b3a90d13a1aea06ab0f23657652e1203774c1ca5482f5e7c3f9588ded904f025ef64a84897b59f085aab14f185e442a7a2527a32e44505545758490c53496bcd53056dec795aea36db4a15273b61848465ff49cbb0f00b9ccdf2b9c4b520dc4a97849d8cfe37374adff7a4809492cde8f6608e25885fb03bdc14c652dae45cd66ca84386b3e8ab3c9b962e18305e5f9653a2b4c88c9ef891ab4cd97f5b2f56e87b12d199e3af6963eee73416ebc8069d3b0f40f906fc51c2783e2825325f84b30fdda3e185bc4c6ffa1cbe865ea5b3562acff34f3c1fa52e4a02b6f2e765c855bd21827a92d02cc2781ef9c9c6201bcf4b304cad2aa11e95e4a04ab3ced8ae53efe81e1e1bf4021646cb0d0eef862ac909ba13edbd9173ea9000aaeefc2c9ddb13c052d5bc4d8c542ff678f8b707c4e5360007f52d0d47b45532213c750da02f1005475d52cb4e8967f3bafe29c6ae836e5fb8d2d2ffaa8c64394e34c00e10f2ba080a45e19d75a6e9ea9be418c3099f1221b210f45a4e4a6a9671ef108c54e191463439a53d5d2a8e175640944f8a7b269ae6697568ed2114cc3b6baf456bf36c75cab28237a89aa63ea8c7e186eedc14ab4b7621e5e74f332ab7bcf6275cfb398d6903dd932c5e7ffd35efe0bce8cd", "ae1b4539afd2bc413edf69955b7ae8a9ab166f7eea0cfa9bf9abbf65b91390229afa2361714d5ebe9c1cd678aab4ad1bae924006732b338d3fe1a87c93efa475017fa3ad08f590d803be8bde0ad2af13b1cba1a7e04f7466e9105f7c7c70d9b592810bfe04ad1a4c0416b57001469234b7f78038463fc8f5d2edfcefa2da3fa29e01202c4796071fb48a05f702ace2a16ae16b712b29f457c913e29f31725fbf4647ab4752d2a9134af9e8b5bc492cc92fa68c0da6df9333fa6263d58fe77a2e68e1c0c36997814435c81bb1f864b75c60a0eb6620cb49cef531bb261aa47e3cbbca2da77b173b96d18660d970d5f9c5267d844ccae72b4f32196e234b13451b915a0d0125add11b7f4236cc48498d9b3548a9127b5bd1178a46d648867d5d970188d5758a10e1d927d9b61f0487afff2db0dcc094d888d34de3086488bf60b49dd0cea6f8663765ccea769263d5d4f02150d06a583aa0069969e3d92a199a46e5bf10894bce498378b9b44f1b7df1dc254b877df4aaf51ba29f0846e382e5cdca6c06ac368f92e8549ca66cf68d8265073d171697caf31af0a65b29bb92aef1f49df4a4818c16511867c3d47cc52881", "a0ac1b725cd8c0342c3d94a00d8973c429d14a1cdc0a20641f09b0194a5d971d37effeeec5c14017b42ff7cef3f9b555933e779e3a403c828c277184971634c22334a95615afc0ddd6077bcdb96b61ba63c066cbd3e58519fa4de0f98ea3f0a98175fa2bd2e0895c4ca58dd6d376d4b987d4b77b3daab2b7074b6b80db06072ee020c451485c4d96fdcaaddf13a53dd0258550cd585175cd86723e046c5054b97c56f6ac3a583e2f819a35923ac0634c37610a7cdd90bab9c7068312f9f1ddd24b1eb8edcd4ea4fef7436a794facf08c347e77368e49c0199e6df04889ad84fd8ce6c3fbc137db29967c8a49948f955b3df3fb053e5a695740fe5d7a3f5519136dc469d4b361747fba0e4c9306e4e3f1503b3126ea29e6ac87fab58ae1db7e8039259db73abebb56d8875d46b512da25161e1afea883ff9906d561c9ad485d0184eed0b79b0b813eade4259ca824b9365d0ae7a4765a4e60a4f1fff79761090f83c9f5cb2799945e22c0b60bc85d26f06202cecfdd38dde2ecc892d2b07703a74291eedb2c1e3499f69006fb7010635b", "92c7ccb952f15b673122be58c54f76949381cfa92343d92d32347073675fe8cabd06ae7fefccb37c7d1c4174be60c140b56a082ca87d12e6a9ea302b74859b96d0688148bc642a44b5c8326a699158aa41e6f59d83e5bccb410736650c8886a2ac517436c69798f7b387958fa5b96ae2fc13af9cf16d8a710a51fc7a1072b926f0b79ae1d8c2316239eacfcd2e11e03167facdcf96d0d394849c72658a5cc72f5c167811a68c86af2a7c212d4f4cd43551c2a1f6a43eb8b42f1a279fd2966fe7fa39bf45b26210d40ab2c46ad964c4e81afbbea81d22c66969e10059ed22f6b47e206b60d37cf470faf6da188451a19c0f72ed48da2c0857521660fed9deabf9700124c1846b14858b9221fc1fb699ec1f1acc749830c09930f0f5350ef72d6958d653a7ae88cd0e559270d97a96eb6404b449149ba8bc7b77195337b95039c719d9c30541c5a67217301b7b902a66c46192bd875f3c81d26bf05594c738cfb28b789b588fd75ef1cf01d887032c6145", "9813c3e94aaaff6fb5a1863ebd349416ef34717f552fe0cc5eaf0980c25f34edd8fd1e63ab6ca2e771a938b2e9ebd8f8a87e16f650953fb638c31ee1fc69bff5a74b71e9b586adf128c58112e3d6747125dcb14a653e1ea8398f3e6f5c95f39cb31855ef53c0507cc4e20e126230be8d8d75d4cb1324b5818e150ed59a036f582ae9f4c0504449f63277c0c4df3f0828580cf7d896c231678e8f4031e3f1d5d9bef5c76d1ad77a8ac766d2719c3b84e31007593691271b3a5f7f7b9d16da5066c06c5fde899ea0632b00bfc11d734d4a507dc9b1da9a177a99d35f3cffd225db4d3632f9c5f972c0887a7be5f89aa1c245b89ffc84212a3918d37bc7abe9bf7537ad6cdcbdd95e2587140f6dade1fea2269a869e2d2c38bb369f97fc57e59bddcf3459f8a90a0ec57250897d1ff1ec4e1f1aa0599b1d56f3441a051844047c1bde1735b6c5e80b1d03cd10faf89abcfe"],
            ["b5b9f65256c36ad76d19d5d452a826d4af75b2d9350ba316b6ddf913eb7d06743b1098c3ce8009d3d88d30b91f51f13a9435ef08498c4380cd9cb41b904060f62a3f17ba64d105b3d7558267c9fccabfcbdc859bae9aad074a02b9730592be448a409bf438872c5a43ca986dffaf4e1710faa9dfb799c9c29c7b3aec5865ea560872c23b9e8925dab1c9a788a9b25b456c27fd67d9d4cbc7676693b8e775de8279c5e094c29bf2c98723719e0f1d88f65364d29604988fe0c6e442ec537cdcef0210049d5e81eba035dd02b319e2a00f441cffc4af0132cc9ef6c38a20bc5cf1b94527fa9f491f1282c725ca06bf0f602a0d8b5dcbb30dc69fd58bc6e55958b1cfef3b08c93ef6d0c4c5698d8022fb442203e06d436df4feb11d844f65d983eb7233f3d31ecdd9f08f05291c4fdba4a02a96b453ff8ff0d4ac0a780350dbf43b34f7b586c5eda9d7cafae92d7640f39e292ef2b5f9a5cded1a511fbb6c17b182b8f00ef5983052182e68d7e944ab8399694db2aef79eb080adddb1e8deea81e8ba53636e7042bf8b872e5e3bc9c105f51a9cad6243eba36e43dc6cac65c19c5ca5c1e619d2f90b63c861c96b919c83b519dbbc6f4e2aa33933f7b553331c0b76aa86985a7c27b0ff900d2079ef2ad1fb25cdd5eb46b4d6150fb28ec06bee553e3535f53a25e550105ad59266070618d5", "b098a27358cebd65b1b93d1ee246b4b0d3520544e490fd9e7c8739d6ae02a99ad3a8ba84f64f45dfa1e62e0883403bc1b433475c2b8d90acf560ae8a7159e470667a7aa76cfdda97e1913e668c4e1122790dc8fa38691851aac825df4a528322918fba2dc2d4b12426798975721b4fbd75b8f6e5664dac6c2cfb739e2c1eed4e299629dfdaff2e535141444b1fe7bf700381fcf255c7df56c175c09c3686ce56c77b6b1f7dbe3bf6f2120246bd4f0f741a75c25f264a67bae0ddec731819d6dc89cf6043ac9e9d4fa6c3c9da3a54719361b5bb720bccfb0d1b6c98f71332b1f45aa8dc075a36cbc512227989adb5e7c9608309f7aa4515cf71a188b7fc2af27d147658acae6fa6a25722c240b760e95620ec43753f6025d5312ac425e1f2ad5f2493a57be3a45f42d8e6bdb995265881041e2c17fb8d78cc4586aae60d12a498ff0445a6f542e92c16f8ee8a3afea2013b942f7973316dbf8d9b2009ae2f25204bfcabe44f8f63f1c92ea2e829bac57a5ae6113be6642c3851fba75672bd8cbe681207a15dcbbdcc374bf175ae719e435f5cce3264a2a38e602dd3ebb7c65438195c9bc2169e48ab33dfb28a80465d091c38ee6fef3ecdb4118bae01dcf0fa823e9afa5f393f653e5d7f433adb1f4d3c", "90048a815aed7cd81efb4dd7e68b634d74ef6423dc5335443b10d875fe55a298f2abcac3e9f4195ebabdb423b4222e9db2cb1a66861dfb51d58229f7e400aea922e9e6378216db948dcf30931e8177d671b551edeeee40cfe800a726f83a1c63b9a9d3367f0882a1317a29d50af9b132a980aa409807ea60a1bde4abbd01f2b1e093a4e164ba65cc47f4e4554732697768ffa6f700a798b79207c4753742d7d66c62fa6d9b4685f5b4b1264c6240c7cd178ff9f9bed251ad3bafa069d39575044e7bcf505481339a7218ef80b6117ecc64f5913b515df993ac0f25888211707d249fcf653f8216e5dee38b5df1f100da06c3ac395620791bd120cad1e23734ba6d1c3242fc1b01e8ff092de4b8181acf3e6b7005082c262a92a180de610d35fba913675fc6c192b506e85c7770716e54040203b3a7431ab3a268251059cab6c83fb0cae49c361caf4ba9ca09b167c8a248dbf187e12e9c63e473355a2e1a48783b4deee33160e918277f1710ffee8d6d3be5a27818f9f69657f325b94c090718a5a851a8f470e5e04b4c34fbf5bc862d15d0e7cdff722d6b5715d427f18841730f2ebb4b8a0cae5eacf35acec9544c19", "8e74ab0cec0b8cd08dbcfb8324153354253fe113d939abe900fc2be2efbb439c9c5ff2935e33833ca9d00f4a0b2742948ab7f7c898fc805d79dec0ae1c12090b7f1e54918dd440a88d099ab6289661d838bc285aa501b194dbe3305915d2d7258e52f7269ad58b81d93425b906639e055b8229d463abcdd835a8efe97a89611741da102cdf2a3fe0a8785bc93e82fe2114f2eb3a5d9a04fb21efa35b465b85c8edcd6d53f9f5620ad5b5a9812ae8eacd431c9427dfc1c84c63a87be299f53b2b83648504561ec99487ecf31b31064c321edd42e83a71af8436cdb50a195b71a33e749ad3ff3cc857f325cf28d5ca44dc08a621b08386100ff25b775eb4c6d46fd34da3cf6fc82fa5700a804e1e185ff74f9d330d5f7e86d770ed72d11a9f0eb095fd9d52c75b9b9a1ba1cfa37e20549d1325d44d7eaf3aac177f85b3c6f3d5c0b46bcd44e5678cf3672b9a7951792bb1285032241d4f90c2c79999a31132e7b62e62173ab328ceb14dca5951434eed85651ea719a9a23f4e2d3a3c2460ca9c2d87a10c14397ec90f8e138d0c160b2b8d", "855567a1e9541d5ed2a80ac348899b28e4d9c41d277646e6082cfc6107ea2b3d68533e2bae076aeb7d70293d7689a544884ce184284734d873dac63628710d46e5b5b8e989403a08d32db9bbac161fd7cc2f48b7aa35588507eda2c6667d70b38b90abaaa5d1972afc224d33c2b33098e5e894d37de6fd218ddb77acfa2880e8227bf0c6496c3402a7e0ee2a653295f6439962c53b31025797f38ad3320616d7c740cf091afc35ba6b1fe2ccc9194c6f06db7c04844eea73aaabef03a11446fb757b7a96eabc5ecd137d04e73205ec001a3c1d65bf252128134436e9d0274c0ff8ddcc25403619a3cda8a43d10b75de210bac980f0be2b3d3b84e745fdc294839707190f7925c37c47fc932c0e38f8dc4c5caeab4267278efd07e2223a7f92e57a912429605f78678aef907d0fb0c511351786501c7bae115310a2fadacf37b91edb7451e0a0b644a6cfb3a5fdaec7a00610ea167946f1db40c9fe9769605ed92edbf4c7bbdb2f37fe288615eefe8e9c", "8fcf3cd95bac204b12b58a92e0e3f246c74e95adef7ce02d4de56cac02eedd66742fe5c1e742d47cefb703c8f7abe4c9a4a7a5996e90a6b435e4fe3ccfbad462fe7a33a09af334fb21b6e5d2561ca2448a098a1e98f98f6edfb9e53e8bbda4a292da054f2d5dbbc73e77a0051b8c204a35daf92fa2649305a421d905485f331c8035daa9351b95f211493c0cec8915c766c34d475928d2b0c64d8f1486259d9f331a756fe18776c670022413ecd1b6a367f96c656893a9f92792a37b664878f6ccf7a8c360ce21c9ebeafbf2ca8045361ddccc8b70780ec076af82dbfb06121d1b3348d4d8d5a39e6faeda4d012ad53c19ef606b341e56fda6825f4edd57b1ac8ac611a1cab272f8e9a073efcb432de52257ce73a9fd1bbb8f917153c370e1176f39918c5fae4cfcc4ba4c31e587f62c359fc3ef1ddb277371240dfe52777f94c77c3da905f5286dff266b7770d42439"],
        ];

    let gens = create_generator_helper(test_atts.len());

    for i in 0..TEST_KEY_INFOS.len() {
        let pk = PublicKey::from(
            &SecretKey::new(KEY_GEN_SEED.as_ref(), TEST_KEY_INFOS[i].as_ref())
                .expect("secret key generation failed"),
        );

        // start with all hidden messages
        let mut proof_msgs: Vec<ProofMessage> =
            test_atts.iter().map(|a| ProofMessage::Hidden(*a)).collect();

        let signature = Signature::from_octets(
            &<[u8; Signature::SIZE_BYTES]>::try_from(
                hex::decode(EXPECTED_SIGS[i]).expect("hex decoding failed"),
            )
            .expect("data conversion failed"),
        )
        .expect("signature deserialization failed");
        assert_eq!(
            signature
                .verify(&pk, Some(&TEST_HEADER), &gens, &test_atts)
                .unwrap(),
            true
        );

        let mut proof_values: Vec<String> = Vec::new();

        // Reveal 1 message at a time
        for j in 0..proof_msgs.len() {
            let proof = Proof::new_with_rng(
                &pk,
                &signature,
                Some(TEST_HEADER.as_ref()),
                Some(TEST_PRESENTATION_HEADER.as_ref()),
                &gens,
                proof_msgs.as_slice(),
                &mut rng,
            )
            .expect("proof generation failed");

            let expected_proof = hex::decode(expected_proofs[i][j]).expect(
                "expected
             proof test data decoding failed",
            );
            assert_eq!(proof.to_octets(), expected_proof);
            proof_values.push(hex::encode(proof.to_octets()));
            let mut revealed_msgs = Vec::new();
            for k in 0..j {
                revealed_msgs.push((k as usize, proof_msgs[k].get_message()));
            }

            assert_eq!(
                proof
                    .verify(
                        &pk,
                        Some(TEST_HEADER.as_ref()),
                        Some(TEST_PRESENTATION_HEADER.as_ref()),
                        &gens,
                        &revealed_msgs
                    )
                    .expect("proof verification failed"),
                true
            );
            proof_msgs[j] = ProofMessage::Revealed(test_atts[j]);
        }
        // println!("{:?},", proof_values);
    }
}