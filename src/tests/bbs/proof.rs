use super::{
    create_generator_helper,
    EXPECTED_SIGS,
    TEST_CLAIMS,
    TEST_HEADER,
    TEST_KEY_GEN_IKM,
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
            ["a3cbb15d5879891fd2e0d6d2acee15dfbfc0600d0963a8ef2d5a7e5127f536dbee3479b96983ab372919b00a1a310cc8a5d74278e1e642b692e5fa41f2d741cda81f96157005b502d54d76e13cea0ec1f71a44bf2a8aaf1c188da30a79f7f8b8b54c8022b5f03ee3260569509dd442ba350d6b25d0bb60fa679f5ccd087dace1e367642f12eeaaa05d9071ec78db04bd24d67adfbfd0445a43ab3a26d2b6b1053f3818d910f21c314c1220c60bfeb7b7064810c339bd19da43e02b2388eff958eff20c827dbd2d5a9f284a5f0f4b75427101d967d0138cfec2295bdfba55860b996b440598e29b36313e1ad208aa9fe04c55638ae50364c2c034c42b519ee377acc1e8c5a7922fd202ae6e4468347f9305341f88219a84f413d10a5ace91e36b0fc0c241d4b694308c8e259b7415a9065fed96f1bba851d55e26e885df38cb6d833fdcbb552ef7b605064af055c71a954f3bce17dbb879666865284aedd71bd91d89cb0afec723fe76847f8953a6e59228312b21a653388518428196d9caab9e9e9180bae4fa6a65ab9f09fdfde9665c1af020661cb7effab3929a2079ea1a963d8bfc2bcac4c81e6440d27a76f6e95a2560bf755cde05278e486091ab3d389bf8f127ab48f873a2902d93e0414060a3315946079cb0bf92916f2ba4cd6161ce784d94fb1708fd5e69c3b149ddf00060", "83ea4819f56c5fc702a1cf901c9f41cd8d1429281aa64d2045d4a6fa346181f75d0f24c3b5d0d8b8f30220357c0fe8049642a659ab56e487cd422655b5b4e6b3dff75f822871566fb637da05bb871f76d874dbccb0fcec7da6146a1258a9c17586e822738bc586e7dc483030e98899219e77935ddaf0526d1403d122352e858be91bdc1346118baf352a4e1759b78cbd32cda1429f750186646606c072bf82682dc86a1a7c88aacf024b67fd4997ff0b54a41855bea11523f49ee74b94220ce2989701e874d5fcffd0dfbf7bafea76f54405585a901ceda1f3119f18073bb103ba01766e52128f90ceca9c0c51f000df09c6c084a3a893b05156e79e93d80046d1b203861a17aee65fe47a6e33eba0d83e0c70455c8576fdbf247a881ada831afdab8a2e24197bd167cf6a4d98233c874d6a019c37fb242bb12813176117873abd567a0ed197c0682638e7467c664fe110d9381f46849793f4242ae80f7146662007d60acc01ba907ebe34518a3816a9211dd6cec37bb79957534cec300ffc5f5cef312eb881d557f72d537d40876eb74f914ab68fec2ee5f1d46cf993a785cebd1d7b8b96d9d2f8f6d940ac5b7b34810b2a1291f91a37a02ed92ee9e528e68ce37dea92947012421483ce24ecd3291b", "b2489a5c89b0aa4903ba4d4a7e8e9ed8e17727688bc67b576f6a2a9298dbe071620458c05fb6083a028995dd273ce7aeaddac96ff97fb84c75825b9ab5a0832d9ff59de569c0b765a39b3feb05bb59585e4bea3596d22b16c5bef886d04b64ad8e484399e63479d7f6e6585f67cd0b1c4d0f01e6b1c072a62bceea20b80ec3538c57cf3ad05487c341929ab56b4294660c1b3e85c10a9299f3c63314bb4726e7e57583c5b9ce819a645f209c8011ea46319310ce339f781f3a49f74caf35f11350901ea6cc682c19d0fb5b512b8a4f914d6d894efe5cd96627e20f6a94d166f22f5311f5c47c6ecfe1d9ceda257d7377551b95401904f57b60e775e8d823ff5c3a0d511c8095b757f500164c1aab910d6d7d5cb58ef963b58c87227a64fd12462cfa3a0c0511e422b98e8d5abf0b80af1880987f7280afe095a651f857a7cffdacc00e3eb8eb7763d52684eb8f2860735e2b0b8994c93e780df802cd169ab63a6c20fcdb6d4df7b356064c00758bf816249eec645a6e7ca02f1ca45aad8b39cd4355e8d71bc6fa9456edfc7313543e9d2ac6e0ef7ee7597f8ea47878ad2f7d2f3bf3da2029e023bd14314a2e1cf681cd", "986f3c4eea5ec4fe04764185ef47f48744c02c35e3f5140ecfd7230cfbea1cd08c0ca9ae7d0b7447008c453f3aba806494afce10a3d52cb6eb99437313899d279e2f86b5dea5d4191ca8dbc487ccff12aeba04ccf0730164a180261ed029788baa61eb6ddc2d7de515bd1f725a3ec3f6055c025405af953fe73d130335c88bb8c5143894d668a30d4d9c520726503b8048c11649a820ce1b777d5b1bccf72b2e8761076a9ff0d02df4e60caa618432ec415743e8e0e4d4e6b28f3c8a3b78b9f9bc1a0199554ecf5b9646d29f009b809e73caa57a9af21f09371737cf46c4eaad32569cc1df0a4ffc0f8cc303dadcdc8325f7e96d9bf04cf16de3f828151e58ae3647f78d8a226827ffd69a8b23facc746dc8f24cdc1bfd7293f3fa30bc5e7d1adb866d11f353fb144d38ac63104414e64d1d670b06297792c6aef92ba85279a078b48ab6569c56251ae0def126f376862866f0ada95af2353c4e68c36a835ebba66e3c869cd6a54323da42a36d2e8b256da6ae29fdccc312cfd8f0c372c332b3485a1d02183f3d84e23264adc014c636", "992447983ee860eb35b8b9bd700cad3bc43930bc74fe896c70d2ed9df088da641d1011a183035807d3e31ff0261d027e8fbeb25f2bc7eb8de18493fc18fd6e4ed2e54cdeee2fb5490d31e7978afc40d7d2cdbc9baeb802884698239e16ab83b9960b16d90154271364579c79325ef09356f3d396ea6efb81981da286dde711228a257db72ce7a9f005bb904de7303ce45b4307766c42bf57402c820bc3669bf5ccf89890c322b595adc6add2e0d3894a6faf40854c8c580aed4396bc45d3aecc1c0751789f81bfe9927526c74207e1a11c24862dcd2bb869cc42777e18cd6fabc4e54dce12a73240f0a6d518c151b0dd4fc8909568a06fb19490afe35807bc5bfe4901a3f6cc6516a47b7c1fd01c8b522d64f5dc4519d92d21d3834c10e78ee8cedecda5ff001d52b7262f669bfaa9dc351aa43963cd4a626e77ea49fc02a5b3d13640397df21e956cf9c2f45ecc755112c2c97cf90a1446f38ddeffb31c6db3e8750840671140ea1d032cda698b7dc1", "8ffbca0d5cdd0dd2f80d3107070a7e91a329ca2a01fe950db2dd335aa6a819d2c0c89c19e336000055a4663895e1ebeb849790ae3affd3926c0ef6a5ffe6fb7ff44904ef885ec1df0cf776f848ab19c81749d113a0b1d98697a67f4a781342f7a7d7367eb35fe743d21f8137b0ff7e7a30e759bdd2a0461abf7b243c62d09e3916bbcb6ba3467c8d1a6e2e3da1a1d86e15e6871889f6e77fa7c4e07bc3c3de863e5865a2e9045e219968bc52281e3172374d2968961988d6827dfcd699e7da3c69b6f290da7a5eeda66b0bf5cd877d2c2e6864588a23aa8b3dfb87021a04b09cd820072086de6579f86378fffc54d11806ff2f04c1e3e8856974e06a23e84168153ea500792b4eaa43313941ca25c058726791a552a500c1ce5349255cde29293a8aef4f63e163eb8d883828d8a71e2b16718b922461a4e2818bdaf734c283c3e58e8b7bddf1c0ccacdb95d40e5a04e4"],
            ["a4106daa3d766c0c7b7dc7bf6dbd572c1d628fca301d309413e61e1a8fc92f3fbc154d77bb50da1b4c83b86e162c0c1497af233ae4e124391118539b83b959239de6058579951ea0d6ced935c56ab77fbf9d7020ef8c0acc22fe65f6046ee10096d5865e5f328ff67e1842cb58d16126ac8a9809bf8d08b04510080db3897c38ed9dfcf8247297482b7984edce9a27a845235916554db0dceddbebf3502d300698c23d3db27fb568b661548a8530f5a8276b8b40290b22d91520af21b8d9152795876ba1c9b46b3f4a9772d55b04e48b345b16b7771e09ff62b1ba9756bc428aad0c6d0ba454b232c64985206a6e2fd171f05d1747dbd463cc05db678b8ebf8371b60d09fabcb65341dca86159e540a45b2299803d15699414ef429421c620abfa3a3f7752bb85b0c33a279028c547fe39b8bb5764a67ae11fbeeffa1b83db4544cf7a84eef746e45abf9f40927fd4fa1e666a90fb76cd34d7c9a90696a8ec6df126e77ec28961e6f1c43be4818866e613f80392d3f680452826a621caa5ca1c7bdef2da474b909028abedf1f95b109d2dad1dec452fc4e7a303b9def2e1149747f084aa82de796fca1572eb7c386aff007efd2b6ba2f5b3a249a6b6c1d15f0b4cb7b0ee82bcbcca8ec266e367665b95596c4c9210143842f0877b603ed9491ebfba7cd8d43286b70b6c01bdd0bef00b", "a29e72cde0bac32041231120e9443180d1742563b3764017cd503f75ca17e7963334556735a376702c9a2757993ef9aca65fa5518e4898769a404f42a962f9bdf816384f28d5c1ea0b48d6750de457288dad0fa56e899a0da61dcaa260c7f2a28f3ad2c990f0d1097653bf907ad35a4e19c2d6d4dcc46a84e278f277f71d71c4f777840c6eccfece1cd162817c3672e423083b11de7c13fafd22190f2b2cd045b3b59807e562baeefc6b3202a5cc01bb0aa6ea2751e96a9bbe42727ac2feb18e44a1e194ab0f48579231234417a77c4a1d7570401fc76f6fb9c5ef33f142c36ebb798f7c3cfbebb77877eeba0df6c0a91c6d30c14e054e316a8f52fcccbe8e75de9ab1e3d09d3df19a25590d398fb80f4f0de9eed9cd3426ad87a7e71cd308885c647465f6cc93e1c54c2bbec058a20463d8916b6ea1f4c6faa07aed2356216a0b0f2f77fa656d8f805b46e4446aff180078300dd6fb9bf6d83ceba78c7e557340380d2bfbf7aada7b1987aade35423d68372b2edf414a7ec83a500a7ee93b91746fc32e407dfa14d1342d36e727003c0b992ad84d67bec9999e538a7d69d7c21dbf026a0fe6263ad29226e6ece3e8bb229816dd01a6cc3bab89bf06edd049205780a216b6d72bdb8aaf1e382b6e2ca3", "8270c7897ed3e9558b50a996132fc9a2321d798013f0af4900c0547383962f2862db674c05736a584287a5c46c92111db53057e142d3a28ee85dd75f89c23ab23f0251a3f572102b7443e28d9df681bc7779d2021c9113abdba3c547011f5354b7970e0c11b01cb129115c18649c50a9c3021312b65d993258c72fc44bd73e376076e680ada11ed2104a41c442b4272266fa987eb901deb06ef766a391a82c7968dc7feb3569bfe006d2b3741249fbfa513628b8bb7c64aaf32a4d013c4e596099a6e4232e694f867f3556ff7e29ce8f655168cd60a4ce35690f7e595498f7eb5872d4099514f5703d76a5f5295fc0344ee2248260c9430b9340961851a1b005612be7325ee4737336b819a557f852f46eb98bc1df25089a1ac92f4ef1d51aa9e6df6544bdd56cca2dc7690960fb660433068314b1d7521b276e28df3d97c3223105a62f6043c9b9426ae6b973f6bf986b408b54b63081eaceb3ae14dbac1dc10a4c5d6de1131801c788e2274a70cbf8298551ff4d51bbd970a260f3443b3f9f869eed0e60e0140ae7c102a4d20215ab3ebcda144dee6a0418298795b4e9dc586b7692e38b1cf9e23741ea0ba09da9b4", "a4057876f2760a1fd342030d2d69763aac7f4b15eb0613ceb7255f7144fbe52b888886afe0c27a193f22340ef881f82794d959d9a9cca414611d029d6a43ab165b6a14f500704202f977d3610b3d6d09f5ebcca4a972ae53587fbecd615c48ebabf8db17084e7bf471bb1552687d29cc74be53491f471caf132e93395b6ef67ab02882acce1dac262fd0bc4270384d291531b8223860dd583495960c97da526377bc780de8b943cb1d2bd45b139e0351141dbbcd78735552e8f15a627651b805cc8ac629774822ae1bc331052f2bb7d745f8a14633f68a06b95aed3e67f84f800fabbbb18ff98ddb72644925dbfe40164d0755bcc757b0e8a6ece65468dc51e9c29d08d76a10d270f08ebc8e78b5f1925b7549b5a4d707a23bae0a75dfd0dcc923555f88e365b2d33e2b9fc9f4527a9961e2a4e104dbadd904bc4d839b82fc9b89529129ec69eb26bea3dcc9a1a57a7628ccded0335b5775991e43feccdfcb4a268cf40b5e3126ec6a32ee2979291cb056d00f41f952b271d7231082ea4478523ca4b5b376fd5c9a45cc565b2318ac6d", "8e80d591b2ef02594d2e3c1e42577da662a9ffb0014b8089a5086d4714f8e791add84cecfc795c5aa3cd747947f7987aa4a55b37b6ecf626447573f56ee265a6a8a78985dc1165915c4d770c3a720c79ebab7cab985224299cb4e3c9aa15feb0ac59bdc0e9c7c6ec82655e0e7cdc0146c801260bd73016c9c908b6235ccf186396339d8a829f6ade872b569ad8e3e375535eed89401e84f5f2695825e09a996973c4ce1435b91687f5846aa3e6eed4fb1975591ceb4c293b1584475a90a075229dc0f5d49afab8f7cf5e8d2417df309c53f1f6811ff6a9a7cc168a40159213962d91bf70eae83c5d6727c07474a659216a6cbbc2ac6c8efd235004a4bdfcc346ce1810cce10d122b5cb0ff6d21a333d818827ceff7507aaa1fd65f7fbf4acc3a13653dcae1ac3794a1b5c62842d2f86a6da0d765252b273918645891cb65b9018ea2e52132744ac17a76116dbb12987e04a9b7ef236c229629b049f207089a6dc0f59c0bbc12b734321778b2ef7a267a", "840dc9909a62036fcb9984f97ed66d619b2fadb184fbe6fbdaafe8d3e3e427af023e9c5962392f32c583eb1179359166a0be91043e40611c738279b522893a286390a391fc0a7895d6cfe3c9dea633df3946411300ea225fc054c6ffe589408eaf759c06a203462e7d50ad349738331c045b7cc798f0db0e4561684d622911ef996829c2777f63cb75eb8f1732acc7e721ff5c39646d893af5bac88642139c61aed870dcd2cc898d85b2b5796523d89d02169ff4dae00d2d12aba4b6a7d5a9cffa7f9de52beb7d21fd4753fccaeb4205336d282aa271ed36689c9fcfe90bb9b7e3f4a2e7cfb716fb24edba12eaeed967013b941fad5184e5803a7a23b21e3dbbac1bc01eb303439152dca40ddb2781b04181ab27e78d677a9966bc4d37b2e785cceaa4fcbcc92fb9817d29fb25e605d304adadf510a2409ba11ae41593c700a03c5765e949e1db2a756aec6e0b47fee6"],
            ["a92a9d55cdbff789314b914ec547ae03907d173d5c708d9ce2e98d313b235be42e0ebe5e085d6234e6822e5ef7003dbab0a36728d8a298d8de6bf5daecb554212d15172832f0db2e04231204e313807e790da1ae2b85bc13705f840d3b59cc138ff7432081c2d0f604a99fd45e6d49385bbafd610afa3a3ac2fd64f86666426a4ecff86a3be138a6cf59235582e4bbb44d7ee0623e17aa730ffca353602c196afd1ae6c5285c45816711fe4e6f63eeb450f3f11ad3afb15fe4c7fb9047f3a8a5ffa8ee20b24153b77ab75d1ddbacd2f6403b6ea20ad811b757ac112bec1ae58179cf1799fcc12351c9f0fe687088d9fb20edcc1f040c403206030516c499b0939934e635570bf85835c5bc3dd5f6aa275a8fa1c66a025029367d6171fca20519d46f9c98bc2b19a5f07de85260335c1562fa840fc02b5d07f81b9af6115ee27ece12dbcfbe118daf4cdc6e56a46ce85a0f77aa8e6f9e538272129bc932a1c95dc762c89485f51d0b6af72f1bf5255bcb6a6bfcc55d97760b006a10be7a183cbcc82ba65814fbb14566440318123b5c6a36c2494f9a41f1307679b8068e48ef7cbd698531c88ca3d5015d4f9ed2e6d2d31c55cb1ccf5b5a5cad14f1aacb1c9796d6e2c4730cfb633f096ae30c8a630fe6403dfa7a551cec47efa8554f4db400295f10327c82658e8504a4465aada169ac", "99548fdfb0ddc5dc756df4e6e7a4971084498e901b7901f27cf765d1f829258a3892e8026483293f2159371e1b38867fa9d07434dab09802fec993524b9de2aa754118df5b67c256a730e476b2b5ddafc472dcc669ebcec042129a19009cc3678668483b624b01cec310bcc43fdcfee384ce1ba5513c6249f0099bdafd27f9e7f7d25c7896ec683dc11b09445646db0b41a003bdc075e4cf3876e03ebc2a62654b528b06b2b405ef6dc918e779b75a22231e25a8acf5bdc7f66fe0dd1f095142a2cd7feea0cd8b1de1b33eaf25b2168e17c7be299f1ce9880032ffa51ad40f5d7dd5642575b2a5468fd127f63620b00c1b35afc6354588faceb17271b60580f47afb7ed7621c252ade4951a582fdb8530094ffe1cbf00ef096a01d9ac4e1f844007fc042b5deffb1a0efbf65e25ce3e4302de3da6988b69ba803e0109681ca41e5eeecf587ac8c949f4bd62214bda9854c3f5ad641aeb3e13ca7c4a28993d0230cd990b4a58939c87c3451047c4bd9e84c82b223d14ad756f4c696336bb1b0d532f8a38853d51e8413cace4351b960573733afee42d526844053cd6d6077d1d3e441ac4c75daa1f1a0ab0f20d7e20e32152b763ad8c25021202337a87bd79b453a7f69c85b5a30def4c3bbb27075e85f", "a4c53d93930c45c846a54e91a3c2cfdcd0ae1a28cc359fd540578c3767a99cb079c71ff41362f5bd3ba6380987b881b6b1a66b4cb3593550b70410db228441ad87ee7f4f3139950079481c6c358286f5be3318acbfc70d4f0a3512ee5baf373da3dfba85061449806cf5c03d0f553abc8cead503aa620a61f13ae0e9a98593d4970fcd29baab23711e15337689c98c305e14bb4adf45e38463452ced7e78f93fe3de92401d7bcc90649b12cb9fb8184b56e3f38c9148039eba25e3ee06fcb402c28c21023399a7985c46dc16e1d335c845ad0b89199e914bc5f184dc0ca6cc09118f062d569fba393631dc8f3e14e3df03a4cd0149094660c5e3fa0d72fffd0b5ca63c268ae783f4d3e7e4497d4766da1c60480d90fdca1f8dd4d25f30fe52bbb76a6a267ffc4ce19cf5364908fce77156998214b944de9fb4ec3d921b260f660936508ab2ca8a67be83401e8980a6b06680ae3ba26e45528b9ee4b6a560d352dc2d38061499b85e98bb87b0dff97e5c55d1d99abed310c0604cfb6f01a930a068e4d27e2fdcc64ab0ad635b595dd370709579d62c3647ea488614ff741ae0c2fdbf94e328b14d0b1043ef81d2a46bc4", "83d0e1972ef402671d2414f2e45f5494c0289ceec185ec34bb45608665c3081c1e09e76d1c41e7804469f19aecc0939c81324b947e2aa0a5efad4264ee3728f5b2bdbbb875497a9c3ac68eb218cc93465b86e75a962bf9c3ceecfa688389b8b3b0de8eed700d1f42db8c4999452c9216cdd0c7800783e884e6409560540251682ca03878b5bedead3505241d9ff76cd53158bf4eb4a45692e1d6519233c1a5ae5367cbdd00151a71cfb763395d7b12bb3361b62a12bb4e406606b78fb3fc4a882b092f21f818ac45b24f66ee6bcfc77c20dc1f9957ebb3449106d73b18b1e12cec0ec574022410ba3a90b5d621d0808e034fc62c39400748ef0e3a10e8bde603fc206d88e65aecfcd611e4329442328e552d7885d128ee6c13c2087b5e6f7ece8eb6afe263c85663f031d889cec588f8028e1e0c73b70d5c01f6fb9ae7c838742283e216714a1ba3a12c71d6b478bbe80b50ded57947dd55941a973b7d464336edba9abbe716b9f1b2c3d0a636fc938d1bad62f066f772149d2e12e9eb736b40bd8eb6dcabfe40ff13bb625732ba07c5", "9015145c3c629ab09e71c7f3916f62d4408d5377ddbfbb7884780a7823c8029f245d9cf48067c71ce5658325095613b4afc3bf2861c4a649c200984110ec3d9ded7f992d8cab2242458ada7a06603d66573afd204e3d5f84534f0d9c9280655db9197159191cb91d58e204d5d57739eb95e38c20cb7595380eb0a028e4700d91b0a83f384b9160c82f265e0119763bbe3d5b741033c217d9d5b95b68d11ce0f214b40a9875902da60b17ea55d8cc2f18495574aad9831364a3e3cf813d3add653dd5f6d18fd33c126c49b1c3be4f98bc48492bbab67a96f3e32d124c6072113fbaccfa5df05d52bd045a74b66cb2226a0189c0a0e609c7be2ca0b1cc719d593dbf5c793d013532b4125b65c2513262a73c92bb31e2a1191eb611226f4ec4f746e8ee75a900a4d320aa53942d27825b7218490a780554157d1d67b042b6c59a2fa4b067835d824543056ef0d1b68bb1b4527c1911f18955c57de663f5cec766d4701a93cd1b505e94fdafa19d12effe5d", "a5648c5fb9ab295ca3fa81754c104f68c77ea2c09cf12453b34ff4881504f2256b8a303e38196c4477137ba3968146b6a3ac634b1262b73c58cbe911fec28c9c2b1b68ac9fecfb22c083c0b922b1dc44bdd353cbb9ddaffc6fc1153bfabd81b8a55ee84660a21aca1d8303fabd0a508af26ba74aa8113aa7d7831b3ef1fd0486153f1114879ab43feec47c08790a90fc1e625028de6f7be3c5b15a772f3011023ca33c2d58ee274a60c8d5f9b61b12704557666be7ae2e145ff1b7d24d3c33e06d0081e757e3df53ca4f14dd2c76b2cf6ab0542865a25a3bdfa7b4570da4231ef0c4af86617f24e32dd3ae08fb613fbb623108f6a5519adb86178ca2b8376d964fd634fc60770442996597098230915436a0c70ec51d7680105d9d44f2d4f81e41ca03526670a82f598a6f6917460a06023d364c83e7e069af7480538661a16dfb98dd19ef00e10044c76ab5964eea47"],
            ["9506238d5b039129f431bd32a59cc44d31592933aa5d33590c00c7712ad8a05616ee69d8ac2be11dc3c37f17835977918f0043400b9f613982fe246e309b1c8bc46d711508dc70d8bbdc0a37f855580c0862d58d555407a2041980f255328e11ad92ad2c1beb0a4d762f10e3b79c13dea38b6533b71873a769f5daf2b05a2c92b4504b22a3e5980a5ee9d832a9b5ccf53ed74084bdd060cc5a0de68950266131e92ee44bc1f2d5f58aa0798c1aa49d4a38bc2bad7ae5bdb703b584f7af0f34e8891c40eeebe277367f8056ff28773575452ace25ef102eba45eb9ed637364cdf198085cfb6ceddb02a69f03472761ac2107aceda1d05ac7b1c03ac25ff4849dac3dbf57a078bb4262b52b357968cae1c4f28890b55951bd5dc20ef90dd38d8069ce00ac8016b0a3aa88fc487b9b1e30e656e07b284f88ca5fa9f3dc5a4902c55f13ce75e62b8b005bace0340be7daceb31ee0805e3f40060e921659775180cfc95ddd38441d2a35f10a3a3c23904b06e4949ca569c159e6b7990c73c28f0ee834e3690232f33664d4835f4a8fad61e2f4a188fe25d96805f02eb1263823961eb61e4a18f05447874a543f94580c7ad043f36ef20132743b553eb303737a29517951426090636663ebe7365a2d1b5112a5721b7813837220f7e25a8cd68b9dd2e1f8db7eeee9e398b3e329f8e50fef455", "88cf3d04065ce71be9aeb6471662ea57507e65537a27bda9e49d6ee671199776b0dfdb96da3473d6a867530b8736f090833d1ac7cd4222ec2e8f8c294bb3f4025e8a8b21da04900dfe10d8d72f2606c311574f22adfea7cf25e3e96b36e4131488ef88d25fbae38b8a395f6a6b230383ff85a613497c6e2a75aab3575e35b73bde48de55770df35fd7ed43abd085b1e2425af28a878e1bee966fe3ecfc26395c84b3b785c9e358b3eb275730c5ad15984201445cac40bbb471804771df8386ca0a21be48f004d559df3cffac3b845b09006e7f5323569c9169c4dfe7c3aba8a8055a20a5258ba2ff365868eebc22701b0239a2a91403e1393fa9e5b9a5975405c65c5ea7163d6be60e0eaae10bd2778f4a5eb13a298de3b8bc6bee3811c4992220eb44441becee921711b5842e7761fa737b4f020abf08231ce59f2dac6386afc4402b665118bfffb97ee9d6ec746827606574c8c83a3e71ea38babc377b1f1466f7ddb5b8933c8200164e22f1de88633ac0f0d4fe73ef5396baffa5ca08152e3caef29d41cf3266d057f0917da6f0e61addbc561c0d2aba8807f220b516d1e40ab98a1bf43dc9c9cc528be7854f646469e063c807596bed291203e325ebb471f1898b56c28c970dde4c6a78b949a4c7", "92712c5c0d2362625e289f8105f195037c58c543c9eff9893f43cbe275b4657a66d152906d83f80cde96e33b95cf7aff983dd4eaa4b6c5c853dc4666d202a878b8ec62d267d73b868ffb43945a8c36fbd4f010d727cb7b0534709ca3b744945593d8ffea022b301d2398199ff668968cbbc316a12506f48f12c25ab662af979997a57bc445c867134b4b893b13971efa1a2352c6fbf1684c4fca8d68a9033f6999b49f3cc1d029697f8aa4b605d0e4a62b8371f7417066ca5ce28a1d4f5ffe11a6d41f471071a460b48b1a400be207384fea13d430e9ad24f96d9adc789b33d12edd919e13eb26d0252eadffad94d9f5443f72a9415a686049a192dd37c3883acc7367dc81099c9d41bbfa3ee981d02a6b22e9cc4bbad3216eca648de6ebe38d8cc427040914b6e12ddc5755f4d7a77e52c6bc988c339a90f74b1bdc4d3ae5c45be84e5299a21456f3d2b625d05ded3526a18b71f9c0caaa07f56194e3b13b934c13ec65c311116d36c90f471649608e5bba0ec5beb51697e1469b418a1731654745b2c41cd38f84adaf3a0fceaa674a57f0a6d6c288c8d49eec351a7c08856ae5d5eac3347183ebd3a4a3abfccbd048", "908fd024aa62d4f7fd8cbeb8a1379e5fcdbaa957c6a68bb6a35da5cef6911ee6f0ac30a03e600dfb84f75d8a881dbf55a6496ffc6be90486c5fcdb3c3754bd143ee4bc2dabd40afa4f4c9fe0fd33301767da1b0f4ec7866a2ff782baf0f0166786f1e73080503b858376bf88ecba35cc9bfc2bd8cae80bad4fde41659322a70b010e8cf8fbce1d117429660dc228a4d30cd5d8ce541a36095aa6441b424884e091ccab0b77cd90279f749c646fd2421f2f9ea8480215e8a67e52bb645e842eece2cefb835a1568cef6e8e74184e724f558ef47be44af27af80e22681335ff208d9b5328f351d4264486af29171cce0a8255a069406ac66e39d4262bb1f923c09eab96d223343aa0c397af55e8d2d8c5d1970ca0f0ffe5a4b2f429489fbe907439296fad1269a7c60928d8d77a4028a27346df2eb491edaa378b5874ff6d76383dc265625f2f58a449f5d075499751314081134a8e17bba6fe9d97c8dd27838e468211daa3aa5c950aaf9fd094a5518c414b388ed30f03cc3c7588ec8c89569d65677a9f332a8573147384b32c9a17236", "888ec27f52574dc62728628bdc719d5109fcfcb8e0951e46b6197157b2c9d2cd4731315a3d32a17ee58378f1736a06aead6db1c4620458cb8d974de0dee9efaf5f29e213e2e92a4cc5136cc8571581ae591ef64a0517f687383fdae1d4fa7b1081d7e0ee49ad90ce23d48d3d71c3189d7eb48835f18183355bc27ca90ac8cbda5e97dd49444ac7d56cc8eccbdeb134417175ba406c96b9b0b2eba9994a2499f90dae39408fd78b89bac4962daad2cd6e3417fb32d43baf1f7825c2c1065dca2d3a53025ff575aed6526d330e865dc31a16a79b598dda753930cda2ee12fee24119b53b8890de874d66ba8999b492f0925c6fd44ba36676dd4352d5a422f4c9d8203aac91716f944560fceb1d3a54dbd257465eb61fe2941a29c81480fe73c3c215fe4e0e04182002e3f85b6950d294b7128aa801e8080fbfeef41ec41486dd719dc48b8d0a53224db7528510e95aeac225cce4efa28d24263f7c38bc35699f526d5616517a3122b7ee07ac0fb1ce29fa", "8fc5e842b98d349222fbac8f4e8dda4099ebe9a8938f38917052f06700b5d7e6f025fa6e42449b41970fff96335a617790632d16e6cfd48c2490052cbace9dacd3aa2347f0e221085c86bde8d710f9fa37d2f7bd48f0bbb4fc49ea611ee9ce27b7b5f8c8f07008a354e9452099cf12b6d5abe0edbee1fe782404e518f2f9d2de602a44be19b0c6d02995be17895d8036134f91cff6cbc29439d9c99da98c1517aecb4ad331fee6a74644c852c5910a7455fd14919948461b404bfa9f523b9e95a04a4a92026a915aaa00b235051c1233688dd7429e162413754149f37a0f08f4bdf58ad5204c2abfe0fbb3269a1a3ae63e433d0a482c9cc4cefc50d781f2a3b1bc04b9d7e4d3903c3aa82a3902d71f4b0c5dc249f40d8558bd456b5d6d038c8e5aa7b047e790e684d08b547b008e13e51d774c084c8839be704398c9abdc2446a0ca881f3cf9276c6928f54526a55d6a"],
            ["92f9851f35df15f5793ec9eeaad5f490a33177a08b2d574c2182cd704afe6d602b554109acf9d2d609b7efd90ecdf4dbaaafd9210def117ccfe1f2e47141740efab4fefcac322a4229f4e3c66138f5eff454fcb188506e621e7ac94e1d344158a9d19f203c603a8c2601b8d7afb51cfc9a1d70c4ba3c1ca48321b819243ac001592d06f5f260e4a88eb7d2cffea7ab5c3dc11264542951902cdac08bdbaa5863ea9b1fac4257956a0a774ba78b31e54645fb6c8403b93f821d1a8e93f27305343df3ae9609340d33812d6b3a27aa4aa80958b22bbcdff93fed49ea1a3da0adaf1d7ee3cf72079041ffd224c07235568c4a921f51ad195c50f5ab3b2aa02de72b4eac35828cf52140e3facc4f47778a9220db70b5fa97985d87034b1eafacf546396199b2f476f62624c16daeada86e7711ff194975b8dc2c9b450a6f5d6cdd23d3a3cca22b4e82d384fedf3a421230ac07e5634c2cb621da08bac69a59c378542a3e25543acacda38aee28340e3385634e5179a7c84051c728a703afb3941ba8683eec4f95dd893bd003113142ed7d981cf3c52d809660c240ce677d3c8824d8d72fec4d803f16b2b64893895ced281d33cf91622dae2580e20a88c796cc1ec1815c276f8cb43930b22d7949e2cbff970c53a39c658cb4ce51c050fecb400a298991491f2842e7ef26d650c26cfde029", "8b75907f4ec68a2f0535a593521d772355e9e70e02a398a41a13223d7125dae73aa46412aaae43fa05b32bad66cd03fb88eaeee38872bc963b1c74d91dec5d0f00ab6e133c7bdf0627cf52932b977c95326b365c74c738dca0da7e09b24403c9ad446c8184d8592eaf2b4df6ff07bb634de78af341a3d81269a0b4f23895af5db0af77d2da5c90de881081d905d363f527bfe6cd25ba91fbfaa4c8c4d3803c315af8d64546ca2a3df45492045c1b1cc04d871e0a46da6c866bccbe4130b9237c612706119453389b8d562c701395723261bbd28640bf2ccfe3debcf86475cbec9a50e4ce48a5dbedbad7bc97f7a46b7d6da0aa5bf44f4fbb31e0d3f45ee99a965cf611ebf9d67400b6a110266dbc13906d479266fd6a596ab1a5b5a76ef2c8b5d39459662dcceba55e123e079b6fbbfc4d3760b0a6bfebb74d1ae093b3cd43d398a45042921e59e638ac2d2630c9f0755d40760214a63a39958316476342c4b4ff4a19b118e0162609a0d781aa83a46a4de93e9c40813a6ddc88947bb176c1822450f9d67f1fe544e19d36403156ea363ef354f6a70278f3b88287072ae86d6b978a869eb4c01f93ec7f08cb3477f5496c99642b36145d7886476feda4e696adc4d151dbc597e74964eea34a21828f11", "8a57d9671f59202ad277785b87a63704152a9b7ac7526db09551aeeda90fa9555504d28a744889d650f15c75c55825f88a27ad00ef41e1bd4a8f33c7e8a82de86322abb7f9c8e02eff5af6215398e633270a5e003a22b80be80eb857bc5f8e05978ad36c1d3fb7955230674168d957c37ef43ce72eaee31f7874b9f0d28013ba68fe5faed8fe72736ade587dc61a455d1b9c45719d4ba261145e7b9794cdcfc7b34519e42071cb6f0d5d3654049e8618687352a14d15f9340624e57e3ac668350ee75582edb20b2e1688aec64c892f681f968128037ba8216ed8070e52c4d815534e8b895bb49fdfafb791dbaeae258f24986e33b9b03abaa5ac822a5b77479dcf4c6350b2cd16584702ac35d48a76330cec9f8d347b2b43ce8444bec9ad43830712e4d0a8d58dcb189f29064a2a37f7388d2e63eb3185e464a9680a9dc80a62b0b402211b439707fc2bf0b50b467bc23e16eaf7104a787052fe86fa2fd693cc9fe8ff7ff672f1e9bc2e3beca5548e043fa97b6044d64823c517a136cb44abfcdd41bfc838e9c286fdba20809eb80d2825d123382307dac2eef4b38ada9075da9b4506c4b6346a5bfee006acbb980c7b", "893613f69f72268e8423294e1c6566168459da82cbd8f0f4858270cf46bac408748d7b33af2a0605d0e6b38faba3342896b7aa673814bb3aea9771780763e64be373ece6bc2917800364cb4ceadff8bc27c049c2b0ad0aafc28269277b5e7dfd8f6f64f817d7f054a9771fabece2dda799bf27816c73362a5bac7581a2c46a8cbf55acfb7871043979b6070231f2da6270d6c21d1fa690d16be6d107620874cc7d888c8bfaf9d4ff587ff8450b5d60cc2f18a91eeb461111b59fcb864af52ada8c708d6b3fe31935241e09925e25b4483bfe5a8ed2c9dbcaf4a6916a77ac3e7e9a75ace0c6b3b33fdc09c876b5b2ad22619afe80f554ff6486d6d8534f30d5df02786d96d5792c783e5ca4d43562a7cc3eae4e860febb3b8fffa1a9552e968909ba3874295ba99a80521d3f28a888d8c510a5908becfcb522e3aa629745a11132148aa9b67d49c193c7919efa05f1fa105c5fcf41113c054b8fe7af562d2d1cc9b2544032a700ae18319582c083ee6cd2f4a5916e0cbe0aed33e60478b2f47347f9125ea8d2d4c192cce101e22b44195", "8cc4e3e8c9867419c023f8a866c947c370fd0f9a3d6fd21f4f54af0388047616df6e058a04a6ffb982a4559943300824a7d4c4f3b5821a3a5324fe8c937e8e48d6c900cbc9e578955fc34eb65b406df525be8cbb5691c8edd8ea4eb707a4de309353dafc5c44e53db094568811bfaaa4e344e9dbe3e945141075512b2dc3a42c1143b545ea1aeb99935af801bc9196ab5d59bbe30e43be571fac3c77e1bf6c6660ff2d9dc87fb4189ce5ee7528066ba54d9e4c2c7c8a60a1e685526ca55d84d2174a3ad22a0808ca10deadf8ccc6748e32e61b76d6cb57803aaf71fc0a70216c811d0561c46bab18295870217a387b112c836e2ea764f9d461889bda70d92d33e484092f4f4fd8e2bd9918e8ba4708e62fee02d60042e7d27ea5828083128a58dcd9d4c66ad51e441e87f2b16a08a58c58b25137a2f41d18460946704b32106c51c5e6fc29b20e396fbba9f0ab81b61951d0f41667b4e55d87179be71b58d8df12a214f8ad12ed836eefa55f8fca6f3c", "b1a898683ef36314401a5fa7264e0cd3e044a658a8ff0ad732b4b8333c415a6ccbfd013110ef9a5e71cbc5edb03f3ece99c366250b6b084127e4ebf2376851346cd6694ed3234509c11fa6710d5a0b989a9494e24bc6349fa9a1f25e1cd0830cac3f5f60b8f57c786a2b1de8a7d6edfaabc230ea62b7ac1ba18c6cb23cacb124ed53d932ef53dbe9e00122c64e4e137e57d9c93037cec96a6e80abf5961460951d0a4721c5a1b55026c5610392fa40811921d4ab36db8da436ef45c0764bed347e776ce1eac13e620860b78ca96f39d82d3a8033a1095ab9e59f9dcd9102ec91e4f3a9928f17739724978fc0a307028a2336009149900193e471adb9dcb683fcfa39b821758d10fdbfd4be404d173f3d3133db29d6b173323f445649fc5e5cbfd81c0e741be34a6bba1422d965d50355277bc0cfd32851700abe24fa4dcfe345dd4f488226c566ed13e76cf75ebc4e2c"],
            ["90865fd1c82d54924720b2c17ddaf02e730898efb14f7dcc25057bd4257983516e6b7c9cdc2ae41dc82b3d08cff4e1ee803ea46a2ef1d3f619c55654ba7d3f91bcff53ddd070218e02ea4540faf92db1a78808c8f347371a382a6472e8c3b1c9a77a5c29adaf6d0444a58de73f8e67d36611c85f948fa352a2a0bec0164ba0aea88e111086bb9a7034eccd788669b39b16c268908bb3805c9d76c20650ee1e3f68026c90fbc2144a442a65dc38e6792201142758991359f0803bc38331b66481b3560c8b187ecc918043cd911bcc79b9607793f7fc015809a82b675ecd261feab3f6910b8c3872d8497cfded44f0b06e6097c82e570ab5a6fe57066a4e2cf4647c0f53118c46b86128e5a84d8607663336ae0d4cc1d3f6c1fdb4b1725ecc49e06ce0a29c9e2387593854f61b97c835f456553b48c03a698f4725d570368e54e7129f8011354a379123cf34b2fdfdaba11d07a3cf23966e70ca8f155fac87d4db9b54ad2686dc07523d25abfa5d4aa1a30deb0c272548787f78d42ee0339a239da76ff926c12479308790a0d4bc1c06ca1497369243c3c6a3bad1bf98bb5afb173093da23381b625ff1dd711ae25f7e4a4b03e587c877e458a86c3e7f3e07e260a0bca9ef8967f2f009f6dda7a3d9c05012141b32f3e85206e5f1b49ecda911d69fe64274dcd31206239f8fb991416f18", "b3a90d13a1aea06ab0f23657652e1203774c1ca5482f5e7c3f9588ded904f025ef64a84897b59f085aab14f185e442a7a2527a32e44505545758490c53496bcd53056dec795aea36db4a15273b61848465ff49cbb0f00b9ccdf2b9c4b520dc4a97849d8cfe37374adff7a4809492cde8f6608e25885fb03bdc14c652dae45cd66ca84386b3e8ab3c9b962e18305e5f964181753fe261806dd826a5c9feaf28bed5b13b2e6577a01091e4b7e0e0147b5d5c8af47de6bdb87f76001a5d84198523d295a3db064ad8d9df7b7905b47ecc682278e9e6b742768990d485b1f5ee1fae9d129d2d60b2af21e7ec9474bbd33fe84a971404974ab5f6350b1d934c567efa22139c168ae7454d34c23d219badc7c127a475df7e46d5e0a378dbe4052b7e235a809086f8505264131fb626dbaf05f52160711661837fbb7e121e05b80d9070af5adf3de3b6d565e4dda23d48d255f052292a8ac81c8d1cd53867b41cf0c365de179443ab669f9818525dd7ccc6fdce372ec409f4caf019b3eb2d97f8f74cc8a1856d371ead99e00d7a35e1689d45ac287b298cccd50839c2f701fed81d697e814ae1954b9b8c2f05082208886293c024c4e30a452d3c9bfcdcc13f2b9b9088879224e7da8d92a96e4e73b70d24ebf2", "ae1b4539afd2bc413edf69955b7ae8a9ab166f7eea0cfa9bf9abbf65b91390229afa2361714d5ebe9c1cd678aab4ad1bae924006732b338d3fe1a87c93efa475017fa3ad08f590d803be8bde0ad2af13b1cba1a7e04f7466e9105f7c7c70d9b592810bfe04ad1a4c0416b57001469234b7f78038463fc8f5d2edfcefa2da3fa29e01202c4796071fb48a05f702ace2a14b2d6daeefb247f631ba35686840b9f68b51531afadcac98b2ef76d3a4bda14435cb894dbd95614f20a6a33adaba925ea4b006c63a50e8df862d8de6471ac1d30592d4ad654002df1f355f1a33440503642f5545e04935bb151ff4cf8ebb06ba3c31403315846b2720041fdddf827966f71bbdc223219a2ff61de8c3ce4fb21d37fcb69a7147ee0e535bdd4383bd0c6a243824a925acec0f816451f0d9fbb8f76c8fb65b79b28f43a18f20d227c3488ac826f39490b16b9c6e08994438f9be6d5634cf444b5206456abc0481ed858075f18c6c959f2bad5bed23d40f0273f5b572eaa4a0ed97ed25473a86e76f6f812915680d67b602cdf438069f51a25a86942a6e5c5d3404f7fcf4ff36e859765e88b8a8133c1fa93815df4face55d15eccd", "a0ac1b725cd8c0342c3d94a00d8973c429d14a1cdc0a20641f09b0194a5d971d37effeeec5c14017b42ff7cef3f9b555933e779e3a403c828c277184971634c22334a95615afc0ddd6077bcdb96b61ba63c066cbd3e58519fa4de0f98ea3f0a98175fa2bd2e0895c4ca58dd6d376d4b987d4b77b3daab2b7074b6b80db06072ee020c451485c4d96fdcaaddf13a53dd04a4fef684933cd47483b05ffd25962e02db8dc6f005eefac572120d247fc5c3f331c335607aef3cd3aa6993584f3410296107b04a7d98d3d42b059eab0efc75b42b3d668ce485ce826a40e56b9ed20454710fbe946a2129ae09c26e8adc6fc8c671c3a95e206bfe45e48545320895ac7cf0a224a6e766db9761aa16a9b662a00141bafc3638847ee075f6cff81fed317f444ea3695edcc8754abcab4291ce0706c412e4007a5ac9c0efdbae01c119999741a0ec79e35176e7823c340a93223ed582f87ebd451de3ed43bbcee05062bdb339ff14d9b3c9d854e9ab4cb1e1573de6cbb72c45c434847ea6b4ea5030b2c693bcbdd34b399c733aef1d4c385fded3f", "92c7ccb952f15b673122be58c54f76949381cfa92343d92d32347073675fe8cabd06ae7fefccb37c7d1c4174be60c140b56a082ca87d12e6a9ea302b74859b96d0688148bc642a44b5c8326a699158aa41e6f59d83e5bccb410736650c8886a2ac517436c69798f7b387958fa5b96ae2fc13af9cf16d8a710a51fc7a1072b926f0b79ae1d8c2316239eacfcd2e11e0311e2e62ea1aa54ebfe4d8640fe3d859709ce7b0340b7b369ab690d491b87cf3da49dae4326e32a9822b3643e5b7ca7abb5f61d50cbfdc8dcafd9f6a0407cda7500567f6e15a7018f1ac2f197b16425592ff291a553ffb4de0de6af2b20b3afe822990b4a2d81eda21391d2674cb37cd1cc1466270410a24441e8ed99dcf34a91c2642a307f860fba3154b9ae06a6f0e3710066413c07669d93cc12951878d61975cf23fc98981ab898a88e908a1223e850bd7c3be819a65b6a6ec5b1c04b7a26d00adf09b811876b5d784142e02b568164d12f0ef54013ba1157568b1e903cbea", "9813c3e94aaaff6fb5a1863ebd349416ef34717f552fe0cc5eaf0980c25f34edd8fd1e63ab6ca2e771a938b2e9ebd8f8a87e16f650953fb638c31ee1fc69bff5a74b71e9b586adf128c58112e3d6747125dcb14a653e1ea8398f3e6f5c95f39cb31855ef53c0507cc4e20e126230be8d8d75d4cb1324b5818e150ed59a036f582ae9f4c0504449f63277c0c4df3f082806a486a347cf2a3f6ca1a609f458b11e8ffcae00e0de5a22854035cd77adb65e3d49507b6354e893518fe39fff510f75d5c75daf201fcd20a9b403f26ec685082584bde691dfa9e96fd78039b4018390ddb8f63043682df42dceada21b4b7b3217b2dc5e537ca801907b8b1afeef14b84c58abf339df9f1aff11ae1ae3a4d2ba263a00c2175bf8924220fce5b6d27dc4a451483503bdcba45be95b67e94cc8c36727ab05f2eaf427b8201663f1ec706f56ad62a8bfc017b34db07c0c8dffe988"],
            ["b5b9f65256c36ad76d19d5d452a826d4af75b2d9350ba316b6ddf913eb7d06743b1098c3ce8009d3d88d30b91f51f13a9435ef08498c4380cd9cb41b904060f62a3f17ba64d105b3d7558267c9fccabfcbdc859bae9aad074a02b9730592be448a409bf438872c5a43ca986dffaf4e1710faa9dfb799c9c29c7b3aec5865ea560872c23b9e8925dab1c9a788a9b25b454390c4a37965d0d94193b3e686814b3dadf1346e49305493841675db73e04b653c21bbea7a63e0c3af1008d6cffeb170470e992bd949d462494ebbc8400b57496cd4044acdb5caea421b65bd5acc58bebe4ba73c60b39d7e96ff2f0d98a3069a3d809665eaf5c69fc2c251e74c606eadb9df68eaec8956b5d80b02e0408e768657293ee0f7931acb240aed55238e4c31009e2dcad049fb701ee4a92f1cfe4f0844f64277b153a3a52f8eb4230ac55852f18c4c3e07a5698eb92f4a9a7939ee350e2e5fbede8684f14c3d7aaf3153b08f1320f1b37281ab02a75fe206b113a66737573929195d5a7b0c586f6f39b3d704ca2cdfab015f5ec7f97b1eb4ca503fc16730da1ebe08d52c5ec6a3809f50a95169c996ab54c76ea45affc35dcd1167003417127e64855d80a2db6f91afd20295341959f24ea236d98724ddb5aca7b5c8243cf02b48c8d77125131ec78b37a8bea1fff9704fe5d3756fe9291be8bd47a1", "b098a27358cebd65b1b93d1ee246b4b0d3520544e490fd9e7c8739d6ae02a99ad3a8ba84f64f45dfa1e62e0883403bc1b433475c2b8d90acf560ae8a7159e470667a7aa76cfdda97e1913e668c4e1122790dc8fa38691851aac825df4a528322918fba2dc2d4b12426798975721b4fbd75b8f6e5664dac6c2cfb739e2c1eed4e299629dfdaff2e535141444b1fe7bf7055f168e72a42c75f7e679e73ddc926b98141b0442682eaa4d484cec33523e4ee6df7b9087d0cdf0145f151ca9ebff79145fe8dd7a307866f205da0652a7aa8232c9a3647df513e982ef1d446024579091f0ff78f5802faddb0ee8dae4cd807471d6cd4ef20391a597f26d87d75a6d9e405d98bc5950ad599632a90386bbdc0c0333a0a07740c1b83d7cd803d7a06fd322d0ced9bd419e9bf8c48f369c12150ca3e78ea8b931a6fda5f427b846d7a4738bf54a5b7093f92305a583bca11405fc8675101e08f620594b3376278e8e7fc7851f64e8de257526e74603a9cc57c5e666418920b3096b6cb3808cfc5112fbf4f9f5461e22acc75e67878727303dc6c33156ef58540c95a101e6d8e21ca5b29ea2d9c64baec0589154d22523ccb70410f11ea839ab617bde6d867f1bf7d525e9d7819a02f2eb7e3b54bf5c36f9c1d3cc5", "90048a815aed7cd81efb4dd7e68b634d74ef6423dc5335443b10d875fe55a298f2abcac3e9f4195ebabdb423b4222e9db2cb1a66861dfb51d58229f7e400aea922e9e6378216db948dcf30931e8177d671b551edeeee40cfe800a726f83a1c63b9a9d3367f0882a1317a29d50af9b132a980aa409807ea60a1bde4abbd01f2b1e093a4e164ba65cc47f4e455473269775453542147f705994d73d980270a0c49ad07d6c978c3e7c6520c7df8b1263518607032c41351ff40a7f34ad523612be8246b93ca4899d2f2c821ccd9d4f827035d9a5b839275f64c56448bb2741f1c301d4a17db614a50901bb1720c573f8eed3efd064efa3792466f62e6d9e653bd292e6e2b2dec0d2aff17bff5e1577da03a177319dc45889ac3f7300b873d20403b0e2faa17acc292d3707133f839f56bfb19a2e57762b4caad11a08ebcc302e211cc50c37d441c763dec2e2b542581b0f95aea5a76d6ed923b92ad3ef16c8336a2d1c0157c4c77bc9e314e1cb572aa562a0868213930a3912b073882136ceaaf1dba502f22b84705e12ab014a298db0662464c869477321365432890f44b3d988d871b30737f9af17c7b951d40ea0df0e4", "8e74ab0cec0b8cd08dbcfb8324153354253fe113d939abe900fc2be2efbb439c9c5ff2935e33833ca9d00f4a0b2742948ab7f7c898fc805d79dec0ae1c12090b7f1e54918dd440a88d099ab6289661d838bc285aa501b194dbe3305915d2d7258e52f7269ad58b81d93425b906639e055b8229d463abcdd835a8efe97a89611741da102cdf2a3fe0a8785bc93e82fe215cab6966d0f0ec8667542d68808f1cbd12b73cbaa0c1665c63313ed42b3f68cf053fa08a225e8208e3a04cefa78926a952e6a5402c5fc38dd9e62cbf699f956c4fba1530bbdecb4f329ae3c33a16206561b0f9617f135fd68aaef74e9a28044230b04246bd3d024da70f91ef837b20076de7ecd033217e6ea658867b3422e05265751908416282a4d231da978ded3c170203c44a1f77ff73fb200484f46d2af637f9aca06e17c14b9de68b16c6e10f9b31d2527c4f52e4b738d7ef93758c1d6103c983a190571e0e38d551fb52c679db7e2acf35c01efdc454cfddf2202efe7f299f771317d38c7ff4033e1cb2097a444d5f933b51695df2ac9a0a75cd600267", "855567a1e9541d5ed2a80ac348899b28e4d9c41d277646e6082cfc6107ea2b3d68533e2bae076aeb7d70293d7689a544884ce184284734d873dac63628710d46e5b5b8e989403a08d32db9bbac161fd7cc2f48b7aa35588507eda2c6667d70b38b90abaaa5d1972afc224d33c2b33098e5e894d37de6fd218ddb77acfa2880e8227bf0c6496c3402a7e0ee2a653295f648be84fa8ef541911241b1619e3fcd0187142703e9d263950bfb50e4ad7a3670541ee1db8c0f296f1c935282f4d3caa6ee8e34c4d206d1150c35a68f791467d36ab395fb79297267de862a7c5b67bb5cfff1686b8b909e3513087a856315defa6d9d1fde1f7a412d2c287fda713172f90be10c060cbefcebe3094157a8283cc72495f3f8e57f79d179f1edbcbb6eaeba7e158b09c18178533554006fab5f43ef66155f344ae2197816eaa5adb53c146bd72c1b8b8d506ba9602d839bb6fdb846587a7ef85202a3107c2729b3d483d827d6d1836696099431edbb33c78f423fac", "8fcf3cd95bac204b12b58a92e0e3f246c74e95adef7ce02d4de56cac02eedd66742fe5c1e742d47cefb703c8f7abe4c9a4a7a5996e90a6b435e4fe3ccfbad462fe7a33a09af334fb21b6e5d2561ca2448a098a1e98f98f6edfb9e53e8bbda4a292da054f2d5dbbc73e77a0051b8c204a35daf92fa2649305a421d905485f331c8035daa9351b95f211493c0cec8915c7219452fc9bb0c661d463c270148d3722a954cdbab2fd9da61146b91c1f464c8862e61950a7fa1fa766f872769758a766bccd28f219f78c489b3e9e43dce6d08272ba8860db1c06e417b3f7697149f95e3de439701ac33d95ee4faf78d22975032b16d27e4239ae4d11e140b98263d89e98034fbe5850b8e1a39938be2086e50152b2a5c2c07762406d24b332b514973221b9e13ec561f9a381a9cc793ec476a62327d150b803fcf344cd0a152264ab488f48062e0e92c2c6b076ed208bfcdc3f"],
        ];

    let gens = create_generator_helper(test_atts.len());

    for i in 0..TEST_KEY_INFOS.len() {
        let pk = PublicKey::from(
            &SecretKey::new(
                TEST_KEY_GEN_IKM.as_ref(),
                TEST_KEY_INFOS[i].as_ref(),
            )
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
