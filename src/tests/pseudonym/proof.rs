use crate::{
    bbs::{
        ciphersuites::bls12_381_g1_shake_256::{
            Bls12381Shake256CipherSuiteParameter,
            Bls12381Shake256InterfaceParameter,
        },
        core::{key_pair::KeyPair, signature::Signature, types::ProofMessage},
    },
    pseudonym::core::{proof::ProofWithNym, pseudonym::Pseudonym},
};
use std::collections::BTreeMap;

use crate::tests::bbs::{
    create_generators_helper,
    get_test_messages,
    TEST_KEY_GEN_IKM,
    TEST_KEY_INFOS,
};

const TEST_PID: &[u8; 14] = b"TEST_PROVER_ID";
const TEST_VID: &[u8; 16] = b"TEST_VERIFIER_ID";

const TEST_API_ID: &[u8; 28] = b"TEST_APPLICATION_IDENTIFIER_";
const TEST_HEADER: &[u8; 16] = b"some_app_context";
const TEST_PRESENTATION_HEADER: &[u8; 15] = b"some_randomness";

mod test_helper {
    use crate::bbs::{
        ciphersuites::bls12_381_g1_shake_256::Bls12381Shake256InterfaceParameter,
        core::types::Message,
        interface::BbsInterfaceParameter,
    };

    pub(super) fn pid_to_message<T: AsRef<[u8]>>(pid: T) -> Message {
        Message::from_arbitrary_data::<
            Bls12381Shake256InterfaceParameter
        >(pid.as_ref(),
            Some(&Bls12381Shake256InterfaceParameter::default_map_message_to_scalar_as_hash_dst())
        ).unwrap()
    }
}

#[test]
fn gen_verify_different_key_pairs() {
    let header = Some(TEST_HEADER.as_ref());
    let ph = Some(TEST_PRESENTATION_HEADER.as_ref());
    let messages = get_test_messages();
    let pid_msg = test_helper::pid_to_message(&TEST_PID);

    let mut messages_with_pid = messages.clone();
    messages_with_pid.push(pid_msg);

    let generators = create_generators_helper(messages.len() + 1);

    for i in 0..TEST_KEY_INFOS.len() {
        let key_pair = KeyPair::new(TEST_KEY_GEN_IKM, TEST_KEY_INFOS[i])
            .expect("key pair generation failed");

        let signature =
            Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.secret_key,
                &key_pair.public_key,
                header,
                &generators,
                &messages_with_pid,
                Some(TEST_API_ID.to_vec()),
            )
            .expect("signature generation failed");

        let verify_res = signature
            .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.public_key,
                header,
                &generators,
                &messages_with_pid,
                Some(TEST_API_ID.to_vec()),
            )
            .expect("signature verification failed");

        assert!(verify_res);

        let mut proof_msgs: Vec<ProofMessage> =
            messages.iter().map(|a| ProofMessage::Hidden(*a)).collect();

        let pseudonym =
            Pseudonym::new::<_, Bls12381Shake256InterfaceParameter>(
                &TEST_VID.as_ref(),
                &TEST_PID.as_ref(),
                Some(TEST_API_ID.to_vec()),
            )
            .expect("failed to calculate pseudonym");

        for j in 0..proof_msgs.len() {
            let proof_with_nym = ProofWithNym::new::<
                _,
                _,
                Bls12381Shake256CipherSuiteParameter,
            >(
                &key_pair.public_key,
                &signature,
                &pseudonym,
                TEST_VID.as_ref(),
                pid_msg,
                header,
                ph,
                &generators,
                &proof_msgs,
                Some(TEST_API_ID.to_vec()),
            )
            .expect("failed to generate proof with pseudonym");

            let mut revealed_msgs = BTreeMap::new();
            for k in 0..j {
                revealed_msgs.insert(k, proof_msgs[k].get_message());
            }

            let proof_verify_res = proof_with_nym
                .verify::<_, _, Bls12381Shake256CipherSuiteParameter>(
                    &key_pair.public_key,
                    &pseudonym,
                    TEST_VID.as_ref(),
                    header,
                    ph,
                    &generators,
                    &revealed_msgs,
                    Some(TEST_API_ID.to_vec()),
                )
                .expect("Proof with nym verification failed unexpectedly");
            assert!(proof_verify_res);

            proof_msgs[j] = ProofMessage::Revealed(messages[j]);
        }
    }
}
