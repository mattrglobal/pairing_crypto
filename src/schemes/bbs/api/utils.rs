// Copyright 2020
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ------------------------------------------------------------------------------

use super::dtos::BbsDeriveProofRevealMessageRequest;
use crate::{
    error::Error,
    schemes::bbs::ciphersuites::bls12_381::{
        HiddenMessage,
        Message,
        ProofMessage,
        APP_MESSAGE_DST,
    },
};

/// Digests the set of input messages and returns in the form of an internal
/// structure
pub fn digest_messages(messages: Vec<Vec<u8>>) -> Result<Vec<Message>, Error> {
    if messages.is_empty() {
        return Err(Error::BadParams {
            cause: "message list to sign is empty, expected at least one \
                    message"
                .to_owned(),
        });
    }

    messages
        .iter()
        .map(|msg| Message::hash(msg, APP_MESSAGE_DST))
        .collect()
}

/// Digests a set of supplied proof messages
pub fn digest_proof_messages(
    messages: Vec<BbsDeriveProofRevealMessageRequest>,
) -> Result<Vec<ProofMessage>, Error> {
    if messages.is_empty() {
        return Err(Error::BadParams {
            cause: "message list to sign is empty, expected at least one \
                    message"
                .to_owned(),
        });
    }

    messages
        .iter()
        .map(|element| {
            match Message::hash(element.value.clone(), APP_MESSAGE_DST) {
                Ok(digested_message) => {
                    // Change this to an enum
                    if element.reveal {
                        Ok(ProofMessage::Revealed(digested_message))
                    } else {
                        Ok(ProofMessage::Hidden(
                            HiddenMessage::ProofSpecificBlinding(
                                digested_message,
                            ),
                        ))
                    }
                }
                Err(e) => Err(e),
            }
        })
        .collect()
}

pub fn digest_revealed_proof_messages(
    messages: Vec<(usize, Vec<u8>)>,
    total_message_count: usize,
) -> Result<Vec<(usize, Message)>, Error> {
    let revealed_message_indexes: Vec<usize> =
        messages.iter().map(|item| item.0).collect();

    if revealed_message_indexes
        .iter()
        .any(|r| *r >= total_message_count)
    {
        return Err(Error::BadParams {
            cause: format!(
                "revealed message index is out of bounds, total_message_count \
                 is {}",
                total_message_count
            ),
        });
    }

    messages
        .iter()
        .map(|(i, m)| match Message::hash(m, APP_MESSAGE_DST) {
            Ok(m) => Ok((*i, m)),
            Err(e) => Err(e),
        })
        .collect()
}
