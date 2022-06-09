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
        MAP_MESSAGE_TO_SCALAR_DST,
    },
};

/// Digests the set of input messages and returns in the form of an internal
/// structure
pub fn digest_messages(
    messages: Option<&Vec<Vec<u8>>>,
) -> Result<Vec<Message>, Error> {
    if let Some(messages) = messages {
        return messages
            .iter()
            .map(|msg| {
                Message::map_to_scalar(
                    msg.as_ref(),
                    MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
                )
            })
            .collect();
    }
    Ok(vec![])
}

/// Digests a set of supplied proof messages
pub fn digest_proof_messages(
    messages: Option<&Vec<BbsDeriveProofRevealMessageRequest>>,
) -> Result<Vec<ProofMessage>, Error> {
    if let Some(messages) = messages {
        return messages
            .iter()
            .map(|element| {
                match Message::map_to_scalar(
                    element.value.clone().as_ref(),
                    MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
                ) {
                    Ok(digested_message) => {
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
            .collect();
    }
    Ok(vec![])
}

pub fn digest_revealed_proof_messages(
    messages: Option<&Vec<(usize, Vec<u8>)>>,
    total_message_count: usize,
) -> Result<Vec<(usize, Message)>, Error> {
    if messages.is_none() {
        return Ok(vec![]);
    }
    let messages = messages.unwrap();

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
        .map(|(i, m)| {
            match Message::map_to_scalar(
                m.as_ref(),
                MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
            ) {
                Ok(m) => Ok((*i, m)),
                Err(e) => Err(e),
            }
        })
        .collect()
}
