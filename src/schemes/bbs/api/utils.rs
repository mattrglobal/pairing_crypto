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

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

use super::dtos::BbsProofGenRevealMessageRequest;
use crate::{
    error::Error,
    schemes::bbs::ciphersuites::bls12_381::{
        Message,
        ProofMessage,
        MAP_MESSAGE_TO_SCALAR_DST,
    },
};

/// Digests the set of input messages and returns in the form of an internal
/// structure
pub(super) fn digest_messages(
    messages: Option<&Vec<Vec<u8>>>,
) -> Result<Vec<Message>, Error> {
    if let Some(messages) = messages {
        return messages
            .iter()
            .map(|msg| {
                Message::from_arbitrary_data(
                    msg.as_ref(),
                    MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
                )
            })
            .collect();
    }
    Ok(vec![])
}

/// Digests a set of supplied proof messages
pub(super) fn digest_proof_messages(
    messages: Option<&Vec<BbsProofGenRevealMessageRequest>>,
) -> Result<Vec<ProofMessage>, Error> {
    if let Some(messages) = messages {
        return messages
            .iter()
            .map(|element| {
                match Message::from_arbitrary_data(
                    element.value.clone().as_ref(),
                    MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
                ) {
                    Ok(digested_message) => {
                        if element.reveal {
                            Ok(ProofMessage::Revealed(digested_message))
                        } else {
                            Ok(ProofMessage::Hidden(digested_message))
                        }
                    }
                    Err(e) => Err(e),
                }
            })
            .collect();
    }
    Ok(vec![])
}

pub(super) fn digest_revealed_proof_messages(
    messages: Option<&Vec<(usize, Vec<u8>)>>,
    total_message_count: usize,
) -> Result<BTreeMap<usize, Message>, Error> {
    if messages.is_none() {
        return Ok(BTreeMap::new());
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
            match Message::from_arbitrary_data(
                m.as_ref(),
                MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
            ) {
                Ok(m) => Ok((*i, m)),
                Err(e) => Err(e),
            }
        })
        .collect()
}
