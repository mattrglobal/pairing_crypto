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

#[cfg(not(feature = "alloc"))]
use std::collections::BTreeMap;

use super::dtos::BbsProofGenRevealMessageRequest;
use crate::{
    bbs::{
        ciphersuites::BbsCiphersuiteParameters,
        core::types::{Message, ProofMessage},
    },
    error::Error,
};

/// Digests the set of input messages and returns in the form of an internal
/// structure
pub(crate) fn digest_messages<T, C>(
    messages: Option<&[T]>,
) -> Result<Vec<Message>, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    if let Some(messages) = messages {
        return messages
            .iter()
            .map(|msg| Message::from_arbitrary_data::<C>(msg.as_ref(), None))
            .collect();
    }
    Ok(vec![])
}

/// Digests a set of supplied proof messages
pub(super) fn digest_proof_messages<T, C>(
    messages: Option<&[BbsProofGenRevealMessageRequest<T>]>,
) -> Result<(Vec<Message>, Vec<ProofMessage>), Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    let mut digested_messages = vec![];
    let mut proof_messages = vec![];
    if let Some(messages) = messages {
        for m in messages {
            match Message::from_arbitrary_data::<C>(m.value.as_ref(), None) {
                Ok(digested_message) => {
                    digested_messages.push(digested_message);
                    if m.reveal {
                        proof_messages
                            .push(ProofMessage::Revealed(digested_message))
                    } else {
                        proof_messages
                            .push(ProofMessage::Hidden(digested_message))
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok((digested_messages, proof_messages))
}

pub(crate) fn digest_revealed_proof_messages<T, C>(
    messages: &[(usize, T)],
    total_message_count: usize,
) -> Result<BTreeMap<usize, Message>, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    if messages.is_empty() {
        return Ok(BTreeMap::new());
    }

    let revealed_message_indices: Vec<usize> =
        messages.iter().map(|item| item.0).collect();

    if revealed_message_indices
        .iter()
        .any(|r| *r >= total_message_count)
    {
        return Err(Error::BadParams {
            cause: format!(
                "revealed message index is out of bounds, total_message_count \
                 is {total_message_count}",
            ),
        });
    }

    messages
        .iter()
        .map(|(i, m)| {
            match Message::from_arbitrary_data::<C>(m.as_ref(), None) {
                Ok(m) => Ok((*i, m)),
                Err(e) => Err(e),
            }
        })
        .collect()
}
