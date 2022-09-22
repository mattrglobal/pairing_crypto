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

use super::dtos::BbsBoundProofGenRevealMessageRequest;
use crate::{
    bbs::{
        ciphersuites::BbsCiphersuiteParameters,
        core::types::{Message, ProofMessage},
    },
    error::Error,
};

/// Digests a set of supplied proof messages
pub(super) fn digest_bound_proof_messages<T, C>(
    messages: Option<&[BbsBoundProofGenRevealMessageRequest<T>]>,
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
