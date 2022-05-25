/*
 * Copyright 2020
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

use super::dtos::BbsDeriveProofRevealMessageRequest;
use crate::bls12_381::bbs::core::{HiddenMessage, Message, ProofMessage};

/// Digests the set of input messages and returns in the form of an internal
/// structure
pub fn digest_messages(messages: Vec<Vec<u8>>) -> Result<Vec<Message>, Error> {
    if messages.len() < 1 {
        return Err(Error::new_bbs_error(
            BbsErrorCode::EmptyMessages,
            "Messages to sign empty, expected > 1",
        ));
    }

    Ok(messages.iter().map(|m| Message::hash(m)).collect())
}

/// Digests a set of supplied proof messages
pub fn digest_proof_messages(
    messages: Vec<BbsDeriveProofRevealMessageRequest>,
) -> Result<Vec<ProofMessage>, Error> {
    if messages.len() < 1 {
        return Err(Error::new_bbs_error(
            BbsErrorCode::EmptyMessages,
            "Messages to sign empty, expected > 1",
        ));
    }

    Ok(messages
        .iter()
        .map(|element| {
            let digested_message = Message::hash(element.value.clone());

            // Change this to an enum
            if element.reveal {
                return ProofMessage::Revealed(digested_message);
            } else {
                return ProofMessage::Hidden(
                    HiddenMessage::ProofSpecificBlinding(digested_message),
                );
            }
        })
        .collect())
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
        return Err(Error::new_bbs_error(
            BbsErrorCode::EmptyMessages,
            "Revealed message index out of bounds, value is >= total_message_count",
        ));
    }

    // TODO deal with the unwrap here and the error response
    Ok(messages
        .iter()
        .map(|(key, value)| (*key, Message::hash(value)))
        .collect())
}

/// Enumeration of error codes
pub enum BbsErrorCode {
    /// Key Generation failed
    KeyGenerationError = 1,
    /// Failed to parse a request element
    ParsingError = 2,
    /// Messages supplied were empty
    EmptyMessages = 3,
    /// Invalid messages
    InvalidMessages = 4,
    /// Invalid signature
    InvalidSignature = 5,
    /// Invalid proof
    InvalidProof = 6,
}

impl Error {
    /// Create a new error
    pub fn new_bbs_error(code: BbsErrorCode, message: &str) -> Self {
        Error::new(code as u32, &String::from(message))
    }
}
