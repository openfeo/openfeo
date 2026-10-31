// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Our DNS decoder against hickory-proto's (ADR-0015): a message hickory accepts and we refuse
//! is a finding about ours; when both accept, the header, the questions and the section counts
//! must agree. A message we accept and hickory refuses is tolerated: real resolvers produce
//! messages stricter parsers reject.

#![no_main]

use hickory_proto::serialize::binary::BinDecodable;
use libfuzzer_sys::fuzz_target;
use openfeo_proto_dns::Message;

fuzz_target!(|data: &[u8]| {
    let ours = Message::decode(data);
    let theirs = hickory_proto::op::Message::from_bytes(data);
    match (ours, theirs) {
        (Err(err), Ok(_)) => panic!("hickory decodes what we refuse: {err}"),
        (Ok(ours), Ok(theirs)) => {
            assert_eq!(ours.header.id, theirs.id());
            assert_eq!(ours.header.rcode, theirs.response_code().low());
            assert_eq!(ours.questions.len(), theirs.queries().len());
            for (q, their_q) in ours.questions.iter().zip(theirs.queries()) {
                // By label bytes: hickory's text form escapes unusual bytes, ours does not.
                let their_labels: Vec<Vec<u8>> = their_q
                    .name()
                    .iter()
                    .map(|label| label.to_ascii_lowercase())
                    .collect();
                assert_eq!(q.name.labels(), their_labels.as_slice(), "question name");
                assert_eq!(q.qtype, u16::from(their_q.query_type()));
            }
            assert_eq!(ours.answers.len(), theirs.answers().len());
            assert_eq!(ours.authorities.len(), theirs.name_servers().len());
            // hickory lifts the OPT record out of the additionals.
            assert_eq!(
                ours.additionals.len(),
                theirs.additionals().len() + usize::from(theirs.extensions().is_some())
            );
        }
        _ => {}
    }
});
