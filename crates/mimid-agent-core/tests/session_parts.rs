//! Parts of disposition `session` are calls to join, never attachments
//! to fetch (bead mimid-0p8s; mimi-content-10 §4.4, §5.10;
//! docs/design/agent-frontends.md §7.24).
//!
//! Oracle: mimi-content-10 §5.10's conferencing example, the WG's CBOR
//! committed under crates/mimi-content/tests/fixtures/wg-10.

#![forbid(unsafe_code)]

use mimi_content::{Disposition, MimiContent, NestedPart, Part, PartSemantics};
use mimid_agent_core::ReceivedMessage;

const CONFERENCING: &[u8] =
    include_bytes!("../../mimi-content/tests/fixtures/wg-10/conferencing.cbor");

fn received(content: MimiContent) -> ReceivedMessage {
    ReceivedMessage {
        room: "mimi://example.com/r/engineering_team".to_owned(),
        sender: "mimi://example.com/u/alice-smith".to_owned(),
        message_id: mimi_content::MessageId([0; 32]),
        accepted_at: 0,
        application_data: content.encode().unwrap(),
        content,
        text: None,
        frank: None,
    }
}

#[test]
fn the_conferencing_example_is_a_session_part_and_no_attachment() {
    let message = received(MimiContent::decode(CONFERENCING).unwrap());
    assert!(message.attachments().is_empty());
    let sessions = message.session_parts();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].disposition, Disposition::SESSION);
    let Part::External(part) = &sessions[0].part else {
        panic!("{sessions:?}");
    };
    assert_eq!(part.url, "https://example.com/join/12345");
    assert_eq!(part.description, "Join the Foo 118 conference");
}

#[test]
fn beside_an_attachment_only_the_attachment_is_fetched() {
    let mut content = MimiContent::decode(CONFERENCING).unwrap();
    let session = content.nested_part.clone();
    let mut attachment = session.clone();
    attachment.disposition = Disposition::ATTACHMENT;
    content.nested_part = NestedPart {
        disposition: Disposition::RENDER,
        language: String::new(),
        part: Part::Multi {
            part_semantics: PartSemantics::ProcessAll,
            parts: vec![session, attachment],
        },
    };
    let message = received(content);
    assert_eq!(message.attachments().len(), 1);
    assert_eq!(message.session_parts().len(), 1);
    assert_eq!(message.session_parts()[0].disposition, Disposition::SESSION);
}
