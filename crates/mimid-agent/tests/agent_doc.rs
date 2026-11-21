//! The example configuration in docs/agent.md parses (bead mimid-f8u8):
//! every TOML block of the guide that is a whole agent configuration, one
//! starting with `server_url =`, is read by [`Config::parse`], the parser
//! `mimid-agent` uses.
//!
//! Oracle: the guide's own text.

use mimid_agent::config::Config;

#[test]
fn the_agent_guide_example_parses() {
    let guide = include_str!("../../../docs/agent.md");
    let mut configs = Vec::new();
    let mut current: Option<String> = None;
    for line in guide.lines() {
        match (&mut current, line.trim_start()) {
            (None, "```toml") => current = Some(String::new()),
            (Some(_), "```") => configs.extend(current.take()),
            (Some(block), _) => {
                block.push_str(line);
                block.push('\n');
            }
            (None, _) => {}
        }
    }
    configs.retain(|block| block.starts_with("server_url ="));
    assert_eq!(configs.len(), 1);
    for config in &configs {
        if let Err(error) = Config::parse(config) {
            panic!("{error}\n{config}");
        }
    }
}
