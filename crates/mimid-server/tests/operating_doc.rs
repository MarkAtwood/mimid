//! The example configurations in docs/operating.md parse (bead
//! mimid-f8u8): every TOML block of the guide that is a whole server
//! configuration, one starting with `domain =`, is read by
//! [`Config::parse`], the parser `mimid` uses.
//!
//! Oracle: the guide's own text.

use mimid_server::config::Config;

/// The TOML code blocks of `markdown`, in order.
fn toml_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in markdown.lines() {
        match (&mut current, line.trim_start()) {
            (None, "```toml") => current = Some(String::new()),
            (Some(_), "```") => blocks.extend(current.take()),
            (Some(block), _) => {
                block.push_str(line);
                block.push('\n');
            }
            (None, _) => {}
        }
    }
    blocks
}

#[test]
fn the_operators_guide_examples_parse() {
    let guide = include_str!("../../../docs/operating.md");
    let configs: Vec<String> = toml_blocks(guide)
        .into_iter()
        .filter(|block| block.starts_with("domain ="))
        .collect();
    // One provider, then a.example and b.example.
    assert_eq!(configs.len(), 3);
    for config in &configs {
        if let Err(error) = Config::parse(config) {
            panic!("{error}\n{config}");
        }
    }
}
